#[path = "common/cabinet.rs"]
mod cabinet;
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/legacy.rs"]
mod legacy;
#[path = "common/pe.rs"]
mod pe;
#[path = "common/zip.rs"]
mod zip;

use daemon::{Daemon, stream_frame, unix_request};
use flate2::{Compression, write::GzEncoder};
use md5::{Digest, Md5};
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

const FIRST: &[u8] = b"Harmless first document attachment.";
const SECOND: &[u8] = b"Harmless second document attachment.";
const CONTEXT: &[u8] = b"Container context for the harmless document attachment.";

fn carrier(parts: &[&[u8]]) -> Vec<u8> {
    let mut doc = b"Reference package\0\x01\x02\x03\x04\xff attachments\0".to_vec();
    for part in parts {
        doc.extend(*part);
    }
    doc
}

fn parent_cases() -> io::Result<Vec<(&'static str, Vec<u8>)>> {
    Ok(vec![
        (
            "CL_TYPE_ZIP",
            carrier(&[&zip::zip(&[("one", CONTEXT)], true, false, false)?]),
        ),
        (
            "CL_TYPE_ZIP",
            carrier(&[&zip::zip_with_method(&[("one", CONTEXT)], 9, false, false)?]),
        ),
        (
            "CL_TYPE_MSCAB",
            carrier(&[&cabinet::cabinet(CONTEXT, b"cover", 0)?]),
        ),
        (
            "CL_TYPE_MSCAB",
            carrier(&[&cabinet::cabinet(b"cover page", CONTEXT, 1)?]),
        ),
    ])
}

#[test]
fn parent_map_types() -> io::Result<()> {
    use barnacle::objects::{self, Options, Verdict};
    let temp = tempfile::tempdir()?;
    for (kind, bytes) in parent_cases()? {
        let result = objects::scan(
            &bytes,
            &Options::default(),
            temp.path(),
            |object, _| {
                if object.bytes != CONTEXT {
                    return Ok(Verdict::Miss);
                }
                let layers: Vec<_> = object.parents.iter().map(|p| p.file_type).collect();
                assert_eq!(layers, ["CL_TYPE_BINARY_DATA", kind]);
                Ok(Verdict::Found(kind.to_owned()))
            },
            || Ok(()),
        )?;
        assert_eq!(result, Verdict::Found(kind.to_owned()));
    }
    Ok(())
}

fn compare(exe: &Path) -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let db = tmp.path().join("db");
    fs::create_dir(&db)?;
    let first = zip::zip(&[("first.txt", FIRST)], true, false, false)?;
    let second = zip::zip(&[("second.txt", SECOND)], true, false, false)?;
    let cab = cabinet::cabinet(b"Reference cabinet notes", SECOND, 1)?;
    let outer = carrier(&[b"outer hash ", &first]);
    let pe_child = pe::benign_pe();
    let mut pe_parent = pe_child.clone();
    pe_parent.extend_from_slice(&pe_child);
    let mut pe_outer_match = pe_parent.clone();
    pe_outer_match[512] ^= 1;
    let mut hashes = String::new();
    for (name, bytes) in [
        ("First", FIRST),
        ("Second", SECOND),
        ("Outer", &outer),
        ("CabSuffix", &cab),
        ("PeChild", &pe_child),
        ("PeParent", &pe_outer_match),
    ] {
        let digest: String = Md5::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        hashes.push_str(&format!("{digest}:{}:Embedded.{name}\n", bytes.len()));
    }
    fs::write(db.join("markers.hdb"), hashes)?;
    let hex: String = CONTEXT.iter().map(|b| format!("{b:02x}")).collect();
    let stock = exe == Path::new("/usr/sbin/clamd");
    if stock {
        fs::write(
            db.join("parents.ldb"),
            ["CL_TYPE_ZIP", "CL_TYPE_MSCAB"]
                .map(|kind| {
                    format!("Embedded.{kind};Engine:81-255,Target:0,Container:{kind};0;{hex}\n")
                })
                .concat(),
        )?;
    }
    let simple = carrier(&[&first]);
    let zipped = zip::zip(&[("one", FIRST), ("two", SECOND)], true, false, true)?;
    let cdir = zipped.windows(4).position(|s| s == b"PK\x01\x02").unwrap();
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    gzip.write_all(&simple)?;
    let mut boundary = carrier(&[]);
    boundary.resize(65534, 0);
    boundary.extend(&first);
    let mut zero_prefix = vec![0; 65534];
    zero_prefix.extend(&first);
    let plain_zip = zip::zip(&[("cover", b"Unmarked harmless part")], true, false, false)?;
    let nine = plain_zip.repeat(9);
    let ten = plain_zip.repeat(10);
    let tests = vec![
        (
            "",
            vec![
                ("ZIP document", simple.clone(), Some("First")),
                (
                    "7z attachment",
                    carrier(&[&legacy::sevenzip(false, &[("notes", FIRST)])?]),
                    Some("First"),
                ),
                (
                    "ARJ attachment",
                    carrier(&[&legacy::arj(1, &[FIRST, SECOND])]),
                    Some("First"),
                ),
                (
                    "CAB document, suffix hash",
                    carrier(&[&cab]),
                    Some("Second"),
                ),
                ("ZIP before CAB", carrier(&[&first, &cab]), Some("First")),
                ("CAB before ZIP", carrier(&[&cab, &first]), Some("Second")),
                ("outer hash before embedded ZIP", outer, Some("Outer")),
                ("PE resource suffix", pe_parent.clone(), Some("PeChild")),
                ("outer PE before suffix", pe_outer_match, Some("PeParent")),
                (
                    "reversed central directory",
                    carrier(&[&zipped]),
                    Some("First"),
                ),
                (
                    "local records only",
                    carrier(&[&zipped[..cdir]]),
                    Some("First"),
                ),
                (
                    "independent local headers",
                    carrier(&[&second, &first]),
                    Some("Second"),
                ),
                (
                    "ZIP descriptor requires directory",
                    carrier(&[&zip::zip(&[("one", FIRST)], true, true, false)?]),
                    None,
                ),
                (
                    "earlier Deflate64 ZIP",
                    carrier(&[
                        &zip::zip_with_method(&[("one", FIRST)], 9, false, false)?,
                        &second,
                    ]),
                    Some("First"),
                ),
                (
                    "descriptor skipped before later match",
                    carrier(&[&zip::zip(&[("one", FIRST)], true, true, false)?, &second]),
                    Some("Second"),
                ),
                ("new gzip buffer", gzip.finish()?, Some("First")),
                ("identifier across search chunk", boundary, Some("First")),
                ("zero-padded document", zero_prefix, Some("First")),
                (
                    "tenth offset can be a CAB",
                    carrier(&[&nine, &cab]),
                    Some("Second"),
                ),
                (
                    "non-ZIP offsets limited to ten",
                    carrier(&[&ten, &cab]),
                    None,
                ),
                (
                    "later ZIP offset",
                    carrier(&[&ten, &second]),
                    Some("Second"),
                ),
            ],
        ),
        (
            "ScanArchive no",
            vec![
                ("disabled archive scanning", simple.clone(), None),
                (
                    "PE with archives disabled",
                    pe_parent.clone(),
                    Some("PeChild"),
                ),
            ],
        ),
        (
            "ScanPE no",
            vec![
                ("disabled nested PE", pe_parent.clone(), None),
                ("direct PE with parser disabled", pe_child, Some("PeChild")),
            ],
        ),
        (
            "MaxEmbeddedPE 1024",
            vec![(
                "exact embedded PE limit",
                pe_parent.clone(),
                Some("PeChild"),
            )],
        ),
        (
            "MaxEmbeddedPE 1023",
            vec![("short embedded PE limit", pe_parent.clone(), None)],
        ),
        (
            "MaxEmbeddedPE 0",
            vec![("zero embedded PE limit", pe_parent.clone(), Some("PeChild"))],
        ),
        (
            "MaxFiles 1",
            vec![("carrier consumes one file", simple.clone(), None)],
        ),
        (
            "MaxFiles 2",
            vec![(
                "suffix map does not consume a file",
                simple.clone(),
                Some("First"),
            )],
        ),
        (
            "MaxRecursion 2",
            vec![("member below suffix map", simple.clone(), None)],
        ),
        (
            "MaxRecursion 3",
            vec![("room for suffix and member", simple.clone(), Some("First"))],
        ),
        (
            "MaxRecursion 2\nAlertExceedsMax yes",
            vec![(
                "alert on suffix recursion",
                simple.clone(),
                Some("Heuristics.Limits.Exceeded.MaxRecursion"),
            )],
        ),
        (
            "MaxFiles 1\nAlertExceedsMax yes",
            vec![(
                "alert on file count",
                simple.clone(),
                Some("Heuristics.Limits.Exceeded.MaxFiles"),
            )],
        ),
    ];
    let size = simple.len() + first.len();
    let exact = format!("MaxScanSize {size}");
    let short = format!("MaxScanSize {}", size - 1);
    let short_alert = format!("{short}\nAlertExceedsMax yes");
    let mut tests = tests;
    tests.push((
        &short_alert,
        vec![(
            "alert on suffix size",
            simple.clone(),
            Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        )],
    ));
    if stock {
        for (kind, bytes) in parent_cases()? {
            tests[0]
                .1
                .push(("stock immediate parent", bytes, Some(kind)));
        }
    }
    tests.push((
        &exact,
        vec![(
            "suffix fits the remaining scan budget",
            simple.clone(),
            Some("First"),
        )],
    ));
    tests.push((
        &short,
        vec![("suffix exceeds remaining scan budget", simple, None)],
    ));
    let mut mismatches = Vec::new();
    for (i, (settings, cases)) in tests.into_iter().enumerate() {
        let config = tmp.path().join(format!("daemon-{i}.conf"));
        let socket = tmp.path().join(format!("daemon-{i}.sock"));
        fs::write(
            &config,
            format!(
                "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nTemporaryDirectory {}\nSelfCheck 0\nDisableCache yes\n{settings}\n",
                socket.display(),
                db.display(),
                tmp.path().display()
            ),
        )?;
        let _daemon = Daemon::start(exe, &config, &socket)?;
        for (label, data, signature) in cases {
            let actual = unix_request(&socket, &stream_frame(&data)?)?;
            let expected = match signature {
                Some(name) if name.starts_with("Heuristics.") => format!("stream: {name} FOUND\0"),
                Some(name) => format!("stream: Embedded.{name}.UNOFFICIAL FOUND\0"),
                None if exe == Path::new("/usr/sbin/clamd") => "stream: OK\0".into(),
                None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
            };
            if actual != expected {
                mismatches.push((label, expected, actual));
            }
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:?}");
    Ok(())
}

#[test]
fn embedded_document_attachments() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
#[ignore = "requires Debian clamd 1.4.3+dfsg-1"]
fn stock_document_attachments() -> io::Result<()> {
    let version = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(version.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"))
}
