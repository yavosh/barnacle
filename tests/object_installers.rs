//! Compare inert PE documents containing ordinary installer resources.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/pe.rs"]
mod pe;

use daemon::{Daemon, stream_frame, unix_request};
use flate2::{Compression, write::ZlibEncoder};
use md5::{Digest, Md5};
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

const FIRST: &[u8] = include_bytes!("fixtures/installers/first.txt");
const SECOND: &[u8] = include_bytes!("fixtures/installers/second.txt");
const HEADER: &[u8] = b"Ordinary installer header notes for the reference comparison.";
const CONTEXT: &[u8] = b"Ordinary installer child parent context notes.";

fn pe_overlay(resource: &[u8]) -> Vec<u8> {
    let mut bytes = pe::benign_pe();
    bytes.extend(resource);
    bytes
}

fn nsis(entries: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::from(0u32.to_le_bytes());
    bytes.extend(b"\xef\xbe\xad\xdeNullsoftInst");
    bytes.extend((entries.first().map_or(0, |entry| entry.len()) as u32).to_le_bytes());
    bytes.extend([0; 4]);
    for entry in entries {
        bytes.extend((entry.len() as u32).to_le_bytes());
        bytes.extend(*entry);
    }
    bytes.extend([0; 4]);
    let size = bytes.len() as u32;
    bytes[24..28].copy_from_slice(&size.to_le_bytes());
    bytes
}

fn ishield(entries: &[(&[u8], &[u8])]) -> io::Result<Vec<u8>> {
    let mut bytes = b"InstallShield\0".to_vec();
    bytes.extend((entries.len() as u32).to_le_bytes());
    bytes.resize(46, 0);
    for &(name, data) in entries {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        let packed = encoder.finish()?;
        let mut descriptor = [0; 312];
        descriptor[..name.len()].copy_from_slice(name);
        descriptor[260] = 6;
        descriptor[268..276].copy_from_slice(&(packed.len() as u64).to_le_bytes());
        descriptor[280] = 1;
        bytes.extend(descriptor);
        for (i, byte) in packed.into_iter().enumerate() {
            let index = (i % 1024) % name.len();
            let key = name[index] ^ [0xec, 0xca, 0x79, 0xf8][index % 4];
            bytes.push((byte ^ key).rotate_left(4));
        }
    }
    Ok(bytes)
}

fn legacy_shield(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut data = Vec::new();
    for &(name, bytes) in entries {
        data.extend(name);
        data.extend(b"\0docs\0v1\0");
        data.extend(bytes.len().to_string().bytes());
        data.push(0);
        data.extend(bytes);
    }
    data.extend([0; 4]);
    let mut image = pe::benign_pe();
    image.resize(1536, 0);
    image[134..136].copy_from_slice(&2u16.to_le_bytes());
    image[208..212].copy_from_slice(&12288u32.to_le_bytes());
    let (first, last) = image.split_at_mut(416);
    last[..40].copy_from_slice(&first[376..416]);
    last[..5].copy_from_slice(b".more");
    last[12..16].copy_from_slice(&8192u32.to_le_bytes());
    last[20..24].copy_from_slice(&1024u32.to_le_bytes());
    image.extend(data);
    image
}

fn compare(exe: &Path) -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let db = temp.path().join("db");
    fs::create_dir(&db)?;
    let with_hash = pe_overlay(&nsis(&[b"header", FIRST]));
    let ordinary_pe = pe::benign_pe();
    let large_header = vec![b'q'; 4096];
    let mut compressor = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
    compressor.write_all(&large_header)?;
    let compressed = compressor.finish()?;
    let mut resource = nsis(&[&compressed, b"ordinary member"]);
    resource[20..24].copy_from_slice(&(large_header.len() as u32).to_le_bytes());
    resource[31] |= 0x80;
    let limited_header = pe_overlay(&resource);
    let exact = format!("MaxScanSize {}", limited_header.len() + large_header.len());
    let short = format!(
        "MaxScanSize {}",
        limited_header.len() + large_header.len() - 1
    );
    let mut hashes = String::new();
    for (name, data) in [
        ("First", FIRST),
        ("Second", SECOND),
        ("Header", HEADER),
        ("Outer", &with_hash),
        ("Pe", &ordinary_pe),
        ("LargeHeader", &large_header),
    ] {
        let hash: String = Md5::digest(data)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        hashes.push_str(&format!("{hash}:{}:Installer.{name}\n", data.len()));
    }
    fs::write(db.join("markers.hdb"), hashes)?;
    let hex: String = CONTEXT.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut rules = String::new();
    for (name, kind) in [
        ("NsisParent", "CL_TYPE_NULSFT"),
        ("ShieldParent", "CL_TYPE_ISHIELD_MSI"),
        ("LegacyParent", "CL_TYPE_MSEXE"),
    ] {
        rules.push_str(&format!(
            "Installer.{name};Engine:81-255,Target:0,Container:{kind};0;{hex}\n"
        ));
    }
    let stock = exe == Path::new("/usr/sbin/clamd");
    if stock {
        fs::write(db.join("parent.ldb"), rules)?;
    }
    let normal = pe_overlay(&nsis(&[b"unmarked header", FIRST, SECOND]));
    let shield = pe_overlay(&ishield(&[(b"report.txt", FIRST), (b"other.txt", SECOND)])?);
    let legacy = legacy_shield(&[(b"first.txt", FIRST), (b"second.txt", SECOND)]);
    let mut cases = vec![
        ("NSIS stored", normal.clone(), "First"),
        (
            "NSIS first of two",
            pe_overlay(&nsis(&[b"unmarked header", SECOND, FIRST])),
            "Second",
        ),
        (
            "NSIS header hash",
            pe_overlay(&nsis(&[HEADER, FIRST])),
            "Header",
        ),
        (
            "NSIS header context",
            pe_overlay(&nsis(&[CONTEXT, FIRST])),
            "NsisParent",
        ),
        (
            "NSIS child context",
            pe_overlay(&nsis(&[b"unmarked header", CONTEXT])),
            "NsisParent",
        ),
        ("NSIS outer hash", with_hash, "Outer"),
        ("InstallShield", shield.clone(), "First"),
        ("legacy InstallShield", legacy.clone(), "First"),
        (
            "one-section legacy carrier",
            pe_overlay(&legacy[1536..]),
            "",
        ),
        (
            "legacy normal members precede cabinets",
            legacy_shield(&[(b"data1.cab", SECOND), (b"first.txt", FIRST)]),
            "First",
        ),
        (
            "legacy InstallShield context",
            legacy_shield(&[(b"report.txt", CONTEXT)]),
            "LegacyParent",
        ),
        (
            "InstallShield context",
            pe_overlay(&ishield(&[(b"report.txt", CONTEXT)])?),
            "ShieldParent",
        ),
    ];
    let resources = [
        (
            "zlib blocks",
            include_bytes!("fixtures/installers/zlib-blocks.bin").as_slice(),
        ),
        (
            "zlib solid",
            include_bytes!("fixtures/installers/zlib-solid.bin").as_slice(),
        ),
        (
            "LZMA blocks",
            include_bytes!("fixtures/installers/lzma-blocks.bin").as_slice(),
        ),
        (
            "LZMA solid",
            include_bytes!("fixtures/installers/lzma-solid.bin").as_slice(),
        ),
        (
            "bzip2 blocks",
            include_bytes!("fixtures/installers/bzip2-blocks.bin").as_slice(),
        ),
        (
            "bzip2 solid",
            include_bytes!("fixtures/installers/bzip2-solid.bin").as_slice(),
        ),
    ];
    for (label, resource) in resources {
        cases.push((
            label,
            pe_overlay(resource),
            if label == "zlib solid" { "" } else { "First" },
        ));
    }
    let last_only_cases = resources
        .into_iter()
        .map(|(label, resource)| {
            (
                label,
                pe_overlay(resource),
                if label == "zlib solid" { "" } else { "Second" },
            )
        })
        .chain([
            ("later InstallShield file", shield.clone(), "Second"),
            ("later legacy file", legacy.clone(), "Second"),
        ])
        .collect();
    let mut groups = vec![
        ("", cases),
        (
            &exact,
            vec![("exact header budget", limited_header.clone(), "LargeHeader")],
        ),
        (&short, vec![("short header budget", limited_header, "")]),
        (
            "ScanArchive no",
            vec![
                ("NSIS disabled", normal.clone(), ""),
                ("InstallShield disabled", shield, ""),
                (
                    "legacy independent of archive parser",
                    legacy.clone(),
                    "First",
                ),
            ],
        ),
        (
            "ScanPE no",
            vec![
                ("NSIS independent of PE parser", normal.clone(), "First"),
                ("ordinary PE hash", ordinary_pe, "Pe"),
                ("legacy requires PE parsing", legacy, ""),
            ],
        ),
        (
            "MaxFiles 1",
            vec![(
                "header at file limit",
                pe_overlay(&nsis(&[HEADER, FIRST])),
                "",
            )],
        ),
        ("MaxFiles 2", vec![("file count", normal.clone(), "First")]),
        (
            "MaxFiles 3",
            vec![("file count with member", normal.clone(), "First")],
        ),
        (
            "MaxRecursion 2",
            vec![
                ("depth limit", normal.clone(), ""),
                (
                    "header at depth limit",
                    pe_overlay(&nsis(&[HEADER, FIRST])),
                    "",
                ),
            ],
        ),
        ("MaxRecursion 3", vec![("room for member", normal, "First")]),
    ];
    let last_only = groups.len();
    groups.push(("", last_only_cases));
    let mut mismatches = Vec::new();
    for (i, (settings, cases)) in groups.into_iter().enumerate() {
        if i == last_only {
            let rule = fs::read_to_string(db.join("markers.hdb"))?;
            let second = rule
                .lines()
                .find(|line| line.ends_with(":Installer.Second"))
                .expect("second marker");
            fs::write(db.join("markers.hdb"), format!("{second}\n"))?;
        }
        let config = temp.path().join(format!("daemon-{i}.conf"));
        let socket = temp.path().join(format!("daemon-{i}.sock"));
        fs::write(
            &config,
            format!(
                "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nTemporaryDirectory {}\nSelfCheck 0\nDisableCache yes\n{settings}\n",
                socket.display(),
                db.display(),
                temp.path().display()
            ),
        )?;
        let _daemon = Daemon::start(exe, &config, &socket)?;
        for (label, content, expected) in cases {
            if !stock && expected.ends_with("Parent") {
                continue;
            }
            let response = unix_request(&socket, &stream_frame(&content)?)?;
            let expected = if expected.is_empty() && !stock {
                // A PE container still has other unimplemented detection stages.
                "stream: Incomplete scan: unsupported detection coverage. ERROR\0".to_owned()
            } else if expected.is_empty() {
                "stream: OK\0".to_owned()
            } else {
                format!("stream: Installer.{expected}.UNOFFICIAL FOUND\0")
            };
            if response != expected {
                mismatches.push(format!(
                    "{label}: expected {expected:?}, received {response:?}"
                ));
            }
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    Ok(())
}

#[test]
fn installer_parents() -> io::Result<()> {
    use barnacle::objects::{self, Options, Verdict};
    let temp = tempfile::tempdir()?;
    for (kind, payload) in [
        ("CL_TYPE_NULSFT", nsis(&[CONTEXT, b"other"])),
        ("CL_TYPE_NULSFT", nsis(&[b"header", CONTEXT])),
        ("CL_TYPE_ISHIELD_MSI", ishield(&[(b"report.txt", CONTEXT)])?),
    ] {
        let verdict = objects::scan(
            &pe_overlay(&payload),
            &Options::default(),
            temp.path(),
            |object, _| {
                if object.bytes != CONTEXT {
                    return Ok(Verdict::Miss);
                }
                let parents: Vec<_> = object.parents.iter().map(|layer| layer.file_type).collect();
                assert_eq!(parents, ["CL_TYPE_MSEXE", kind]);
                Ok(Verdict::Found("context".into()))
            },
            || Ok(()),
        )?;
        assert_eq!(verdict, Verdict::Found("context".into()));
    }
    Ok(())
}

#[test]
fn installer_resources() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
#[ignore = "requires Debian clamd 1.4.3+dfsg-1"]
fn stock_installer_resources() -> io::Result<()> {
    let package = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(package.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"))
}
