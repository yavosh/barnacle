//! Reference controls for passive PowerPoint external-object records in compound storage.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;
use daemon::{Daemon, stream_frame, unix_request};
use flate2::write::ZlibEncoder;
use std::{
    fs,
    io::{self, Cursor, Write},
    path::Path,
};
const PPT: &str = "PowerPoint Document";
const FIRST: &[u8] = b"A harmless first attachment in a presentation.";
const SECOND: &[u8] = b"A harmless second attachment in the presentation.";
const NATIVE: &str = "\x01Ole10Native";
fn compound(entries: &[(&str, &[u8])]) -> io::Result<Vec<u8>> {
    let mut doc =
        cfb::CompoundFile::create_with_version(cfb::Version::V3, Cursor::new(Vec::new()))?;
    for &(name, data) in entries {
        let path = Path::new(name);
        doc.create_storage_all(path.parent().unwrap())?;
        doc.create_stream(path)?.write_all(data)?;
    }
    Ok(doc.into_inner().into_inner())
}
fn record(instance: u16, kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = (instance << 4).to_le_bytes().to_vec();
    out.extend(kind.to_le_bytes());
    out.extend((data.len() as u32).to_le_bytes());
    out.extend(data);
    out
}
fn encoded(data: &[u8], advertised: u32, instance: u16) -> io::Result<Vec<u8>> {
    let mut z = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(data)?;
    let mut blob = advertised.to_le_bytes().to_vec();
    blob.extend(z.finish()?);
    Ok(record(instance, 0x1011, &blob))
}
fn single(stream: &[u8]) -> io::Result<Vec<u8>> {
    compound(&[(PPT, stream)])
}
fn package(note: &[u8]) -> Vec<u8> {
    let mut native = b"\x02\0note.txt\0note.txt\0\0\0\0\0\0\0\0\0note.txt\0".to_vec();
    native.extend((note.len() as u32).to_le_bytes());
    native.extend(note);
    [(native.len() as u32).to_le_bytes().as_slice(), &native].concat()
}
fn compare(exe: &Path, stock: bool) -> io::Result<Vec<Option<&'static str>>> {
    let mut ordered = Vec::new();
    let tmp = tempfile::tempdir_in("/tmp")?;
    let dir = tmp.path();
    let db = dir.join("db");
    fs::create_dir(&db)?;
    let first = encoded(FIRST, FIRST.len() as u32, 1)?;
    let second = encoded(SECOND, SECOND.len() as u32, 1)?;
    let aside = record(0, 0x0fa0, b"A regular slide text atom");
    let dual = [first.as_slice(), &aside, &second].concat();
    let both = single(&dual)?;
    let rev = single(&[second.as_slice(), &aside, &first].concat())?;
    let inner = compound(&[("Note", FIRST)])?;
    let child = encoded(&inner, inner.len() as u32, 1)?;
    let nested = single(&child)?;
    let plain = single(&record(0, 0x1011, &inner))?;
    let withraw = single(&first)?;
    let other = compound(&[(PPT, &first), ("Sibling", SECOND)])?;
    let lower = compound(&[("Folder/PowerPoint Document", &first), ("Sibling", SECOND)])?;
    let native = package(SECOND);
    let host = compound(&[(PPT, &first), (NATIVE, &native)])?;
    let mut document_container = record(0, 0x03e8, &record(0, 0x03ea, &[]));
    document_container[0] = 0x0f;
    let mut tail = first.clone();
    tail.extend(record(0, 0x03ea, &[]));
    let mut short = first.clone();
    short.extend([1, 0, 4, 0]);
    let big = vec![b'R'; 32768];
    let large = encoded(&big, big.len() as u32, 1)?;
    let huge = single(&large)?;
    let mixed = single(&[large.as_slice(), &second].concat())?;
    let first_small = single(&[second.as_slice(), &large].concat())?;
    let raw_with_outer = [second.as_slice(), &large, &aside].concat();
    let known_outer = single(&raw_with_outer)?;
    let raw_only = [large.as_slice(), &second, &aside].concat();
    let known_raw = single(&raw_only)?;
    let rules = [
        ("MixedWhole", known_outer.as_slice()),
        ("MixedRaw", &raw_with_outer),
        ("OtherRaw", &raw_only),
        ("First", FIRST),
        ("Second", SECOND),
        ("Raw", first.as_slice()),
        ("Whole", &withraw),
        ("Big", &big),
        ("Partial", &big[..8192]),
    ];
    let mut hashes = String::new();
    for (name, data) in rules {
        hashes.push_str(&format!(
            "{}:{}:Ppt.{name}\n",
            barnacle::hash_reader(data)?.md5_hex(),
            data.len()
        ));
    }
    fs::write(db.join("local.hdb"), hashes)?;
    let opts = format!("MaxScanSize {}\nAlertExceedsMax yes", huge.len() + 10000);
    let a = Some("First");
    let b = Some("Second");
    let unique = single(&encoded(SECOND, 0, 1)?)?;
    let zero_declared = single(&encoded(FIRST, 0, 1)?)?;
    let clean = encoded(b"Other harmless attachment", 25, 1)?;
    let folder = compound(&[
        ("Folder/PowerPoint Document", &clean),
        ("Folder/Child", SECOND),
    ])?;
    let no_hit_folder = compound(&[("Folder/PowerPoint Document", &encoded(FIRST, 2, 1)?)])?;
    let files_budget = format!("{opts}\nMaxFiles 1");
    let depth_budget = format!("{opts}\nMaxRecursion 1");
    let all_limits = format!("{files_budget}\nMaxRecursion 1\nMaxFileSize 10000");
    let quiet_opt = opts.replace("yes", "no");
    let mixed_limits = format!(
        "MaxFileSize 10000\nMaxScanSize {}\nAlertExceedsMax yes",
        huge.len() + 10001
    );
    let count_mixed = format!("MaxFiles 1\n{mixed_limits}");
    let depth_mixed = format!("MaxRecursion 1\n{mixed_limits}");
    let count_limit = "Heuristics.Limits.Exceeded.MaxFiles";
    let depth_limit = "Heuristics.Limits.Exceeded.MaxRecursion";
    let byte_limit = "Heuristics.Limits.Exceeded.MaxScanSize";
    for (id, conf, cases) in [
        (
            "mixed-count",
            count_mixed.as_str(),
            vec![
                ("small then large", first_small.clone(), Some(count_limit)),
                ("large then small", mixed.clone(), Some(byte_limit)),
                ("raw only", known_raw.clone(), Some(byte_limit)),
                ("raw and outer", known_outer.clone(), Some("MixedWhole")),
            ],
        ),
        (
            "mixed-depth",
            depth_mixed.as_str(),
            vec![
                ("small then large", first_small, Some(depth_limit)),
                ("large then small", mixed.clone(), Some(byte_limit)),
                ("raw only", known_raw, Some(byte_limit)),
                ("raw and outer", known_outer, Some("MixedWhole")),
            ],
        ),
        (
            "base",
            "",
            vec![
                ("raw stream and outer compete", withraw.clone(), a),
                ("both", both.clone(), a),
                ("reversed", rev, b),
                ("nested CFB", nested.clone(), a),
                ("stored CFB", plain, None),
                ("plain storage", single(&record(0, 0x1011, FIRST))?, None),
                ("wrong declared size", single(&encoded(FIRST, 1, 1)?)?, a),
                (
                    "compressed instance zero",
                    single(&encoded(FIRST, 1, 0)?)?,
                    a,
                ),
                ("zero declared size", zero_declared, a),
                ("other zero declared size", unique, b),
                (
                    "ZIP wraps PPT",
                    zip::zip(&[("notes.ppt", &nested)], true, false, false)?,
                    a,
                ),
                ("sibling stream", other, a),
                (
                    "nested PPT with competing raw root pass",
                    lower,
                    Some("Raw"),
                ),
                ("child of otherwise empty storage", no_hit_folder, a),
                ("nested clean object and matching sibling", folder, b),
                ("root Native Package", host, b),
                ("short trailing header", single(&short)?, a),
                (
                    "ordinary trailing record",
                    single(&[first.as_slice(), &aside].concat())?,
                    a,
                ),
                (
                    "end marker within trailing document container",
                    single(&[first.as_slice(), &document_container].concat())?,
                    a,
                ),
                ("zero-length end marker at top level", single(&tail)?, None),
                (
                    "nested record container",
                    single(&record(0, 0x03e8, &first))?,
                    None,
                ),
            ],
        ),
        (
            "off",
            "ScanOLE2 no",
            vec![
                ("outer", withraw, Some("Whole")),
                ("children", nested.clone(), None),
            ],
        ),
        (
            "archive",
            "ScanArchive no",
            vec![("embedded CFB", nested.clone(), a)],
        ),
        (
            "depth",
            "MaxRecursion 1\nAlertExceedsMax yes",
            vec![(
                "PPT",
                nested.clone(),
                Some("Heuristics.Limits.Exceeded.MaxRecursion"),
            )],
        ),
        (
            "files",
            "MaxFiles 1\nAlertExceedsMax yes",
            vec![("PPT", nested, Some("Heuristics.Limits.Exceeded.MaxFiles"))],
        ),
        (
            "size",
            "MaxFileSize 10000\nAlertExceedsMax yes",
            vec![
                (
                    "large",
                    huge.clone(),
                    Some("Heuristics.Limits.Exceeded.MaxFileSize"),
                ),
                (
                    "large and small",
                    mixed.clone(),
                    Some("Heuristics.Limits.Exceeded.MaxFileSize"),
                ),
            ],
        ),
        (
            "sizequiet",
            "MaxFileSize 10000\nAlertExceedsMax no",
            vec![("large and small", mixed, None)],
        ),
        (
            "budget",
            &opts,
            vec![(
                "large",
                huge.clone(),
                Some("Heuristics.Limits.Exceeded.MaxScanSize"),
            )],
        ),
        (
            "budgetquiet",
            &quiet_opt,
            vec![("large", huge.clone(), None)],
        ),
        (
            "files-over-depth",
            "MaxFiles 1\nMaxRecursion 1\nAlertExceedsMax yes",
            vec![(
                "large",
                huge.clone(),
                Some("Heuristics.Limits.Exceeded.MaxFiles"),
            )],
        ),
        (
            "file-over-count",
            "MaxFiles 1\nMaxFileSize 10000\nAlertExceedsMax yes",
            vec![(
                "large",
                huge.clone(),
                Some("Heuristics.Limits.Exceeded.MaxFileSize"),
            )],
        ),
        (
            "file-over-depth",
            "MaxRecursion 1\nMaxFileSize 10000\nAlertExceedsMax yes",
            vec![(
                "large",
                huge.clone(),
                Some("Heuristics.Limits.Exceeded.MaxFileSize"),
            )],
        ),
        (
            "budget-over-count",
            &files_budget,
            vec![(
                "large",
                huge.clone(),
                Some("Heuristics.Limits.Exceeded.MaxScanSize"),
            )],
        ),
        (
            "budget-over-depth",
            &depth_budget,
            vec![(
                "large",
                huge.clone(),
                Some("Heuristics.Limits.Exceeded.MaxScanSize"),
            )],
        ),
        (
            "all-limits",
            &all_limits,
            vec![(
                "large",
                huge,
                Some("Heuristics.Limits.Exceeded.MaxScanSize"),
            )],
        ),
    ] {
        let cfg = dir.join(format!("{id}.conf"));
        let sock = dir.join(format!("{id}.sock"));
        fs::write(
            &cfg,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nTemporaryDirectory {}\nSelfCheck 0\nDisableCache yes\n{conf}\n",
                db.display(),
                sock.display(),
                dir.display()
            ),
        )?;
        let _service = Daemon::start(exe, &cfg, &sock)?;
        for (label, data, expected) in cases {
            let actual = unix_request(&sock, &stream_frame(&data)?)?;
            let reply = |expected: Option<&str>| match expected {
                Some(h) if h.starts_with("Heuristics.") => format!("stream: {h} FOUND\0"),
                Some(h) => format!("stream: Ppt.{h}.UNOFFICIAL FOUND\0"),
                None if stock => "stream: OK\0".to_owned(),
                None => {
                    "stream: Incomplete scan: unsupported detection coverage. ERROR\0".to_owned()
                }
            };
            // The temporary directory's entry order selects the winner in these controls.
            // The Linux test checks the exact result against the reference on the same filesystem.
            let alternative = match (id, label) {
                ("mixed-count" | "mixed-depth", "small then large") => Some(byte_limit),
                ("mixed-count", "large then small" | "raw only") => Some(count_limit),
                ("mixed-depth", "large then small" | "raw only") => Some(depth_limit),
                ("base", "both" | "nested PPT with competing raw root pass")
                | ("size" | "sizequiet", "large and small") => Some("Second"),
                ("base", "reversed") => Some("First"),
                _ => None,
            };
            if let Some(other) = alternative {
                if actual == reply(Some(other)) {
                    ordered.push(Some(other));
                    continue;
                }
                ordered.push(expected);
            }
            assert_eq!(actual, reply(expected), "{id} {label}");
        }
    }
    Ok(ordered)
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_powerpoint_objects() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    let stock = compare(Path::new("/usr/sbin/clamd"), true)?;
    let candidate = compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)?;
    assert_eq!(candidate, stock);
    Ok(())
}
#[test]
fn barnacle_powerpoint_objects() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false).map(|_| ())
}
#[test]
fn powerpoint_object_name_and_parent() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let temp = tempfile::tempdir()?;
    let text = record(0, 0x0fa0, b"Ordinary slide text");
    let image = single(&[text.as_slice(), &encoded(FIRST, 0, 1)?].concat())?;
    let name = format!("ppt{:08x}.doc", text.len() + 12);
    let zip = zip::zip(&[("presentation.ppt", &image)], true, false, false)?;
    let mut count = 0;
    scan(
        &zip,
        &Options::default(),
        temp.path(),
        |obj, _| {
            if !obj.normalized && obj.bytes == FIRST {
                let chain: Vec<_> = obj.parents.iter().map(|p| p.file_type).collect();
                assert_eq!(chain, ["CL_TYPE_ZIP", "CL_TYPE_MSOLE2"]);
                assert_eq!(obj.layer.name.as_deref(), Some(name.as_bytes()));
                count += 1;
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(count, 1);
    Ok(())
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_powerpoint_container() -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let dir = temp.path();
    let db = dir.join("db");
    fs::create_dir(&db)?;
    let data: String = FIRST.iter().map(|b| format!("{b:02x}")).collect();
    fs::write(
        db.join("parent.ldb"),
        format!(
            "Ppt.Parent;Engine:81-255,Target:0,Container:CL_TYPE_MSOLE2,FileSize:{0}-{0};0;{data}\n",
            FIRST.len()
        ),
    )?;
    let cfg = dir.join("stock.conf");
    let sock = dir.join("sock");
    fs::write(
        &cfg,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nTemporaryDirectory {}\nGenerateMetadataJson yes\nLeaveTemporaryFiles yes\nDisableCache yes\n",
            db.display(),
            sock.display(),
            dir.display()
        ),
    )?;
    let _daemon = Daemon::start(Path::new("/usr/sbin/clamd"), &cfg, &sock)?;
    let file = single(&encoded(FIRST, 0, 1)?)?;
    let zip = zip::zip(&[("presentation.ppt", &file)], true, false, false)?;
    assert_eq!(
        unix_request(&sock, &stream_frame(&zip)?)?,
        "stream: Ppt.Parent.UNOFFICIAL FOUND\0"
    );
    let mut dirs = vec![dir.to_path_buf()];
    let mut named = false;
    while let Some(path) = dirs.pop() {
        for child in fs::read_dir(path)? {
            let child = child?;
            if child.file_type()?.is_dir() {
                dirs.push(child.path());
            } else if child.file_name() == "metadata.json" {
                let meta = fs::read_to_string(child.path())?;
                named |= meta.contains("\"ppt0000000c.doc\"");
            }
        }
    }
    assert!(
        named,
        "missing the original PowerPoint attachment name in stock metadata"
    );
    assert_eq!(unix_request(&sock, &stream_frame(FIRST)?)?, "stream: OK\0");
    Ok(())
}

#[test]
fn powerpoint_scratch_limit_and_cleanup() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    let options = Options {
        max_files: 0,
        ..Options::default()
    };
    let atom = encoded(FIRST, FIRST.len() as u32, 1)?;
    for (count, expected) in [
        (4096, Verdict::Found("Exact".into())),
        (4097, Verdict::Incomplete),
    ] {
        let presentation = single(&atom.repeat(count))?;
        let verdict = scan(
            &presentation,
            &options,
            tmp.path(),
            |obj, _| {
                Ok(if obj.bytes == FIRST {
                    Verdict::Found("Exact".into())
                } else {
                    Verdict::Miss
                })
            },
            || Ok(()),
        )?;
        assert_eq!(verdict, expected);
        assert!(fs::read_dir(tmp.path())?.next().is_none());
    }
    let presentation = single(&atom.repeat(12))?;
    let mut calls = 0;
    let interrupted = scan(
        &presentation,
        &options,
        tmp.path(),
        |_, _| Ok(Verdict::Miss),
        || {
            if fs::read_dir(tmp.path())?.next().is_some() {
                calls += 1;
                if calls == 3 {
                    return Err(io::ErrorKind::Interrupted.into());
                }
            }
            Ok(())
        },
    );
    assert_eq!(interrupted.unwrap_err().kind(), io::ErrorKind::Interrupted);
    assert!(fs::read_dir(tmp.path())?.next().is_none());
    Ok(())
}

#[test]
fn compound_input_and_operational_errors() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let options = Options::default();
    let tmp = tempfile::tempdir()?;
    let record = encoded(FIRST, 0, 1)?;
    let two = single(&record.repeat(2))?;
    let miss =
        |_: barnacle::objects::Object<'_>, _: &mut dyn FnMut() -> io::Result<()>| Ok(Verdict::Miss);
    let error = scan(&two, &options, &tmp.path().join("missing"), miss, || Ok(())).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);

    for (bytes, kind) in [
        (single(&record)?, io::ErrorKind::InvalidData),
        (
            compound(&[(NATIVE, &package(FIRST))])?,
            io::ErrorKind::UnexpectedEof,
        ),
    ] {
        let error = scan(
            &bytes,
            &options,
            tmp.path(),
            |obj, _| {
                if obj.bytes == FIRST {
                    return Err(io::Error::new(kind, "child matcher"));
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), kind);
        assert_eq!(error.to_string(), "child matcher");
    }
    let mut malformed = two;
    // Version 3 requires zero here. The inventory still contains an ordinary presentation.
    malformed[40..44].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        scan(&malformed, &options, tmp.path(), miss, || Ok(()))?,
        Verdict::Incomplete
    );
    Ok(())
}

#[test]
fn powerpoint_blocked_child_skips_inflation() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    let payload = vec![b'R'; 1 << 20];
    let doc = single(&encoded(&payload, 1, 1)?)?;
    for (files, depth, expected) in [
        (0, 17, None),
        (1, 17, Some("MaxFiles")),
        (0, 1, Some("MaxRecursion")),
    ] {
        let options = Options {
            max_files: files,
            max_recursion: depth,
            alert_exceeds_max: true,
            ..Options::default()
        };
        let mut checks = 0;
        let verdict = scan(
            &doc,
            &options,
            tmp.path(),
            |obj, _| {
                Ok(if obj.bytes == payload {
                    Verdict::Found("Child".into())
                } else {
                    Verdict::Miss
                })
            },
            || {
                checks += 1;
                Ok(())
            },
        )?;
        if let Some(limit) = expected {
            assert_eq!(
                verdict,
                Verdict::Found(format!("Heuristics.Limits.Exceeded.{limit}"))
            );
            assert!(checks < 32, "blocked child performed {checks} work checks");
        } else {
            assert_eq!(verdict, Verdict::Found("Child".into()));
            assert!(
                checks >= payload.len() / 8192,
                "inflater checks its work per output block"
            );
        }
    }
    // The expanded size may affect the winner here. Count it without touching scratch.
    let options = Options {
        max_files: 1,
        max_file_size: 150_000,
        alert_exceeds_max: true,
        ..Options::default()
    };
    assert_eq!(
        scan(
            &doc,
            &options,
            &tmp.path().join("missing"),
            |_, _| Ok(Verdict::Miss),
            || Ok(())
        )?,
        Verdict::Found("Heuristics.Limits.Exceeded.MaxFileSize".into())
    );
    Ok(())
}
