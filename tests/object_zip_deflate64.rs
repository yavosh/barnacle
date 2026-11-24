//! Compare ZIP method 9 with a 7-Zip-authored ledger and small Rust-built archives.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const PACKED: &[u8] = include_bytes!("fixtures/zip/ledger-deflate64.zip");
const SECOND: &[u8] = b"ordinary archive attachment\n";

fn ledger() -> Vec<u8> {
    let mut text = String::new();
    for i in 0..1500 {
        writeln!(text, "Report {i:04}: Unit {:08}", (i * 65537) % 948283).unwrap();
    }
    text.repeat(2).into_bytes()
}

fn rule(name: &str, bytes: &[u8]) -> io::Result<String> {
    let hash = barnacle::hash_reader(bytes)?.md5_hex();
    Ok(format!("{hash}:{}:Zip.{name}\n", bytes.len()))
}

struct Server {
    socket: PathBuf,
    _daemon: daemon::Daemon,
    _dir: tempfile::TempDir,
}

impl Server {
    fn start(exe: &Path, rules: &str, options: &str) -> io::Result<Self> {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join("children.hdb"), rules)?;
        let socket = dir.path().join("daemon.sock");
        let conf = dir.path().join("clamd.conf");
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nTemporaryDirectory {}\nDisableCache yes\n{options}\n",
                db.display(),
                socket.display(),
                dir.path().display(),
            ),
        )?;
        let daemon = daemon::Daemon::start(exe, &conf, &socket)?;
        Ok(Self {
            socket,
            _daemon: daemon,
            _dir: dir,
        })
    }

    fn check(&self, label: &str, sample: &[u8], winner: &str) -> io::Result<()> {
        assert_eq!(
            daemon::unix_request(&self.socket, &daemon::stream_frame(sample)?)?,
            format!("stream: {winner} FOUND\0"),
            "{label}",
        );
        Ok(())
    }
}

fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let data = ledger();
    let first = b"Ordinary notes for an archive member";
    let both = rule("Ledger", &data)? + &rule("Second", SECOND)? + &rule("First", first)?;
    let all = both.clone() + &rule("Outer", PACKED)?;
    let srv = Server::start(exe, &all, "")?;
    srv.check(
        "ledger before archive and later member",
        PACKED,
        "Zip.Ledger.UNOFFICIAL",
    )?;
    let outer = zip::zip(&[("report.zip", PACKED)], true, true, false)?;
    srv.check("nested Deflate64 ledger", &outer, "Zip.Ledger.UNOFFICIAL")?;
    for (a, b, name) in [
        (first.as_slice(), SECOND, "First"),
        (SECOND, first, "Second"),
    ] {
        let arc = zip::zip_with_method(&[("first", a), ("next", b)], 9, true, true)?;
        srv.check(
            "descriptor and reversed directory",
            &arc,
            &format!("Zip.{name}.UNOFFICIAL"),
        )?;
    }
    let short = &first[..first.len() - 3];
    let mut truncated = zip::zip_with_method(&[("note", first)], 9, false, false)?;
    let compressed = u32::from_le_bytes(truncated[18..22].try_into().unwrap());
    truncated[18..22].copy_from_slice(&(compressed - 3).to_le_bytes());
    let srv = Server::start(exe, &rule("Short", short)?, "")?;
    srv.check(
        "truncated final stored block",
        &truncated,
        "Zip.Short.UNOFFICIAL",
    )?;

    let limits = both + &rule("Eight", &data[..8192])? + &rule("Sixteen", &data[..16384])?;
    Server::start(exe, &rule("Second", SECOND)?, "")?.check(
        "later stored member after a Deflate64 miss",
        PACKED,
        "Zip.Second.UNOFFICIAL",
    )?;
    for (option, name) in [
        ("MaxFileSize 16383".into(), "Zip.Eight.UNOFFICIAL"),
        ("MaxFileSize 16384".into(), "Zip.Sixteen.UNOFFICIAL"),
        ("MaxFileSize 81000".into(), "Zip.Ledger.UNOFFICIAL"),
        (
            format!("MaxScanSize {}", PACKED.len() + data.len()),
            "Zip.Ledger.UNOFFICIAL",
        ),
        (
            format!("MaxScanSize {}", PACKED.len() + data.len() - 1),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
        ("MaxFiles 1".into(), "Heuristics.Limits.Exceeded.MaxFiles"),
        (
            "MaxRecursion 1".into(),
            "Heuristics.Limits.Exceeded.MaxRecursion",
        ),
        (
            format!(
                "MaxRecursion 1\nMaxScanSize {}",
                PACKED.len() + data.len() - 1
            ),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
        (
            format!(
                "MaxFiles 1\nMaxRecursion 1\nMaxScanSize {}",
                PACKED.len() + 1
            ),
            "Heuristics.Limits.Exceeded.MaxFiles",
        ),
        ("MaxFiles 2\nMaxRecursion 2".into(), "Zip.Ledger.UNOFFICIAL"),
    ] {
        let srv = Server::start(exe, &limits, &format!("AlertExceedsMax yes\n{option}"))?;
        srv.check(&option, PACKED, name)?;
    }
    for size in [0, 1, 5, 6] {
        let sample =
            zip::zip_with_method(&[("tiny.txt", &b"short note"[..size])], 9, false, false)?;
        for (room, option, limit) in [
            (0, "MaxFiles 1", Some("MaxFiles")),
            (0, "", (size > 5).then_some("MaxScanSize")),
            (0, "MaxRecursion 1", (size > 5).then_some("MaxScanSize")),
            (size, "MaxRecursion 1", (size > 5).then_some("MaxRecursion")),
        ] {
            let options = format!(
                "AlertExceedsMax yes\nMaxScanSize {}\n{option}",
                sample.len() + room
            );
            let srv = Server::start(exe, &limits, &options)?;
            let reply = daemon::unix_request(&srv.socket, &daemon::stream_frame(&sample)?)?;
            let expected = match limit {
                Some(limit) => format!("stream: Heuristics.Limits.Exceeded.{limit} FOUND\0"),
                None if stock => "stream: OK\0".into(),
                None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
            };
            assert_eq!(
                reply, expected,
                "method 9 size={size}, room={room}, {option}"
            );
        }
    }
    Server::start(exe, &all, "ScanArchive no")?.check(
        "disabled parser",
        PACKED,
        "Zip.Outer.UNOFFICIAL",
    )
}

#[test]
fn excluded_deflate64_members_need_no_scratch() -> io::Result<()> {
    use barnacle::objects::{Limit, Options, Verdict, scan};
    let temp = tempfile::tempdir()?;
    let missing = temp.path().join("missing");
    for (files, depth, room, expected) in [
        (10, 10, 73800, Limit::MaxScanSize),
        (10, 1, 73800, Limit::MaxScanSize),
        (1, 1, 73800, Limit::MaxFiles),
        (10, 1, 81000, Limit::MaxRecursion),
    ] {
        let options = Options {
            max_files: files,
            max_recursion: depth,
            max_scan_size: (PACKED.len() + room) as u64,
            scan_html: false,
            alert_exceeds_max: true,
            ..Options::default()
        };
        assert_eq!(
            scan(
                PACKED,
                &options,
                &missing,
                |_, _| Ok(Verdict::Miss),
                || Ok(())
            )?,
            Verdict::Found(expected.signature())
        );
    }
    let options = Options {
        max_scan_size: (PACKED.len() + 81000) as u64,
        ..Options::default()
    };
    assert_eq!(
        scan(
            PACKED,
            &options,
            &missing,
            |_, _| Ok(Verdict::Miss),
            || Ok(())
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::NotFound
    );
    Ok(())
}

#[test]
fn deflate64_checks_cancellation_during_count_and_replay() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    let data = ledger().repeat(2);
    let archive = zip::zip_with_method(&[("year-ledger.txt", &data)], 9, true, false)?;
    let options = Options {
        scan_html: false,
        max_scan_size: (archive.len() + data.len()) as u64,
        ..Options::default()
    };
    let run = |stop| {
        let mut calls = 0;
        let result = scan(
            &archive,
            &options,
            tmp.path(),
            |object, _| {
                Ok(if object.bytes == data {
                    Verdict::Found("Ledger".into())
                } else {
                    Verdict::Miss
                })
            },
            || {
                calls += 1;
                if calls == stop {
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "archive scan cancelled",
                    ))
                } else {
                    Ok(())
                }
            },
        );
        (result, calls)
    };
    let (result, total) = run(0);
    assert_eq!(result?, Verdict::Found("Ledger".into()));
    for stop in 1..=total {
        let error = run(stop).0.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(error.to_string(), "archive scan cancelled");
        assert!(fs::read_dir(tmp.path())?.next().is_none());
    }
    Ok(())
}

#[test]
fn ledger_preserves_member_name_and_parent() -> io::Result<()> {
    use barnacle::objects::{self, Options, Verdict};
    let data = ledger();
    let tmp = tempfile::tempdir()?;
    let verdict = objects::scan(
        PACKED,
        &Options::default(),
        tmp.path(),
        |object, _| {
            if object.bytes != data {
                return Ok(Verdict::Miss);
            }
            assert_eq!(object.parents.len(), 1);
            assert_eq!(object.parents[0].file_type, "CL_TYPE_ZIP");
            assert_eq!(object.layer.name.as_deref(), Some(b"ledger.txt".as_slice()));
            Ok(Verdict::Found("ledger".to_owned()))
        },
        || Ok(()),
    )?;
    assert_eq!(verdict, Verdict::Found("ledger".to_owned()));
    Ok(())
}

#[test]
fn independent_fixture_requires_deflate64() {
    let len = u32::from_le_bytes(PACKED[18..22].try_into().unwrap()) as usize;
    let start = 30 + "ledger.txt".len();
    let mut ordinary = Vec::new();
    let result =
        flate2::read::DeflateDecoder::new(&PACKED[start..start + len]).read_to_end(&mut ordinary);
    assert!(result.is_err() || ordinary != ledger());
}

#[test]
fn method9_children() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires the pinned Debian clamd"]
fn stock_method9_children() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"), true)
}

#[test]
#[ignore = "requires the pinned Debian clamd"]
fn stock_member_names() -> io::Result<()> {
    let server = Server::start(
        Path::new("/usr/sbin/clamd"),
        &rule("Other", b"unrelated note")?,
        "GenerateMetadataJson yes\nLeaveTemporaryFiles yes",
    )?;
    assert_eq!(
        daemon::unix_request(&server.socket, &daemon::stream_frame(PACKED)?)?,
        "stream: OK\0"
    );
    let mut dirs = vec![server._dir.path().to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                dirs.push(entry.path());
            } else if entry.file_name() == "metadata.json" {
                let meta: serde_json::Value = serde_json::from_slice(&fs::read(entry.path())?)?;
                if meta["FileType"] == "CL_TYPE_ZIP" {
                    let children = meta["ContainedObjects"].as_array().unwrap();
                    assert_eq!(children[0]["FileName"], "ledger.txt");
                    assert_eq!(children[1]["FileName"], "second.txt");
                    return Ok(());
                }
            }
        }
    }
    panic!("missing ZIP metadata");
}
