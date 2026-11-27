//! Compare local logical signatures with pinned Debian clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;
#[path = "common/pe.rs"]
mod pe;
#[path = "common/zip.rs"]
mod zip;

use client::{Daemon, stream_frame, unix_request};
use std::{fs, io, path::Path};

const ANY: &str = "Engine:81-255,Target:0";
const CREDIT: &str = "637265646974";
const DEBIT: &str = "6465626974";
const LEDGER: &str = "6c6564676572";
const NOTE: &[u8] = b"ordinary credit ledger note";

fn logical(name: &str, target: &str, expression: &str, children: &str) -> String {
    format!("Logic.{name};{target};{expression};{children}\n")
}

fn compare(executable: &Path, stock: bool) -> io::Result<()> {
    let temporary = tempfile::tempdir_in("/tmp")?;
    let db = temporary.path().join("db");
    let socket = temporary.path().join("socket");
    let config = temporary.path().join("clamd.conf");
    fs::create_dir(&db)?;
    fs::write(
        &config,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\nSelfCheck 0\n",
            db.display(),
            socket.display()
        ),
    )?;

    let run = |rules: &str, body: &str, hashes: &str, cases: &[(&[u8], Option<&str>)]| {
        fs::write(db.join("local.ldb"), rules)?;
        if !body.is_empty() {
            fs::write(db.join("local.ndb"), body)?;
        }
        if !hashes.is_empty() {
            fs::write(db.join("local.hdb"), hashes)?;
        }
        let daemon = Daemon::start(executable, &config, &socket)?;
        for &(bytes, winner) in cases {
            let expected = match winner {
                Some(name) => format!("stream: Logic.{name}.UNOFFICIAL FOUND\0"),
                None if stock || bytes.len() <= 5 => "stream: OK\0".into(),
                None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
            };
            assert_eq!(
                unix_request(&socket, &stream_frame(bytes)?)?,
                expected,
                "{rules:?} on {} bytes",
                bytes.len()
            );
        }
        drop(daemon);
        if !body.is_empty() {
            fs::remove_file(db.join("local.ndb"))?;
        }
        if !hashes.is_empty() {
            fs::remove_file(db.join("local.hdb"))?;
        }
        io::Result::Ok(())
    };

    let notes = format!("{CREDIT};{DEBIT};{LEDGER}");
    run(
        &(logical("Right", ANY, "0&1|2", &notes) + &logical("Grouped", ANY, "(0&1|2)", &notes)),
        "",
        "",
        &[
            (b"ordinary ledger note", Some("Grouped")),
            (NOTE, Some("Right")),
            (b"ordinary receipt note", None),
        ],
    )?;
    run(
        &logical(
            "Occurrences",
            ANY,
            "(0|1)=2,2",
            &format!("{CREDIT};{DEBIT}"),
        ),
        "",
        "",
        &[
            (b"credit then debit", Some("Occurrences")),
            (b"credit then credit", None),
            (b"credit debit debit", None),
        ],
    )?;
    run(
        &logical("Duplicate", ANY, "(0|1)=2,2", &format!("{CREDIT};{CREDIT}")),
        "",
        "",
        &[(NOTE, Some("Duplicate")), (b"credit then credit", None)],
    )?;
    run(
        &logical("Overlap", ANY, "0=2", "61616161"),
        "",
        "",
        &[(b"note aaaaa note", Some("Overlap")), (b"aaaaa", None)],
    )?;
    run(
        &logical("Absent", ANY, "(0&1)=0", &format!("{CREDIT};{DEBIT}")),
        "",
        "",
        &[
            (NOTE, Some("Absent")),
            (b"ordinary receipt note", Some("Absent")),
            (b"credit then debit", None),
        ],
    )?;

    let by_offset = logical(
        "Offset",
        &format!("{ANY},FileSize:{0}-{0}", NOTE.len()),
        "0",
        &format!("9:{CREDIT}"),
    );
    run(
        &by_offset,
        "",
        "",
        &[
            (NOTE, Some("Offset")),
            (b"extraordinary credit ledger note", None),
        ],
    )?;

    let nested = zip::zip(&[("receipt.txt", NOTE)], true, false, false)?;
    assert!(!nested.windows(6).any(|bytes| bytes == b"credit"));
    run(
        &logical("Root", &format!("{ANY},Container:CL_TYPE_ANY"), "0", CREDIT),
        "",
        "",
        &[(NOTE, Some("Root")), (&nested, None)],
    )?;

    run(
        &logical(
            "InZip",
            &format!("{ANY},Container:CL_TYPE_ZIP"),
            "0",
            CREDIT,
        ),
        "",
        "",
        &[(NOTE, None), (&nested, Some("InZip"))],
    )?;
    let basic = logical("Logical", ANY, "0", CREDIT);
    let html = b"<html><body>ordinary CREDIT ledger note</body></html>";
    run(
        &basic,
        "",
        "",
        &[(NOTE, Some("Logical")), (html, Some("Logical"))],
    )?;

    // The unmapped script pass uses the source size and skips generic relative offsets.
    let upper = b"LEDGER  CREDIT";
    run(
        &logical("GenericEof", ANY, "0", &format!("EOF-6:{CREDIT}")),
        "",
        "",
        &[(upper, None)],
    )?;
    run(
        &logical(
            "SourceSize",
            &format!("{ANY},FileSize:14-14"),
            "0",
            &format!("7:{CREDIT}"),
        ),
        "",
        "",
        &[(upper, Some("SourceSize"))],
    )?;
    let ascii = "Engine:81-255,Target:7";
    run(
        &logical(
            "Mapped",
            &format!("{ascii},FileSize:13-13,Container:CL_TYPE_ANY"),
            "0",
            &format!("EOF-6:{CREDIT}"),
        ),
        "",
        "",
        &[(upper, Some("Mapped"))],
    )?;

    let zero = logical(
        "OriginalZero",
        &format!("{ascii},FileSize:14-14"),
        "0=0",
        CREDIT,
    );
    let space = b"LEDGER  credit";
    run(&zero, "", "", &[(space, None)])?;
    let map_trigger = logical("MapTrigger", ascii, "0", "EOF-6:7a7a7a7a");
    run(
        &(zero + &map_trigger),
        "",
        "",
        &[(space, Some("OriginalZero"))],
    )?;

    let hashes = format!(
        "{}:{}:Logic.Hash\n",
        barnacle::hash_reader(NOTE)?.md5_hex(),
        NOTE.len()
    );
    run(&basic, "", &hashes, &[(NOTE, Some("Hash"))])?;
    run(
        &basic,
        &format!("Logic.Body:0:*:{CREDIT}\n"),
        &hashes,
        &[(NOTE, Some("Body"))],
    )?;
    let mut executable = pe::benign_pe();
    executable[600..606].copy_from_slice(b"credit");
    run(
        &(basic + &logical("Typed", "Engine:81-255,Target:1", "0", CREDIT)),
        "",
        "",
        &[(&executable, Some("Typed"))],
    )
}

#[test]
fn local_logical_signatures() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_logical_signatures() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"), true)
}
