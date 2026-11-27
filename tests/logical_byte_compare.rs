//! Compare byte-comparison subsignatures with pinned Debian clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;

use client::{Daemon, stream_frame, unix_request};
use std::{fs, io, path::Path};

fn wrap(bytes: &[u8]) -> Vec<u8> {
    [b"\xff\0\x81\x02\xfd\x04\x80\x06".as_slice(), bytes].concat()
}

fn compare(executable: &Path, stock: bool) -> io::Result<()> {
    let temporary = tempfile::tempdir_in("/tmp")?;
    let db = temporary.path().join("db");
    let socket = temporary.path().join("socket");
    let config = temporary.path().join("clamd.conf");
    fs::create_dir(&db)?;
    let run = |expression: &str, children: &str, options: &str, cases: &[(&[u8], bool)]| {
        fs::write(
            &config,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\nSelfCheck 0\n{options}",
                db.display(),
                socket.display()
            ),
        )?;
        let record =
            format!("Logical.Bytes;Engine:100-255,Target:0;{expression};6c6564676572;{children}\n");
        fs::write(db.join("local.ldb"), &record)?;
        let _daemon = Daemon::start(executable, &config, &socket)?;
        for &(bytes, found) in cases {
            let expected = match (stock, found) {
                (_, true) => "stream: Logical.Bytes.UNOFFICIAL FOUND\0",
                (true, false) => "stream: OK\0",
                (false, false) => {
                    "stream: Incomplete scan: unsupported detection coverage. ERROR\0"
                }
            };
            assert_eq!(
                unix_request(&socket, &stream_frame(bytes)?)?,
                expected,
                "{record:?} on {} bytes",
                bytes.len()
            );
        }
        io::Result::Ok(())
    };

    let raw = "ScanHTML no\nScanMail no\n";
    let first = wrap(b"ledger\0\x0b ledger\0\x05");
    let last = wrap(b"ledger\0\x05 ledger\0\x0b");
    let both = wrap(b"ledger\0\x0b ledger\0\x0b");
    run(
        "1",
        "0(>>6#ib2#>10,<12)",
        raw,
        &[
            (&first, false),
            (&last, true),
            (&both, true),
            (&wrap(b"ledger\x0b"), false),
        ],
    )?;
    run("1=2", "0(>>6#ib2#=11)", raw, &[(&both, false)])?;
    run(
        "1",
        "0(<<2#il2#=11)",
        raw,
        &[
            (&wrap(b"\x0b\0ledger"), true),
            (&wrap(b"\0\x0bledger"), false),
        ],
    )?;
    for (format, value, positive, negative) in [
        ("db4", "12", b" 12x".as_slice(), b"21xx".as_slice()),
        ("dbe3", "12", b"+12", b" 12"),
        ("hl3", "0x2f01", b"12f", b"f21"),
        ("ab4", "31", b"0x1f", b"30x0"),
    ] {
        run(
            "1",
            &format!("0(>>6#{format}#={value})"),
            raw,
            &[
                (&wrap(&[b"ledger", positive].concat()), true),
                (&wrap(&[b"ledger", negative].concat()), false),
            ],
        )?;
    }
    run(
        "2",
        "0(>>6#ib2#=11);1/ledger/",
        raw,
        &[(&first, false), (&last, true)],
    )?;
    run(
        "1",
        "0(>>7#ib1#=99)",
        "",
        &[(b"LEDGER  CREDIT", true), (b"LEDGER  DEBIT", false)],
    )?;

    let mut early = wrap(b"ledger\0\x0b");
    early.resize(131_090, b'.');
    early.extend_from_slice(b"ledger\0\x05");
    let mut late = early.clone();
    late[15] = 5;
    *late.last_mut().unwrap() = 11;
    let mut crosses = wrap(&[]);
    crosses.resize(131_065, b'.');
    crosses.extend_from_slice(b"ledger\0\x0b");
    run(
        "1",
        "0(>>6#ib2#=11)",
        raw,
        &[(&early, true), (&late, false), (&crosses, false)],
    )
}

#[test]
fn local_byte_comparisons() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_byte_comparisons() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"), true)
}
