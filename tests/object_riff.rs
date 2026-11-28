//! Compare payload-free RIFF headers with pinned Debian clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;

use std::{fs, io, path::Path};

const ALERT: &str = "Heuristics.Exploit.W32.MS05-002";

fn integer(value: u32, big: bool) -> [u8; 4] {
    if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

fn cursor(big: bool, short: bool, group: Option<&[u8; 4]>) -> Vec<u8> {
    // The positive contains a zero-length header and no cursor or instruction payload.
    let mut chunk = b"anih".to_vec();
    let size = if short { 0 } else { 36 };
    chunk.extend(integer(size, big));
    chunk.resize(8 + size as usize, 0);
    if let Some(kind) = group {
        let mut group = kind.to_vec();
        group.extend(integer(4 + chunk.len() as u32, big));
        group.extend(b"fram");
        group.extend(chunk);
        chunk = group;
    }
    let mut bytes = if big { b"RIFX" } else { b"RIFF" }.to_vec();
    bytes.extend(integer(4 + chunk.len() as u32, big));
    bytes.extend(b"ACON");
    bytes.extend(chunk);
    bytes
}

fn compare(executable: &Path, miss: &str) -> io::Result<()> {
    let mut cases = Vec::new();
    for big in [false, true] {
        for short in [false, true] {
            for group in [
                None,
                Some(b"LIST"),
                Some(b"PROP"),
                Some(b"FORM"),
                Some(b"CAT "),
            ] {
                cases.push((cursor(big, short, group), short));
            }
        }
        let mut followed = cursor(big, false, None);
        followed.extend(b"anih\0\0\0\0");
        let size = followed.len() as u32 - 8;
        followed[4..8].copy_from_slice(&integer(size, big));
        cases.push((followed, true));
        let mut padded = cursor(big, true, None);
        let padding = [b"note".as_slice(), &integer(1, big), b"x\0"].concat();
        padded.splice(12..12, padding);
        let size = padded.len() as u32 - 8;
        padded[4..8].copy_from_slice(&integer(size, big));
        cases.push((padded, true));
    }
    for heuristics in [false, true] {
        for immediate in [false, true] {
            for raw in [0, 1, 2] {
                let root = tempfile::tempdir_in("/tmp")?;
                let db = root.path().join("db");
                fs::create_dir(&db)?;
                fs::write(
                    db.join("receipt.ndb"),
                    if raw == 1 {
                        "Receipt.Riff:0:8:41434f4e\n"
                    } else {
                        "Receipt.Unused:0:0:72656365697074207061706572\n"
                    },
                )?;
                if raw == 2 {
                    let mut hashes = String::new();
                    for (bytes, _) in &cases {
                        hashes += &format!(
                            "{}:{}:Receipt.Hash\n",
                            barnacle::hash_reader(bytes.as_slice())?.md5_hex(),
                            bytes.len()
                        );
                    }
                    fs::write(db.join("receipt.hdb"), hashes)?;
                }
                let socket = root.path().join("sock");
                let config = root.path().join("clamd.conf");
                fs::write(
                    &config,
                    format!(
                        "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\nHeuristicAlerts {}\nHeuristicScanPrecedence {}\nScanImage no\nScanArchive no\n",
                        db.display(),
                        socket.display(),
                        if heuristics { "yes" } else { "no" },
                        if immediate { "yes" } else { "no" }
                    ),
                )?;
                let _daemon = daemon::Daemon::start(executable, &config, &socket)?;
                for (index, (bytes, short)) in cases.iter().enumerate() {
                    let name = if heuristics && *short && (immediate || raw == 0) {
                        Some(ALERT)
                    } else {
                        match raw {
                            1 => Some("Receipt.Riff.UNOFFICIAL"),
                            2 => Some("Receipt.Hash.UNOFFICIAL"),
                            _ => None,
                        }
                    };
                    let expected = name
                        .map_or_else(|| miss.to_owned(), |name| format!("stream: {name} FOUND\0"));
                    assert_eq!(
                        daemon::unix_request(&socket, &daemon::stream_frame(bytes)?)?,
                        expected,
                        "heuristics={heuristics}, immediate={immediate}, raw={raw}, case={index}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn riff_headers() -> io::Result<()> {
    compare(
        Path::new(env!("CARGO_BIN_EXE_barnacle")),
        "stream: Incomplete scan: unsupported detection coverage. ERROR\0",
    )
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_riff_headers() -> io::Result<()> {
    let package = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert!(package.status.success());
    assert_eq!(package.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), "stream: OK\0")
}
