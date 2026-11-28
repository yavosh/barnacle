//! Inert, checksum-bearing receipts for the pinned log heuristic.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
use daemon::{Daemon, stream_frame, unix_request};
use std::{fs, io, path::Path};

const HEURISTIC: &str = "Heuristics.Worm.Mydoom.M.log";
const HASH: &str = "Receipt.Hash.UNOFFICIAL";

fn receipt(total: u32, second_amount: u32) -> Vec<u8> {
    let amounts = [
        1,
        second_amount,
        1,
        1,
        1,
        1,
        total.wrapping_sub(second_amount).wrapping_sub(5),
    ];
    let record: Vec<_> = std::iter::once(total)
        .chain(amounts.map(|amount| amount ^ !total))
        .flat_map(u32::to_be_bytes)
        .collect();
    record.repeat(2)
}

fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let dir = temp.path();
    let db = dir.join("db");
    fs::create_dir(&db)?;
    let binary = receipt(0x00010002, 1);
    let mut competing = binary.clone();
    competing.push(0);
    fs::write(
        db.join("receipts.hdb"),
        format!(
            "{}:{}:Receipt.Hash\n",
            barnacle::hash_reader(competing.as_slice())?.md5_hex(),
            competing.len()
        ),
    )?;
    let mut bad_first = binary.clone();
    bad_first[31] ^= 1;
    let mut bad_second = binary.clone();
    bad_second[63] ^= 1;
    let mut screened = receipt(0x00010002, 0x00010002);
    screened.resize(96, 0);
    let big_endian_text = receipt(0x01000100, 1);
    let little_endian_text = receipt(0xfffe1234, 1);
    let extended_text = (u32::MAX - 6).to_be_bytes().repeat(16);

    for (profile, options, cases) in [
        (
            "default",
            "",
            vec![
                ("binary", binary.as_slice(), Some(HEURISTIC)),
                ("big-endian text", &big_endian_text, Some(HEURISTIC)),
                ("little-endian text", &little_endian_text, None),
                ("extended text", &extended_text, None),
                ("size", &binary[..63], None),
                ("first checksum", &bad_first, None),
                ("second checksum", &bad_second, None),
                ("two screened words", &screened[..95], Some(HEURISTIC)),
                ("three screened words", &screened, None),
                ("competing hash", &competing, Some(HASH)),
            ],
        ),
        (
            "precedence",
            "HeuristicScanPrecedence yes",
            vec![("competing hash", &competing, Some(HEURISTIC))],
        ),
        (
            "disabled",
            "HeuristicAlerts no",
            vec![
                ("binary", &binary, None),
                ("competing hash", &competing, Some(HASH)),
            ],
        ),
    ] {
        let socket = dir.join(format!("{profile}.sock"));
        let config = dir.join(format!("{profile}.conf"));
        fs::write(
            &config,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\nSelfCheck 0\n{options}\n",
                db.display(),
                socket.display()
            ),
        )?;
        let _daemon = Daemon::start(exe, &config, &socket)?;
        for (label, bytes, winner) in cases {
            let expected = match winner {
                Some(name) => format!("stream: {name} FOUND\0"),
                None if stock => "stream: OK\0".to_owned(),
                None => {
                    "stream: Incomplete scan: unsupported detection coverage. ERROR\0".to_owned()
                }
            };
            assert_eq!(
                unix_request(&socket, &stream_frame(bytes)?)?,
                expected,
                "{profile} {label}"
            );
        }
    }
    Ok(())
}

#[test]
fn barnacle_log_receipts() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_log_receipts() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}
