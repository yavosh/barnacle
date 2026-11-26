//! Compare UPX-packed PE32 files with pinned Debian clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;
use client::{Daemon, stream_frame, unix_request};
use std::{fs, io, path::Path};

const PACKED: &[(&str, &[u8])] = &[
    ("nrv2b", include_bytes!("fixtures/upx/ledger-nrv2b.exe")),
    ("nrv2d", include_bytes!("fixtures/upx/ledger-nrv2d.exe")),
    ("nrv2e", include_bytes!("fixtures/upx/ledger-nrv2e.exe")),
];
const UNSUPPORTED: &[(&str, &[u8])] = &[
    ("lzma", include_bytes!("fixtures/upx/ledger-lzma.exe")),
    ("dll", include_bytes!("fixtures/upx/ledger-dll-nrv2b.dll")),
    ("pe32+", include_bytes!("fixtures/upx/ledger64-nrv2b.exe")),
];
// Stock rebuilds the same image from each NRV method.
const UNPACKED: &str = "52bd7b6f5b3a2c728c73c46d48c1ac51:69632:Upx.Unpacked\n";
// This GUI program keeps a resource section and imports from two libraries.
const RICH: &[u8] = include_bytes!("fixtures/upx/rich-nrv2b.exe");
const RICH_UNPACKED: &str = "698e5c674981701552d61d76f56f6bff:73728:Upx.Rich\n";
// NRV2B reads this NRV2D stream past its declared size to an end marker.
const STEERED: &[u8] = include_bytes!("fixtures/upx/ledger-nrv2d-steered.exe");
const LEDGER: &str = "Upx.Ledger:0:*:4261726e61636c6520555058206c6564676572\n";
const UNRELATED: &str = "00000000000000000000000000000000:6:Upx.Unrelated\n";
// Stock checks a buffer that spans the UPX0 and UPX1 sections before it decodes.
const BUFFER: usize = 0x12000;

fn hash(data: &[u8], name: &str) -> io::Result<String> {
    Ok(format!(
        "{}:{}:Upx.{name}\n",
        barnacle::hash_reader(data)?.md5_hex(),
        data.len()
    ))
}

fn virtual_size(bytes: &[u8], section: usize, size: u32) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let optional = u16::from_le_bytes([bytes[pe + 20], bytes[pe + 21]]) as usize;
    let at = pe + 24 + optional + 40 * section + 8;
    bytes[at..at + 4].copy_from_slice(&size.to_le_bytes());
    bytes
}

// Move the pack header and stream one byte later, and point the stub at them.
fn skewed(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    bytes.insert(0x1f0, 0);
    for (at, delta) in [(0xa8, 1), (0x52f3, 1), (0x52f9, -1)] {
        let value = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        bytes[at..at + 4].copy_from_slice(&value.wrapping_add_signed(delta).to_le_bytes());
    }
    bytes
}

fn check(exe: &Path, stock: bool) -> io::Result<()> {
    let root = tempfile::tempdir_in("/tmp")?;
    let db = root.path().join("db");
    fs::create_dir(&db)?;
    let check = |bytes: &[u8], rules: &str, body: &str, extra: &str, want: &str| {
        fs::write(db.join("stock.hdb"), rules)?;
        if !body.is_empty() {
            fs::write(db.join("body.ndb"), body)?;
        }
        let config = root.path().join("conf");
        let sock = root.path().join("s");
        fs::write(
            &config,
            format!(
                "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n{extra}\n",
                db.display(),
                sock.display()
            ),
        )?;
        let daemon = Daemon::start(exe, &config, &sock)?;
        let reply = unix_request(&sock, &stream_frame(bytes)?)?;
        drop(daemon);
        if !body.is_empty() {
            fs::remove_file(db.join("body.ndb"))?;
        }
        let expected = if want == "Miss" {
            if stock {
                "stream: OK\0".into()
            } else {
                "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into()
            }
        } else if want.starts_with("Heuristics.") {
            format!("stream: {want} FOUND\0")
        } else {
            format!("stream: Upx.{want}.UNOFFICIAL FOUND\0")
        };
        assert_eq!(reply, expected, "{extra}, {want}, {} bytes", bytes.len());
        io::Result::Ok(())
    };
    let limit = |name: &str, value: usize| format!("{name} {value}\nAlertExceedsMax yes");
    let exceeded = |name: &str| format!("Heuristics.Limits.Exceeded.{name}");
    for &(_, bytes) in PACKED {
        check(bytes, UNPACKED, "", "", "Unpacked")?;
        check(bytes, UNRELATED, LEDGER, "", "Ledger")?;
        // The raw packed file is matched before its unpacked child.
        let both = hash(bytes, "Packed")? + UNPACKED;
        check(bytes, &both, "", "", "Packed")?;
        check(bytes, UNPACKED, LEDGER, "ScanPE no", "Miss")?;
        let rules = UNPACKED;
        let size = limit("MaxFileSize", BUFFER);
        check(bytes, rules, "", &size, "Unpacked")?;
        let size = limit("MaxFileSize", BUFFER - 1);
        check(bytes, rules, "", &size, &exceeded("MaxFileSize"))?;
        let size = limit("MaxScanSize", bytes.len() + BUFFER);
        check(bytes, rules, "", &size, "Unpacked")?;
        let size = limit("MaxScanSize", bytes.len() + BUFFER - 1);
        check(bytes, rules, "", &size, &exceeded("MaxScanSize"))?;
        let depth = limit("MaxRecursion", 1);
        check(bytes, rules, "", &depth, &exceeded("MaxRecursion"))?;
        check(
            bytes,
            rules,
            "",
            &limit("MaxFiles", 1),
            &exceeded("MaxFiles"),
        )?;
        check(bytes, rules, "", &limit("MaxFiles", 2), "Unpacked")?;
    }
    // Stock rounds each section size up to 0x1000 before it checks the buffer.
    for (section, size, buffer) in [(0, 0xc001, 0x13000), (1, 0x5401, 0x12000)] {
        let bytes = virtual_size(PACKED[0].1, section, size);
        let size = limit("MaxFileSize", buffer);
        check(&bytes, UNPACKED, "", &size, "Unpacked")?;
        let size = limit("MaxFileSize", buffer - 1);
        check(&bytes, UNPACKED, "", &size, &exceeded("MaxFileSize"))?;
    }
    check(RICH, RICH_UNPACKED, "", "", "Rich")?;
    let size = limit("MaxFileSize", 0x13000);
    check(RICH, RICH_UNPACKED, "", &size, "Rich")?;
    let size = limit("MaxFileSize", 0x12fff);
    check(RICH, RICH_UNPACKED, "", &size, &exceeded("MaxFileSize"))?;
    // Stock decodes nothing when the stream starts 0x16 bytes into UPX1.
    // It still checks the buffer first.
    let bytes = skewed(PACKED[0].1);
    check(&bytes, UNPACKED, LEDGER, "", "Miss")?;
    let size = limit("MaxFileSize", 70000);
    check(&bytes, UNPACKED, "", &size, &exceeded("MaxFileSize"))?;
    // Stock builds its image from the NRV2B decoding. Barnacle keeps the file incomplete.
    check(STEERED, UNPACKED, "", "", "Miss")?;
    // Stock does not unpack these files. Barnacle keeps them incomplete.
    for &(_, bytes) in UNSUPPORTED {
        check(bytes, UNPACKED, LEDGER, "", "Miss")?;
    }
    Ok(())
}

#[test]
fn upx_children() -> io::Result<()> {
    check(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_upx_children() -> io::Result<()> {
    check(Path::new("/usr/sbin/clamd"), true)
}
