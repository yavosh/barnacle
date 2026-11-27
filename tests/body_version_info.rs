//! VI offsets on passive PE resource images with no code or entry point.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/pe.rs"]
mod pe;
use std::{fs, io, path::Path};

fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}
fn put32(bytes: &mut [u8], pos: usize, n: u32) {
    bytes[pos..pos + 4].copy_from_slice(&n.to_le_bytes());
}
fn block(key: &str, value: &[u8], text: bool, children: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = vec![0; 6];
    let units = if text { value.len() / 2 } else { value.len() };
    buf[2..4].copy_from_slice(&(units as u16).to_le_bytes());
    buf[4] = text.into();
    buf.extend(wide(key));
    buf.resize(buf.len().next_multiple_of(4), 0);
    buf.extend(value);
    for child in children {
        buf.resize(buf.len().next_multiple_of(4), 0);
        buf.extend(child);
    }
    let size = buf.len() as u16;
    buf[..2].copy_from_slice(&size.to_le_bytes());
    buf
}
fn version(fields: &[(&str, &str)]) -> Vec<u8> {
    let entries = fields
        .iter()
        .map(|(k, v)| block(k, &wide(v), true, &[]))
        .collect::<Vec<_>>();
    let table = block("040904B0", &[], true, &entries);
    let info = block("StringFileInfo", &[], true, &[table]);
    let mut fixed = [0; 52];
    fixed[..8].copy_from_slice(&[0xbd, 4, 0xef, 0xfe, 0, 0, 1, 0]);
    block("VS_VERSION_INFO", &fixed, false, &[info])
}
fn image(leaves: &[Vec<u8>], plus: bool) -> Vec<u8> {
    let mut image = pe::benign_pe();
    let data = (80 + leaves.len() * 24).next_multiple_of(4);
    let size = (data
        + leaves
            .iter()
            .map(|v| v.len().next_multiple_of(4))
            .sum::<usize>())
    .next_multiple_of(512);
    image.resize(512 + size, 0);
    image[512..].fill(0);
    let (section, dirs) = if plus {
        image.copy_within(376..416, 392);
        image[376..392].fill(0);
        image[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
        image[148..150].copy_from_slice(&240u16.to_le_bytes());
        image[152..154].copy_from_slice(&0x20bu16.to_le_bytes());
        image[176..184].copy_from_slice(&0x140000000u64.to_le_bytes());
        put32(&mut image, 152 + 108, 16);
        (392, 112)
    } else {
        (376, 96)
    };
    image[section..section + 8].copy_from_slice(b".rsrc\0\0\0");
    put32(&mut image, section + 8, size as u32);
    put32(&mut image, section + 16, size as u32);
    put32(
        &mut image,
        152 + 56,
        (4096 + size).next_multiple_of(4096) as u32,
    );
    put32(&mut image, 152 + dirs + 16, 4096);
    put32(&mut image, 152 + dirs + 20, size as u32);
    let tree = &mut image[512..];
    for (pos, id, next) in [(0, 16, 32), (32, 1, 64)] {
        tree[pos + 14] = 1;
        put32(tree, pos + 16, id);
        put32(tree, pos + 20, 0x80000000 | next);
    }
    tree[78..80].copy_from_slice(&(leaves.len() as u16).to_le_bytes());
    let mut payload = data;
    for (i, leaf) in leaves.iter().enumerate() {
        let entry = 80 + leaves.len() * 8 + i * 16;
        put32(tree, 80 + i * 8, 0x409 + i as u32);
        put32(tree, 84 + i * 8, entry as u32);
        put32(tree, entry, 4096 + payload as u32);
        put32(tree, entry + 4, leaf.len() as u32);
        tree[payload..payload + leaf.len()].copy_from_slice(leaf);
        payload += leaf.len().next_multiple_of(4);
    }
    image
}
fn compare(executable: &Path, stock: bool) -> io::Result<()> {
    if stock {
        let package = std::process::Command::new("dpkg-query")
            .args(["-W", "-f=${Version}", "clamav-daemon"])
            .output()?;
        assert_eq!(package.stdout, b"1.4.3+dfsg-1");
    }
    let run = |rules: &str, ndb: bool, cases: &[(&[u8], Option<&str>)]| -> io::Result<()> {
        let temp = tempfile::tempdir_in("/tmp")?;
        let p = temp.path();
        let sock = p.join("sock");
        let conf = p.join("clamd.conf");
        let db = p.join("db");
        fs::create_dir(&db)?;
        fs::write(
            db.join(if ndb { "local.ndb" } else { "local.ldb" }),
            format!("{rules}\n"),
        )?;
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nSelfCheck 0\nDisableCache yes\n",
                db.display(),
                sock.display()
            ),
        )?;
        let _daemon = daemon::Daemon::start(executable, &conf, &sock)?;
        for &(bytes, name) in cases {
            let expected = match name {
                Some(n) => format!("stream: Ledger.{n}.UNOFFICIAL FOUND\0"),
                None if stock => "stream: OK\0".to_owned(),
                None => {
                    "stream: Incomplete scan: unsupported detection coverage. ERROR\0".to_owned()
                }
            };
            assert_eq!(
                daemon::unix_request(&sock, &daemon::stream_frame(bytes)?)?,
                expected,
                "{rules}"
            );
        }
        Ok(())
    };
    let info = version(&[
        ("CompanyName", "Example Ledger"),
        ("ProductName", "Invoice"),
    ]);
    let i = image(std::slice::from_ref(&info), false);
    let i64 = image(&[info], true);
    let blank = pe::benign_pe();
    let text = |name: &str, body: &str| format!("Ledger.{name};Engine:81-255,Target:1;0;{body}");
    let body = |s: &str| {
        wide(s)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let key = &body("CompanyName");
    let val = &body("Example Ledger");
    run(
        &text("Key", &format!("VI:{key}")),
        false,
        &[(&i, Some("Key")), (&i64, Some("Key")), (&blank, None)],
    )?;
    run(
        &text("Shift", &format!("VI,512:{val}")),
        false,
        &[(&i, None)],
    )?;
    run(
        &text("Value", &format!("*:{val}")),
        false,
        &[(&i, Some("Value"))],
    )?;
    run(
        &text("Both", "VI:43006f00*50007200"),
        false,
        &[(&i, Some("Both"))],
    )?;
    run(
        &text("OnlyFirst", "VI:43006f00*45007800"),
        false,
        &[(&i, None)],
    )?;
    run("Ledger.Short:1:VI:4300", true, &[(&i, Some("Short"))])?;
    run(
        "Ledger.Key:1:VI:43006f006d00\nLedger.Header:1:*:4d5a0000",
        true,
        &[(&i, Some("Header"))],
    )?;
    run(
        "Ledger.Regex;Engine:81-255,Target:1;1;4d5a;VI,1:0/MZ/e",
        false,
        &[(&blank, Some("Regex")), (&i, Some("Regex"))],
    )?;
    let leaves = (0..17)
        .map(|n| {
            version(&[(
                if n == 15 {
                    "Selected"
                } else if n == 16 {
                    "Skipped"
                } else {
                    "CompanyName"
                },
                "Odd",
            )])
        })
        .collect::<Vec<_>>();
    let localized = image(&leaves, false);
    run(
        &text("Sixteen", &format!("VI:{}", body("Selected"))),
        false,
        &[(&localized, Some("Sixteen"))],
    )?;
    run(
        &text("Seventeen", &format!("VI:{}", body("Skipped"))),
        false,
        &[(&localized, None)],
    )?;
    let short = image(&[version(&[("ProductName", "FR")])], false);
    let padded = image(
        &[version(&[("ProductName", "FR"), ("Comments", "Odd")])],
        false,
    );
    run(
        &text("Last", &format!("VI:{}", body("ProductName"))),
        false,
        &[(&short, None), (&padded, Some("Last"))],
    )?;
    Ok(())
}
#[test]
fn local_version_information() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_version_information() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"), true)
}
