//! Paired scanner controls for ordinary HWP compound streams and embedded documents.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;
use daemon::{Daemon, stream_frame, unix_request};
use std::{
    fs,
    io::{self, Cursor, Write},
    path::Path,
};
const ATTACH: &[u8] = b"A harmless attachment from the binary document.";
const NEXT: &[u8] = b"An ordinary second attachment, stored separately.";
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
fn header(flags: u32) -> Vec<u8> {
    let mut h = vec![0; 256];
    h[..17].copy_from_slice(b"HWP Document File");
    h[32..36].copy_from_slice(&0x05000302u32.to_le_bytes());
    h[36..40].copy_from_slice(&flags.to_le_bytes());
    h
}
fn deflate(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut w = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    w.write_all(bytes)?;
    w.finish()
}
fn body() -> Vec<u8> {
    let letters: Vec<u8> = "Ordinary paragraph text.\r"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut out = (67u32 | ((letters.len() as u32) << 20))
        .to_le_bytes()
        .to_vec();
    out.extend(&letters);
    out
}
fn wrap(doc: &[u8], advertised: u32) -> Vec<u8> {
    [advertised.to_le_bytes().as_slice(), doc].concat()
}
fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let dir = tmp.path();
    let db = dir.join("db");
    fs::create_dir(&db)?;
    let plain = header(0);
    let packed = header(1);
    let para = body();
    let zpara = deflate(&para)?;
    let zbin = deflate(ATTACH)?;
    let mut short = plain[..17].to_vec();
    short.extend([0; 3]);
    let document = compound(&[
        ("FileHeader", &packed),
        ("BodyText/Section0", &zpara),
        ("BinData/BIN0001.bin", &zbin),
    ])?;
    let stored = compound(&[
        ("FileHeader", &plain),
        ("BodyText/Section0", &para),
        ("BinData/BIN0001.bin", ATTACH),
    ])?;
    let part = compound(&[("Notes", NEXT)])?;
    let wrapper = wrap(&part, part.len() as u32);
    let nested = compound(&[
        ("FileHeader", &packed),
        ("BinData/BIN0001.ole", &deflate(&wrapper)?),
    ])?;
    let mut special = header(1);
    special[80] = 41;
    let reserved = compound(&[("FileHeader", &special), ("BinData/BIN0002.bin", &zbin)])?;
    let big = vec![b'P'; 32768];
    let bigz = deflate(&big)?;
    let bulk = compound(&[
        ("FileHeader", &packed),
        ("Section0", &bigz),
        ("Section1", &zbin),
    ])?;
    let some = |h: &[u8], name: &str, data: &[u8]| compound(&[("FileHeader", h), (name, data)]);
    let mut hashes = String::new();
    for (name, bytes) in [
        ("Body", para.as_slice()),
        ("Attach", ATTACH),
        ("Second", NEXT),
        ("Packed", zbin.as_slice()),
        ("Header", &special),
        ("Outer", &document),
        ("Large", &big),
        ("Prefix", &big[..8192]),
    ] {
        hashes.push_str(&format!(
            "{}:{}:Hwp.{name}\n",
            barnacle::hash_reader(bytes)?.md5_hex(),
            bytes.len()
        ));
    }
    fs::write(db.join("local.hdb"), hashes)?;
    let budgets = format!("MaxScanSize {}\nAlertExceedsMax yes", bulk.len() + 1024);
    let hit = Some("Attach");
    let expanded = some(&packed, "Section0", &bigz)?;
    for (id, opts, cases) in [
        (
            "baseline",
            "",
            vec![
                (
                    "ordinary FileHeader",
                    some(b"Other format data", "Notes", ATTACH)?,
                    hit,
                ),
                ("short signature", some(&short, "Section0", ATTACH)?, hit),
                (
                    "stored paragraph",
                    some(&plain, "BodyText/Section0", &para)?,
                    Some("Body"),
                ),
                (
                    "compressed paragraph",
                    some(&packed, "BodyText/Section0", &zpara)?,
                    Some("Body"),
                ),
                (
                    "compressed attachment",
                    some(&packed, "BinData/BIN0001.bin", &zbin)?,
                    hit,
                ),
                (
                    "stored attachment",
                    some(&plain, "BinData/BIN0001.bin", ATTACH)?,
                    hit,
                ),
                ("stored order", stored, Some("Body")),
                ("outer vs decoded", document, Some("Body")),
                ("header vs attachment", reserved, Some("Header")),
                (
                    "different stream under BinData",
                    some(&packed, "BinData/Notes", &zbin)?,
                    Some("Packed"),
                ),
                (
                    "compressed DocInfo",
                    some(&packed, "DocInfo", &zpara)?,
                    Some("Body"),
                ),
                ("preview as-is", some(&packed, "PrvText", ATTACH)?, hit),
                ("invalid deflate", some(&packed, "Section0", ATTACH)?, None),
                (
                    "nested FileHeader",
                    compound(&[("Folder/FileHeader", &packed), ("Folder/Section0", &zpara)])?,
                    Some("Body"),
                ),
                (
                    "compressed flag with password flag",
                    some(&header(3), "BodyText/Section0", &zbin)?,
                    Some("Packed"),
                ),
                (
                    "opaque password-flagged data",
                    some(&header(2), "Section0", b"fixed opaque fixture bytes")?,
                    None,
                ),
                ("embedded OLE", nested.clone(), Some("Second")),
                ("prefixed CFB", wrapper.clone(), Some("Second")),
                ("mismatched prefix", wrap(&part, 1), Some("Second")),
                (
                    "ZIP parent",
                    zip::zip(&[("notes.hwp", &nested)], true, false, false)?,
                    Some("Second"),
                ),
            ],
        ),
        (
            "ole",
            "ScanOLE2 no",
            vec![
                ("HWP5", nested.clone(), None),
                ("wrapper", wrapper.clone(), None),
            ],
        ),
        (
            "disable3",
            "ScanHWP3 no",
            vec![
                ("HWP5", nested.clone(), Some("Second")),
                ("wrapper", wrapper.clone(), Some("Second")),
            ],
        ),
        (
            "xml",
            "ScanXMLDOCS no",
            vec![("HWP5", nested.clone(), Some("Second"))],
        ),
        (
            "depth",
            "MaxRecursion 1\nAlertExceedsMax yes",
            vec![
                (
                    "HWP5",
                    nested.clone(),
                    Some("Heuristics.Limits.Exceeded.MaxRecursion"),
                ),
                (
                    "wrapper",
                    wrapper,
                    Some("Heuristics.Limits.Exceeded.MaxRecursion"),
                ),
            ],
        ),
        (
            "count",
            "MaxFiles 1\nAlertExceedsMax yes",
            vec![("HWP5", nested, Some("Heuristics.Limits.Exceeded.MaxFiles"))],
        ),
        (
            "size",
            "MaxFileSize 8192\nAlertExceedsMax yes",
            vec![
                ("next stream may still win", bulk.clone(), hit),
                ("inflated prefix", expanded, Some("Prefix")),
            ],
        ),
        (
            "budget",
            &budgets,
            vec![("next stream may still win", bulk, hit)],
        ),
    ] {
        let conf = dir.join(format!("{id}.conf"));
        let sock = dir.join(format!("{id}.sock"));
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nSelfCheck 0\nDisableCache yes\n{opts}\n",
                db.display(),
                sock.display()
            ),
        )?;
        let _daemon = Daemon::start(exe, &conf, &sock)?;
        for (label, bytes, expected) in cases {
            let actual = unix_request(&sock, &stream_frame(&bytes)?)?;
            let expected = match expected {
                Some(h) if h.starts_with("Heuristics.") => format!("stream: {h} FOUND\0"),
                Some(h) => format!("stream: Hwp.{h}.UNOFFICIAL FOUND\0"),
                None if stock => "stream: OK\0".to_owned(),
                None => {
                    "stream: Incomplete scan: unsupported detection coverage. ERROR\0".to_owned()
                }
            };
            assert_eq!(actual, expected, "{id} {label}");
        }
    }
    Ok(())
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_hwp() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}
#[test]
fn barnacle_hwp() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
fn compound_stream_parent_names() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    for (flags, name) in [(0, Some(b"bin0001.bin".as_slice())), (1, None)] {
        let input = if flags == 0 {
            ATTACH.to_vec()
        } else {
            deflate(ATTACH)?
        };
        let hwp = compound(&[
            ("FileHeader", &header(flags)),
            ("BinData/BIN0001.bin", &input),
        ])?;
        let wrapped = wrap(&hwp, hwp.len() as u32);
        let mut seen = false;
        scan(
            &wrapped,
            &Options::default(),
            tmp.path(),
            |object, _| {
                if !object.normalized && object.bytes == ATTACH {
                    let chain: Vec<_> = object.parents.iter().map(|p| p.file_type).collect();
                    assert_eq!(chain, ["CL_TYPE_HWPOLE2", "CL_TYPE_MSOLE2"]);
                    assert_eq!(object.layer.name.as_deref(), name);
                    seen = true;
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert!(seen);
    }
    Ok(())
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_hwp_parent() -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let dir = tmp.path();
    let db = dir.join("db");
    fs::create_dir(&db)?;
    let data: String = ATTACH.iter().map(|b| format!("{b:02x}")).collect();
    fs::write(
        db.join("parents.ldb"),
        format!("Hwp.Parent;Engine:81-255,Target:0,Container:CL_TYPE_MSOLE2;0;{data}\n"),
    )?;
    let conf = dir.join("s.conf");
    let sock = dir.join("sock");
    fs::write(
        &conf,
        format!(
            "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n",
            db.display(),
            sock.display()
        ),
    )?;
    let _daemon = Daemon::start(Path::new("/usr/sbin/clamd"), &conf, &sock)?;
    let doc = compound(&[
        ("FileHeader", &header(1)),
        ("BinData/BIN0001.bin", &deflate(ATTACH)?),
    ])?;
    assert_eq!(
        unix_request(&sock, &stream_frame(&wrap(&doc, doc.len() as u32))?)?,
        "stream: Hwp.Parent.UNOFFICIAL FOUND\0"
    );
    assert_eq!(unix_request(&sock, &stream_frame(ATTACH)?)?, "stream: OK\0");
    Ok(())
}

#[path = "object_hwp/v3.rs"]
mod v3;
