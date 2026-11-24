//! Small HWP3 documents contain one ordinary paragraph and optional information records.
use super::{ATTACH, Daemon, NEXT, deflate, fs, stream_frame, unix_request, zip};
use std::{io, path::Path};
pub(super) fn contents(records: &[(u32, &[u8])]) -> Vec<u8> {
    let mut out = vec![0; 16]; // Seven font counts, then the style count.
    let text: Vec<_> = "Ordinary paragraph\r".encode_utf16().collect();
    let mut p = [0; 230];
    p[1..3].copy_from_slice(&(text.len() as u16).to_le_bytes());
    p[3] = 1;
    out.extend(p);
    out.extend([0; 14]);
    for c in text {
        out.extend(c.to_le_bytes());
    }
    out.extend([0; 43]); // Empty paragraph ends the list.
    for &(kind, data) in records {
        out.extend(kind.to_le_bytes());
        if kind != 5 {
            out.extend((data.len() as u32).to_le_bytes());
            out.extend(data);
        }
    }
    out.extend([0; 8]);
    out
}
pub(super) fn document(body: &[u8], compressed: bool) -> io::Result<Vec<u8>> {
    let mut out = vec![0; 30 + 128 + 1008];
    out[..30].copy_from_slice(b"HWP Document File V3.00 \x1a\x01\x02\x03\x04\x05");
    out[30 + 124] = u8::from(compressed);
    if compressed {
        out.extend(deflate(body)?);
    } else {
        out.extend(body);
    }
    Ok(out)
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_hwp3() -> io::Result<()> {
    compare_v3(Path::new("/usr/sbin/clamd"), true)
}
pub(super) fn records() -> (Vec<u8>, Vec<u8>) {
    let image = [[0; 32].as_slice(), ATTACH].concat();
    (contents(&[(1, &image), (2, NEXT)]), contents(&[]))
}
fn compare_v3(exe: &Path, stock: bool) -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let dir = temp.path();
    let db = dir.join("db3");
    fs::create_dir(&db)?;
    let (attachments, plain) = records();
    let written = document(&attachments, false)?;
    let compressed = document(&attachments, true)?;
    let only = document(&plain, false)?;
    let mut flags = written.clone();
    flags[30 + 96] = 1;
    let big = contents(&[(2, &vec![b'A'; 24 * 1024])]);
    let mut hashes = String::new();
    for (key, data) in [
        ("Image", ATTACH),
        ("Second", NEXT),
        ("Outer", written.as_slice()),
        ("Content", &plain),
        ("Prefix", &big[..8192]),
        ("Link", &[b'Q'; 325]),
    ] {
        hashes.push_str(&format!(
            "{}:{}:Hwp3.{key}\n",
            barnacle::hash_reader(data)?.md5_hex(),
            data.len()
        ));
    }
    fs::write(db.join("local.hdb"), hashes)?;
    let image = Some("Image");
    let hyper = vec![b'Q'; 325];
    let link = [&[0; 288][..], &hyper, &[0; 4]].concat();
    let background = [&[0; 324][..], NEXT].concat();
    let label_record = contents(&[(5, b""), (0x100, b"ordinary table entry"), (6, &background)]);
    let unknown = contents(&[(55, NEXT)]);
    let mut damaged = compressed.clone();
    damaged.truncate(125);
    for (id, opts, cases) in [
        (
            "on",
            "",
            vec![
                ("stored", written.clone(), image),
                ("deflated", compressed.clone(), image),
                ("paragraph only", only, Some("Content")),
                (
                    "deflated paragraphs",
                    document(&plain, true)?,
                    Some("Content"),
                ),
                ("password flag", flags, None),
                (
                    "nested ZIP",
                    zip::zip(&[("notes.hwp", &compressed)], true, false, false)?,
                    image,
                ),
                (
                    "hyperlink data area",
                    document(&contents(&[(3, &link)]), true)?,
                    Some("Link"),
                ),
                (
                    "background image",
                    document(&label_record, false)?,
                    Some("Second"),
                ),
                (
                    "OLE data field",
                    document(&contents(&[(2, NEXT)]), true)?,
                    Some("Second"),
                ),
                (
                    "unknown information record",
                    document(&unknown, true)?,
                    Some("Second"),
                ),
                ("truncated document", damaged, None),
            ],
        ),
        (
            "off",
            "ScanHWP3 no",
            vec![
                ("outer", written, Some("Outer")),
                ("deflated", compressed.clone(), None),
            ],
        ),
        (
            "ole",
            "ScanOLE2 no",
            vec![("image", compressed.clone(), image)],
        ),
        (
            "archive",
            "ScanArchive no",
            vec![("image", compressed.clone(), image)],
        ),
        (
            "rec",
            "MaxRecursion 1\nAlertExceedsMax yes",
            vec![(
                "attachment",
                compressed.clone(),
                Some("Heuristics.Limits.Exceeded.MaxRecursion"),
            )],
        ),
        (
            "hwprec",
            "MaxRecHWP3 0\nAlertExceedsMax yes",
            vec![("attachment", compressed, None)],
        ),
        (
            "size",
            "MaxFileSize 8192\nAlertExceedsMax yes",
            vec![(
                "raw decompression prefix",
                document(&big, true)?,
                Some("Prefix"),
            )],
        ),
    ] {
        let conf = dir.join(format!("{id}.conf"));
        let sock = dir.join(format!("{id}.sock"));
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\n{opts}\n",
                db.display(),
                sock.display()
            ),
        )?;
        let _daemon = Daemon::start(exe, &conf, &sock)?;
        for (name, data, expected) in cases {
            let r = unix_request(&sock, &stream_frame(&data)?)?;
            let expected = match expected {
                Some(h) if h.starts_with("Heuristics.") => format!("stream: {h} FOUND\0"),
                Some(h) => format!("stream: Hwp3.{h}.UNOFFICIAL FOUND\0"),
                None if stock => "stream: OK\0".to_owned(),
                None => {
                    "stream: Incomplete scan: unsupported detection coverage. ERROR\0".to_owned()
                }
            };
            assert_eq!(r, expected, "{id} {name}");
        }
    }
    Ok(())
}
#[test]
fn barnacle_hwp3() -> io::Result<()> {
    compare_v3(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
fn hwp3_attachment_parent() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let dir = tempfile::tempdir()?;
    let bytes = document(&records().0, true)?;
    let zip = zip::zip(&[("ordinary.hwp", &bytes)], true, false, false)?;
    let mut found = false;
    scan(
        &zip,
        &Options::default(),
        dir.path(),
        |object, _| {
            if !object.normalized && object.bytes == ATTACH {
                let chain: Vec<_> = object.parents.iter().map(|p| p.file_type).collect();
                assert_eq!(chain, ["CL_TYPE_ZIP", "CL_TYPE_HWP3"]);
                assert!(object.layer.name.is_none());
                found = true;
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert!(found);
    Ok(())
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_hwp3_attachment_parent() -> io::Result<()> {
    let dir = tempfile::tempdir_in("/tmp")?;
    let root = dir.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let hex: String = ATTACH.iter().map(|b| format!("{b:02x}")).collect();
    fs::write(
        db.join("parent.ldb"),
        format!(
            "Hwp3.Parent;Engine:81-255,Target:0,Container:CL_TYPE_HWP3,FileSize:{0}-{0};0;{hex}\n",
            ATTACH.len()
        ),
    )?;
    let conf = root.join("stock.conf");
    let sock = root.join("sock");
    fs::write(
        &conf,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\n",
            db.display(),
            sock.display()
        ),
    )?;
    let _service = Daemon::start(Path::new("/usr/sbin/clamd"), &conf, &sock)?;
    let zip = zip::zip(
        &[("ordinary.hwp", &document(&records().0, true)?)],
        true,
        false,
        false,
    )?;
    assert_eq!(
        unix_request(&sock, &stream_frame(&zip)?)?,
        "stream: Hwp3.Parent.UNOFFICIAL FOUND\0"
    );
    assert_eq!(unix_request(&sock, &stream_frame(ATTACH)?)?, "stream: OK\0");
    Ok(())
}
