//! Pinned comparisons of harmless UDF images and independent optical-image authoring controls.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;
use daemon::{Daemon, stream_frame, unix_request};
use flate2::read::GzDecoder;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

const SECTOR: usize = 2048;
const FIRST: &[u8] = b"Ordinary UDF text from the first member";
const SECOND: &[u8] = b"Ordinary UDF text from the second member";
fn put16(data: &mut [u8], at: usize, v: u16) {
    data[at..at + 2].copy_from_slice(&v.to_le_bytes())
}
fn put32(data: &mut [u8], at: usize, v: u32) {
    data[at..at + 4].copy_from_slice(&v.to_le_bytes())
}
fn tag(record: &mut [u8], id: u16, pos: u32, n: usize) {
    put16(record, 0, id);
    put16(record, 2, 2);
    put16(record, 6, 1);
    put16(record, 10, (n - 16) as u16);
    put32(record, 12, pos);
    let mut crc = 0u16;
    for b in &record[16..n] {
        crc ^= u16::from(*b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                crc << 1 ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    put16(record, 8, crc);
    record[4] = 0;
    record[4] = record[..16].iter().fold(0u8, |sum, n| sum.wrapping_add(*n));
}
fn fid(name: &[u8], dir: bool, block: u32, pos: u32) -> Vec<u8> {
    let n = if dir { 0 } else { name.len() + 1 };
    let mut data = vec![0; (38 + n).next_multiple_of(4)];
    put16(&mut data, 16, 1);
    data[18] = if dir { 10 } else { 0 };
    data[19] = n as u8;
    put32(&mut data, 20, SECTOR as u32);
    put32(&mut data, 24, block);
    if n != 0 {
        data[38] = 8;
        data[39..39 + name.len()].copy_from_slice(name);
    }
    let len = data.len();
    tag(&mut data, 257, pos, len);
    data
}
fn file(data: &mut [u8], pos: u32, block: u32, len: usize, mode: u16, dir: bool) {
    put16(data, 20, 4);
    data[27] = if dir { 4 } else { 5 };
    put16(data, 34, mode);
    put16(data, 48, 1);
    data[56..64].copy_from_slice(&(len as u64).to_le_bytes());
    let n = match mode {
        0 => 8,
        1 => 16,
        _ => 20,
    };
    put32(data, 172, n);
    put32(data, 176, len as u32);
    if mode == 2 {
        put32(data, 180, len as u32);
        put32(data, 184, len as u32);
        put32(data, 188, block);
    } else {
        put32(data, 180, block);
    }
    tag(data, 261, pos, 176 + n as usize);
}
fn image(first: &[u8], second: &[u8], mode: u16) -> Vec<u8> {
    let mut bytes = vec![0; 284 * SECTOR];
    let blocks = bytes.as_chunks_mut::<SECTOR>().0;
    for (i, name) in [(16, b"BEA01"), (17, b"NSR02"), (18, b"TEA01")] {
        blocks[i][1..6].copy_from_slice(name);
        blocks[i][6] = 1;
    }
    let part = if mode == 0 { 258 } else { 0 };
    for (block, kind) in [
        (20, 1),
        (21, 4),
        (22, 6),
        (23, 5),
        (24, 7),
        (25, 8),
        (26, 9),
        (27, 8),
        (256, 2),
        (258, 256),
    ] {
        let b = &mut blocks[block];
        match kind {
            6 => put32(b, 212, SECTOR as u32),
            5 => {
                put32(b, 188, part);
                put32(b, 192, 284 - part);
            }
            2 => {
                put32(b, 16, 6 * SECTOR as u32);
                put32(b, 20, 20);
            }
            256 => {
                put32(b, 400, SECTOR as u32);
                put32(b, 404, 259 - part);
            }
            _ => {}
        }
        tag(b, kind, block as u32, 512);
    }
    let list = [
        fid(b"", true, 259 - part, 260 - part),
        fid(b"First.txt", false, 261 - part, 260 - part),
        fid(b"Second.txt", false, 262 - part, 260 - part),
    ]
    .concat();
    file(
        &mut blocks[259],
        259 - part,
        260 - part,
        list.len(),
        mode,
        true,
    );
    blocks[260][..list.len()].copy_from_slice(&list);
    file(
        &mut blocks[261],
        261 - part,
        274 - part,
        first.len(),
        mode,
        false,
    );
    file(
        &mut blocks[262],
        262 - part,
        278 - part,
        second.len(),
        mode,
        false,
    );
    bytes[274 * SECTOR..274 * SECTOR + first.len()].copy_from_slice(first);
    bytes[278 * SECTOR..278 * SECTOR + second.len()].copy_from_slice(second);
    bytes
}
fn reordered_entries() -> Vec<u8> {
    let mut bytes = image(FIRST, SECOND, 0);
    let blocks = bytes.as_chunks_mut::<SECTOR>().0;
    let partition = 258;
    // Both names retain their own ICB references and extents. The second file entry
    // precedes the first on disc while the directory lists First.txt before Second.txt.
    let ids = [
        fid(b"", true, 1, 2),
        fid(b"First.txt", false, 4, 2),
        fid(b"Second.txt", false, 3, 2),
    ]
    .concat();
    blocks[260][..ids.len()].copy_from_slice(&ids);
    file(&mut blocks[261], 3, 278 - partition, SECOND.len(), 0, false);
    file(&mut blocks[262], 4, 274 - partition, FIRST.len(), 0, false);
    bytes
}

fn authored(source: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    GzDecoder::new(source).read_to_end(&mut out)?;
    Ok(out)
}

fn allocation_images() -> io::Result<[Vec<u8>; 3]> {
    Ok([
        authored(include_bytes!("fixtures/udf/allocation-single.udf.gz"))?,
        authored(include_bytes!("fixtures/udf/allocation-fragmented.udf.gz"))?,
        authored(include_bytes!("fixtures/udf/allocation-inline.udf.gz"))?,
    ])
}

fn hash_rule(name: &str, data: &[u8]) -> io::Result<String> {
    Ok(format!(
        "{}:{}:Udf.{name}\n",
        barnacle::hash_reader(data)?.md5_hex(),
        data.len()
    ))
}

fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let root = tmp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let first = image(FIRST, SECOND, 0);
    let reversed = image(SECOND, FIRST, 0);
    let outer = image(FIRST, b"another ordinary file", 0);
    let big = FIRST.repeat(100);
    let size_competition = image(&big, SECOND, 0);
    let silent = image(b"unrelated member", SECOND, 0);
    let udf = authored(include_bytes!("fixtures/udf/hdiutil-udf.iso.gz"))?;
    let bridge = authored(include_bytes!("fixtures/udf/hdiutil-bridge.iso.gz"))?;
    let mut rules = String::new();
    for (name, b) in [
        ("First", FIRST),
        ("Second", SECOND),
        ("Large", big.as_slice()),
        ("Outer", outer.as_slice()),
    ] {
        rules.push_str(&hash_rule(name, b)?);
    }
    fs::write(db.join("local.hdb"), rules)?;
    let start = |id: &str, opts: &str| -> io::Result<_> {
        let sock = root.join(format!("{id}.sock"));
        let conf = root.join(format!("{id}.conf"));
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\nSelfCheck 0\n{opts}\n",
                db.display(),
                sock.display()
            ),
        )?;
        Ok((Daemon::start(exe, &conf, &sock)?, sock))
    };
    let check = |socket: &Path, label: &str, bytes: &[u8], name: Option<&str>| -> io::Result<()> {
        let expected = match name {
            Some(s) if s.starts_with("Heuristics.") => format!("stream: {s} FOUND\0"),
            Some(s) => format!("stream: Udf.{s}.UNOFFICIAL FOUND\0"),
            None if stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        let actual = unix_request(socket, &stream_frame(bytes)?)?;
        assert_eq!(actual, expected, "{label}");
        Ok(())
    };
    let (daemon, socket) = start("base", "")?;
    let mut trunc = first.clone();
    trunc.truncate(265 * SECTOR);
    let cases = [
        ("first descriptor", first.clone(), Some("First")),
        ("swapped data", reversed, Some("Second")),
        (
            "physical entries versus directory names",
            reordered_entries(),
            Some("Second"),
        ),
        ("second descriptor", silent, Some("Second")),
        ("raw before child", outer.clone(), Some("Outer")),
        ("cross-sector extent", image(&big, SECOND, 0), Some("Large")),
        ("long allocation", image(FIRST, SECOND, 1), Some("First")),
        (
            "extended allocation",
            image(FIRST, SECOND, 2),
            Some("First"),
        ),
        ("short image", trunc, None),
        (
            "ZIP with UDF",
            zip::zip(&[("notes.udf", &first)], true, false, false)?,
            Some("First"),
        ),
        ("hdiutil UDF 1.02", udf, None),
        ("hdiutil ISO/UDF bridge", bridge, Some("First")),
    ];
    for (label, bytes, name) in cases {
        check(&socket, label, &bytes, name)?;
    }
    drop(daemon);
    for (id, opt, data, name) in [
        (
            "depth",
            "MaxRecursion 1\nAlertExceedsMax yes".to_owned(),
            &first,
            Some("Heuristics.Limits.Exceeded.MaxRecursion"),
        ),
        (
            "count",
            "MaxFiles 1\nAlertExceedsMax yes".into(),
            &first,
            Some("Heuristics.Limits.Exceeded.MaxFiles"),
        ),
        (
            "size",
            format!("MaxScanSize {}\nAlertExceedsMax yes", first.len() + 4),
            &first,
            Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        ),
        (
            "later-small",
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                size_competition.len() + SECOND.len()
            ),
            &size_competition,
            Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        ),
        (
            "later-small-noalert",
            format!(
                "MaxScanSize {}\nAlertExceedsMax no",
                size_competition.len() + SECOND.len()
            ),
            &size_competition,
            None,
        ),
        ("disabled", "ScanArchive no".into(), &first, None),
        (
            "disabledouter",
            "ScanArchive no".into(),
            &outer,
            Some("Outer"),
        ),
    ] {
        let (_daemon, socket) = start(id, &opt)?;
        check(&socket, id, data, name)?;
    }
    // Physical order is c.txt (SECOND), b.txt (the allocation control), a.txt (FIRST).
    let discs = allocation_images()?;
    let ledger: String = (1..=110)
        .map(|i| format!("Quarterly allocation ledger for ordinary record {i:03}.\n"))
        .collect();
    let inline = b"Quarterly allocation ledger stored inside its UDF file entry.";
    let late = hash_rule("Later", FIRST)?;
    let (prefix, suffix) = ledger.as_bytes().split_at(SECTOR);
    let mut middle = late.clone();
    for (name, data) in [
        ("Ledger", ledger.as_bytes()),
        ("Extent1", prefix),
        ("Extent2", suffix),
        ("Inline", inline.as_slice()),
    ] {
        middle.push_str(&hash_rule(name, data)?);
    }
    let early = middle.clone() + &hash_rule("Earlier", SECOND)?;
    let mut outer = early.clone();
    for disc in &discs {
        outer.push_str(&hash_rule("Disc", disc)?);
    }
    for (id, rules, expected) in [
        ("middle", middle, [Some("Ledger"), None, None]),
        ("later", late.clone(), [Some("Later"), None, None]),
        ("earlier", early, [Some("Earlier"); 3]),
        ("raw", outer, [Some("Disc"); 3]),
    ] {
        fs::write(db.join("local.hdb"), rules)?;
        let (_daemon, socket) = start(id, "")?;
        for (disc, name) in discs.iter().zip(expected) {
            check(&socket, id, disc, name)?;
        }
    }
    fs::write(db.join("local.hdb"), late)?;
    for (id, opt, expected) in [
        (
            "allocation-count",
            "MaxFiles 2".into(),
            [Some("Heuristics.Limits.Exceeded.MaxFiles"), None, None],
        ),
        (
            "allocation-size",
            format!("MaxScanSize {}", discs[0].len() + SECOND.len()),
            [Some("Heuristics.Limits.Exceeded.MaxScanSize"), None, None],
        ),
        (
            "allocation-depth",
            "MaxRecursion 1".into(),
            [Some("Heuristics.Limits.Exceeded.MaxRecursion"); 3],
        ),
    ] {
        let (_daemon, socket) = start(id, &format!("{opt}\nAlertExceedsMax yes"))?;
        for (disc, name) in discs.iter().zip(expected) {
            check(&socket, id, disc, name)?;
        }
    }
    Ok(())
}
#[test]
fn barnacle_udf_objects() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}
#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn stock_udf_objects() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}

#[test]
fn optical_members_use_the_post_raw_parent_type() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let temp = tempfile::tempdir()?;
    let bridge = authored(include_bytes!("fixtures/udf/hdiutil-bridge.iso.gz"))?;
    let discs = [
        (image(FIRST, SECOND, 0), "CL_TYPE_UDF", FIRST),
        (bridge, "CL_TYPE_ISO9660", FIRST),
    ]
    .into_iter()
    .chain(allocation_images()?.map(|disc| (disc, "CL_TYPE_UDF", SECOND)));
    for (disc, ty, marker) in discs {
        let archive = zip::zip(&[("notes.iso", &disc)], true, false, false)?;
        let verdict = scan(
            &archive,
            &Options::default(),
            temp.path(),
            |object, _| {
                if object.bytes == disc {
                    assert_eq!(object.layer.file_type, "CL_TYPE_BINARY_DATA");
                }
                if object.bytes == marker {
                    assert_eq!(
                        object
                            .parents
                            .iter()
                            .map(|p| p.file_type)
                            .collect::<Vec<_>>(),
                        ["CL_TYPE_ZIP", ty]
                    );
                    assert_eq!(
                        object.parents[1].name.as_deref(),
                        Some(b"notes.iso".as_slice())
                    );
                    if ty == "CL_TYPE_UDF" {
                        assert_eq!(object.layer.name.as_deref(), Some(b"".as_slice()));
                    }
                    return Ok(Verdict::Found(ty.into()));
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert_eq!(verdict, Verdict::Found(ty.into()));
    }
    Ok(())
}

#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn stock_optical_parent_types() -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let db = tmp.path().join("db");
    fs::create_dir(&db)?;
    let hex = |marker: &[u8]| {
        marker
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let rules: String = ["CL_TYPE_UDF", "CL_TYPE_ISO9660"]
        .iter()
        .map(|ty| {
            format!(
                "Optical.{ty};Engine:81-255,Target:0,Container:{ty};0|1;{};{}\n",
                hex(FIRST),
                hex(SECOND)
            )
        })
        .collect();
    fs::write(db.join("parent.ldb"), rules)?;
    let sock = tmp.path().join("sock");
    let conf = tmp.path().join("clamd.conf");
    fs::write(
        &conf,
        format!(
            "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n",
            db.display(),
            sock.display()
        ),
    )?;
    let _service = Daemon::start(Path::new("/usr/sbin/clamd"), &conf, &sock)?;
    let bridge = authored(include_bytes!("fixtures/udf/hdiutil-bridge.iso.gz"))?;
    let discs = [
        (image(FIRST, SECOND, 0), "CL_TYPE_UDF"),
        (bridge, "CL_TYPE_ISO9660"),
    ]
    .into_iter()
    .chain(allocation_images()?.map(|disc| (disc, "CL_TYPE_UDF")));
    for (disc, ty) in discs {
        let zip = zip::zip(&[("notes.iso", &disc)], true, false, false)?;
        assert_eq!(
            unix_request(&sock, &stream_frame(&zip)?)?,
            format!("stream: Optical.{ty}.UNOFFICIAL FOUND\0")
        );
    }
    assert_eq!(unix_request(&sock, &stream_frame(FIRST)?)?, "stream: OK\0");
    Ok(())
}
