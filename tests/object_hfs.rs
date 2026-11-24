//! Scan ordinary HFS+/HFSX partitions in UDIF disk images with both daemons.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;
#[path = "common/dmg.rs"]
mod dmg;
use client::{Daemon, stream_frame, unix_request};
use flate2::read::GzDecoder;
use md5::{Digest, Md5};
use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
};

const RESOURCE: &[u8] = b"ordinary HFS resource fork";
const CHILD: &[u8] = b"ordinary HFS nested file";
const SYMLINK: &[u8] = b"ordinary HFS symbolic link target";
const REAL_FIRST: &[u8] = b"Ordinary UDF text from the first member";
const REAL_SECOND: &[u8] = b"Ordinary UDF text from the second member";
const BLOCK: usize = 512;
const NODE: usize = 4096;

fn put16(d: &mut [u8], p: usize, n: u16) {
    d[p..p + 2].copy_from_slice(&n.to_be_bytes())
}
fn put32(d: &mut [u8], p: usize, n: u32) {
    d[p..p + 4].copy_from_slice(&n.to_be_bytes())
}
fn fork(d: &mut [u8], size: usize, runs: &[(u32, u32)]) {
    d[..8].copy_from_slice(&(size as u64).to_be_bytes());
    put32(d, 12, runs.iter().map(|p| p.1).sum());
    for (i, &(start, len)) in runs.iter().enumerate() {
        put32(d, 16 + 8 * i, start);
        put32(d, 20 + 8 * i, len);
    }
}
fn tree(d: &mut [u8], size: u16, key_size: u16, nodes: u32, first: u32, last: u32) {
    d[8] = 1;
    put16(d, 10, 3);
    put16(d, 14, 1);
    put32(d, 16, first);
    put32(d, 24, first);
    put32(d, 28, last);
    put16(d, 32, size);
    put16(d, 34, key_size);
    put32(d, 36, nodes);
}
fn leaf(d: &mut [u8], next: u32, records: &[Vec<u8>]) {
    d[8] = 255;
    d[9] = 1;
    put32(d, 0, next);
    put16(d, 10, records.len() as u16);
    let mut at = 14;
    for (i, r) in records.iter().enumerate() {
        put16(d, NODE - 2 * i - 2, at as u16);
        d[at..at + r.len()].copy_from_slice(r);
        at += r.len();
    }
    put16(d, NODE - 2 * records.len() - 2, at as u16);
}
fn key(parent: u32, name: &str) -> Vec<u8> {
    let n: Vec<_> = name.encode_utf16().collect();
    let mut r = ((6 + 2 * n.len()) as u16).to_be_bytes().to_vec();
    r.extend(parent.to_be_bytes());
    r.extend((n.len() as u16).to_be_bytes());
    for u in n {
        r.extend(u.to_be_bytes());
    }
    r
}

fn file(
    parent: u32,
    name: &str,
    id: u32,
    mode: u16,
    data: &[(u32, u32)],
    size: usize,
    resource: bool,
) -> Vec<u8> {
    let mut k = key(parent, name);
    let mut r = [0; 248];
    put16(&mut r, 0, 2);
    put32(&mut r, 8, id);
    put16(&mut r, 42, mode);
    fork(&mut r[88..], size, data);
    if resource {
        fork(&mut r[168..], RESOURCE.len(), &[(34, 1)]);
    }
    k.extend(r);
    k
}

fn volume(hfsx: bool, data: &[u8]) -> Vec<u8> {
    let mut b = vec![0; BLOCK * 64];
    let h = &mut b[1024..1536];
    h[..4].copy_from_slice(if hfsx { b"HX\0\x05" } else { b"H+\0\x04" });
    put32(h, 40, BLOCK as u32);
    put32(h, 44, 64);
    fork(&mut h[192..], BLOCK, &[(3, 1)]);
    fork(&mut h[272..], NODE * 3, &[(4, 24)]);
    tree(&mut b[3 * BLOCK..], 512, 10, 1, 0, 0);
    tree(&mut b[4 * BLOCK..], NODE as u16, 516, 3, 1, 2);
    let mut folder = key(2, "folder");
    let mut r = [0; 88];
    put16(&mut r, 0, 1);
    put32(&mut r, 8, 17);
    folder.extend(r);
    let root = file(
        2,
        "note.txt",
        18,
        0o100644,
        &[(28, 1), (31, 1)],
        data.len(),
        true,
    );
    leaf(&mut b[12 * BLOCK..20 * BLOCK], 2, &[folder, root]);
    let nested = file(
        17,
        "Résumé.txt",
        21,
        0o100644,
        &[(36, 1)],
        CHILD.len(),
        false,
    );
    let link = file(17, "link", 22, 0o120777, &[(37, 1)], SYMLINK.len(), false);
    leaf(&mut b[20 * BLOCK..28 * BLOCK], 0, &[nested, link]);
    b[28 * BLOCK..29 * BLOCK].copy_from_slice(&data[..BLOCK]);
    b[31 * BLOCK..31 * BLOCK + data.len() - BLOCK].copy_from_slice(&data[BLOCK..]);
    for (block, value) in [(34, RESOURCE), (36, CHILD), (37, SYMLINK)] {
        b[block * BLOCK..block * BLOCK + value.len()].copy_from_slice(value);
    }
    b
}

const COMPRESSED: &[u8] = b"compressed HFS catalog attachment";

fn large_allocation_blocks(original: &[u8], data: &[u8]) -> Vec<u8> {
    const LARGE: usize = NODE * 2;
    let mut b = vec![0; LARGE * 8];
    b[1024..1536].copy_from_slice(&original[1024..1536]);
    let h = &mut b[1024..1536];
    put32(h, 40, LARGE as u32);
    put32(h, 44, 8);
    fork(&mut h[192..], BLOCK, &[(1, 1)]);
    fork(&mut h[272..], NODE * 3, &[(2, 2)]);
    tree(&mut b[LARGE..], 512, 10, 1, 0, 0);
    tree(&mut b[2 * LARGE..], NODE as u16, 516, 3, 1, 2);
    let file = file(2, "note.txt", 18, 0o100644, &[(4, 1)], data.len(), false);
    leaf(&mut b[2 * LARGE + NODE..3 * LARGE], 0, &[file]);
    b[4 * LARGE..4 * LARGE + data.len()].copy_from_slice(data);
    b
}

fn zlib(input: &[u8]) -> io::Result<Vec<u8>> {
    let mut w = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    w.write_all(input)?;
    w.finish()
}

// A classic resource map with one cmpf resource and two independent zlib blocks.
fn resource_bytes() -> io::Result<Vec<u8>> {
    let mut table = vec![0; 20];
    table[..4].copy_from_slice(&2u32.to_le_bytes());
    for (i, part) in [&COMPRESSED[..11], &COMPRESSED[11..]]
        .into_iter()
        .enumerate()
    {
        let bytes = zlib(part)?;
        let offset = table.len() as u32;
        table[4 + 8 * i..8 + 8 * i].copy_from_slice(&offset.to_le_bytes());
        table[8 + 8 * i..12 + 8 * i].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        table.extend(bytes);
    }
    let mut r = vec![0; 260];
    put32(&mut r, 0, 256);
    put32(&mut r, 4, 32);
    put32(&mut r, 8, (table.len() + 4) as u32);
    put32(&mut r, 12, 50);
    put16(&mut r, 32 + 24, 28);
    put16(&mut r, 32 + 26, 50);
    r[62..66].copy_from_slice(b"cmpf");
    put16(&mut r, 68, 10);
    put32(&mut r, 256, table.len() as u32);
    r.extend(table);
    r.resize(4096, 0);
    Ok(r)
}

fn with_attribute(
    original: &[u8],
    kind: u32,
    stored: bool,
    prior_zlib: bool,
) -> io::Result<Vec<u8>> {
    let mut b = original.to_vec();
    fork(&mut b[1024 + 352..1536], 2 * NODE, &[(40, 16)]);
    tree(&mut b[40 * BLOCK..], NODE as u16, 516, 2, 1, 1);
    let mut records = Vec::new();
    let file_id = if prior_zlib {
        let other = b"earlier zlib attachment";
        records.push(attribute_record(18, 3, other.len(), &zlib(other)?));
        21
    } else {
        18
    };
    let mut payload = Vec::new();
    if kind == 3 {
        if stored {
            payload.push(0xff);
            payload.extend(COMPRESSED);
        } else {
            payload = zlib(COMPRESSED)?;
        }
    } else if kind == 4 {
        let resource = resource_bytes()?;
        let leaf = &mut b[12 * BLOCK..20 * BLOCK];
        let record_at = u16::from_be_bytes(leaf[NODE - 4..NODE - 2].try_into().unwrap()) as usize;
        let data_at = record_at + key(2, "note.txt").len();
        fork(&mut leaf[data_at + 168..], resource.len(), &[(56, 8)]);
        b[56 * BLOCK..56 * BLOCK + resource.len()].copy_from_slice(&resource);
    }
    records.push(attribute_record(file_id, kind, COMPRESSED.len(), &payload));
    leaf(&mut b[48 * BLOCK..56 * BLOCK], 0, &records);
    Ok(dmg::single(dmg::ZLIB, &b, "attr")?.0)
}

fn attribute_record(id: u32, kind: u32, size: usize, payload: &[u8]) -> Vec<u8> {
    let mut record = vec![0; 14];
    let name = "com.apple.decmpfs".encode_utf16().collect::<Vec<_>>();
    put16(&mut record, 0, (12 + 2 * name.len()) as u16);
    put32(&mut record, 4, id);
    put16(&mut record, 12, name.len() as u16);
    for v in name {
        record.extend(v.to_be_bytes());
    }
    let mut value = b"fpmc".to_vec();
    value.extend(kind.to_le_bytes());
    value.extend((size as u64).to_le_bytes());
    value.extend(payload);
    record.extend(0x10u32.to_be_bytes());
    record.extend([0; 8]);
    record.extend((value.len() as u32).to_be_bytes());
    record.extend(value);
    if !record.len().is_multiple_of(2) {
        record.push(0);
    }
    record
}

fn hash(input: &[u8], name: &str) -> String {
    let hex: String = Md5::digest(input)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{hex}:{}:Local.{name}\n", input.len())
}
fn compare(executable: &Path, stock: bool) -> io::Result<()> {
    let mut data = vec![b'd'; 710];
    data[BLOCK..].fill(b'r');
    let volume_plus = volume(false, &data);
    let large_blocks = large_allocation_blocks(&volume_plus, &data);
    let large_dmg = dmg::single(dmg::ZLIB, &large_blocks, "large blocks")?.0;
    let (plus, xml) = dmg::single(dmg::ZLIB, &volume_plus, "notes")?;
    let (x, _) = dmg::single(dmg::RAW, &volume(true, &data), "case-sensitive")?;
    let mut real = vec![];
    GzDecoder::new(include_bytes!("fixtures/dmg/hdiutil-hfsplus.dmg.gz").as_slice())
        .read_to_end(&mut real)?;
    let all = hash(&data, "Data")
        + &hash(RESOURCE, "Resource")
        + &hash(CHILD, "Nested")
        + &hash(SYMLINK, "Link")
        + &hash(&volume_plus, "Partition");
    let attr_zlib = with_attribute(&volume_plus, 3, false, false)?;
    let attr_stored = with_attribute(&volume_plus, 3, true, false)?;
    let attr_resource = with_attribute(&volume_plus, 4, false, false)?;
    let attr_unknown = with_attribute(&volume_plus, 99, false, false)?;
    let stored_after_zlib = with_attribute(&volume_plus, 3, true, true)?;
    let with_compressed = hash(COMPRESSED, "Compressed") + &hash(&data, "Data");
    let first_budget = plus.len() + xml.len() + volume_plus.len() + data.len();
    let scenarios = &[
        (
            "".into(),
            hash(&data, "Data") + &hash(&large_blocks, "Partition"),
            &large_dmg,
            Some("Local.Partition.UNOFFICIAL"),
        ),
        (
            "".into(),
            hash(COMPRESSED, "Compressed"),
            &stored_after_zlib,
            Some("Local.Compressed.UNOFFICIAL"),
        ),
        (
            "".to_string(),
            with_compressed.clone(),
            &attr_zlib,
            Some("Local.Compressed.UNOFFICIAL"),
        ),
        (
            "".to_string(),
            with_compressed.clone(),
            &attr_stored,
            Some("Local.Data.UNOFFICIAL"),
        ),
        (
            "".to_string(),
            with_compressed.clone(),
            &attr_resource,
            Some("Local.Compressed.UNOFFICIAL"),
        ),
        (
            "".to_string(),
            with_compressed,
            &attr_unknown,
            Some("Local.Data.UNOFFICIAL"),
        ),
        (
            "".to_string(),
            all.clone() + &hash(&plus, "Outer"),
            &plus,
            Some("Local.Outer.UNOFFICIAL"),
        ),
        (
            "".to_string(),
            all.clone(),
            &plus,
            Some("Local.Data.UNOFFICIAL"),
        ),
        ("".into(), all.clone(), &x, Some("Local.Data.UNOFFICIAL")),
        (
            "".into(),
            hash(RESOURCE, "Resource") + &hash(CHILD, "Nested"),
            &plus,
            Some("Local.Resource.UNOFFICIAL"),
        ),
        (
            "".into(),
            hash(CHILD, "Nested") + &hash(SYMLINK, "Link"),
            &plus,
            Some("Local.Nested.UNOFFICIAL"),
        ),
        ("".into(), hash(SYMLINK, "Link"), &plus, None),
        (
            "MaxFiles 3\nAlertExceedsMax yes".into(),
            hash(&data, "Data"),
            &plus,
            Some("Heuristics.Limits.Exceeded.MaxFiles"),
        ),
        (
            "MaxFiles 4\nAlertExceedsMax yes".into(),
            hash(&data, "Data"),
            &plus,
            Some("Local.Data.UNOFFICIAL"),
        ),
        (
            "ScanArchive no".into(),
            all.clone() + &hash(&plus, "Outer"),
            &plus,
            Some("Local.Outer.UNOFFICIAL"),
        ),
        (
            "".into(),
            hash(REAL_FIRST, "First") + &hash(REAL_SECOND, "Second"),
            &real,
            Some("Local.Second.UNOFFICIAL"),
        ),
        (
            "".into(),
            hash(REAL_FIRST, "First"),
            &real,
            Some("Local.First.UNOFFICIAL"),
        ),
        (
            format!("MaxScanSize {first_budget}\nAlertExceedsMax yes"),
            hash(&data, "Data"),
            &plus,
            Some("Local.Data.UNOFFICIAL"),
        ),
        (
            format!("MaxScanSize {}\nAlertExceedsMax yes", first_budget - 1),
            hash(&data, "Data"),
            &plus,
            Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        ),
        (
            "MaxRecursion 2\nAlertExceedsMax yes".into(),
            hash(&data, "Data"),
            &plus,
            Some("Heuristics.Limits.Exceeded.MaxRecursion"),
        ),
    ];
    for (i, (cfg, dbtext, bytes, expected)) in scenarios.iter().enumerate() {
        let temp = tempfile::tempdir_in("/tmp")?;
        let db = temp.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join("fixture.hdb"), dbtext)?;
        let socket = temp.path().join("socket");
        let config = temp.path().join("daemon.conf");
        fs::write(
            &config,
            format!(
                "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nSelfCheck 0\nDisableCache yes\n{cfg}\n",
                socket.display(),
                db.display()
            ),
        )?;
        let _daemon = Daemon::start(executable, &config, &socket)?;
        let response = unix_request(&socket, &stream_frame(bytes)?)?;
        let wanted = match expected {
            Some(r) => format!("stream: {r} FOUND\0"),
            None if stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        assert_eq!(
            response, wanted,
            "HFS case {i}, options {cfg}, expected {expected:?}"
        );
    }
    Ok(())
}
#[test]
fn barnacle_hfs_files() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}
#[test]
#[ignore = "requires Debian clamd 1.4.3+dfsg-1"]
fn stock_hfs_files() -> io::Result<()> {
    let pkg = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pkg.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}

#[test]
fn partition_files_keep_the_catalog_basename_and_parent() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let data = vec![b'd'; 710];
    let image = dmg::single(dmg::ZLIB, &volume(false, &data), "notes")?.0;
    let tmp = tempfile::tempdir()?;
    let mut observed = Vec::new();
    scan(
        &image,
        &Options::default(),
        tmp.path(),
        |obj, _| {
            if !obj.normalized
                && obj
                    .parents
                    .last()
                    .is_some_and(|p| p.file_type == "CL_TYPE_PART_HFSPLUS")
            {
                observed.push((
                    obj.layer.name.as_deref().unwrap_or(b"").to_vec(),
                    obj.bytes.len(),
                ));
                assert_eq!(
                    obj.parents.iter().map(|p| p.file_type).collect::<Vec<_>>(),
                    ["CL_TYPE_DMG", "CL_TYPE_PART_HFSPLUS"]
                );
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(
        observed,
        [
            (b"note.txt".to_vec(), data.len()),
            (b"note.txt".to_vec(), RESOURCE.len()),
            ("Résumé.txt".as_bytes().to_vec(), CHILD.len())
        ]
    );
    Ok(())
}
