#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;

use barnacle::objects::{self, Options, Verdict};
use std::{fs, io, io::Read, path::Path};

const SECTOR: usize = 2048;
const FIRST: &[u8] = b"Quarterly notes from the first meeting";
const SECOND: &[u8] = b"Quarterly notes from the second meeting";

fn record(block: u32, size: usize, name: &[u8], dir: bool) -> Vec<u8> {
    let length = 33 + name.len() + usize::from(name.len().is_multiple_of(2));
    let mut data = vec![0; length];
    data[0] = length as u8;
    data[2..6].copy_from_slice(&block.to_le_bytes());
    data[6..10].copy_from_slice(&block.to_be_bytes());
    data[10..14].copy_from_slice(&(size as u32).to_le_bytes());
    data[14..18].copy_from_slice(&(size as u32).to_be_bytes());
    data[25] = if dir { 2 } else { 0 };
    data[28..32].copy_from_slice(&[1, 0, 0, 1]);
    data[32] = name.len() as u8;
    data[33..33 + name.len()].copy_from_slice(name);
    data
}

fn image(joliet: bool, block_size: usize, first: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 28 * SECTOR];
    let record = |sector: u32, size, name: &[u8], dir| {
        record(sector * (SECTOR / block_size) as u32, size, name, dir)
    };
    let size = block_size as u16;
    let size_field = [size.to_le_bytes(), size.to_be_bytes()].concat();
    let mut put = |block: usize, offset: usize, data: &[u8]| {
        let start = block * SECTOR + offset;
        bytes[start..start + data.len()].copy_from_slice(data);
    };
    put(16, 0, b"\x01CD001\x01");
    put(16, 128, &size_field);
    put(16, 156, &record(20, SECTOR, &[0], true));
    if joliet {
        put(17, 0, b"\x02CD001\x01");
        put(17, 88, b"%/E");
        put(17, 128, &size_field);
        put(17, 156, &record(22, SECTOR, &[0], true));
        let name: Vec<_> = "Résumé.txt;1"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        put(22, 0, &record(24, first.len(), &name, false));
        put(18, 0, b"\xffCD001\x01");
    } else {
        put(17, 0, b"\xffCD001\x01");
        let folder = record(21, SECTOR, b"NOTES", true);
        put(20, 0, &folder);
        put(
            20,
            folder.len(),
            &record(27, SECOND.len(), b"SECOND.TXT;1", false),
        );
        put(21, 0, &record(24, first.len(), b"FIRST.TXT;1", false));
    }
    put(24, 0, first);
    put(27, 0, SECOND);
    bytes
}

fn raw_cd(image: &[u8], stride: usize, prefix: usize) -> Vec<u8> {
    let mut raw = Vec::new();
    for data in image.as_chunks::<SECTOR>().0 {
        let mut sector = vec![0; stride];
        sector[1..11].fill(0xff);
        sector[15] = if prefix == 16 { 1 } else { 2 };
        sector[prefix..prefix + SECTOR].copy_from_slice(data);
        raw.extend(sector);
    }
    raw
}

fn signature(data: &[u8], name: &str) -> io::Result<String> {
    Ok(format!(
        "{}:{}:ISO.{name}\n",
        barnacle::hash_reader(data)?.md5_hex(),
        data.len()
    ))
}

fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    for (opts, outer, expected) in [
        ("", false, "ISO.First.UNOFFICIAL FOUND"),
        ("", true, "ISO.Outer.UNOFFICIAL FOUND"),
        (
            "MaxFiles 1\nAlertExceedsMax yes\n",
            false,
            "Heuristics.Limits.Exceeded.MaxFiles FOUND",
        ),
        (
            "ScanArchive no\n",
            false,
            if stock {
                "OK"
            } else {
                "Incomplete scan: unsupported detection coverage. ERROR"
            },
        ),
    ] {
        let tmp = tempfile::tempdir_in("/tmp")?;
        let db = tmp.path().join("db");
        fs::create_dir(&db)?;
        let first = FIRST.repeat(88);
        let primary = image(false, SECTOR, &first);
        let supplementary = image(true, SECTOR, &first);
        let mut labelled = primary.clone();
        let label = b"Inventory release system area";
        labelled[..label.len()].copy_from_slice(label);
        let mut appended = primary.clone();
        appended.extend(zip::zip(&[("notes.txt", SECOND)], true, false, false)?);
        let images = [
            raw_cd(&primary, 2352, 16),
            raw_cd(&supplementary, 2352, 24),
            raw_cd(&primary, 2448, 16),
            raw_cd(&supplementary, 2448, 24),
            image(false, 512, &first),
            image(true, 1024, &first),
            primary,
            labelled,
            supplementary,
            appended,
        ];
        let mut hashes = signature(&first, "First")? + &signature(SECOND, "Second")?;
        if outer {
            for bytes in &images {
                hashes += &signature(bytes, "Outer")?;
            }
        }
        fs::write(db.join("local.hdb"), hashes)?;
        let sock = tmp.path().join("sock");
        let conf = tmp.path().join("instance.conf");
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\n{opts}",
                db.display(),
                sock.display()
            ),
        )?;
        let _daemon = daemon::Daemon::start(exe, &conf, &sock)?;
        for (case, bytes) in images.iter().enumerate() {
            let actual = daemon::unix_request(&sock, &daemon::stream_frame(bytes)?)?;
            assert_eq!(
                actual,
                format!("stream: {expected}\0"),
                "{opts:?} outer={outer} case={case}"
            );
        }
    }
    Ok(())
}

#[test]
fn iso_daemon() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires the pinned Debian clamd"]
fn iso_stock() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"), true)
}

const HYBRID_CARD: &[u8] = b"Inventory terminal operator card, revision five.\n";
const HYBRID_NOTICE: &[u8] = b"Quarterly installation guide for the inventory terminal.\n";
const HYBRID_MBR: &[u8] = include_bytes!("fixtures/iso-hybrid/mbr.iso.gz");
const HYBRID_GPT: &[u8] = include_bytes!("fixtures/iso-hybrid/gpt.iso.gz");

fn mbr_data_only(mut image: Vec<u8>) -> Vec<u8> {
    // The second descriptor is the El Torito record. Keep the Joliet
    // supplementary descriptor and volume descriptor set terminator.
    assert_eq!(&image[17 * SECTOR..][..7], b"\0CD001\x01");
    image.copy_within(18 * SECTOR..20 * SECTOR, 17 * SECTOR);
    image
}

fn hybrid_image(compressed: &[u8]) -> io::Result<Vec<u8>> {
    let mut image = Vec::new();
    flate2::read::GzDecoder::new(compressed).read_to_end(&mut image)?;
    Ok(image)
}

fn compare_hybrids(exe: &Path, stock: bool) -> io::Result<()> {
    let mbr = hybrid_image(HYBRID_MBR)?;
    let gpt = hybrid_image(HYBRID_GPT)?;
    for (image, partition_sector, first, files) in [
        (mbr.clone(), 36, "Outer", 10),
        (mbr_data_only(mbr), 36, "Outer", 10),
        (gpt, 57, "Partition", 17),
    ] {
        let partition = &image[partition_sector * SECTOR..][..1440 * 1024];
        let card = signature(HYBRID_CARD, "Card")?;
        let notice = signature(HYBRID_NOTICE, "Notice")?;
        let children = card + &notice;
        let partition = signature(partition, "Partition")?;
        let outer = signature(&image, "Outer")?;
        let label = signature(
            b"EFI recovery volume label for the inventory terminal.\n",
            "Recovery",
        )?;
        let all = children.clone() + &partition + &outer;
        let exact = image.len() + HYBRID_CARD.len() + HYBRID_NOTICE.len();
        for (rules, options, expected) in [
            (&all, String::new(), first),
            (&outer, String::new(), "Outer"),
            (&children, String::new(), "Card"),
            (&(children.clone() + &partition), String::new(), "Partition"),
            (&notice, format!("MaxScanSize {exact}"), "Notice"),
            (&notice, format!("MaxScanSize {}", exact - 1), "MaxScanSize"),
            (&all, "ScanArchive no".into(), "Outer"),
            (&children, "MaxFiles 1".into(), "MaxFiles"),
            (&children, "MaxRecursion 1".into(), "MaxRecursion"),
            (&label, format!("MaxFiles {}", files - 1), "MaxFiles"),
            (&label, format!("MaxFiles {files}"), ""),
        ] {
            let tmp = tempfile::tempdir_in("/tmp")?;
            let db = tmp.path().join("db");
            fs::create_dir(&db)?;
            fs::write(db.join("local.hdb"), rules)?;
            let sock = tmp.path().join("sock");
            let conf = tmp.path().join("instance.conf");
            fs::write(
                &conf,
                format!(
                    "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\nAlertExceedsMax yes\n{options}\n",
                    db.display(),
                    sock.display()
                ),
            )?;
            let _daemon = daemon::Daemon::start(exe, &conf, &sock)?;
            let expected = if expected.is_empty() {
                if stock {
                    "OK".to_owned()
                } else {
                    "Incomplete scan: unsupported detection coverage. ERROR".to_owned()
                }
            } else if expected.starts_with("Max") {
                format!("Heuristics.Limits.Exceeded.{expected} FOUND")
            } else {
                format!("ISO.{expected}.UNOFFICIAL FOUND")
            };
            assert_eq!(
                daemon::unix_request(&sock, &daemon::stream_frame(&image)?)?,
                format!("stream: {expected}\0"),
                "partition sector {partition_sector}, {options}"
            );
        }
    }
    Ok(())
}

#[test]
fn hybrid_iso_daemon() -> io::Result<()> {
    compare_hybrids(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires the pinned Debian clamd"]
fn hybrid_iso_stock() -> io::Result<()> {
    compare_hybrids(Path::new("/usr/sbin/clamd"), true)
}

#[test]
fn hybrid_members_reuse_iso_bytes_and_context() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    for compressed in [HYBRID_MBR, HYBRID_GPT] {
        let image = hybrid_image(compressed)?;
        let position = image
            .windows(HYBRID_CARD.len())
            .position(|bytes| bytes == HYBRID_CARD)
            .expect("authored ISO file");
        let verdict = objects::scan(
            &image,
            &Options::default(),
            tmp.path(),
            |obj, _| {
                if obj.bytes != HYBRID_CARD {
                    return Ok(Verdict::Miss);
                }
                assert_eq!(obj.bytes.as_ptr(), image[position..].as_ptr());
                assert_eq!(obj.parents.len(), 1);
                assert_eq!(obj.parents[0].file_type, "CL_TYPE_ISO9660");
                assert_eq!(obj.layer.name.as_deref(), Some(&b"CARD.TXT"[..]));
                Ok(Verdict::Found("operator card".into()))
            },
            || Ok(()),
        )?;
        assert_eq!(verdict, Verdict::Found("operator card".into()));
    }
    Ok(())
}

#[test]
fn borrowed_members_have_iso_parent_and_entry_name() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    for (joliet, name) in [(false, "FIRST.TXT"), (true, "Résumé.txt")] {
        let bytes = image(joliet, SECTOR, FIRST);
        let verdict = objects::scan(
            &bytes,
            &Options::default(),
            tmp.path(),
            |obj, _| {
                if obj.bytes != FIRST {
                    return Ok(Verdict::Miss);
                }
                assert_eq!(obj.bytes.as_ptr(), bytes[24 * SECTOR..].as_ptr());
                assert_eq!(obj.parents.last().unwrap().file_type, "CL_TYPE_ISO9660");
                assert_eq!(obj.layer.name.as_deref(), Some(name.as_bytes()));
                Ok(Verdict::Found("first member".into()))
            },
            || Ok(()),
        )?;
        assert!(matches!(verdict, Verdict::Found(_)));
    }
    Ok(())
}
