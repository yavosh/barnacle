//! Compare harmless UDIF resource metadata and rebuilt partitions with the pinned daemon.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;
use daemon::{Daemon, stream_frame, unix_request};
#[path = "common/dmg.rs"]
mod builder;
use builder::{ADC, BZIP, RAW, Stripe, ZLIB, catalog, dmg, mish, single};
use flate2::read::GzDecoder;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

const FIRST: &[u8] = b"Ordinary text copied from the first read-only partition";
const SECOND: &[u8] = b"Ordinary text copied from the second read-only partition";
fn sector(note: &[u8]) -> Vec<u8> {
    let mut b = vec![b' '; 512];
    b[..note.len()].copy_from_slice(note);
    b
}
fn authored(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    GzDecoder::new(data).read_to_end(&mut out)?;
    Ok(out)
}

fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let root = tmp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let first = sector(FIRST);
    let second = sector(SECOND);
    let mixed = [&first[..], &[0; 512], &second].concat();
    let (stored, _) = single(RAW, &first, "stored")?;
    let (outer, _) = single(ZLIB, &second, "outer")?;
    let (zlib, xml) = single(ZLIB, &first, "catalog")?;
    let (compressed_first, _) = single(ZLIB, &first, "plain")?;
    let (large, _) = single(ZLIB, &vec![b'Q'; 8192], "large")?;
    let original = authored(include_bytes!("fixtures/udf/hdiutil-udf.iso.gz"))?;
    let mut rules = String::new();
    for (name, b) in [
        ("First", first.as_slice()),
        ("Second", &second),
        ("Catalog", xml.as_bytes()),
        ("Outer", &outer),
        ("Mixed", &mixed),
        ("Authored", &original),
        ("Zero", &[0; 512]),
    ] {
        rules.push_str(&format!(
            "{}:{}:Dmg.{name}\n",
            barnacle::hash_reader(b)?.md5_hex(),
            b.len()
        ));
    }
    fs::write(db.join("local.hdb"), rules)?;
    let start = |id: &str, opts: &str| -> io::Result<_> {
        let sock = root.join(format!("{id}.sock"));
        let conf = root.join(format!("{id}.conf"));
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nTemporaryDirectory {}\nDisableCache yes\nSelfCheck 0\n{opts}\n",
                db.display(),
                sock.display(),
                root.display()
            ),
        )?;
        Ok((Daemon::start(exe, &conf, &sock)?, sock))
    };
    let check = |socket: &Path, label: &str, bytes: &[u8], name: Option<&str>| -> io::Result<()> {
        let expected = match name {
            Some(s) if s.starts_with("Heuristics.") => format!("stream: {s} FOUND\0"),
            Some(s) => format!("stream: Dmg.{s}.UNOFFICIAL FOUND\0"),
            None if stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        let actual = unix_request(socket, &stream_frame(bytes)?)?;
        assert_eq!(actual, expected, "{label}");
        Ok(())
    };
    let (daemon, socket) = start("base", "")?;
    let a = Stripe {
        kind: RAW,
        sector: 0,
        count: 1,
        offset: 0,
        len: 512,
    };
    let b = Stripe {
        sector: 2,
        offset: 512,
        ..a
    };
    let zero = Stripe {
        kind: 2,
        sector: 1,
        count: 1,
        offset: 0,
        len: 0,
    };
    let fork = [first.as_slice(), &second].concat();
    let original_zip = zip::zip(&[("notes.dmg", &compressed_first)], true, false, false)?;
    let catalog_large = single(ZLIB, &first, &"ordinary ".repeat(240))?.0;
    let projected_large = dmg(
        &fork,
        &catalog(
            &[mish(&[Stripe { count: 128, ..a }]), mish(&[b])],
            "projected-size",
        ),
    );
    let cases = [
        ("stored partition", stored, Some("First")),
        ("direct zlib", compressed_first.clone(), Some("First")),
        ("direct ADC", single(ADC, &first, "adc")?.0, Some("First")),
        (
            "direct bzip",
            single(BZIP, &second, "bzip")?.0,
            Some("Second"),
        ),
        ("catalog before partition", zlib, Some("Catalog")),
        ("outer before catalog", outer.clone(), Some("Outer")),
        (
            "stripe order",
            dmg(&fork, &catalog(&[mish(&[b, zero, a])], "mixed")),
            Some("Mixed"),
        ),
        (
            "partition order",
            dmg(&fork, &catalog(&[mish(&[b]), mish(&[a])], "map order")),
            Some("Second"),
        ),
        (
            "malformed map before good",
            dmg(
                &fork,
                &catalog(&[b"ordinary short metadata".to_vec(), mish(&[a])], "maps"),
            ),
            Some("First"),
        ),
        (
            "zero only",
            dmg(&[], &catalog(&[mish(&[zero])], "zero")),
            None,
        ),
        ("nested ZIP", original_zip, Some("First")),
        (
            "hdiutil UDRO",
            authored(include_bytes!("fixtures/dmg/hdiutil-udro.dmg.gz"))?,
            Some("Authored"),
        ),
        (
            "hdiutil UDZO",
            authored(include_bytes!("fixtures/dmg/hdiutil-udzo.dmg.gz"))?,
            Some("Authored"),
        ),
        (
            "hdiutil UDCO",
            authored(include_bytes!("fixtures/dmg/hdiutil-udco.dmg.gz"))?,
            Some("Authored"),
        ),
        (
            "hdiutil UDBZ",
            authored(include_bytes!("fixtures/dmg/hdiutil-udbz.dmg.gz"))?,
            Some("Authored"),
        ),
    ];
    for (label, data, name) in cases {
        check(&socket, label, &data, name)?;
    }
    drop(daemon);
    for (id, opts, data, name) in [
        (
            "catalogbudget",
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                catalog_large.len() + 600
            ),
            &catalog_large,
            Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        ),
        (
            "catalogquiet",
            format!(
                "MaxScanSize {}\nAlertExceedsMax no",
                catalog_large.len() + 600
            ),
            &catalog_large,
            None,
        ),
        (
            "projectedbudget",
            "MaxFileSize 4096\nAlertExceedsMax yes".into(),
            &projected_large,
            Some("Heuristics.Limits.Exceeded.MaxFileSize"),
        ),
        (
            "projectedquiet",
            "MaxFileSize 4096\nAlertExceedsMax no".into(),
            &projected_large,
            None,
        ),
        ("disabled", "ScanArchive no".into(), &compressed_first, None),
        (
            "depth",
            "MaxRecursion 1\nAlertExceedsMax yes".into(),
            &compressed_first,
            Some("Heuristics.Limits.Exceeded.MaxRecursion"),
        ),
        (
            "count",
            "MaxFiles 2\nAlertExceedsMax yes".into(),
            &compressed_first,
            Some("Heuristics.Limits.Exceeded.MaxFiles"),
        ),
        (
            "filesize",
            "MaxFileSize 2048\nAlertExceedsMax yes".into(),
            &large,
            Some("Heuristics.Limits.Exceeded.MaxFileSize"),
        ),
        (
            "scansize",
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                compressed_first.len() + 690
            ),
            &compressed_first,
            Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        ),
    ] {
        let (_daemon, sock) = start(id, &opts)?;
        check(&sock, id, data, name)?;
    }
    Ok(())
}
#[test]
fn barnacle_dmg_objects() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}
#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn stock_dmg_objects() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}

#[test]
fn disk_catalog_and_partition_have_separate_contexts() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let temp = tempfile::tempdir()?;
    let first = sector(FIRST);
    let (image, xml) = single(ZLIB, &first, "context")?;
    let zip = zip::zip(&[("notes.dmg", &image)], true, false, false)?;
    let mut stages = Vec::new();
    scan(
        &zip,
        &Options::default(),
        temp.path(),
        |object, _| {
            if !object.normalized && (object.bytes == xml.as_bytes() || object.bytes == first) {
                assert_eq!(
                    object
                        .parents
                        .iter()
                        .map(|l| l.file_type)
                        .collect::<Vec<_>>(),
                    ["CL_TYPE_ZIP", "CL_TYPE_DMG"]
                );
                assert!(object.layer.name.is_none());
                stages.push(object.layer.file_type);
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(stages, ["CL_TYPE_TEXT_ASCII", "CL_TYPE_PART_ANY"]);
    Ok(())
}

#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn stock_dmg_parent() -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let db = temp.path().join("db");
    fs::create_dir(&db)?;
    let hex: String = FIRST.iter().map(|b| format!("{b:02x}")).collect();
    fs::write(
        db.join("guard.ldb"),
        format!("Dmg.Parent;Engine:81-255,Target:0,Container:CL_TYPE_DMG;0;{hex}\n"),
    )?;
    let sock = temp.path().join("sock");
    let conf = temp.path().join("clamd.conf");
    fs::write(
        &conf,
        format!(
            "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n",
            db.display(),
            sock.display()
        ),
    )?;
    let _service = Daemon::start(Path::new("/usr/sbin/clamd"), &conf, &sock)?;
    let disc = single(ZLIB, &sector(FIRST), "notes")?.0;
    assert_eq!(
        unix_request(
            &sock,
            &stream_frame(&zip::zip(&[("notes.dmg", &disc)], true, false, false)?)?
        )?,
        "stream: Dmg.Parent.UNOFFICIAL FOUND\0"
    );
    assert_eq!(unix_request(&sock, &stream_frame(FIRST)?)?, "stream: OK\0");
    Ok(())
}
