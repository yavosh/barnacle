//! Compare harmless compound documents and embedded text packages with stock clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;

use daemon::{Daemon, stream_frame, unix_request};
use md5::{Digest, Md5};
use std::fs;
use std::io::{self, Cursor, Write};
use std::path::Path;

const FIRST: &[u8] = b"ordinary first note inside compound storage";
const SECOND: &[u8] = b"ordinary second note inside compound storage";
const NATIVE: &str = "\x01Ole10Native";

fn cfb(entries: &[(&str, &[u8])]) -> io::Result<Vec<u8>> {
    compound(cfb::Version::V3, entries)
}

fn compound(version: cfb::Version, entries: &[(&str, &[u8])]) -> io::Result<Vec<u8>> {
    let mut doc = cfb::CompoundFile::create_with_version(version, Cursor::new(Vec::new()))?;
    for &(name, data) in entries {
        let path = Path::new(name);
        doc.create_storage_all(path.parent().unwrap())?;
        doc.create_stream(path)?.write_all(data)?;
    }
    Ok(doc.into_inner().into_inner())
}

fn package(payload: &[u8]) -> Vec<u8> {
    let mut native = b"\x02\0note.txt\0note.txt\0\0\0\0\0\0\0\0\0note.txt\0".to_vec();
    native.extend((payload.len() as u32).to_le_bytes());
    native.extend(payload);
    let mut bytes = (native.len() as u32).to_le_bytes().to_vec();
    bytes.extend(native);
    bytes
}

fn word_document() -> Vec<u8> {
    let mut fib = vec![0; 0x140];
    fib[..4].copy_from_slice(&[0xec, 0xa5, 0xc1, 0]);
    fib
}

fn powerpoint() -> Vec<u8> {
    let text: Vec<u8> = "Sample notes"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut atom = vec![0, 0, 0xa0, 0x0f];
    atom.extend((text.len() as u32).to_le_bytes());
    atom.extend(text);
    atom
}

fn workbook() -> Vec<u8> {
    // BIFF8 worksheet directory with one visible worksheet and EOF.
    let mut data = vec![0x09, 0x08, 0x10, 0x00, 0x00, 0x06, 0x05, 0x00];
    data.extend([0; 12]);
    data.extend([
        0x85, 0, 0x09, 0, 0, 0, 0, 0, 0, 0, 1, 0, b'A', 0x0a, 0, 0, 0,
    ]);
    data
}

fn start_daemon(
    exe: &Path,
    root: &Path,
    db: &Path,
    id: &str,
    options: &str,
) -> io::Result<(Daemon, std::path::PathBuf)> {
    let config = root.join(format!("{id}.conf"));
    let socket = root.join(format!("{id}.sock"));
    fs::write(
        &config,
        format!(
            "Foreground yes\nDisableCache yes\nSelfCheck 0\nDatabaseDirectory {}\nTemporaryDirectory {}\nLocalSocket {}\n{options}\n",
            db.display(),
            root.display(),
            socket.display()
        ),
    )?;
    Ok((Daemon::start(exe, &config, &socket)?, socket))
}

fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let root = tmp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let native = package(SECOND);
    let dual = package(FIRST);
    let packed = cfb(&[(NATIVE, &native)])?;
    let ordered = cfb(&[("A", FIRST), ("B", SECOND), ("C", b"plain third note")])?;
    let whole = cfb(&[("Data", FIRST), ("Other", b"ordinary outer field")])?;
    let nested = cfb(&[("ObjectPool/First/Notes", SECOND)])?;
    let muted = b"a harmless unrelated stream";
    let mut raw_atom = powerpoint();
    raw_atom[8..10].copy_from_slice(&[b'X', 0]);
    let big = [b'a'; 7001];
    let mut rules = String::new();
    for (name, data) in [
        ("First", FIRST),
        ("Second", SECOND),
        ("Outer", &whole),
        ("Large", &big[..]),
        ("Atom", &raw_atom),
        ("NativeStream", &dual),
    ] {
        rules.push_str(&format!(
            "{}:{}:Ole.{name}\n",
            Md5::digest(data)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            data.len()
        ));
    }
    fs::write(db.join("local.hdb"), rules)?;
    let start = |id: &str, options: &str| start_daemon(exe, root, &db, id, options);
    let (service, socket) = start("base", "")?;
    let right_first = cfb(&[("B", muted), ("A", FIRST), ("C", SECOND)])?;
    let left_first = cfb(&[("C", FIRST), ("A", SECOND), ("B", muted)])?;
    let embedded = cfb(&[("ObjectPool/First/\x01Ole10Native", &native)])?;
    let odd = cfb(&[(NATIVE, b"abc"), ("Notes", FIRST)])?;
    let anchored = cfb(&[("WordDocument", muted), ("Notes", FIRST)])?;
    let cases = [
        ("single stream", cfb(&[("Notes", FIRST)])?, Some("First")),
        ("ordinary raw PowerPoint text atom", raw_atom, Some("Atom")),
        (
            "CFB version four",
            compound(cfb::Version::V4, &[("Notes", FIRST)])?,
            Some("First"),
        ),
        (
            "hashed root package envelope",
            cfb(&[(NATIVE, &dual)])?,
            Some("First"),
        ),
        (
            "hashed nested package envelope",
            cfb(&[("Folder/\x01Ole10Native", &dual)])?,
            Some("NativeStream"),
        ),
        (
            "package preceding Word processing",
            cfb(&[(NATIVE, &native), ("WordDocument", muted)])?,
            Some("Second"),
        ),
        (
            "OLE containing ZIP",
            cfb(&[(
                "Archive",
                &zip::zip(&[("notes.txt", FIRST)], true, false, false)?,
            )])?,
            Some("First"),
        ),
        (
            "regular-sector stream",
            cfb(&[("Big", &big)])?,
            Some("Large"),
        ),
        ("storage directories", nested.clone(), Some("Second")),
        ("root of sibling tree", ordered.clone(), Some("Second")),
        ("right sibling first", right_first, Some("Second")),
        ("first inserted C", left_first, Some("First")),
        ("outer vs child", whole.clone(), Some("First")),
        ("native payload", packed.clone(), Some("Second")),
        (
            "package wins root",
            cfb(&[("Notes", FIRST), (NATIVE, &native)])?,
            Some("Second"),
        ),
        ("nested package", embedded, Some("Second")),
        ("inert Word stream", anchored, Some("First")),
        (
            "Word FIB with zero macro length",
            cfb(&[("WordDocument", &word_document()), ("1Table", FIRST)])?,
            Some("First"),
        ),
        (
            "plain Excel worksheet",
            cfb(&[("Workbook", &workbook()), ("Notes", SECOND)])?,
            Some("Second"),
        ),
        (
            "plain PowerPoint text atom",
            cfb(&[("PowerPoint Document", &powerpoint()), ("Notes", SECOND)])?,
            Some("Second"),
        ),
        ("ordinary neighbor of short package", odd, Some("First")),
        (
            "WordDocument with several storages",
            cfb(&[
                ("WordDocument", &word_document()),
                ("FolderA/Notes", muted),
                ("FolderB/Notes", FIRST),
            ])?,
            Some("First"),
        ),
        (
            "ZIP containing OLE",
            zip::zip(&[("ordinary.ole", &packed)], true, false, false)?,
            Some("Second"),
        ),
        ("clean", cfb(&[("Notes", muted)])?, None),
        ("truncated header", packed[..400].to_vec(), None),
    ];
    let check =
        |socket: &Path, label: &str, bytes: &[u8], expect: Option<&str>| -> io::Result<()> {
            let expected = match expect {
                Some(name) if name.starts_with("Heuristics.") => format!("stream: {name} FOUND\0"),
                Some(name) => format!("stream: Ole.{name}.UNOFFICIAL FOUND\0"),
                None if stock => "stream: OK\0".into(),
                None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
            };
            let actual = unix_request(socket, &stream_frame(bytes)?)?;
            assert_eq!(actual, expected, "{label}");
            Ok(())
        };
    for (label, bytes, expect) in &cases {
        check(&socket, label, bytes, *expect)?;
    }
    drop(service);
    for (id, options, sample, expected) in [
        (
            "depth",
            "MaxRecursion 1\nAlertExceedsMax yes",
            &packed,
            Some("Heuristics.Limits.Exceeded.MaxRecursion"),
        ),
        (
            "storage",
            "MaxRecursion 2\nAlertExceedsMax yes",
            &nested,
            Some("Heuristics.Limits.Exceeded.MaxRecursion"),
        ),
        (
            "count",
            "MaxFiles 1\nAlertExceedsMax yes",
            &ordered,
            Some("Heuristics.Limits.Exceeded.MaxFiles"),
        ),
        (
            "within-count",
            "MaxFiles 2\nAlertExceedsMax yes",
            &ordered,
            Some("Second"),
        ),
        ("disabled", "ScanOLE2 no", &packed, None),
        ("disabled-outer", "ScanOLE2 no", &whole, Some("Outer")),
    ] {
        let (_instance, socket) = start(id, options)?;
        check(&socket, id, sample, expected)?;
    }
    let (_instance, socket) = start(
        "scan-size",
        &format!("MaxScanSize {}\nAlertExceedsMax yes", packed.len() + 10),
    )?;
    check(
        &socket,
        "child exceeds remaining bytes",
        &packed,
        Some("Heuristics.Limits.Exceeded.MaxScanSize"),
    )?;
    Ok(())
}

#[test]
fn barnacle_ole_objects() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn stock_ole_objects() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}

#[test]
fn ordinary_stream_and_package_keep_the_compound_parent() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    let wrap = package(SECOND);
    for doc in [cfb(&[("Storage/Notes", SECOND)])?, cfb(&[(NATIVE, &wrap)])?] {
        let archive = zip::zip(&[("ordinary.ole", &doc)], true, false, false)?;
        let verdict = scan(
            &archive,
            &Options::default(),
            tmp.path(),
            |object, _| {
                if object.bytes == SECOND {
                    assert_eq!(
                        object
                            .parents
                            .iter()
                            .map(|e| e.file_type)
                            .collect::<Vec<_>>(),
                        ["CL_TYPE_ZIP", "CL_TYPE_MSOLE2"]
                    );
                    assert_eq!(
                        object.parents[1].name.as_deref(),
                        Some(b"ordinary.ole".as_slice())
                    );
                    assert_eq!(object.layer.name, None);
                    return Ok(Verdict::Found("compound parent".into()));
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert_eq!(verdict, Verdict::Found("compound parent".into()));
    }
    Ok(())
}

#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn stock_compound_parent() -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let db = tmp.path().join("db");
    fs::create_dir(&db)?;
    let marker = b"ordinary compound parent marker";
    let hex: String = marker.iter().map(|b| format!("{b:02x}")).collect();
    fs::write(
        db.join("contexts.ldb"),
        format!("Ole.Parent;Engine:81-255,Target:0,Container:CL_TYPE_MSOLE2;0;{hex}\n"),
    )?;
    let socket = tmp.path().join("sock");
    let conf = tmp.path().join("clamd.conf");
    fs::write(
        &conf,
        format!(
            "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n",
            db.display(),
            socket.display()
        ),
    )?;
    let _service = Daemon::start(Path::new("/usr/sbin/clamd"), &conf, &socket)?;
    let wrap = package(marker);
    for doc in [cfb(&[("Storage/Notes", marker)])?, cfb(&[(NATIVE, &wrap)])?] {
        let zip = zip::zip(&[("ordinary.ole", &doc)], true, false, false)?;
        assert_eq!(
            unix_request(&socket, &stream_frame(&zip)?)?,
            "stream: Ole.Parent.UNOFFICIAL FOUND\0"
        );
    }
    assert_eq!(
        unix_request(&socket, &stream_frame(marker)?)?,
        "stream: OK\0"
    );
    Ok(())
}

#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn stock_and_barnacle_office_stream_priority() -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let root = tmp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let mut rules = String::new();
    for (name, data) in [("First", FIRST), ("Second", SECOND)] {
        let digest: String = Md5::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        rules.push_str(&format!("{digest}:{}:Ole.{name}\n", data.len()));
    }
    fs::write(db.join("local.hdb"), rules)?;
    let (_stock, stock) = start_daemon(Path::new("/usr/sbin/clamd"), root, &db, "stock", "")?;
    let (_candidate, candidate) = start_daemon(
        Path::new(env!("CARGO_BIN_EXE_barnacle")),
        root,
        &db,
        "candidate",
        "",
    )?;
    let first_package = package(FIRST);
    let second_package = package(SECOND);
    for (name, office) in [
        ("WordDocument", word_document()),
        ("PowerPoint Document", powerpoint()),
        ("Workbook", workbook()),
    ] {
        for streams in [
            vec![
                (name, office.as_slice()),
                ("NotesA", FIRST),
                ("NotesB", SECOND),
            ],
            vec![
                ("NotesB", FIRST),
                ("NotesA", SECOND),
                (name, office.as_slice()),
            ],
            vec![
                (name, office.as_slice()),
                ("FolderA/Child/Notes", FIRST),
                ("FolderB/Notes", SECOND),
            ],
            vec![
                ("FolderB/Notes", FIRST),
                ("FolderA/Child/Notes", SECOND),
                (name, office.as_slice()),
            ],
            vec![
                ("ObjectPool/B/\x01Ole10Native", first_package.as_slice()),
                (name, office.as_slice()),
                ("ObjectPool/A/\x01Ole10Native", second_package.as_slice()),
            ],
            vec![
                ("ObjectPool/B/\x01Ole10Native", second_package.as_slice()),
                (name, office.as_slice()),
                ("FolderA/Summary", FIRST),
            ],
        ] {
            let request = stream_frame(&cfb(&streams)?)?;
            let expected = unix_request(&stock, &request)?;
            assert!(matches!(
                expected.as_str(),
                "stream: Ole.First.UNOFFICIAL FOUND\0" | "stream: Ole.Second.UNOFFICIAL FOUND\0"
            ));
            assert_eq!(unix_request(&candidate, &request)?, expected, "{name}");
        }
    }
    let multi = cfb(&[
        ("WordDocument", &word_document()),
        ("FolderA/Notes", FIRST),
        ("FolderB/\x01Ole10Native", &second_package),
    ])?;
    let request = stream_frame(&multi)?;
    for count in [2, 3, 4] {
        let options = format!("MaxFiles {count}\nAlertExceedsMax yes");
        let (_stock, stock) = start_daemon(
            Path::new("/usr/sbin/clamd"),
            root,
            &db,
            &format!("stock{count}"),
            &options,
        )?;
        let (_bn, bn) = start_daemon(
            Path::new(env!("CARGO_BIN_EXE_barnacle")),
            root,
            &db,
            &format!("bn{count}"),
            &options,
        )?;
        assert_eq!(
            unix_request(&bn, &request)?,
            unix_request(&stock, &request)?,
            "MaxFiles {count}"
        );
    }
    Ok(())
}
