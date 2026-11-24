//! Compare ordinary OneNote desktop attachments with Debian clamd 1.4.3+dfsg-1.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;
#[path = "object_onenote/package.rs"]
mod package;

use client::{Daemon, stream_frame, unix_request};
use md5::{Digest, Md5};
use sha2::Sha256;
use std::{fs, io, path::Path};

const SECTION: &[u8] = b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3";
const RECORD: &[u8] = b"\xe7\x16\xe3\xbd\x65\x26\x11\x45\xa4\xc4\x8d\x4d\x0b\x7a\x9e\xac";
const FOOTER: &[u8] = b"\x22\xa7\xfb\x71\x79\x0f\x0b\x4a\xbb\x13\x89\x92\x56\x42\x6b\x24";
const FIRST: &[u8] = b"first ordinary attachment";
const SECOND: &[u8] = b"second ordinary attachment";
const LABEL: &[u8] = b"notebook-marker";

fn document(start: usize, files: &[&[u8]]) -> Vec<u8> {
    let mut doc = SECTION.to_vec();
    doc.resize(start, 0);
    for file in files {
        doc.extend(RECORD);
        doc.extend((file.len() as u64).to_le_bytes());
        doc.extend([0; 12]);
        doc.extend(*file);
        doc.resize(doc.len().next_multiple_of(8), 0);
        doc.extend(FOOTER);
    }
    doc.extend(LABEL);
    doc
}

fn hash(file: &[u8], name: &str) -> String {
    let hex: String = Md5::digest(file)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{hex}:{}:{name}\n", file.len())
}

fn compare(executable: &Path, stock: bool) -> io::Result<()> {
    let ordinary = document(1024, &[FIRST, SECOND]);
    let unlabeled = &ordinary[..ordinary.len() - LABEL.len()];
    let parent_context = document(1024, &[b"reference label"]);
    let reverse = document(1024, &[SECOND, FIRST]);
    let mut packaged = package::section(false, FIRST, SECOND);
    packaged.extend(LABEL);
    let packaged_reverse = package::section(true, FIRST, SECOND);
    let large = vec![b'x'; 4 << 20];
    let large_package = package::section(true, &large, SECOND);
    let boundary = document(65531, &[FIRST]);
    let short = document(1024, &[b"tiny", SECOND]);
    let nested = document(1024, &[&reverse]);
    let mut header_only = SECTION.to_vec();
    header_only.extend(LABEL);
    let mut truncated = document(1024, &[FIRST]);
    truncated.truncate(1044);
    truncated.extend(LABEL);
    let expectations: &[(&str, &[u8], &str)] = &[
        ("", &ordinary, "Local.First.UNOFFICIAL"),
        ("", &reverse, "Local.Second.UNOFFICIAL"),
        ("", &packaged, "Local.Second.UNOFFICIAL"),
        ("", &packaged_reverse, "Local.First.UNOFFICIAL"),
        ("", &large_package, "Local.Large.UNOFFICIAL"),
        ("ScanOneNote no", &packaged, "Local.Envelope.UNOFFICIAL"),
        (
            &format!("MaxScanSize {}", packaged.len() + SECOND.len()),
            &packaged,
            "Local.Second.UNOFFICIAL",
        ),
        ("", &boundary, "Local.First.UNOFFICIAL"),
        ("", &short, "Local.Second.UNOFFICIAL"),
        ("", &parent_context, "Local.Parent.UNOFFICIAL"),
        ("", &nested, "Local.Second.UNOFFICIAL"),
        ("", &header_only, "Local.Envelope.UNOFFICIAL"),
        ("", &truncated, "Local.Envelope.UNOFFICIAL"),
        ("ScanOneNote no", &ordinary, "Local.Envelope.UNOFFICIAL"),
        ("ScanArchive no", &ordinary, "Local.First.UNOFFICIAL"),
        (
            &format!("MaxScanSize {}", ordinary.len() + FIRST.len()),
            &ordinary,
            "Local.First.UNOFFICIAL",
        ),
        (
            "MaxRecursion 1\nAlertExceedsMax yes",
            &ordinary,
            "Local.Envelope.UNOFFICIAL",
        ),
        (
            "MaxRecursion 1\nAlertExceedsMax yes",
            unlabeled,
            "Heuristics.Limits.Exceeded.MaxRecursion",
        ),
        (
            "MaxFiles 1\nAlertExceedsMax yes",
            unlabeled,
            "Heuristics.Limits.Exceeded.MaxFiles",
        ),
        (
            &format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                unlabeled.len() + FIRST.len() - 1
            ),
            unlabeled,
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
    ];
    let outer = LABEL.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let data =
        hash(FIRST, "Local.First") + &hash(SECOND, "Local.Second") + &hash(&large, "Local.Large");
    let mut settings: Vec<_> = expectations.iter().map(|e| e.0).collect();
    settings.sort_unstable();
    settings.dedup();
    for setting in settings {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join("children.hdb"), &data)?;
        if stock {
            fs::write(
                db.join("parent.ldb"),
                "Local.Parent;Engine:81-255,Target:0,Container:CL_TYPE_ONENOTE;0;7265666572656e6365206c6162656c\n",
            )?;
        }
        fs::write(
            db.join("envelope.ndb"),
            format!("Local.Envelope:0:*:{outer}\n"),
        )?;
        let socket = dir.path().join("socket");
        let config = dir.path().join("daemon.conf");
        fs::write(
            &config,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nSelfCheck 0\nDisableCache yes\n{setting}\n",
                db.display(),
                socket.display()
            ),
        )?;
        let _daemon = Daemon::start(executable, &config, &socket)?;
        for &(s, doc, expected) in expectations {
            if s == setting && (stock || expected != "Local.Parent.UNOFFICIAL") {
                assert_eq!(
                    unix_request(&socket, &stream_frame(doc)?)?,
                    format!("stream: {expected} FOUND\0"),
                    "{setting:?}, doc size {}",
                    doc.len()
                );
            }
        }
    }
    if let Some(path) = std::env::var_os("BARNACLE_ONENOTE_DESKTOP_FIXTURE") {
        public_desktop(executable, &fs::read(path)?)?;
    }
    if let Some(path) = std::env::var_os("BARNACLE_ONENOTE_PACKAGE_FIXTURE") {
        // Pinned onenote.rs test file New Section Group/New Section 2.one.
        let mut doc = fs::read(path)?;
        assert_eq!(
            sha256(&doc),
            "ab93b8cb1c0d7f45043637cf63b0f06785b8234eb4185acff7cf79b8b122fb0b"
        );
        // Stock skips ID3 content. Substitute text in the existing file-data blob
        // so a whole-child hash can verify attachment boundaries on both daemons.
        let audio = &mut doc[54059..54059 + 77279];
        assert_eq!(
            sha256(audio),
            "d2318cc34b6254cdc2db84b931adad166a4b2b701b4241c27b338b959ac738b0"
        );
        audio.fill(b'a');
        let rules = format!(
            "{}:{}:Local.PackageAttachment\n",
            sha256(audio),
            audio.len()
        );
        check_public(executable, &doc, &rules, "PackageAttachment")?;
    }
    Ok(())
}

// Upstream onenote.rs test fixture OneWithFileData.one, Git blob 61a3d90be7f37498959e09c95b0abab57e30e068.
fn public_desktop(executable: &Path, section: &[u8]) -> io::Result<()> {
    let sha = sha256(section);
    assert_eq!(
        sha,
        "26ec59da7bb81c48e8f41554d06d381b53f88166727eed231baa665d9833266e"
    );
    let second =
        "aa075cde449be8b020df256cac1eda81844f229b350b01749a130667c216b98d:718:Local.PublicSecond\n";
    let first = "8e99dc44681b8399608f7a181e44d3e41dc36fbacd35a9cfb2d1fc330ac68459:14660:Local.PublicFirst\n";
    for (rules, expected) in [
        (format!("{first}{second}"), "PublicFirst"),
        (second.into(), "PublicSecond"),
    ] {
        check_public(executable, section, &rules, expected)?;
    }
    Ok(())
}

fn sha256(section: &[u8]) -> String {
    Sha256::digest(section)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn check_public(executable: &Path, section: &[u8], rules: &str, expected: &str) -> io::Result<()> {
    let dir = tempfile::tempdir_in("/tmp")?;
    let db = dir.path().join("db");
    fs::create_dir(&db)?;
    fs::write(db.join("attachments.hsb"), rules)?;
    let socket = dir.path().join("socket");
    let config = dir.path().join("daemon.conf");
    fs::write(
        &config,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nSelfCheck 0\nDisableCache yes\n",
            db.display(),
            socket.display()
        ),
    )?;
    let _daemon = Daemon::start(executable, &config, &socket)?;
    assert_eq!(
        unix_request(&socket, &stream_frame(section)?)?,
        format!("stream: Local.{expected}.UNOFFICIAL FOUND\0")
    );
    Ok(())
}

#[test]
fn barnacle_onenote_objects() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
fn desktop_child_keeps_section_parent() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let dir = tempfile::tempdir()?;
    let verdict = scan(
        &document(1024, &[FIRST]),
        &Options::default(),
        dir.path(),
        |object, _| {
            if object.bytes == FIRST {
                assert_eq!(
                    object.parents.last().map(|layer| layer.file_type),
                    Some("CL_TYPE_ONENOTE")
                );
                assert!(object.layer.name.is_none());
                return Ok(Verdict::Found("attachment".into()));
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(verdict, Verdict::Found("attachment".into()));
    Ok(())
}

#[test]
#[ignore = "requires Debian clamd 1.4.3+dfsg-1"]
fn stock_onenote_objects() -> io::Result<()> {
    let pkg = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pkg.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}

#[test]
fn package_attachments_keep_page_order_and_names() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let dir = tempfile::tempdir()?;
    let mut names = Vec::new();
    scan(
        &package::section(false, FIRST, SECOND),
        &Options::default(),
        dir.path(),
        |object, _| {
            if !object.normalized && object.parents.len() == 1 {
                assert_eq!(object.parents[0].file_type, "CL_TYPE_ONENOTE");
                names.push(
                    object
                        .layer
                        .name
                        .as_deref()
                        .expect("named package attachment")
                        .to_vec(),
                );
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(names, [b"second.txt".to_vec(), b"first.txt".to_vec()]);
    Ok(())
}

#[test]
fn large_package_blob_borrows_the_input() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let mut large = vec![b'x'; 4 << 20];
    large[..FIRST.len()].copy_from_slice(FIRST);
    let doc = package::section(true, &large, SECOND);
    let dir = tempfile::tempdir()?;
    let verdict = scan(
        &doc,
        &Options::default(),
        dir.path(),
        |object, _| {
            if object.layer.name.as_deref() == Some(b"first.txt") {
                assert_eq!(object.bytes, large);
                assert!(doc.as_ptr_range().contains(&object.bytes.as_ptr()));
                return Ok(Verdict::Found("borrowed".into()));
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(verdict, Verdict::Found("borrowed".into()));
    Ok(())
}
