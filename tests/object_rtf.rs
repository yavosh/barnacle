#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;

use std::{fs, io, path::Path};

fn package(text: &[u8]) -> Vec<u8> {
    let mut package = b"\x02\0note.txt\0note.txt\0".to_vec();
    package.extend_from_slice(&[0; 8]);
    package.extend_from_slice(b"note.txt\0");
    package.extend_from_slice(&(text.len() as u32).to_le_bytes());
    package.extend_from_slice(text);
    let mut embedded = b"\x01\x05\0\0\x02\0\0\0\x08\0\0\0Package\0".to_vec();
    embedded.extend_from_slice(&[0; 8]);
    embedded.extend_from_slice(&(package.len() as u32).to_le_bytes());
    embedded.extend_from_slice(&package);
    let hex: String = embedded.iter().map(|b| format!("{b:02x}")).collect();
    format!("{{\\object\\objemb{{\\*\\objclass Package}}{{\\*\\objdata {hex}}}}}").into_bytes()
}

fn compare(exe: &Path) -> io::Result<()> {
    let dir = tempfile::tempdir_in("/tmp")?;
    let db = dir.path().join("db");
    fs::create_dir(&db)?;
    let markers = [
        ("Outer", "QuarterlyCover"),
        ("First", "QuarterlyNotes"),
        ("Last", "BudgetMemo"),
    ];
    let ndb: String = markers
        .iter()
        .map(|(name, marker)| {
            let bytes: String = marker.bytes().map(|b| format!("{b:02x}")).collect();
            format!("RTF.{name}:0:*:{bytes}\n")
        })
        .collect();
    fs::write(db.join("markers.ndb"), ndb)?;
    let socket = dir.path().join("sock");
    let conf = dir.path().join("instance.conf");
    fs::write(
        &conf,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\n",
            db.display(),
            socket.display()
        ),
    )?;
    let _daemon = daemon::Daemon::start(exe, &conf, &socket)?;
    for (children, expected) in [
        (vec![], "Outer"),
        (
            vec![package(b"plain QuarterlyNotes for committee")],
            "First",
        ),
        (
            vec![
                package(b"ordinary summary"),
                package(b"BudgetMemo for next month"),
            ],
            "Last",
        ),
        (
            vec![
                package(b"BudgetMemo for next month"),
                package(b"QuarterlyNotes"),
            ],
            "Last",
        ),
    ] {
        let mut bytes = b"{\\rtf1\\ansi QuarterlyCover ".to_vec();
        for child in children {
            bytes.extend(child);
        }
        bytes.push(b'}');
        assert_eq!(
            daemon::unix_request(&socket, &daemon::stream_frame(&bytes)?)?,
            format!("stream: RTF.{expected}.UNOFFICIAL FOUND\0")
        );
    }
    Ok(())
}

#[test]
fn embedded_text_precedes_outer_rtf() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
#[ignore = "requires the pinned Debian clamd"]
fn stock_extracts_the_same_rtf_objects() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"))
}
