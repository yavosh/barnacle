//! Harmless ancestry fixtures for the pinned ClamAV logical matcher.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;
#[path = "common/zip.rs"]
mod zip;

use flate2::{Compression, write::GzEncoder};
use std::io::{self, Write};
use std::{fs, path::Path};

#[derive(Clone, Copy)]
enum View {
    Raw,
    Script,
    Html,
    Utf16Html,
    DataUrl,
}

fn compare(exe: &Path, stock: bool, mapped: bool) -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let db = temp.path().join("db");
    fs::create_dir(&db)?;
    let socket = temp.path().join("socket");
    let config = temp.path().join("clamd.conf");
    fs::write(
        &config,
        format!(
            "Foreground yes\nDisableCache yes\nMaxRecursion 24\nSelfCheck 0\nLocalSocket {}\nDatabaseDirectory {}\n",
            socket.display(),
            db.display()
        ),
    )?;
    let mut rules = String::new();
    if mapped {
        rules.push_str("Local.ForceMap;Target:7;0;EOF-1:6e6576657270726573656e74\n");
    }
    let mut samples = Vec::new();
    let mut add = |view: View,
                   wraps: &str,
                   chain: &str,
                   container: Option<&str>,
                   hit: bool|
     -> io::Result<()> {
        let id = samples.len();
        let marker = format!("ledger{id:03}x");
        let hex: String = marker.bytes().map(|c| format!("{c:02x}")).collect();
        let text = marker.to_ascii_uppercase();
        let (mut bytes, target) = match view {
            View::Raw => {
                let mut bytes = vec![0; 1_024];
                bytes.extend_from_slice(marker.as_bytes());
                (bytes, 0)
            }
            View::Script => (format!("ORDINARY {text} REFERENCE\n").into_bytes(), 7),
            View::Html => (format!("<html><body>{text}</body></html>").into_bytes(), 3),
            View::Utf16Html => {
                let text = format!("\u{feff}<html><body>{text}</body></html>");
                (text.encode_utf16().flat_map(u16::to_le_bytes).collect(), 3)
            }
            View::DataUrl => {
                let encoded: String = marker.bytes().map(|c| format!("%{c:02x}")).collect();
                (
                    format!("<html><body><img src=\"data:text/plain,{encoded}\"></body></html>")
                        .into_bytes(),
                    0,
                )
            }
        };
        for kind in wraps.bytes().rev() {
            bytes = match kind {
                b'Z' => zip::zip(&[("report", &bytes)], true, false, false)?,
                b'G' => {
                    let mut writer = GzEncoder::new(Vec::new(), Compression::default());
                    writer.write_all(&bytes)?;
                    writer.finish()?
                }
                _ => unreachable!(),
            }
        }
        let types = chain
            .split('>')
            .map(|kind| format!("CL_TYPE_{kind}"))
            .collect::<Vec<_>>()
            .join(">");
        let parent = container.map_or(String::new(), |kind| format!(",Container:CL_TYPE_{kind}"));
        let name = format!("Local.Ancestry{id}");
        rules.push_str(&format!(
            "{name};Engine:51-255,Target:{target},Intermediates:{types}{parent};0;{hex}\n"
        ));
        samples.push((bytes, name, hit, format!("{wraps} {chain} {container:?}")));
        Ok(())
    };
    use View::*;
    add(Raw, "", "ANY", None, false)?;
    add(Raw, "Z", "ANY", None, true)?;
    add(Raw, "Z", "ZIP", None, true)?;
    add(Raw, "Z", "ANY>ZIP", None, false)?;
    add(Raw, "ZG", "ZIP>GZ", None, true)?;
    add(Raw, "ZG", "GZ>ZIP", None, false)?;
    add(Raw, "ZG", "GZ", None, true)?;
    add(Raw, "ZG", "ZIP", None, false)?;
    add(Raw, "ZG", "ZIP>ANY", None, false)?;
    add(Raw, "ZG", "GZ>ANY", None, true)?;
    add(Raw, "ZG", "ANY>GZ", None, true)?;
    add(Raw, "ZG", "ANY>ANY", None, true)?;
    add(Raw, "ZG", "ANY>ANY>ANY", None, false)?;
    add(Raw, "ZZG", "ZIP>ANY>GZ", None, true)?;
    add(Raw, "ZG", "ZIP>GZ", Some("ZIP"), false)?;
    add(Raw, "ZG", "ZIP>GZ", Some("GZ"), true)?;
    add(Raw, "ZG", "ANY", Some("ANY"), false)?;
    add(Script, "", "ANY", None, mapped)?;
    add(Script, "Z", "ANY>ZIP", Some("ZIP"), mapped)?;
    add(Script, "ZG", "ZIP>GZ", Some("GZ"), true)?;
    add(Html, "", "ANY", Some("ANY"), true)?;
    add(Html, "Z", "ANY>ZIP", Some("ZIP"), true)?;
    add(Html, "Z", "ZIP>HTML", Some("HTML"), false)?;
    add(Utf16Html, "", "ANY>ANY", Some("ANY"), true)?;
    add(Utf16Html, "Z", "ANY>ANY>ZIP", Some("ZIP"), true)?;
    add(DataUrl, "Z", "ANY>ZIP", Some("ZIP"), true)?;
    let sixteen = ["ZIP"; 16].join(">");
    add(Raw, &"Z".repeat(15), &sixteen, None, false)?;
    add(Raw, &"Z".repeat(16), &sixteen, None, true)?;
    add(Raw, &"Z".repeat(16), &format!("{sixteen}>GZ"), None, true)?;
    // Only the original map has this size. A mapped script restores its original
    // recursion depth before evaluating the caller's empty subsignature counts.
    let source = format!("ORDINARY{}REPORT", " ".repeat(700)).into_bytes();
    let size = source.len();
    let name = "Local.Restored".to_owned();
    rules.push_str(&format!(
        "{name};Engine:51-255,Target:7,Intermediates:CL_TYPE_ANY,FileSize:{size}-{size};0=0;6f6d6974746564\n"
    ));
    let member = zip::zip(&[("report", &source)], true, false, false)?;
    samples.push((source, name.clone(), false, "restored root".into()));
    samples.push((member, name, true, "restored member".into()));
    fs::write(db.join("local.ldb"), rules)?;
    let _daemon = client::Daemon::start(exe, &config, &socket)?;
    let mut mismatches = Vec::new();
    for (bytes, name, hit, description) in samples {
        let reply = client::unix_request(&socket, &client::stream_frame(&bytes)?)?;
        let expected = if hit {
            format!("stream: {name}.UNOFFICIAL FOUND\0")
        } else if stock {
            "stream: OK\0".into()
        } else {
            "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into()
        };
        if reply != expected {
            mismatches.push(format!(
                "{name} {description} mapped={mapped}: expected {expected:?}, got {reply:?}"
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    Ok(())
}

#[test]
fn nested_and_normalized_ancestry() -> io::Result<()> {
    for mapped in [false, true] {
        compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false, mapped)?;
    }
    Ok(())
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_nested_and_normalized_ancestry() -> io::Result<()> {
    for mapped in [false, true] {
        compare(Path::new("/usr/sbin/clamd"), true, mapped)?;
    }
    Ok(())
}
