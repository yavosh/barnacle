//! Compare harmless Flash metadata against Debian clamd 1.4.3+dfsg-1.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;

use client::{Daemon, stream_frame, unix_request};
use flate2::{Compression, write::ZlibEncoder};
use lzma_rust2::{LzmaOptions, LzmaWriter};
use md5::{Digest, Md5};
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

fn movies(varied: bool) -> io::Result<[Vec<u8>; 3]> {
    let mut metadata = b"<report>".to_vec();
    metadata.resize(17_000, b'a');
    if varied {
        let mut seed = 1u32;
        for b in &mut metadata[8..] {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *b = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                [(seed & 63) as usize];
        }
    }
    metadata.extend_from_slice(b"</report>\0");
    let mut body = vec![8, 0, 0, 12, 1, 0]; // A zero-sized stage and one frame at 12 fps.
    body.extend(((77u16 << 6) | 63).to_le_bytes()); // Metadata tag with a long length.
    body.extend((metadata.len() as u32).to_le_bytes());
    body.extend(metadata);
    body.extend([0x40, 0, 0, 0]); // ShowFrame, End.

    let mut fws = b"FWS\x0d".to_vec();
    fws.extend(((8 + body.len()) as u32).to_le_bytes());
    let mut cws = fws.clone();
    let mut zws = fws.clone();
    fws.extend(&body);
    cws[0] = b'C';
    let mut deflate = ZlibEncoder::new(cws, Compression::default());
    deflate.write_all(&body)?;
    let cws = deflate.finish()?;
    zws[0] = b'Z';
    let options = LzmaOptions {
        dict_size: 8192,
        ..Default::default()
    };
    let mut lzma = LzmaWriter::new_no_header(Vec::new(), &options, true)?;
    lzma.write_all(&body)?;
    let compressed = lzma.finish()?;
    zws.extend((compressed.len() as u32).to_le_bytes());
    zws.push(options.get_props());
    zws.extend(options.dict_size.to_le_bytes());
    zws.extend(compressed);
    Ok([fws, cws, zws])
}

fn hash(bytes: &[u8], name: &str) -> String {
    let hex: String = Md5::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{hex}:{}:Local.{name}\n", bytes.len())
}

fn compare(executable: &Path) -> io::Result<()> {
    let [fws, cws, zws] = movies(false)?;
    let [varied_fws, _, varied_zws] = movies(true)?;
    let mut stored = ZlibEncoder::new(cws[..8].to_vec(), Compression::none());
    stored.write_all(&fws[8..])?;
    let stored = stored.finish()?;
    let hashes = [
        hash(&fws, "Movie"),
        hash(&fws[..8200], "Block"),
        hash(&fws[..8], "Header"),
        hash(&fws[..8193], "StoredBlock"),
        hash(&varied_fws[..10491], "LzmaBlock"),
    ]
    .concat();
    let fws_len = fws.len();
    type Detections<'a> = &'a [(&'a [u8], &'a str)];
    let fixtures: &[(&str, &str, Detections<'_>)] = &[
        (
            "",
            "hash",
            &[(&fws, "Movie"), (&cws, "Movie"), (&zws, "Movie")],
        ),
        (
            "ScanSWF no",
            "hash",
            &[(&fws, "Movie"), (&cws, "OuterC"), (&zws, "OuterZ")],
        ),
        (
            "",
            "body",
            &[(&fws, "Typed"), (&cws, "Typed"), (&zws, "Typed")],
        ),
        (
            &format!("MaxFileSize {fws_len}"),
            "hash",
            &[(&cws, "Movie"), (&zws, "Movie")],
        ),
        (
            "MaxFileSize 8200",
            "hash",
            &[(&cws, "Block"), (&zws, "Block")],
        ),
        (
            "MaxFileSize 8199",
            "hash",
            &[(&cws, "Header"), (&zws, "Header")],
        ),
        (
            &format!("MaxScanSize {}", cws.len() + fws.len()),
            "hash",
            &[(&cws, "Movie")],
        ),
        (
            &format!("MaxScanSize {}", zws.len() + 8200),
            "hash",
            &[(&zws, "Block")],
        ),
        (
            &format!("MaxScanSize {}", stored.len() + 8199),
            "hash",
            &[(&stored, "StoredBlock")],
        ),
        (
            &format!("MaxScanSize {}", varied_zws.len() + 11000),
            "hash",
            &[(&varied_zws, "LzmaBlock")],
        ),
        (
            "MaxFileSize 8200\nAlertExceedsMax yes",
            "limit",
            &[(&cws, "Heuristics.Limits.Exceeded.MaxFileSize")],
        ),
        (
            &format!(
                "MaxFileSize 8200\nMaxScanSize {}\nAlertExceedsMax yes",
                zws.len() + 9000
            ),
            "limit",
            &[(&zws, "Heuristics.Limits.Exceeded.MaxScanSize")],
        ),
        (
            &format!(
                "MaxFileSize 10000\nMaxScanSize {}\nAlertExceedsMax yes",
                cws.len() + 17000
            ),
            "limit",
            &[(&cws, "Heuristics.Limits.Exceeded.MaxFileSize")],
        ),
    ];
    for &(settings, profile, cases) in fixtures {
        let root = tempfile::tempdir_in("/tmp")?;
        let db = root.path().join("db");
        fs::create_dir(&db)?;
        let bodies = if profile == "hash" {
            fs::write(db.join("movies.hdb"), &hashes)?;
            "Local.OuterC:11:0:4357530d\nLocal.OuterZ:11:0:5a57530d\n"
        } else if profile == "body" {
            "Local.Any:0:*:3c7265706f72743e\nLocal.Typed:11:*:3c7265706f72743e\n"
        } else {
            "Local.Other:11:*:6368617274\n"
        };
        fs::write(db.join("movie.ndb"), bodies)?;
        let config = root.path().join("daemon.conf");
        let socket = root.path().join("socket");
        fs::write(
            &config,
            format!(
                "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nSelfCheck 0\nDisableCache yes\n{settings}\n",
                socket.display(),
                db.display()
            ),
        )?;
        let _daemon = Daemon::start(executable, &config, &socket)?;
        for &(bytes, expected) in cases {
            let expected = if profile == "limit" {
                (*expected).to_string()
            } else {
                format!("Local.{expected}.UNOFFICIAL")
            };
            assert_eq!(
                unix_request(&socket, &stream_frame(bytes)?)?,
                format!("stream: {expected} FOUND\0"),
                "{settings:?}, {profile}, {}",
                bytes[0] as char
            );
        }
    }
    Ok(())
}

#[test]
fn flash_input_block_boundary() -> io::Result<()> {
    use barnacle::objects::{self, Options, Verdict};
    let [fws, _, zws] = movies(true)?;
    let tmp = tempfile::tempdir()?;
    let options = Options {
        max_scan_size: zws.len() as u64 + 11000,
        ..Options::default()
    };
    let verdict = objects::scan(
        &zws,
        &options,
        tmp.path(),
        |obj, _| {
            if obj.parents.is_empty() {
                return Ok(Verdict::Miss);
            }
            assert_eq!(obj.bytes.len(), 10491);
            assert_eq!(obj.bytes, &fws[..10491]);
            Ok(Verdict::Found("clipped movie".into()))
        },
        || Ok(()),
    )?;
    assert_eq!(verdict, Verdict::Found("clipped movie".into()));
    Ok(())
}

#[test]
fn barnacle_flash_objects() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
#[ignore = "requires Debian clamd 1.4.3+dfsg-1"]
fn stock_flash_objects() -> io::Result<()> {
    let package = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(package.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"))
}
