//! Record stock clamd replies and detection logs for object ordering and scan limits.
#[path = "compat_oracle/daemon.rs"]
mod daemon;
#[path = "../tests/common/zip.rs"]
mod zip;

use daemon::{Daemon, stream_frame, unix_request};
use flate2::{Compression, write::GzEncoder};
use md5::{Digest, Md5};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, Instant};

fn gzip(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

fn hash_rule(data: &[u8], name: &str) -> String {
    let digest: String = Md5::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{digest}:{}:{name}\n", data.len())
}

fn detection_line(path: &Path, offset: usize, signature: &str) -> io::Result<String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let text = fs::read_to_string(path)?;
        if let Some(line) = text.get(offset..).and_then(|new| {
            new.lines()
                .filter_map(|line| line.split_once("): ").map(|(_, detail)| detail))
                .find(|detail| detail.starts_with(signature) && detail.ends_with(" FOUND"))
        }) {
            return Ok(line.to_owned());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "missing detection log for {signature}"
            )));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn probe(
    exe: &Path,
    profile: &str,
    settings: &str,
    hashes: &str,
    inputs: &[(&str, &[u8])],
) -> io::Result<()> {
    for alert in [false, true] {
        let tmp = tempfile::tempdir_in("/tmp")?;
        let root = tmp.path();
        let db = root.join("db");
        fs::create_dir(&db)?;
        fs::write(db.join("local.hdb"), hashes)?;
        let pattern: String = b"harmless signature"
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        fs::write(db.join("local.ndb"), format!("InnerBody:0:*:{pattern}\n"))?;
        let sock = root.join("sock");
        let conf = root.join("instance.conf");
        let log = root.join("detections");
        fs::write(
            &conf,
            format!(
                "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nTemporaryDirectory {}\nLogFile {}\nExtendedDetectionInfo yes\nDisableCache yes\nSelfCheck 0\nAlertExceedsMax {}\n{settings}\n",
                sock.display(),
                db.display(),
                root.display(),
                log.display(),
                if alert { "yes" } else { "no" }
            ),
        )?;
        let _daemon = Daemon::start(exe, &conf, &sock)?;
        for &(name, data) in inputs {
            let offset = fs::metadata(&log)?.len() as usize;
            let reply = unix_request(&sock, &stream_frame(data)?)?;
            let compact = reply
                .trim_end_matches('\0')
                .strip_prefix("stream: ")
                .unwrap_or(&reply);
            let detail = if let Some(signature) = compact.strip_suffix(" FOUND") {
                detection_line(&log, offset, signature)?
            } else {
                String::new()
            };
            println!(
                "{profile}\t{alert}\t{name}\t{}\t{compact}\t{detail}",
                data.len()
            );
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [executable] = args.as_slice() else {
        return Err(io::Error::other("usage: object_reference DAEMON"));
    };
    let exe = Path::new(executable);
    let member = b"ordinary reference document with a harmless signature.\n".repeat(4);
    let hash_only = b"ordinary whole file fixture with a separate hash.\n".repeat(4);
    let archive = gzip(&member)?;
    let nested = gzip(&archive)?;
    let clean = gzip(b"ordinary document without a local signature")?;
    let hash_archive = gzip(&hash_only)?;
    let mut cut = clean.clone();
    cut.truncate(cut.len() - 6);
    let inputs = [
        ("member", member.as_slice()),
        ("gzip", archive.as_slice()),
        ("nested", &nested),
        ("hash-only", &hash_archive),
        ("clean", &clean),
        ("truncated", &cut),
    ];
    let hashes = hash_rule(&hash_only, "InnerHash") + &hash_rule(&member, "CompetingHash");
    let competing =
        hashes.clone() + &hash_rule(&archive, "GzipHash") + &hash_rule(&nested, "NestedHash");
    for (profile, settings) in [
        ("base", "".into()),
        ("priority", "".into()),
        ("no-archive", "ScanArchive no".into()),
        ("recursion1", "MaxRecursion 1".into()),
        ("recursion2", "MaxRecursion 2".into()),
        ("recursion3", "MaxRecursion 3".into()),
        ("files1", "MaxFiles 1".into()),
        ("files2", "MaxFiles 2".into()),
        ("files3", "MaxFiles 3".into()),
        ("file-under", format!("MaxFileSize {}", member.len() - 1)),
        ("file-exact", format!("MaxFileSize {}", member.len())),
        (
            "size-under",
            format!("MaxScanSize {}", archive.len() + member.len() - 1),
        ),
        (
            "size-exact",
            format!("MaxScanSize {}", archive.len() + member.len()),
        ),
        ("size-outer", format!("MaxScanSize {}", archive.len())),
        ("time", "MaxScanTime 30000".into()),
        (
            "zero",
            "MaxFiles 0\nMaxRecursion 0\nMaxScanSize 0\nMaxFileSize 0".into(),
        ),
    ] {
        probe(
            exe,
            profile,
            &settings,
            if profile == "priority" {
                &competing
            } else {
                &hashes
            },
            &inputs,
        )?;
    }

    let long = b"ordinary large member with whitespace.\n".repeat(128);
    let zip = zip::zip(
        &[("large.txt", &long), ("small.txt", &member)],
        true,
        false,
        false,
    )?;
    let clean_zip = zip::zip(
        &[("large.txt", &long), ("small.txt", b"ordinary notes")],
        true,
        false,
        false,
    )?;
    let reversed = zip::zip(
        &[("first.txt", &hash_only), ("last.txt", &member)],
        true,
        false,
        true,
    )?;
    let small = b"abcde";
    let zip_hashes = hashes + &hash_rule(&clean_zip, "OuterOnly") + &hash_rule(small, "Tiny");
    let zip_inputs = [
        ("two-members", zip.as_slice()),
        ("outer-hash", &clean_zip),
        ("reversed", &reversed),
        ("tiny", small.as_slice()),
    ];
    for (label, options) in [
        ("zip-base", "".into()),
        ("zip-file", "MaxFileSize 1024".into()),
        ("zip-files", "MaxFiles 2".into()),
        (
            "zip-size",
            format!("MaxScanSize {}", zip.len() + member.len()),
        ),
        ("zip-both-size", "MaxScanSize 1024\nMaxFileSize 1024".into()),
        ("zip-both-count", "MaxFiles 1\nMaxRecursion 1".into()),
        (
            "zip-all",
            "MaxFileSize 1024\nMaxScanSize 1024\nMaxFiles 1\nMaxRecursion 1".into(),
        ),
    ] {
        probe(exe, label, &options, &zip_hashes, &zip_inputs)?;
    }
    // A finite 2 MiB archive provides enough ordinary work for a 1 ms deadline.
    let page = b"Report with ordinary text and spaces.\n".repeat(100);
    let names: Vec<_> = (0..512).map(|i| format!("page-{i}.txt")).collect();
    let entries: Vec<_> = names
        .iter()
        .map(|s| (s.as_str(), page.as_slice()))
        .collect();
    let catalog = zip::zip(&entries, false, false, false)?;
    probe(
        exe,
        "deadline",
        "MaxScanTime 1",
        &zip_hashes,
        &[("catalog", &catalog)],
    )?;
    Ok(())
}
