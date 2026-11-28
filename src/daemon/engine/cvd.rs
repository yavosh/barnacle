//! The byte-for-byte signed archives verified for the pinned ClamAV comparison.
use super::invalid;
use barnacle::bytecode::PINNED_ARCHIVE;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(super) const DAILY_TIMESTAMP: u64 = 1_794_983_319;
pub(super) const PINNED: [(&str, u64, &str); 3] = [
    (
        "daily.cvd",
        23_450_852,
        "423f7774182bfbc82b50c7796c68a93f8b1817ef7ebbc88d7def444bc2c8f35b",
    ),
    (
        "main.cvd",
        89_072_577,
        "0b2182d229f46981ec8f535382222f7c9dfdd656b250ad47988b910a8d302365",
    ),
    PINNED_ARCHIVE,
];

pub(super) fn extract(
    source: &Path,
    dir: &Path,
    paths: &mut Vec<(PathBuf, bool)>,
) -> io::Result<()> {
    let &(name, length, digest) = PINNED
        .iter()
        .find(|(name, _, _)| source.file_name().is_some_and(|n| n == *name))
        .ok_or_else(|| invalid(format!("unverified database archive: {}", source.display())))?;
    let mut db = super::open_database(source)?.take(length + 1);
    let mut snapshot = tempfile::tempfile_in(dir)?;
    let mut hasher = Sha256::new();
    let mut block = [0u8; 64 * 1024];
    loop {
        let n = db.read(&mut block)?;
        if n == 0 {
            break;
        }
        snapshot.write_all(&block[..n])?;
        hasher.update(&block[..n]);
    }
    let actual: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if snapshot.stream_position()? != length || actual != digest {
        return Err(invalid(format!(
            "{name}: SHA-256 differs from the verified generation"
        )));
    }
    // Parse exactly the bytes just authenticated, even if FreshClam replaced the source.
    snapshot.seek(SeekFrom::Start(512))?;
    let mut archive = tar::Archive::new(GzDecoder::new(snapshot));
    let stem = name.trim_end_matches(".cvd");
    for member in archive.entries()? {
        let mut member = member?;
        let path = member.path()?;
        if path.file_stem().and_then(|s| s.to_str()) != Some(stem)
            || path.components().count() != 1
            || !matches!(
                path.extension().and_then(|s| s.to_str()),
                Some(
                    "hdb"
                        | "hsb"
                        | "ndb"
                        | "ldb"
                        | "idb"
                        | "ign"
                        | "ign2"
                        | "fp"
                        | "sfp"
                        | "hdu"
                        | "hsu"
                )
            )
        {
            continue;
        }
        if !member.header().entry_type().is_file() {
            return Err(invalid(format!(
                "{name}: expected a regular database member"
            )));
        }
        let output = dir.join(path);
        io::copy(&mut member, &mut File::create_new(&output)?)?;
        paths.push((output, true));
    }
    Ok(())
}
