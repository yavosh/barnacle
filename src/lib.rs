//! Offline whole-file hash matching. An unmatched file still needs a full scan.

use std::io::{self, Read};

use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

pub mod body;
mod feed;
pub mod index;
pub mod objects;
pub use feed::{Feed, FileInventory, IgnoreSet, PINNED_FLEVEL};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Algorithm {
    Md5,
    Sha1,
    Sha256,
}

impl Algorithm {
    pub const ALL: [Self; 3] = [Self::Md5, Self::Sha1, Self::Sha256];

    pub fn digest_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rule {
    pub algorithm: Algorithm,
    /// MD5 and SHA-1 digests have trailing zero bytes.
    pub digest: [u8; 32],
    /// None represents the wildcard size.
    pub size: Option<u32>,
    pub name: String,
}

pub struct FileHashes {
    pub size: u64,
    digests: [[u8; 32]; 3],
}

/// Hash the same bytes with all three algorithms in one pass.
pub fn hash_reader(mut input: impl Read) -> io::Result<FileHashes> {
    let (mut md5, mut sha1, mut sha256) = (Md5::new(), Sha1::new(), Sha256::new());
    let mut buf = [0u8; 32 * 1024];
    let mut size = 0u64;
    loop {
        let n = match input.read(&mut buf) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            break;
        }
        size = size
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("file size overflow"))?;
        md5.update(&buf[..n]);
        sha1.update(&buf[..n]);
        sha256.update(&buf[..n]);
    }
    Ok(FileHashes::finish(size, md5, sha1, sha256))
}

impl FileHashes {
    fn finish(size: u64, md5: Md5, sha1: Sha1, sha256: Sha256) -> Self {
        let mut digests = [[0; 32]; 3];
        digests[0][..16].copy_from_slice(&md5.finalize());
        digests[1][..20].copy_from_slice(&sha1.finalize());
        digests[2].copy_from_slice(&sha256.finalize());
        Self { size, digests }
    }

    /// Format the whole-file MD5 reported by clamd's ExtendedDetectionInfo log.
    pub fn md5_hex(&self) -> String {
        use std::fmt::Write;
        let mut hex = String::with_capacity(32);
        for byte in &self.digests[Algorithm::Md5 as usize][..16] {
            write!(hex, "{byte:02x}").expect("writing a String cannot fail");
        }
        hex
    }

    /// Apply the pinned engine's algorithm order and prefer exact sizes within each algorithm.
    pub fn lookup(
        &self,
        mut find: impl FnMut(Algorithm, &[u8; 32], Option<u32>) -> io::Result<Option<String>>,
    ) -> io::Result<Option<String>> {
        for algorithm in Algorithm::ALL {
            let digest = &self.digests[algorithm as usize];
            if let Ok(size) = u32::try_from(self.size)
                && let Some(name) = find(algorithm, digest, Some(size))?
            {
                return Ok(Some(name));
            }
            if let Some(name) = find(algorithm, digest, None)? {
                return Ok(Some(name));
            }
        }
        Ok(None)
    }
}
