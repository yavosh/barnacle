//! An immutable, checksummed whole-file hash index shared by the three lookup backends.

use std::fs::{File, Permissions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::Path;

use memmap2::Mmap;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::{Algorithm, FileHashes, Rule};

const MAGIC: &[u8; 8] = b"BNHASH01";
const HEADER: usize = 16;
const CHECKSUM: usize = 32;
const KEY: usize = 38;
// Each fixed-width record stores its key, an absolute name offset, and a name length.
const RECORD: usize = KEY + 8 + 2;
const BLOCK: usize = 64;

type Key = [u8; KEY];

fn invalid(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

fn key(algorithm: Algorithm, digest: &[u8; 32], size: Option<u32>) -> Key {
    let mut bytes = [0; KEY];
    bytes[0] = algorithm as u8;
    bytes[1..33].copy_from_slice(digest);
    if let Some(size) = size {
        bytes[33] = 1;
        bytes[34..38].copy_from_slice(&size.to_be_bytes());
    }
    bytes
}

fn valid_key(key: &[u8]) -> bool {
    let width = match key[0] {
        0 => 16,
        1 => 20,
        2 => 32,
        _ => return false,
    };
    let size = u32::from_be_bytes(key[34..38].try_into().unwrap());
    key[1 + width..33].iter().all(|b| *b == 0)
        && match key[33] {
            0 => size == 0,
            1 => (1..u32::MAX).contains(&size),
            _ => false,
        }
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty() && !name.iter().any(u8::is_ascii_control) && std::str::from_utf8(name).is_ok()
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn table_end(count: usize) -> io::Result<usize> {
    count
        .checked_mul(RECORD)
        .and_then(|n| n.checked_add(HEADER))
        .ok_or_else(|| invalid("record table size overflows"))
}

/// Publish a new generation. An existing destination is never overwritten.
pub fn build(path: &Path, rules: &mut [Rule]) -> io::Result<()> {
    rules.sort_unstable_by(|a, b| {
        (a.algorithm, &a.digest, a.size).cmp(&(b.algorithm, &b.digest, b.size))
    });
    let mut name_offset = table_end(rules.len())?;
    let directory = parent(path);
    let mut temp = NamedTempFile::new_in(directory)?;
    let mut hash = Sha256::new();
    let mut header = [0; HEADER];
    header[..8].copy_from_slice(MAGIC);
    header[8..].copy_from_slice(&(rules.len() as u64).to_be_bytes());
    let mut writer = BufWriter::new(temp.as_file_mut());
    writer.write_all(&header)?;
    hash.update(header);
    let mut previous = None;
    for rule in rules.iter() {
        let k = key(rule.algorithm, &rule.digest, rule.size);
        if !valid_key(&k) || Some(k) == previous {
            return Err(invalid("invalid or duplicate index key"));
        }
        let name = rule.name.as_bytes();
        let length = u16::try_from(name.len())
            .map_err(|_| invalid("signature name exceeds index format"))?;
        if !valid_name(name) {
            return Err(invalid("invalid signature name"));
        }
        let mut row = [0; RECORD];
        row[..KEY].copy_from_slice(&k);
        row[KEY..KEY + 8].copy_from_slice(&(name_offset as u64).to_be_bytes());
        row[KEY + 8..].copy_from_slice(&length.to_be_bytes());
        writer.write_all(&row)?;
        hash.update(row);
        hash.update(name);
        name_offset = name_offset
            .checked_add(name.len())
            .ok_or_else(|| invalid("name table overflows"))?;
        previous = Some(k);
    }
    for rule in rules.iter() {
        writer.write_all(rule.name.as_bytes())?;
    }
    writer.write_all(&hash.finalize())?;
    writer.flush()?;
    drop(writer);
    temp.as_file()
        .set_permissions(Permissions::from_mode(0o400))?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path)?;
    File::open(directory)?.sync_all()
}

enum Storage {
    Memory(Vec<u8>),
    Pread(File),
    Mapped(Mmap),
}

impl Storage {
    fn bytes<'a>(
        &'a self,
        offset: usize,
        len: usize,
        scratch: &'a mut [u8],
    ) -> io::Result<&'a [u8]> {
        let range = offset
            ..offset
                .checked_add(len)
                .ok_or_else(|| invalid("offset overflows"))?;
        let direct: &[u8] = match self {
            Self::Memory(data) => data,
            Self::Mapped(data) => data,
            Self::Pread(file) => {
                let buf = &mut scratch[..len];
                file.read_exact_at(buf, offset as u64)?;
                return Ok(buf);
            }
        };
        direct
            .get(range)
            .ok_or_else(|| invalid("index data out of bounds"))
    }
}

// Each reader owns its offset, including when two buffered readers use the same file.
struct Reader<'a> {
    data: &'a Storage,
    offset: usize,
    end: usize,
}

impl Read for Reader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len().min(self.end - self.offset);
        match self.data {
            Storage::Pread(file) => file.read_exact_at(&mut buf[..len], self.offset as u64)?,
            Storage::Memory(data) => {
                buf[..len].copy_from_slice(&data[self.offset..self.offset + len])
            }
            Storage::Mapped(data) => {
                buf[..len].copy_from_slice(&data[self.offset..self.offset + len])
            }
        }
        self.offset += len;
        Ok(len)
    }
}

fn name_span(row: &[u8]) -> io::Result<(usize, usize)> {
    let offset = u64::from_be_bytes(row[KEY..KEY + 8].try_into().unwrap());
    let len = u16::from_be_bytes(row[KEY + 8..RECORD].try_into().unwrap());
    Ok((
        usize::try_from(offset).map_err(|_| invalid("name offset overflows"))?,
        usize::from(len),
    ))
}

struct Sizes {
    min: u32,
    max: u32,
    wildcard: bool,
}

pub struct Index {
    data: Storage,
    count: usize,
    directory: Vec<Key>,
    sizes: [Sizes; 3],
}

impl Index {
    pub fn open_memory(path: &Path) -> io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let length = bytes.len();
        Self::validate(Storage::Memory(bytes), length)
    }

    pub fn open_pread(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let length =
            usize::try_from(file.metadata()?.len()).map_err(|_| invalid("index too large"))?;
        Self::validate(Storage::Pread(file), length)
    }

    /// Open a read-only mapping pinned to the current inode.
    ///
    /// # Safety
    ///
    /// The caller must prevent changes to the backing file (including truncation)
    /// from this call until the index is dropped. Replacing the path with a new
    /// inode is safe. The builder publishes immutable files under new names.
    pub unsafe fn open_mapped(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        if file.metadata()?.len() < (HEADER + CHECKSUM) as u64 {
            return Err(invalid("truncated index"));
        }
        // SAFETY: the caller guarantees that the opened inode remains immutable.
        let map = unsafe { Mmap::map(&file)? };
        let length = map.len();
        Self::validate(Storage::Mapped(map), length)
    }

    fn validate(data: Storage, length: usize) -> io::Result<Self> {
        if length < HEADER + CHECKSUM {
            return Err(invalid("truncated index"));
        }
        let end = length - CHECKSUM;
        let mut rows = BufReader::new(Reader {
            data: &data,
            offset: 0,
            end,
        });
        let mut header = [0; HEADER];
        rows.read_exact(&mut header)?;
        if &header[..8] != MAGIC {
            return Err(invalid("unknown index format"));
        }
        let count = usize::try_from(u64::from_be_bytes(header[8..].try_into().unwrap()))
            .map_err(|_| invalid("record count overflows"))?;
        let mut offset = table_end(count)?;
        if offset > end {
            return Err(invalid("truncated record table"));
        }
        let mut names = BufReader::new(Reader {
            data: &data,
            offset,
            end,
        });
        let mut directory = Vec::new();
        let mut sizes = std::array::from_fn(|_| Sizes {
            min: u32::MAX,
            max: 0,
            wildcard: false,
        });
        let mut hash = Sha256::new();
        hash.update(header);
        let mut previous = None;
        let mut name = Vec::new();
        for i in 0..count {
            let mut row = [0; RECORD];
            rows.read_exact(&mut row)?;
            let k: Key = row[..KEY].try_into().unwrap();
            let (start, len) = name_span(&row)?;
            if start != offset || len > end - offset {
                return Err(invalid("invalid name table"));
            }
            if !valid_key(&k) || previous.is_some_and(|p| p >= k) {
                return Err(invalid("invalid or unordered lookup key"));
            }
            let range = &mut sizes[usize::from(k[0])];
            if k[33] == 0 {
                range.wildcard = true;
            } else {
                let size = u32::from_be_bytes(k[34..38].try_into().unwrap());
                range.min = range.min.min(size);
                range.max = range.max.max(size);
            }
            name.resize(len, 0);
            names.read_exact(&mut name)?;
            if !valid_name(&name) {
                return Err(invalid("invalid signature name"));
            }
            hash.update(row);
            hash.update(&name);
            if i % BLOCK == 0 {
                directory.push(k);
            }
            previous = Some(k);
            offset += len;
        }
        let mut buffer = [0; CHECKSUM];
        if offset != end || data.bytes(end, CHECKSUM, &mut buffer)? != hash.finalize().as_slice() {
            return Err(invalid("invalid index length or checksum"));
        }
        Ok(Self {
            data,
            count,
            directory,
            sizes,
        })
    }

    /// Hash extracted bytes only when the generation could match their algorithm and size.
    pub fn match_bytes(
        &self,
        bytes: &[u8],
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        check()?;
        let size = u32::try_from(bytes.len()).ok();
        let exact = self
            .sizes
            .each_ref()
            .map(|r| size.is_some_and(|n| (r.min..=r.max).contains(&n)));
        let eligible = Algorithm::ALL.map(|a| exact[a as usize] || self.sizes[a as usize].wildcard);
        if !eligible.contains(&true) {
            return Ok(None);
        }
        let mut md5 = md5::Md5::new();
        let mut sha1 = sha1::Sha1::new();
        let mut sha256 = Sha256::new();
        for chunk in bytes.chunks(32 * 1024) {
            if eligible[0] {
                md5.update(chunk);
            }
            if eligible[1] {
                sha1.update(chunk);
            }
            if eligible[2] {
                sha256.update(chunk);
            }
            check()?;
        }
        FileHashes::finish(bytes.len() as u64, md5, sha1, sha256).lookup(
            |algorithm, digest, size| {
                let i = algorithm as usize;
                let can_match = if size.is_some() {
                    exact[i]
                } else {
                    self.sizes[i].wildcard
                };
                if can_match {
                    self.lookup(algorithm, digest, size)
                } else {
                    Ok(None)
                }
            },
        )
    }

    pub fn lookup(
        &self,
        algorithm: Algorithm,
        digest: &[u8; 32],
        size: Option<u32>,
    ) -> io::Result<Option<String>> {
        let target = key(algorithm, digest, size);
        let Some(block) = self
            .directory
            .partition_point(|first| *first <= target)
            .checked_sub(1)
        else {
            return Ok(None);
        };
        let first = block * BLOCK;
        let n = (self.count - first).min(BLOCK);
        let mut scratch = [0; BLOCK * RECORD];
        let bytes = self
            .data
            .bytes(HEADER + first * RECORD, n * RECORD, &mut scratch)?;
        let rows = bytes.as_chunks::<RECORD>().0;
        let Ok(i) = rows.binary_search_by(|row| row[..KEY].cmp(&target)) else {
            return Ok(None);
        };
        let (start, len) = name_span(&rows[i])?;
        let mut buffer = vec![0; len];
        match &self.data {
            Storage::Pread(file) => file.read_exact_at(&mut buffer, start as u64)?,
            data => buffer.copy_from_slice(data.bytes(start, len, &mut [])?),
        }
        let name = String::from_utf8(buffer).map_err(|_| invalid("invalid signature name"))?;
        Ok(Some(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(i: u16) -> Rule {
        let mut digest = [0; 32];
        digest[..2].copy_from_slice(&i.to_be_bytes());
        Rule {
            algorithm: Algorithm::Md5,
            digest,
            size: Some(11),
            name: format!("Example.{i}"),
        }
    }

    #[test]
    fn extracted_hashes_keep_reference_order_and_check_cancellation() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let payload = vec![b'Q'; 96 * 1024];
        let hashes = crate::hash_reader(&payload[..])?;
        let mut rows = Vec::new();
        hashes.lookup(|algorithm, digest, size| {
            rows.push(Rule {
                algorithm,
                digest: *digest,
                size,
                name: format!("{algorithm:?}.{size:?}"),
            });
            Ok(None)
        })?;
        // Remove each winning rule in turn. Both exact and wildcard lookups must
        // still precede the next algorithm, including when only SHA-256 remains.
        for start in 0..=rows.len() {
            let path = directory.path().join(start.to_string());
            let mut rules = rows[start..].to_vec();
            let mut unrelated = rows[0].clone();
            unrelated.size = Some(8);
            rules.push(unrelated);
            build(&path, &mut rules)?;
            let index = Index::open_pread(&path)?;
            let actual = index.match_bytes(&payload, &mut || Ok(()))?;
            let reference = hashes.lookup(|a, d, s| index.lookup(a, d, s))?;
            assert_eq!(actual, reference);
            assert_eq!(actual.as_ref(), rows.get(start).map(|r| &r.name));
            if start == 0 {
                let mut checks = 0;
                let error = index
                    .match_bytes(&payload, &mut || {
                        checks += 1;
                        if checks == 3 {
                            Err(io::ErrorKind::TimedOut.into())
                        } else {
                            Ok(())
                        }
                    })
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            }
        }
        Ok(())
    }

    #[test]
    fn all_backends_agree_across_record_blocks() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("generation");
        let mut rules: Vec<_> = (0..140).rev().map(rule).collect();
        let mut wildcard = rule(64);
        wildcard.size = None;
        wildcard.name = "Wildcard".into();
        rules.push(wildcard);
        build(&path, &mut rules)?;
        // SAFETY: this private test directory has no writers for the lifetime of the map.
        let mapped = unsafe { Index::open_mapped(&path)? };
        for index in [
            Index::open_memory(&path)?,
            Index::open_pread(&path)?,
            mapped,
        ] {
            for i in [0, 1, 63, 64, 65, 127, 128, 139] {
                let r = rule(i);
                assert_eq!(index.lookup(r.algorithm, &r.digest, r.size)?, Some(r.name));
            }
            let r = rule(64);
            assert_eq!(
                index.lookup(r.algorithm, &r.digest, None)?.as_deref(),
                Some("Wildcard")
            );
            assert_eq!(index.lookup(r.algorithm, &r.digest, Some(12))?, None);
            assert_eq!(index.lookup(r.algorithm, &rule(141).digest, r.size)?, None);
        }
        Ok(())
    }

    #[test]
    fn publication_preserves_existing_generation() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("generation");
        build(&path, &mut [rule(8)])?;
        let original = std::fs::read(&path)?;
        assert!(build(&path, &mut [rule(4)]).is_err());
        assert_eq!(std::fs::read(&path)?, original);
        let mut malformed = rule(0);
        malformed.name = "nested\nreply".into();
        let fresh = directory.path().join("fresh");
        assert!(build(&fresh, &mut [malformed]).is_err());
        assert!(!fresh.exists());
        Ok(())
    }

    #[test]
    fn corrupt_indexes_fail_closed_on_open() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("generation");
        build(&path, &mut [rule(0)])?;
        let original = std::fs::read(&path)?;
        let mut corruptions = Vec::new();
        for byte in [
            0,
            8,
            HEADER,
            HEADER + KEY,
            HEADER + RECORD,
            original.len() - 1,
        ] {
            let mut damaged = original.clone();
            damaged[byte] ^= 0x80;
            corruptions.push(damaged);
        }
        corruptions.push(original[..HEADER].to_vec());
        for (i, damaged) in corruptions.iter().enumerate() {
            let broken = directory.path().join(format!("broken-{i}"));
            std::fs::write(&broken, damaged)?;
            assert!(Index::open_memory(&broken).is_err());
            assert!(Index::open_pread(&broken).is_err());
            // SAFETY: the completed damaged file remains unchanged while mapped.
            assert!(unsafe { Index::open_mapped(&broken) }.is_err());
        }
        Ok(())
    }

    #[test]
    fn reserved_exact_sizes_are_rejected() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let valid = directory.path().join("valid");
        build(&valid, &mut [rule(0)])?;
        for size in [0, u32::MAX] {
            let path = directory.path().join(format!("reserved-{size}"));
            let mut r = rule(0);
            r.size = Some(size);
            assert_eq!(
                build(&path, &mut [r]).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(!path.exists());

            let mut bytes = std::fs::read(&valid)?;
            bytes[HEADER + 34..HEADER + KEY].copy_from_slice(&size.to_be_bytes());
            // With one record, checksum order is identical to on-disk byte order.
            let end = bytes.len() - CHECKSUM;
            let checksum = Sha256::digest(&bytes[..end]);
            bytes[end..].copy_from_slice(&checksum);
            std::fs::write(&path, bytes)?;
            assert!(Index::open_memory(&path).is_err());
            assert!(Index::open_pread(&path).is_err());
            // SAFETY: the test does not modify the file after writing it.
            assert!(unsafe { Index::open_mapped(&path) }.is_err());
        }
        Ok(())
    }

    #[test]
    fn truncated_positional_read_is_an_error() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("generation");
        let r = rule(0);
        build(&path, &mut [rule(0)])?;
        let index = Index::open_pread(&path)?;
        std::fs::set_permissions(&path, Permissions::from_mode(0o600))?;
        File::options()
            .write(true)
            .open(&path)?
            .set_len(HEADER as u64)?;
        assert_eq!(
            index
                .lookup(r.algorithm, &r.digest, r.size)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        Ok(())
    }
}
