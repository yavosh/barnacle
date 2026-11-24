//! Read the physical directory links. The `cfb` iterator exposes only sorted sibling order.
use crate::objects::ChildSink;
use std::io;
use std::path::PathBuf;

const HEADER: usize = 512;
const END: u32 = 0xffff_fffe;
const NONE: u32 = 0xffff_ffff;
const RECORDS_PER_BLOCK: usize = HEADER / 128;
const MAX_ENTRIES: usize = 100_000;

fn word(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

struct Directory<'a>(Vec<&'a [u8]>);

impl<'a> Directory<'a> {
    fn read(bytes: &'a [u8]) -> Option<Self> {
        let header = bytes.get(..HEADER)?;
        let sector_size: usize = match (&header[26..28], &header[30..32]) {
            ([3, 0], [9, 0]) => 512,
            ([4, 0], [12, 0]) => 4096,
            _ => return None,
        };
        let sectors = (bytes.len() / sector_size).checked_sub(1)?;
        let sector = |id: u32| {
            let start = (id as usize).checked_add(1)?.checked_mul(sector_size)?;
            bytes.get(start..start.checked_add(sector_size)?)
        };
        let fat_count = word(header, 44)? as usize;
        if fat_count != sectors.div_ceil(sector_size / 4) {
            return None;
        }
        let mut fat = Vec::with_capacity(fat_count);
        let mut next_difat = word(header, 68)?;
        let mut indices = &header[76..];
        while fat.len() < fat_count {
            for entry in indices
                .as_chunks::<4>()
                .0
                .iter()
                .take(fat_count - fat.len())
            {
                fat.push(sector(word(entry, 0)?)?);
            }
            if fat.len() < fat_count {
                let table = sector(next_difat)?;
                indices = &table[..sector_size - 4];
                next_difat = word(table, sector_size - 4)?;
            }
        }
        if next_difat != END
            || word(header, 72)? as usize
                != fat_count.saturating_sub(109).div_ceil(sector_size / 4 - 1)
        {
            return None;
        }
        // A valid MiniFAT cannot describe more mini sectors than fit in this file.
        if word(header, 64)? as usize > bytes.len().div_ceil(64 * (sector_size / 4)) {
            return None;
        }
        let mut blocks = Vec::new();
        let mut seen = vec![false; sectors];
        let mut id = word(header, 48)?;
        while id != END {
            let idx = id as usize;
            if *seen.get(idx)? || blocks.len() * RECORDS_PER_BLOCK >= MAX_ENTRIES {
                return None;
            }
            seen[idx] = true;
            // For version 4 we currently verify only the first four directory entries.
            if sector_size == 4096 && !blocks.is_empty() {
                return None;
            }
            blocks.push(&sector(id)?[..HEADER]);
            id = word(
                fat.get(idx / (sector_size / 4))?,
                (idx % (sector_size / 4)) * 4,
            )?;
        }
        Some(Self(blocks))
    }

    fn record(&self, id: u32) -> Option<&[u8]> {
        let id = id as usize;
        let sector = self.0.get(id / RECORDS_PER_BLOCK)?;
        let start = (id % RECORDS_PER_BLOCK) * 128;
        Some(&sector[start..start + 128])
    }
}

pub(super) struct Stream {
    pub name: String,
    pub size: u64,
    pub parent: usize,
    pub depth: usize,
}

#[derive(Clone, Copy)]
pub(super) enum Member {
    Folder(usize),
    File(usize),
}

#[derive(Default)]
pub(super) struct Inventory {
    folders: Vec<(usize, String, u32)>,
    pub members: Vec<Member>,
    pub streams: Vec<Stream>,
}

impl Inventory {
    pub fn path(&self, stream: &Stream) -> PathBuf {
        let mut stack = Vec::new();
        let mut dir = stream.parent;
        while dir != 0 {
            let (parent, name, _) = &self.folders[dir - 1];
            stack.push(name);
            dir = *parent;
        }
        let mut path = PathBuf::from("/");
        path.extend(stack.into_iter().rev());
        path.push(&stream.name);
        path
    }

    pub fn temporary_path(&self, mut dir: usize) -> PathBuf {
        let mut stack = Vec::new();
        while dir != 0 {
            let (parent, _, id) = &self.folders[dir - 1];
            stack.push(format!("{id:06}"));
            dir = *parent;
        }
        stack.into_iter().rev().collect()
    }

    pub fn read(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Option<Self>> {
        let Some(directory) = Directory::read(bytes) else {
            return Ok(None);
        };
        let Some(root) = directory.record(0) else {
            return Ok(None);
        };
        if root[66] != 5 {
            return Ok(None);
        }
        let mut out = Self::default();
        let mut todo = vec![(word(root, 76).unwrap(), 0usize, 1usize)];
        let mut seen = vec![false; directory.0.len() * RECORDS_PER_BLOCK];
        while let Some((id, parent, depth)) = todo.pop() {
            if id == NONE {
                continue;
            }
            sink.check()?;
            let Some(record) = directory.record(id) else {
                return Ok(None);
            };
            if std::mem::replace(&mut seen[id as usize], true) || depth > 100 {
                return Ok(None);
            }
            let is_stream = record[66] == 2;
            let preceding = if is_stream { out.streams.len() } else { 0 };
            if sink.ole_directory_limit(depth, preceding) {
                break;
            }
            let n = u16::from_le_bytes([record[64], record[65]]) as usize;
            if !(4..=64).contains(&n) || !n.is_multiple_of(2) || record[n - 2..n] != [0, 0] {
                return Ok(None);
            }
            let units = record[..n - 2]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&s| u16::from_le_bytes(s));
            let Ok(name) = char::decode_utf16(units).collect::<Result<String, _>>() else {
                return Ok(None);
            };
            if name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
                return Ok(None);
            }
            // Stock visits the current object, its storage children, then its right and left siblings.
            todo.push((word(record, 68).unwrap(), parent, depth));
            todo.push((word(record, 72).unwrap(), parent, depth));
            if is_stream {
                out.members.push(Member::File(out.streams.len()));
                out.streams.push(Stream {
                    name,
                    size: u64::from_le_bytes(record[120..128].try_into().unwrap()),
                    parent,
                    depth,
                });
            } else if record[66] == 1 {
                out.folders.push((parent, name, id));
                out.members.push(Member::Folder(out.folders.len()));
                todo.push((word(record, 76).unwrap(), out.folders.len(), depth + 1));
            } else {
                return Ok(None);
            }
        }
        Ok(Some(out))
    }
}
