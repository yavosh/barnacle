//! ISO 9660 volumes in cooked disk images and raw CD sectors.
use super::{ChildSink, Handling};
use std::collections::HashSet;
use std::io::{self, Read};

pub(super) const PVD: &[u8] = b"\x01CD001\x01";
const SECTOR: usize = 2048;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Layout {
    stride: usize,
    prefix: usize,
}

impl Layout {
    pub fn descriptor_offset(self) -> usize {
        16 * self.stride + self.prefix
    }

    fn cooked(bytes: &[u8]) -> Option<Self> {
        let layout = Self {
            stride: SECTOR,
            prefix: 0,
        };
        let primary = layout.sector(bytes, 16)?;
        if !primary.starts_with(PVD)
            || !matches!(
                u16::from_le_bytes([primary[128], primary[129]]),
                512 | 1024 | 2048
            )
        {
            return None;
        }
        // A populated system area can have its own outer format. Only recognize a
        // separate cooked volume when its descriptor sequence reaches a terminator.
        for index in 17..32 {
            let header = layout.sector(bytes, index)?;
            if &header[1..7] != b"CD001\x01" {
                break;
            }
            match header[0] {
                255 => return Some(layout),
                0..=3 => (),
                _ => break,
            }
        }
        None
    }

    pub fn at(bytes: &[u8], offset: usize) -> Option<(&[u8], Self)> {
        if !offset.is_multiple_of(SECTOR) {
            return None;
        }
        let base = offset.checked_sub(16 * SECTOR)?;
        let layout = Self::cooked(bytes)?;
        if base == 0 {
            return Some((bytes, layout));
        }
        // A partitioned ISO can include a second descriptor set whose extents
        // are relative to its own system area.
        let volume = bytes.get(base..)?;
        super::partition::from_mbr(bytes)?;
        Some((volume, Self::cooked(volume)?))
    }

    pub fn recognize(bytes: &[u8]) -> Option<Self> {
        for (stride, prefix) in [(SECTOR, 0), (2352, 16), (2352, 24), (2448, 16), (2448, 24)] {
            let layout = Self { stride, prefix };
            let primary = layout.descriptor_offset();
            if bytes.get(primary..primary + 7) == Some(PVD)
                && bytes.get(primary + stride + 1..primary + stride + 6) == Some(b"CD001")
                && (0..16).all(|i| {
                    bytes[i * stride + prefix..i * stride + prefix + SECTOR]
                        .iter()
                        .all(|&b| b == 0)
                })
                && (prefix == 0
                    || bytes.starts_with(&[0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0]))
            {
                return Some(layout);
            }
        }
        None
    }

    fn offset(self, logical: usize) -> Option<usize> {
        (logical / SECTOR)
            .checked_mul(self.stride)?
            .checked_add(self.prefix + logical % SECTOR)
    }

    fn sector(self, bytes: &[u8], index: usize) -> Option<&[u8]> {
        bytes
            .get(self.offset(index.checked_mul(SECTOR)?)?..)?
            .get(..SECTOR)
    }
}

struct Record<'a> {
    block: u32,
    size: usize,
    name: &'a [u8],
    directory: bool,
    interleaved: bool,
}

impl<'a> Record<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        let offset = u32::from_le_bytes(data.get(2..6)?.try_into().ok()?);
        let size = u32::from_le_bytes(data.get(10..14)?.try_into().ok()?);
        Some(Self {
            block: offset.checked_add(u32::from(data[1]))?,
            size: size as usize,
            name: data.get(33..33 + usize::from(*data.get(32)?))?,
            directory: data[25] & 2 != 0,
            interleaved: data[26] != 0 || data[27] != 0,
        })
    }

    fn name(&self, joliet: bool) -> std::borrow::Cow<'a, [u8]> {
        if joliet {
            let units = self
                .name
                .as_chunks::<2>()
                .0
                .iter()
                .copied()
                .map(u16::from_be_bytes);
            let name: String = char::decode_utf16(units)
                .map_while(Result::ok)
                .take_while(|&c| c != ';' && c != '\0')
                .collect();
            name.into_bytes().into()
        } else {
            self.name
                .split(|&b| b == b';' || b == 0)
                .next()
                .unwrap_or_default()
                .into()
        }
    }
}

// One directory record never spans a logical block. Retain the parent's position
// while scanning a subdirectory, without putting the directory tree on the call stack.
struct Directory {
    block: u32,
    left: usize,
    position: usize,
}

impl From<&Record<'_>> for Directory {
    fn from(record: &Record<'_>) -> Self {
        Self {
            block: record.block,
            left: record.size,
            position: 0,
        }
    }
}

struct Extent<'a> {
    layout: Layout,
    bytes: &'a [u8],
    at: usize,
    left: usize,
}

impl<'a> Extent<'a> {
    fn new(bytes: &'a [u8], layout: Layout, block_size: usize, entry: &Record<'_>) -> Option<Self> {
        let at = (entry.block as usize).checked_mul(block_size)?;
        // The reference reads the complete last logical block.
        if entry.size > 0 {
            let end = at.checked_add(entry.size.checked_next_multiple_of(block_size)?)?;
            bytes.get(layout.offset(end - 1)?)?;
        }
        Some(Self {
            layout,
            bytes,
            at,
            left: entry.size,
        })
    }
}

impl Read for Extent<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.left.min(SECTOR - self.at % SECTOR).min(out.len());
        if count != 0 {
            let start = self.layout.offset(self.at).expect("validated extent");
            out[..count].copy_from_slice(&self.bytes[start..start + count]);
            self.at += count;
            self.left -= count;
        }
        Ok(count)
    }
}

fn volume(
    bytes: &[u8],
    layout: Layout,
    header: &[u8],
    block_size: usize,
    joliet: bool,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let Some(root) = Record::parse(&header[156..190]) else {
        return Ok(Handling::Incomplete);
    };
    if root.interleaved {
        return Ok(Handling::Complete);
    }
    let mut work = vec![Directory::from(&root)];
    let mut visited = HashSet::new();
    while let Some(dir) = work.last_mut() {
        sink.check()?;
        if dir.left == 0 {
            work.pop();
            continue;
        }
        let available = dir.left.min(block_size);
        if dir.position == 0 {
            if visited.len() > 1024 {
                return Ok(Handling::Incomplete);
            }
            if !visited.insert(dir.block) {
                dir.position = available;
            }
        }
        if dir.position >= available {
            dir.left -= available;
            dir.block = dir.block.saturating_add(1);
            dir.position = 0;
            continue;
        }
        let block = (dir.block as usize)
            .checked_mul(block_size)
            .and_then(|start| layout.offset(start))
            .and_then(|start| bytes.get(start..)?.get(..block_size));
        let Some(block) = block else {
            return Ok(Handling::Incomplete);
        };
        let len = usize::from(block[dir.position]);
        if len == 0 {
            dir.position = available;
            continue;
        }
        let start = dir.position;
        dir.position += len;
        if dir.position > available {
            return Ok(Handling::Incomplete);
        }
        if len < 34 {
            continue;
        }
        let Some(entry) = Record::parse(&block[start..dir.position]) else {
            return Ok(Handling::Incomplete);
        };
        if matches!(entry.name, [0] | [1]) || entry.interleaved {
            continue;
        }
        if entry.directory {
            work.push(Directory::from(&entry));
        } else if !sink.skip_declared_size(entry.size as u64) {
            let Some(mut member) = Extent::new(bytes, layout, block_size, &entry) else {
                return Ok(Handling::Incomplete);
            };
            let name = entry.name(joliet);
            let stopped = if layout.stride == SECTOR && member.left > 0 {
                sink.child_bytes(&bytes[member.at..member.at + member.left], Some(&name))?
            } else {
                sink.child(&mut member, None, Some(&name))?
            };
            if stopped {
                return Ok(Handling::Stopped);
            }
        }
    }
    Ok(Handling::Complete)
}

pub(super) fn extract(
    bytes: &[u8],
    layout: Layout,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let Some(header) = layout.sector(bytes, 16) else {
        return Ok(Handling::Incomplete);
    };
    let size = usize::from(u16::from_le_bytes([header[128], header[129]]));
    if !matches!(size, 512 | 1024 | 2048) {
        return Ok(Handling::Incomplete);
    }
    let first = volume(bytes, layout, header, size, false, sink)?;
    if first != Handling::Complete {
        return Ok(first);
    }
    for index in 17..32 {
        let Some(supplementary) = layout.sector(bytes, index) else {
            break;
        };
        if supplementary[0] == 255 || &supplementary[1..6] != b"CD001" {
            break;
        }
        if supplementary[0] == 2
            && matches!(&supplementary[88..91], b"%/@" | b"%/C" | b"%/E")
            && supplementary[182..184] == [0, 0]
        {
            return volume(bytes, layout, supplementary, size, true, sink);
        }
    }
    Ok(Handling::Complete)
}
