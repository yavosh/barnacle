//! Visit UDF file extents in the order of their on-disc descriptors.
use super::{ChildSink, Handling};
use std::io;

const SECTOR: usize = 2048;
pub(super) const RECOGNITION: usize = 16 * SECTOR;
const IDENTIFIER: u16 = 257;
const FILE: u16 = 261;

pub(super) fn recognized(bytes: &[u8]) -> bool {
    bytes.get(RECOGNITION..RECOGNITION + 6) == Some(b"\0BEA01")
}

fn u16le(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("descriptor field"))
}
fn u32le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("descriptor field"))
}

#[derive(Default)]
struct Volume {
    block_size: u32,
    partition: u16,
    start: u32,
}

impl Volume {
    fn extent<'a>(&self, file: &[u8], bytes: &'a [u8]) -> Option<&'a [u8]> {
        let start = 176usize.checked_add(u32le(file, 168) as usize)?;
        let ad = file.get(start..)?;
        let flags = u16le(file, 34) & 3;
        // The pinned reader handles one short, long, or extended allocation descriptor.
        let (position, length, extra) = match (flags, ad.len()) {
            (0, 8) => (u32le(ad, 4), u32le(ad, 0), 0),
            (1, 16) if u16le(ad, 8) == self.partition => (u32le(ad, 4), u32le(ad, 0), self.start),
            (2, 20) if u16le(ad, 16) == self.partition => (u32le(ad, 12), u32le(ad, 4), self.start),
            _ => return None,
        };
        let offset = self
            .start
            .checked_add(position)?
            .checked_mul(self.block_size)?
            .checked_add(extra)? as usize;
        bytes.get(offset..offset.checked_add(length as usize)?)
    }
}

// Each sector may hold several records of the same kind. Independent cursors pair
// identifiers and file entries in physical order without retaining a pointer per record.
struct Records<'a> {
    sectors: std::slice::Iter<'a, [u8; SECTOR]>,
    current: &'a [u8],
    kind: u16,
}
impl<'a> Records<'a> {
    fn new(sectors: &'a [[u8; SECTOR]], kind: u16) -> Self {
        Self {
            sectors: sectors.iter(),
            current: &[],
            kind,
        }
    }

    fn next(&mut self, sink: &mut dyn ChildSink) -> io::Result<Option<&'a [u8]>> {
        let header = if self.kind == IDENTIFIER { 38 } else { 176 };
        loop {
            sink.check()?;
            if self.current.len() >= header && u16le(self.current, 0) == self.kind {
                let size = if self.kind == IDENTIFIER {
                    (38 + usize::from(u16le(self.current, 36)) + usize::from(self.current[19]))
                        .next_multiple_of(4)
                } else {
                    176usize
                        .saturating_add(u32le(self.current, 168) as usize)
                        .saturating_add(u32le(self.current, 172) as usize)
                };
                if let Some((record, rest)) = self.current.split_at_checked(size) {
                    self.current = rest;
                    return Ok(Some(record));
                }
            }
            let Some(block) = self.sectors.next() else {
                return Ok(None);
            };
            self.current = block;
        }
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let (sectors, _) = bytes.as_chunks::<SECTOR>();
    let mut next = 19; // BEA, NSR, TEA follow the system area.
    loop {
        let mut volume = Volume::default();
        for tag in [1, 4, 6, 5, 7, 8, 9, 8, 2] {
            let block = loop {
                sink.check()?;
                let Some(b) = sectors.get(next) else {
                    return Ok(Handling::Complete);
                };
                next += 1;
                if b.iter().any(|&b| b != 0) {
                    break b;
                }
            };
            if u16le(block, 0) != tag {
                return Ok(Handling::Complete);
            }
            match tag {
                6 => volume.block_size = u32le(block, 212),
                5 => {
                    volume.partition = u16le(block, 22);
                    volume.start = u32le(block, 188);
                }
                _ => {}
            }
        }
        while let Some(block) = sectors.get(next) {
            sink.check()?;
            if block.iter().any(|&b| b != 0) {
                break;
            }
            next += 1;
        }
        if sectors.get(next).is_some_and(|b| u16le(b, 0) == 256) {
            next += 1;
        }
        let begin = next;
        loop {
            sink.check()?;
            let Some(b) = sectors.get(next) else {
                return Ok(Handling::Complete);
            };
            if !matches!(u16le(b, 0), 0 | 8 | IDENTIFIER | FILE | 266) {
                break;
            }
            next += 1;
        }
        let mut ids = Records::new(&sectors[begin..next], IDENTIFIER);
        let mut files = Records::new(&sectors[begin..next], FILE);
        while let (Some(id), Some(file)) = (ids.next(sink)?, files.next(sink)?) {
            if id[18] & 2 != 0 {
                continue;
            }
            let Some(contents) = volume.extent(file, bytes) else {
                return Ok(Handling::Complete);
            };
            if contents.is_empty() {
                return Ok(Handling::Complete);
            }
            // Stock supplies an empty original filename for UDF members.
            let exceeds_budget = contents.len() as u64 > sink.remaining();
            if sink.child_bytes(contents, Some(b""))? {
                return Ok(Handling::Stopped);
            }
            if exceeds_budget {
                return Ok(Handling::Complete);
            }
        }
        next += 1;
    }
}
