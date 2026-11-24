//! HFS+ and HFSX catalog leaf and fork traversal (Apple Technical Note TN1150).
mod resource;

use super::{ChildSink, Handling};
use std::{
    borrow::Cow,
    collections::HashMap,
    io::{self, Read},
    ops::Range,
};

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "unsupported HFS+ structure")
}
fn u16be(data: &[u8], at: usize) -> io::Result<u16> {
    Ok(u16::from_be_bytes(
        data.get(at..)
            .and_then(|d| d.first_chunk())
            .ok_or_else(invalid)?
            .to_owned(),
    ))
}
fn u32be(data: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_be_bytes(
        data.get(at..)
            .and_then(|d| d.first_chunk())
            .ok_or_else(invalid)?
            .to_owned(),
    ))
}
fn u64be(data: &[u8], at: usize) -> io::Result<u64> {
    Ok(u64::from_be_bytes(
        data.get(at..)
            .and_then(|d| d.first_chunk())
            .ok_or_else(invalid)?
            .to_owned(),
    ))
}

#[derive(Clone, Copy)]
struct Fork<'a> {
    size: u64,
    blocks: u32,
    extents: &'a [[u8; 8]],
}
impl<'a> Fork<'a> {
    fn new(bytes: &'a [u8], pos: usize) -> io::Result<Self> {
        let record = bytes
            .get(pos..)
            .and_then(|d| d.get(..80))
            .ok_or_else(invalid)?;
        Ok(Self {
            size: u64be(record, 0)?,
            blocks: u32be(record, 12)?,
            extents: record[16..].as_chunks::<8>().0,
        })
    }
}

struct Parts<'a> {
    segments: [&'a [u8]; 8],
    count: usize,
    position: usize,
}
impl Read for Parts<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.position < self.count {
            if !self.segments[self.position].is_empty() {
                return self.segments[self.position].read(out);
            }
            self.position += 1;
        }
        Ok(0)
    }
}

struct Volume<'a> {
    bytes: &'a [u8],
    block: u64,
    total: u32,
}
impl<'a> Volume<'a> {
    fn parts(&self, fork: Fork, range: Range<u64>) -> io::Result<Parts<'a>> {
        let mut out = Parts {
            segments: [&[]; 8],
            count: 0,
            position: 0,
        };
        let mut pos = 0;
        for extent in fork.extents {
            if pos >= range.end {
                break;
            }
            let start = u32be(extent, 0)?;
            let count = u32be(extent, 4)?;
            if start == 0 || count == 0 {
                break;
            }
            if start.checked_add(count).ok_or_else(invalid)? > self.total {
                return Err(invalid());
            }
            let next: u64 = pos + u64::from(count) * self.block;
            if next > range.start && pos < range.end {
                let block = u64::from(start) * self.block;
                let from = block + range.start.saturating_sub(pos);
                let to = block + range.end.min(next) - pos;
                let bytes = self
                    .bytes
                    .get(
                        usize::try_from(from).map_err(|_| invalid())?
                            ..usize::try_from(to).map_err(|_| invalid())?,
                    )
                    .ok_or_else(invalid)?;
                out.segments[out.count] = bytes;
                out.count += 1;
            }
            pos = next;
        }
        if pos < range.end {
            return Err(invalid());
        }
        Ok(out)
    }
}

#[derive(Clone, Copy)]
struct Tree<'a> {
    fork: Fork<'a>,
    size: u16,
    first: u32,
    nodes: u32,
}

impl<'a> Tree<'a> {
    fn open(volume: &Volume, fork: Fork<'a>, kind: usize) -> io::Result<Self> {
        let start = u64::from(u32be(&fork.extents[0], 0)?) * volume.block;
        let offset = usize::try_from(start).map_err(|_| invalid())?;
        let node = volume
            .bytes
            .get(offset..)
            .and_then(|b| b.get(..volume.block as usize))
            .ok_or_else(invalid)?;
        if node[8] != 1 || node[9] != 0 || u32be(node, 4)? != 0 || u16be(node, 10)? != 3 {
            return Err(invalid());
        }
        let size = u16be(node, 32)?;
        let min = if kind == 192 { 512 } else { 4096 };
        if !(min..=32768).contains(&size) || !size.is_power_of_two() {
            return Err(invalid());
        }
        let key_size = u16be(node, 34)?;
        if kind == 192 && key_size != 10 || kind == 272 && !(6..=516).contains(&key_size) {
            return Err(invalid());
        }
        Ok(Self {
            fork,
            size,
            first: u32be(node, 24)?,
            nodes: u32be(node, 36)?,
        })
    }
    fn node<'b>(&self, volume: &Volume<'b>, num: u32) -> io::Result<Cow<'b, [u8]>> {
        // The reference fetches at least one allocation block into its node buffer.
        if num >= self.nodes || volume.block > u64::from(self.size) {
            return Err(invalid());
        }
        let start = u64::from(num) * u64::from(self.size);
        let end = start + u64::from(self.size);
        if end > self.fork.size || end > u64::from(self.fork.blocks) * volume.block {
            return Err(invalid());
        }
        let mut parts = volume.parts(self.fork, start..end)?;
        if parts.count == 1 {
            return Ok(Cow::Borrowed(parts.segments[0]));
        }
        let mut node = vec![0; usize::from(self.size)];
        parts.read_exact(&mut node)?;
        Ok(Cow::Owned(node))
    }
    fn leaves(
        &self,
        volume: &Volume,
        sink: &mut dyn ChildSink,
        mut record: impl FnMut(u32, usize, &[u8], &mut dyn ChildSink) -> io::Result<Option<Handling>>,
    ) -> io::Result<Handling> {
        let mut current = self.first;
        for _ in 0..=self.nodes.min(1000) {
            if current == 0 {
                return Ok(Handling::Complete);
            }
            sink.check()?;
            let node = self.node(volume, current)?;
            if node[8] != 255 || node[9] != 1 {
                return Err(invalid());
            }
            let count = usize::from(u16be(&node, 10)?);
            if count > node.len() / 4 {
                return Err(invalid());
            }
            let table = node.len() - 2 * (count + 1);
            let mut previous = 14;
            for i in 0..count {
                let offset = usize::from(u16be(&node, node.len() - 2 * (i + 1))?);
                let end = usize::from(u16be(&node, node.len() - 2 * (i + 2))?);
                if offset < previous || end > table || offset >= end {
                    return Err(invalid());
                }
                if let Some(result) = record(current, offset, &node[offset..end], sink)? {
                    return Ok(result);
                }
                previous = end;
            }
            let next = u32be(&node, 0)?;
            if current == next {
                return Err(invalid());
            }
            current = next;
        }
        Ok(Handling::Complete)
    }
}

fn scan_fork(
    volume: &Volume,
    fork: Fork,
    name: Option<&[u8]>,
    sink: &mut dyn ChildSink,
) -> io::Result<Option<Handling>> {
    if fork.size == 0 || fork.blocks == 0 {
        return Ok(None);
    }
    // Stock stops walking this partition when the next fork fails its size check.
    if sink.skip_declared_size(fork.size) {
        return Ok(Some(Handling::Complete));
    }
    let mut parts = volume.parts(fork, 0..fork.size)?;
    let stop = if parts.count == 1 {
        sink.child_bytes(parts.segments[0], name)?
    } else {
        sink.child(&mut parts, None, name)?
    };
    Ok(stop.then_some(Handling::Stopped))
}

const COMPRESSED: &[u8] = b"com.apple.decmpfs";

fn compression_attr(record: &[u8]) -> io::Result<Option<(u32, &[u8])>> {
    let n = usize::from(u16be(record, 12)?);
    if n != COMPRESSED.len() {
        return Ok(None);
    }
    let attr_pos = 14 + n * 2;
    let name = record.get(14..attr_pos).ok_or_else(invalid)?;
    if !name
        .as_chunks::<2>()
        .0
        .iter()
        .zip(COMPRESSED)
        .all(|(code, b)| *code == [0, *b])
        || u32be(record, attr_pos)? != 0x10
    {
        return Ok(None);
    }
    let length = u32be(record, attr_pos + 12)? as usize;
    if length > 8192 {
        return Err(invalid());
    }
    let data = record
        .get(attr_pos + 16..)
        .and_then(|b| b.get(..length))
        .ok_or_else(invalid)?;
    Ok(Some((u32be(record, 4)?, data)))
}

fn volume(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let head = bytes.get(1024..1536).ok_or_else(invalid)?;
    if !matches!(&head[..4], b"H+\0\x04" | b"HX\0\x05") {
        return Err(invalid());
    }
    let block = u64::from(u32be(head, 40)?);
    if !(512..=1 << 20).contains(&block) || !block.is_power_of_two() {
        return Err(invalid());
    }
    let v = Volume {
        bytes,
        block,
        total: u32be(head, 44)?,
    };
    Tree::open(&v, Fork::new(head, 192)?, 192)?;
    let catalog = Tree::open(&v, Fork::new(head, 272)?, 272)?;
    if block > u64::from(catalog.size) {
        // Stock skips the catalog and still matches the containing partition.
        return Ok(Handling::Complete);
    }
    if catalog.fork.blocks >= v.total
        || catalog.fork.size > u64::from(catalog.fork.blocks) * block
        || catalog.fork.size < u64::from(catalog.size) * u64::from(catalog.nodes)
    {
        return Err(invalid());
    }
    // Index only matching attribute locations. Keep file payloads in the partition.
    let attr = Tree::open(&v, Fork::new(head, 352)?, 352).ok();
    let mut attrs = HashMap::new();
    if let Some(tree) = attr {
        tree.leaves(&v, sink, |node, offset, record, _| {
            if let Some((id, _)) = compression_attr(record)? {
                if attrs.len() >= 32768 {
                    return Err(invalid());
                }
                attrs.entry(id).or_insert((node, offset));
            }
            Ok(None)
        })?;
    }
    let mut inflated_file = false;
    catalog.leaves(&v, sink, |_, _, record, sink| {
        let key = usize::from(u16be(record, 0)?).next_multiple_of(2);
        let data = record.get(2 + key..).ok_or_else(invalid)?;
        if u16be(data, 0)? != 2 {
            return Ok(None);
        }
        if u16be(data, 42)? & 0xf000 != 0x8000 {
            return Ok(None);
        }
        let name_units = usize::from(u16be(record, 6)?);
        let name = record
            .get(8..8 + name_units * 2)
            .filter(|_| {
                name_units > 0 && name_units <= 255 && name_units * 2 <= key.saturating_sub(6)
            })
            .and_then(|utf16| {
                char::decode_utf16(
                    utf16
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|v| u16::from_be_bytes(*v))
                        .take_while(|v| *v != 0),
                )
                .collect::<Result<String, _>>()
                .ok()
            });
        let name = name.as_deref().map(str::as_bytes);
        if let Some(&(node, offset)) = attrs.get(&u32be(data, 8)?) {
            let n = attr.ok_or_else(invalid)?.node(&v, node)?;
            let (_, value) =
                compression_attr(n.get(offset..).ok_or_else(invalid)?)?.ok_or_else(invalid)?;
            if let Some(result) = compressed(
                value,
                &v,
                Fork::new(data, 168)?,
                sink,
                name,
                &mut inflated_file,
            )? {
                return Ok(Some(result));
            }
        }
        if let Some(result) = scan_fork(&v, Fork::new(data, 88)?, name, sink)? {
            return Ok(Some(result));
        }
        scan_fork(&v, Fork::new(data, 168)?, name, sink)
    })
}

fn compressed(
    value: &[u8],
    volume: &Volume,
    resource_fork: Fork,
    sink: &mut dyn ChildSink,
    name: Option<&[u8]>,
    inflated_file: &mut bool,
) -> io::Result<Option<Handling>> {
    let header = value.get(..16).ok_or_else(invalid)?;
    let kind: [u8; 4] = header[4..8].try_into().expect("compression kind");
    let size: [u8; 8] = header[8..16].try_into().expect("compression size");
    let (kind, size) = match &header[..4] {
        b"fpmc" => (u32::from_le_bytes(kind), u64::from_le_bytes(size)),
        b"cmpf" => (u32::from_be_bytes(kind), u64::from_be_bytes(size)),
        _ => return Err(invalid()),
    };
    if kind == 4 {
        let result = resource::scan(volume, resource_fork, sink, name)?;
        *inflated_file = true;
        return Ok(result);
    }
    if kind != 3 {
        return Ok(None);
    }
    let body = &value[16..];
    let first = *body.first().ok_or_else(invalid)?;
    let stop = if first & 15 == 15 {
        let plain = &body[1..];
        if plain.len() as u64 != size {
            return Err(invalid());
        }
        // Stock retains this flag across all files in the catalog.
        if !*inflated_file {
            return Ok(None);
        }
        sink.child_bytes(plain, name)?
    } else {
        if size > 65536 {
            return Err(invalid());
        }
        let mut plain = Vec::new();
        flate2::read::ZlibDecoder::new(body)
            .take(size + 1)
            .read_to_end(&mut plain)?;
        if plain.len() as u64 != size {
            return Err(invalid());
        }
        *inflated_file = true;
        sink.child_bytes(&plain, name)?
    };
    Ok(stop.then_some(Handling::Stopped))
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    match volume(bytes, sink) {
        Err(e) if e.kind() == io::ErrorKind::InvalidData => Ok(Handling::Incomplete),
        other => other,
    }
}
