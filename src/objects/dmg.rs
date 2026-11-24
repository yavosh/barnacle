//! Apple UDIF images contain an XML block list and independently scanned partitions.
use super::{ChildSink, Handling, Snapshot, text};
use bzip2::read::BzDecoder;
use flate2::read::ZlibDecoder;
use quick_xml::{Reader, events::Event};
use std::io::{self, Read, Write};
mod adc;

const SECTOR: u64 = 512;
const RAW: u32 = 1;
const ADC: u32 = 0x8000_0004;
const ZLIB: u32 = 0x8000_0005;
const BZIP: u32 = 0x8000_0006;
fn u64be(bytes: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(bytes[at..at + 8].try_into().expect("validated UDIF field"))
}
fn u32be(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().expect("validated UDIF field"))
}
pub(super) fn recognized(bytes: &[u8]) -> bool {
    bytes
        .last_chunk::<512>()
        .is_some_and(|t| t.starts_with(b"koly"))
}

fn extent(bytes: &[u8], off: u64, length: u64) -> Option<&[u8]> {
    let off = usize::try_from(off).ok()?;
    bytes.get(off..off.checked_add(usize::try_from(length).ok()?)?)
}

fn copy(
    input: &mut dyn Read,
    out: &mut Snapshot,
    limit: u64,
    sink: &mut dyn ChildSink,
) -> io::Result<Option<u64>> {
    let mut size = 0u64;
    let mut buf = [0; 8192];
    loop {
        sink.check()?;
        let n = match input.read(&mut buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::InvalidData
                        | io::ErrorKind::InvalidInput
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::Other
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok(Some(size));
        }
        size += n as u64;
        if size > limit {
            return Ok(None);
        }
        out.write_all(&buf[..n])?;
    }
}

fn partition(map: &[u8], fork: &[u8], sink: &mut dyn ChildSink) -> io::Result<Option<Handling>> {
    if !map.starts_with(b"mish") || map.len() < 204 {
        return Ok(None);
    }
    let count = u32be(map, 200) as usize;
    let Some(stripes) = map[204..].as_chunks::<40>().0.get(..count) else {
        return Ok(None);
    };
    let mut sectors = 0u64;
    let mut has_data = false;
    let mut sorted = true;
    let mut previous = 0u64;
    for stripe in stripes {
        sink.check()?;
        let pos = u64be(stripe, 8);
        sorted &= pos >= previous;
        previous = pos;
        if extent(fork, u64be(stripe, 24), u64be(stripe, 32)).is_none() {
            return Ok(Some(Handling::Complete));
        }
        let kind = u32be(stripe, 0);
        if matches!(kind, 0 | 2 | RAW | ADC | ZLIB | BZIP) {
            let Some(n) = sectors.checked_add(u64be(stripe, 16)) else {
                return Ok(Some(Handling::Incomplete));
            };
            sectors = n;
            has_data |= matches!(kind, RAW | ADC | ZLIB | BZIP);
        }
    }
    if !has_data || sectors == 0 {
        return Ok(None);
    }
    let Some(projected) = sectors.checked_mul(SECTOR) else {
        return Ok(Some(Handling::Incomplete));
    };
    if sink.skip_declared_size(projected) {
        return Ok(Some(Handling::Complete));
    }
    if projected > i32::MAX as u64 {
        return Ok(Some(Handling::Incomplete));
    }
    let mut order = Vec::new();
    if !sorted {
        order.extend(0..stripes.len());
        order.sort_unstable_by_key(|&i| (u64be(&stripes[i], 8), i));
    }
    let mut out = Snapshot::new(sink.temporary_directory());
    let mut written = 0u64;
    for index in 0..stripes.len() {
        sink.check()?;
        let stripe = &stripes[if sorted { index } else { order[index] }];
        let amount = u64be(stripe, 16).saturating_mul(SECTOR);
        let kind = u32be(stripe, 0);
        let bytes = extent(fork, u64be(stripe, 24), u64be(stripe, 32)).expect("validated stripe");
        let remaining = sink
            .remaining()
            .min(i32::MAX as u64)
            .saturating_sub(written);
        let size = match kind {
            0 | 2 => copy(&mut io::repeat(0).take(amount), &mut out, remaining, sink)?,
            RAW => copy(&mut &bytes[..], &mut out, remaining, sink)?,
            ADC => copy(
                &mut adc::Decoder::new(bytes),
                &mut out,
                remaining.min(amount),
                sink,
            )?,
            ZLIB => copy(
                &mut ZlibDecoder::new(bytes),
                &mut out,
                remaining.min(amount),
                sink,
            )?,
            BZIP => copy(
                &mut BzDecoder::new(bytes),
                &mut out,
                remaining.min(amount),
                sink,
            )?,
            _ => continue,
        };
        let Some(size) = size else {
            return Ok(Some(Handling::Incomplete));
        };
        written += size;
    }
    Ok(sink.partition(out)?.then_some(Handling::Stopped))
}

fn block(encoded: &[u8], fork: &[u8], sink: &mut dyn ChildSink) -> io::Result<Option<Handling>> {
    if !text::valid_base64(encoded, sink)? {
        return Ok(Some(Handling::Incomplete));
    }
    let mut reader = text::base64_reader(encoded);
    let mut snapshot = Snapshot::new(sink.temporary_directory());
    let max = (encoded.len() as u64).saturating_mul(3) / 4 + 4;
    if max > 1 << 30 {
        return Ok(Some(Handling::Incomplete));
    }
    if copy(&mut reader, &mut snapshot, max, sink)?.is_none() {
        return Ok(None);
    }
    snapshot.with_bytes(|m| partition(m, fork, sink))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Node {
    Plist,
    Root,
    Resources,
    Blocks,
    Item,
    Key,
    Data,
    Other,
}

fn scan_catalog(xml: &[u8], fork: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let exceeds_limit = xml.len() as u64 > sink.remaining();
    if sink.child_bytes(xml, None)? {
        return Ok(Handling::Stopped);
    }
    if exceeds_limit {
        return Ok(Handling::Complete);
    }
    let mut reader = Reader::from_reader(xml);
    let mut stack = Vec::new();
    let mut key = None;
    loop {
        sink.check()?;
        let Ok(event) = reader.read_event() else {
            return Ok(Handling::Incomplete);
        };
        match event {
            Event::Start(ref tag) | Event::Empty(ref tag) => {
                if stack.len() > 50 {
                    return Ok(Handling::Incomplete);
                }
                let parent = stack.last().copied();
                let node = match (parent, tag.local_name().as_ref(), key.take()) {
                    (None, "plist", _) => Node::Plist,
                    (Some(Node::Plist), "dict", _) => Node::Root,
                    (Some(Node::Root), "dict", Some("resource-fork")) => Node::Resources,
                    (Some(Node::Resources), "array" | "dict", Some("blkx")) => Node::Blocks,
                    (Some(Node::Blocks), "dict", _) => Node::Item,
                    (Some(Node::Item | Node::Blocks), "data", Some("Data")) => Node::Data,
                    (_, "key", _) => Node::Key,
                    _ => Node::Other,
                };
                if matches!(event, Event::Start(_)) {
                    stack.push(node);
                }
            }
            Event::Text(value) => match stack.last() {
                Some(Node::Key) => {
                    key = match value.as_ref() {
                        "resource-fork" => Some("resource-fork"),
                        "blkx" => Some("blkx"),
                        "Data" => Some("Data"),
                        _ => None,
                    };
                }
                Some(Node::Data) => {
                    if let Some(status) = block(value.as_ref().as_bytes(), fork, sink)? {
                        return Ok(status);
                    }
                }
                _ => {}
            },
            Event::End(_) => {
                if stack.pop() != Some(Node::Key) {
                    key = None;
                }
            }
            Event::Eof => {
                return Ok(if stack.is_empty() {
                    Handling::Complete
                } else {
                    Handling::Incomplete
                });
            }
            _ => {}
        }
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(trailer) = bytes.last_chunk::<512>() else {
        return Ok(Handling::Complete);
    };
    let offset = u64be(trailer, 216);
    let len = u64be(trailer, 224);
    if len == 0 || len > i32::MAX as u64 {
        return Ok(Handling::Complete);
    }
    let Some(xml) = extent(bytes, offset, len) else {
        return Ok(Handling::Complete);
    };
    scan_catalog(xml, &bytes[..offset as usize], sink)
}
