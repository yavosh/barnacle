//! Scan external-object records from the top level of a PowerPoint Document stream.
use super::{ChildSink, Document, Handling, Input, Inventory, Stream};
use crate::objects::Snapshot;
use flate2::read::ZlibDecoder;
use std::{
    fs,
    io::{self, Read, Seek, SeekFrom, Write},
};

const MAX_RECORDS: usize = 4096;
// Each DEFLATE literal/length symbol uses at least one bit and emits at most 258 bytes.
// Stored blocks copy input bytes directly. Zlib and record headers only loosen this bound.
const MAX_EXPANSION: u64 = 8 * 258;

fn filename(offset: u64) -> String {
    format!("ppt{offset:08x}.doc")
}

fn scan_at(
    stream: &mut (impl Read + Seek),
    offset: u64,
    name: &str,
    sink: &mut dyn ChildSink,
) -> io::Result<Option<Handling>> {
    // Offset points past the record header and its four-byte uncompressed-size field.
    stream.seek(SeekFrom::Start(offset - 8))?;
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    stream.seek(SeekFrom::Start(offset))?;
    let mut z = ZlibDecoder::new(stream.take(u64::from(u32::from_le_bytes(length)) - 4));
    let mut file = sink
        .child_limit()
        .is_none()
        .then(|| Snapshot::new(sink.temporary_directory()));
    let mut buf = [0; 8192];
    let mut size = 0u64;
    loop {
        sink.check()?;
        let count = match z.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if super::input::malformed(&e) => return Err(e),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::InvalidInput
                        | io::ErrorKind::InvalidData
                        | io::ErrorKind::UnexpectedEof
                ) =>
            {
                break;
            }
            Err(e) => return Err(e),
        };
        size += count as u64;
        if sink.skip_declared_size(size) {
            return Ok(Some(Handling::Complete));
        }
        if let Some(file) = &mut file {
            file.write_all(&buf[..count])?;
        }
    }
    if size <= 5 {
        return Ok(None);
    }
    let Some(file) = file else {
        // This record reached child admission before any byte limit fired.
        sink.can_enter_child();
        return Ok(Some(Handling::Complete));
    };
    file.with_bytes(|b| {
        Ok(sink
            .child_bytes(b, Some(name.as_bytes()))?
            .then_some(Handling::Stopped))
    })
}

pub(super) fn scan(
    doc: &mut Document,
    dir: &Inventory,
    entry: &Stream,
    sink: &mut dyn ChildSink,
) -> io::Result<Option<Handling>> {
    let mut stream = Input::open(doc, dir, entry)?;
    let size = stream.len();
    if sink.child_limit().is_some() && size.saturating_mul(MAX_EXPANSION) <= sink.remaining() {
        // The raw stream pass will record the child limit. No extracted record can exceed a byte limit.
        return Ok(None);
    }
    let mut position = 0;
    let mut offsets = Vec::new();
    while size.saturating_sub(position) >= 8 {
        sink.check()?;
        stream.seek(SeekFrom::Start(position))?;
        let mut header = [0; 8];
        stream.read_exact(&mut header)?;
        let length = u64::from(u32::from_le_bytes(header[4..8].try_into().unwrap()));
        if length == 0 {
            return Ok(None);
        }
        let next = position + 8 + length;
        if u16::from_le_bytes([header[2], header[3]]) == 0x1011 {
            if length < 4 || next > size {
                return Ok(None);
            }
            if offsets.len() == MAX_RECORDS {
                return Ok(Some(Handling::Incomplete));
            }
            offsets.push(position + 12);
        }
        position = next;
    }
    match offsets.as_slice() {
        [] => return Ok(None),
        &[offset] => return scan_at(&mut stream, offset, &filename(offset), sink),
        _ => {}
    }
    // Match readdir order without keeping expanded objects. Leave all payloads in the CFB.
    let folder = tempfile::tempdir_in(sink.temporary_directory())?;
    for offset in offsets {
        sink.check()?;
        fs::File::create_new(folder.path().join(filename(offset)))?;
    }
    for entry in fs::read_dir(folder.path())? {
        sink.check()?;
        let name = entry?.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| io::Error::other("invalid PowerPoint temporary name"))?;
        let offset = name
            .strip_prefix("ppt")
            .and_then(|s| s.strip_suffix(".doc"))
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .ok_or_else(|| io::Error::other("invalid PowerPoint record offset"))?;
        if let Some(result) = scan_at(&mut stream, offset, name, sink)? {
            return Ok(Some(result));
        }
    }
    Ok(None)
}
