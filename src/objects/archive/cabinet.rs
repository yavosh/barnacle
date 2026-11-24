//! Read a single cabinet in CFFILE order. Folder bytes stay in a bounded block buffer.
use super::{ChildSink, Handling, decoded};
use flate2::{Decompress, FlushDecompress, Status};
use lzxd::{Lzxd, WindowSize};
use std::io::{self, Cursor, Read};

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

enum Compression {
    Stored,
    MsZip(Vec<u8>),
    Lzx(Box<Lzxd>),
}

struct Folder<'a> {
    bytes: &'a [u8],
    blocks: u16,
    reserve: usize,
    decoder: Compression,
    block: Cursor<Vec<u8>>,
    position: u64,
}

impl<'a> Folder<'a> {
    fn new(bytes: &'a [u8], record: &[u8], reserve: usize) -> Option<Self> {
        let kind = u16_at(record, 6);
        let decoder = match kind & 15 {
            0 => Compression::Stored,
            1 => Compression::MsZip(Vec::new()),
            3 => {
                const WINDOWS: [WindowSize; 7] = [
                    WindowSize::KB32,
                    WindowSize::KB64,
                    WindowSize::KB128,
                    WindowSize::KB256,
                    WindowSize::KB512,
                    WindowSize::MB1,
                    WindowSize::MB2,
                ];
                let exponent = (kind >> 8) & 31;
                let window = WINDOWS.get(usize::from(exponent.checked_sub(15)?))?;
                Compression::Lzx(Box::new(Lzxd::new(*window)))
            }
            _ => return None,
        };
        Some(Self {
            bytes: bytes.get(u32_at(record, 0) as usize..)?,
            blocks: u16_at(record, 4),
            reserve,
            decoder,
            block: Cursor::default(),
            position: 0,
        })
    }

    fn next_block(&mut self) -> io::Result<()> {
        let (head, tail) = self.bytes.split_at_checked(8).ok_or_else(invalid)?;
        let compressed = usize::from(u16_at(head, 4));
        let size = usize::from(u16_at(head, 6));
        if !(1..=32768).contains(&size) {
            return Err(invalid());
        }
        let (data, remaining) = tail
            .split_at_checked(self.reserve + compressed)
            .ok_or_else(invalid)?;
        self.bytes = remaining;
        self.blocks -= 1;
        let expected = u32_at(head, 0);
        if expected != 0 {
            let (words, remainder) = data.as_chunks::<4>();
            let last = remainder
                .iter()
                .fold(0u32, |sum, &b| (sum << 8) | u32::from(b));
            let actual = words.iter().fold(last ^ u32_at(head, 4), |sum, word| {
                sum ^ u32::from_le_bytes(*word)
            });
            if expected != actual {
                return Err(invalid());
            }
        }
        let data = &data[self.reserve..];
        self.block.set_position(0);
        let out = self.block.get_mut();
        out.clear();
        match &mut self.decoder {
            Compression::Stored => out.extend_from_slice(data),
            Compression::Lzx(decoder) => {
                out.extend_from_slice(decoder.decompress_next(data, size).map_err(|_| invalid())?)
            }
            Compression::MsZip(dictionary) => {
                let deflate = data.strip_prefix(b"CK").ok_or_else(invalid)?;
                let mut stream = Decompress::new(false);
                if !dictionary.is_empty() {
                    stream.set_dictionary(dictionary).map_err(|_| invalid())?;
                }
                out.resize(size + 1, 0);
                let status = stream
                    .decompress(deflate, out, FlushDecompress::Finish)
                    .map_err(|_| invalid())?;
                if status != Status::StreamEnd || stream.total_out() != size as u64 {
                    return Err(invalid());
                }
                out.truncate(size);
                let obsolete = (dictionary.len() + size).saturating_sub(32768);
                dictionary.drain(..obsolete);
                dictionary.extend_from_slice(out);
            }
        }
        if out.len() != size {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Read for Folder<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.block.position() as usize == self.block.get_ref().len() && self.blocks != 0 {
            self.next_block()?;
        }
        let n = self.block.read(out)?;
        self.position += n as u64;
        Ok(n)
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(head) = bytes.get(..36) else {
        return Ok(Handling::Incomplete);
    };
    let flags = u16_at(head, 30);
    // Files spanning multiple cabinets need another volume.
    if flags & 3 != 0 || u32_at(head, 8) as usize > bytes.len() {
        return Ok(Handling::Incomplete);
    }
    let mut at = 36;
    let (folder_reserve, block_reserve) = if flags & 4 != 0 {
        let Some(sizes) = bytes.get(36..40) else {
            return Ok(Handling::Incomplete);
        };
        at = 40 + usize::from(u16_at(sizes, 0));
        (usize::from(sizes[2]), usize::from(sizes[3]))
    } else {
        (0, 0)
    };
    let stride = 8 + folder_reserve;
    let folders = usize::from(u16_at(head, 26));
    let Some(table) = bytes.get(at..at + stride * folders) else {
        return Ok(Handling::Incomplete);
    };
    let Some(mut files) = bytes.get(u32_at(head, 16) as usize..) else {
        return Ok(Handling::Incomplete);
    };
    let mut active = None::<(usize, Folder<'_>)>;
    for _ in 0..u16_at(head, 28) {
        sink.check()?;
        let Some((file, rest)) = files.split_at_checked(16) else {
            return Ok(Handling::Incomplete);
        };
        let Some(end) = rest.iter().take(256).position(|&b| b == 0) else {
            return Ok(Handling::Incomplete);
        };
        let name = &rest[..end];
        files = &rest[end + 1..];
        let size = u64::from(u32_at(file, 0));
        let offset = u64::from(u32_at(file, 4));
        let index = usize::from(u16_at(file, 8));
        if index >= folders {
            return Ok(Handling::Incomplete);
        }
        if size == 0 {
            continue;
        }
        if active
            .as_ref()
            .is_none_or(|(i, f)| *i != index || f.position > offset)
        {
            let Some(folder) = Folder::new(bytes, &table[index * stride..], block_reserve) else {
                return Ok(Handling::Incomplete);
            };
            active = Some((index, folder));
        }
        let folder = &mut active.as_mut().unwrap().1;
        while folder.position < offset {
            sink.check()?;
            let skip = (offset - folder.position).min(32768);
            if !matches!(io::copy(&mut (&mut *folder).take(skip), &mut io::sink()), Ok(n) if n == skip)
            {
                return Ok(Handling::Incomplete);
            }
        }
        let limit = size.min(sink.remaining());
        if limit == 0 {
            break;
        }
        let start = folder.position;
        match decoded((&mut *folder).take(limit), Some(name), true, sink)? {
            Handling::Stopped => return Ok(Handling::Stopped),
            Handling::Complete if folder.position - start == limit => {}
            _ => return Ok(Handling::Incomplete),
        }
    }
    Ok(Handling::Complete)
}
