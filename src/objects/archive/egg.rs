use super::{ChildSink, Handling, decoded};
use bzip2::read::BzDecoder;
use flate2::read::DeflateDecoder;
use std::io::{self, Read};

const END: u32 = 0x08e28222;
const FILE: u32 = 0x0a8590e3;
const BLOCK: u32 = 0x02b50c13;
const COMMENT: u32 = 0x04c63672;

fn number(input: &mut &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(input.split_off(..4)?.try_into().ok()?))
}

fn field<'a>(input: &mut &'a [u8]) -> Option<(u8, &'a [u8])> {
    let flags = *input.split_off_first()?;
    let size = if flags & 1 == 0 {
        usize::from(u16::from_le_bytes(input.split_off(..2)?.try_into().ok()?))
    } else {
        number(input)? as usize
    };
    Some((flags, input.split_off(..size)?))
}

#[derive(Default)]
struct Properties<'a> {
    name: Option<&'a [u8]>,
    directory: bool,
    unsupported: bool,
}

fn extras<'a>(input: &mut &'a [u8]) -> Option<Properties<'a>> {
    let mut result = Properties::default();
    loop {
        let kind = number(input)?;
        if kind == END {
            return Some(result);
        }
        let (flags, value) = field(input)?;
        match kind {
            0x0a8591ac => {
                if flags & 0x1c == 0 && std::str::from_utf8(value).is_ok() {
                    result.name = value.split(|&b| b == 0).next();
                } else {
                    result.unsupported = true;
                }
            }
            0x2c86950b => result.directory |= value.get(8)? & 0x40 != 0,
            0x1ee922e5 => result.directory |= number(&mut &value[..])? & 0x4000 != 0,
            0x24f5a262 | 0x24e5a060 | 0x08d1470f => result.unsupported = true,
            _ => {}
        }
    }
}

struct Block<'a> {
    method: u8,
    size: u32,
    data: &'a [u8],
}

enum Record<'a> {
    File(Properties<'a>),
    Block(Block<'a>),
    Comment(Option<&'a [u8]>),
    End,
}

fn record<'a>(input: &mut &'a [u8]) -> Option<Record<'a>> {
    match number(input)? {
        END => Some(Record::End),
        FILE => {
            input.split_off(..12)?;
            Some(Record::File(extras(input)?))
        }
        BLOCK => {
            let method = input.split_off(..2)?[0];
            let size = number(input)?;
            let packed = number(input)? as usize;
            input.split_off(..4)?;
            extras(input)?;
            Some(Record::Block(Block {
                method,
                size,
                data: input.split_off(..packed)?,
            }))
        }
        COMMENT => {
            let (flags, value) = field(input)?;
            let comment = (flags & 12 == 0).then(|| value.split(|&b| b == 0).next().unwrap());
            Some(Record::Comment(comment))
        }
        _ => None,
    }
}

// A file can span several differently compressed blocks. Keep only its current decoder.
struct Member<'a> {
    blocks: &'a [u8],
    current: Option<Box<dyn Read + 'a>>,
}

impl Read for Member<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(reader) = &mut self.current {
                let count = reader.read(out)?;
                if count != 0 {
                    return Ok(count);
                }
                self.current = None;
            }
            if self.blocks.is_empty() {
                return Ok(0);
            }
            match record(&mut self.blocks) {
                Some(Record::Block(block)) => {
                    self.current = Some(match block.method {
                        0 => Box::new(block.data),
                        1 => Box::new(DeflateDecoder::new(block.data)),
                        2 => Box::new(BzDecoder::new(block.data)),
                        _ => return Err(io::ErrorKind::Unsupported.into()),
                    });
                }
                Some(Record::Comment(_)) => {}
                _ => return Err(io::ErrorKind::InvalidData.into()),
            }
        }
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(mut records) = bytes.get(14..) else {
        return Ok(Handling::Incomplete);
    };
    let Some(archive) = extras(&mut records) else {
        return Ok(Handling::Incomplete);
    };
    // Stock indexes the entire record stream, then scans global comments before files.
    // Revisit borrowed records to keep memory independent of the archive's entry count.
    let mut cursor = records;
    let mut has_comment = false;
    loop {
        sink.check()?;
        match record(&mut cursor) {
            None => return Ok(Handling::Incomplete),
            Some(Record::End) => break,
            Some(Record::Comment(_)) => has_comment = true,
            _ => {}
        }
    }
    let mut result = Handling::Complete;
    if has_comment {
        cursor = records;
        loop {
            sink.check()?;
            match record(&mut cursor) {
                Some(Record::Comment(Some(mut comment))) => {
                    if sink.child(&mut comment, None, None)? {
                        return Ok(Handling::Stopped);
                    }
                }
                Some(Record::Comment(None)) => result = Handling::Incomplete,
                Some(Record::End) | None => break,
                _ => {}
            }
        }
    }
    if archive.unsupported {
        return Ok(Handling::Incomplete);
    }
    loop {
        sink.check()?;
        let file = match record(&mut records) {
            Some(Record::File(file)) => file,
            Some(Record::Comment(_)) => continue,
            Some(Record::End) => return Ok(result),
            _ => return Ok(Handling::Incomplete),
        };
        let start = records;
        let mut size = 0u64;
        let mut eligible = !file.unsupported;
        loop {
            sink.check()?;
            let mut after = records;
            match record(&mut after) {
                Some(Record::Block(block)) => {
                    size += u64::from(block.size);
                    eligible &= block.method <= 2;
                }
                Some(Record::Comment(_)) => {}
                _ => break,
            }
            records = after;
        }
        if file.directory || sink.skip_declared_size(size) {
            continue;
        }
        if !eligible {
            result = Handling::Incomplete;
            continue;
        }
        let reader = Member {
            blocks: &start[..start.len() - records.len()],
            current: None,
        };
        match decoded(reader, file.name, false, sink)? {
            Handling::Stopped => return Ok(Handling::Stopped),
            Handling::Incomplete => result = Handling::Incomplete,
            _ => {}
        }
    }
}
