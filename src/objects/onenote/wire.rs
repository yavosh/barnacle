//! MS-FSSHTTPB compact values and nested stream-object records.
use super::super::ChildSink;
use std::io;

pub(super) fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "unsupported OneNote package structure",
    )
}

pub(super) fn take<'a>(input: &mut &'a [u8], n: usize) -> io::Result<&'a [u8]> {
    let (value, tail) = input.split_at_checked(n).ok_or_else(invalid)?;
    *input = tail;
    Ok(value)
}

pub(super) fn word(input: &mut &[u8]) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        take(input, 4)?.try_into().expect("four bytes"),
    ))
}

pub(super) fn compact(input: &mut &[u8]) -> io::Result<usize> {
    let first = *input.first().ok_or_else(invalid)?;
    let value = match first {
        0 => {
            take(input, 1)?;
            0
        }
        128 => {
            take(input, 1)?;
            u64::from_le_bytes(take(input, 8)?.try_into().expect("eight bytes"))
        }
        _ => {
            let n = first.trailing_zeros() as usize + 1;
            let mut bytes = [0u8; 8];
            bytes[..n].copy_from_slice(take(input, n)?);
            u64::from_le_bytes(bytes) >> n
        }
    };
    usize::try_from(value).map_err(|_| invalid())
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(super) struct Id {
    pub(super) guid: [u8; 16],
    pub(super) number: u32,
}

pub(super) fn id(input: &mut &[u8]) -> io::Result<Id> {
    let first = take(input, 1)?[0];
    let number = match first {
        0 => return Ok(Id::default()),
        b if b & 7 == 4 => u32::from(b >> 3),
        b if b & 63 == 32 => u32::from(b >> 6) | (u32::from(take(input, 1)?[0]) << 2),
        b if b & 127 == 64 => {
            u32::from(b >> 7)
                | (u32::from(u16::from_le_bytes(
                    take(input, 2)?.try_into().expect("two bytes"),
                )) << 1)
        }
        128 => word(input)?,
        _ => return Err(invalid()),
    };
    Ok(Id {
        guid: take(input, 16)?.try_into().expect("GUID"),
        number,
    })
}

pub(super) type Cell = (Id, Id);

pub(super) fn cell(input: &mut &[u8]) -> io::Result<Cell> {
    Ok((id(input)?, id(input)?))
}

pub(super) struct Work<'a> {
    pub(super) sink: &'a mut dyn ChildSink,
    n: usize,
}

impl<'a> Work<'a> {
    pub(super) fn new(sink: &'a mut dyn ChildSink) -> Self {
        Self { sink, n: 0 }
    }
    pub(super) fn step(&mut self) -> io::Result<()> {
        self.n += 1;
        if self.n.is_multiple_of(512) {
            self.sink.check()?;
        }
        if self.n > 4_000_000 {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) struct Node<'a> {
    pub(super) kind: u16,
    pub(super) value: &'a [u8],
    pub(super) children: &'a [u8],
}

pub(super) fn next<'a>(input: &mut &'a [u8], work: &mut Work) -> io::Result<Node<'a>> {
    fn object<'a>(data: &mut &'a [u8], depth: u8, work: &mut Work) -> io::Result<Node<'a>> {
        work.step()?;
        if depth > 12 {
            return Err(invalid());
        }
        let first = *data.first().ok_or_else(invalid)?;
        let (kind, length) = match first & 3 {
            0 => {
                let h = u16::from_le_bytes(take(data, 2)?.try_into().expect("two bytes"));
                ((h >> 3) & 63, usize::from(h >> 9))
            }
            2 => {
                let h = word(data)?;
                let n = (h >> 17) as usize;
                (
                    ((h >> 3) & 0x3fff) as u16,
                    if n == 0x7fff { compact(data)? } else { n },
                )
            }
            _ => return Err(invalid()),
        };
        let value = take(data, length)?;
        let start = *data;
        let mut children = &start[..0];
        if first & 4 != 0 {
            while data.first().is_some_and(|b| b & 1 == 0) {
                object(data, depth + 1, work)?;
            }
            children = &start[..start.len() - data.len()];
            let flag = *data.first().ok_or_else(invalid)?;
            let end = if flag & 3 == 1 {
                u16::from(take(data, 1)?[0] >> 2)
            } else {
                u16::from_le_bytes(take(data, 2)?.try_into().expect("two bytes")) >> 2
            };
            if end != kind {
                return Err(invalid());
            }
        }
        Ok(Node {
            kind,
            value,
            children,
        })
    }
    object(input, 0, work)
}
