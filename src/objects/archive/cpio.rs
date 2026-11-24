use super::{ChildSink, Handling, digits};
use std::io;

struct Header {
    size: usize,
    name: usize,
    header: usize,
    alignment: usize,
}

impl Header {
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(b"070701") || bytes.starts_with(b"070702") {
            return Some(Self {
                size: digits(bytes.get(54..62)?, 16)?,
                name: digits(bytes.get(94..102)?, 16)?,
                header: 110,
                alignment: 4,
            });
        }
        if bytes.starts_with(b"070707") {
            return Some(Self {
                size: digits(bytes.get(65..76)?, 8)?,
                name: digits(bytes.get(59..65)?, 8)?,
                header: 76,
                alignment: 1,
            });
        }
        let little = match bytes.get(..2)? {
            [0xc7, 0x71] => true,
            [0x71, 0xc7] => false,
            _ => return None,
        };
        let word = |at: usize| {
            let pair = bytes.get(at..at + 2)?.try_into().ok()?;
            Some(usize::from(if little {
                u16::from_le_bytes(pair)
            } else {
                u16::from_be_bytes(pair)
            }))
        };
        Some(Self {
            size: (word(22)? << 16) | word(24)?,
            name: word(20)?,
            header: 26,
            alignment: 2,
        })
    }
}

pub(super) fn extract(mut bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let mut trailer = false;
    while !bytes.is_empty() {
        sink.check()?;
        if trailer && bytes[0] == 0 {
            break;
        }
        let Some(entry) = Header::parse(bytes) else {
            return Ok(Handling::Incomplete);
        };
        let Some(name_end) = entry.header.checked_add(entry.name) else {
            return Ok(Handling::Incomplete);
        };
        let Some(name) = bytes.get(entry.header..name_end) else {
            return Ok(Handling::Incomplete);
        };
        let name = name.strip_suffix(&[0]).unwrap_or(name);
        trailer |= name == b"TRAILER!!!";
        let Some(start) = name_end.checked_next_multiple_of(entry.alignment) else {
            return Ok(Handling::Incomplete);
        };
        let Some(rest) = bytes.get(start..) else {
            return Ok(Handling::Incomplete);
        };
        let Some(member) = rest.get(..entry.size) else {
            return Ok(Handling::Incomplete);
        };
        if !member.is_empty() {
            // Only bounded display names cross the CPIO handler boundary.
            let name: Vec<u8> = name
                .iter()
                .copied()
                .take(512)
                .take_while(|&b| b != 0)
                .map(|b| {
                    if !b.is_ascii() || matches!(b, b'%' | b'\\' | b'\t' | b'\r' | b'\n') {
                        b'_'
                    } else {
                        b
                    }
                })
                .collect();
            if sink.child_bytes(member, Some(&name))? {
                return Ok(Handling::Stopped);
            }
        }
        let Some(consumed) = entry.size.checked_next_multiple_of(entry.alignment) else {
            return Ok(Handling::Incomplete);
        };
        let Some(rest) = rest.get(consumed..) else {
            return Ok(Handling::Incomplete);
        };
        bytes = rest;
    }
    Ok(Handling::Complete)
}
