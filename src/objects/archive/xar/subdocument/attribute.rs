//! Serialize ordinary XAR attributes without allocating a decoded value.
use super::ChildSink;
use crate::objects::xml::entity;
use std::io::{self, Write};

const MAX_VALUE: usize = 10_000_000;
const CHECK_INTERVAL: usize = 64 * 1024;

#[derive(Default)]
pub(in crate::objects::archive::xar) enum Encoding {
    #[default]
    Undeclared,
    Utf8,
    Ascii,
}

fn plain_byte(b: u8) -> bool {
    (b' '..=0x7f).contains(&b) && !matches!(b, b'&' | b'<' | b'>' | b'"')
}

pub(super) fn plain(value: &str) -> bool {
    value.len() <= CHECK_INTERVAL && value.bytes().all(plain_byte)
}

impl Encoding {
    pub(in crate::objects::archive::xar) fn set(&mut self, name: &str) -> bool {
        if name.eq_ignore_ascii_case("UTF-8") {
            *self = Self::Utf8;
        } else if name.eq_ignore_ascii_case("US-ASCII") {
            *self = Self::Ascii;
        } else {
            return false;
        }
        true
    }

    pub(super) fn write(
        &self,
        value: &str,
        out: &mut impl Write,
        sink: &mut dyn ChildSink,
    ) -> io::Result<bool> {
        if value.len() > MAX_VALUE {
            return Ok(false);
        }
        if plain(value) {
            out.write_all(value.as_bytes())?;
            return Ok(true);
        }
        let bytes = value.as_bytes();
        let mut pos = 0;
        let mut start = 0;
        let mut next_check = 0;
        while pos < bytes.len() {
            if pos >= next_check {
                sink.check()?;
                out.write_all(&bytes[start..pos])?;
                start = pos;
                next_check = pos + CHECK_INTERVAL;
            }
            if plain_byte(bytes[pos]) {
                pos += 1;
                continue;
            }
            out.write_all(&bytes[start..pos])?;
            let tail = &value[pos..];
            let (ch, consumed) = match bytes[pos] {
                b'&' => {
                    let Some(end) = tail.bytes().take(32).position(|b| b == b';') else {
                        return Ok(false);
                    };
                    let Some(ch) = entity(&tail[1..end]) else {
                        return Ok(false);
                    };
                    (ch, end + 1)
                }
                b'\r' if tail.starts_with("\r\n") => (' ', 2),
                b'\t' | b'\n' | b'\r' => (' ', 1),
                b'"' | b'>' => (char::from(bytes[pos]), 1),
                0x80.. if !matches!(self, Self::Ascii) => {
                    let ch = tail.chars().next().unwrap();
                    if matches!(ch, '\u{fffe}' | '\u{ffff}') {
                        return Ok(false);
                    }
                    (ch, ch.len_utf8())
                }
                _ => return Ok(false),
            };
            match ch {
                '&' => out.write_all(b"&amp;")?,
                '<' => out.write_all(b"&lt;")?,
                '>' => out.write_all(b"&gt;")?,
                '"' => out.write_all(b"&quot;")?,
                '\t' => out.write_all(b"&#9;")?,
                '\n' => out.write_all(b"&#10;")?,
                '\r' => out.write_all(b"&#13;")?,
                ch if !ch.is_ascii() && matches!(self, Self::Undeclared) => {
                    write!(out, "&#x{:X};", u32::from(ch))?
                }
                ch => out.write_all(ch.encode_utf8(&mut [0; 4]).as_bytes())?,
            }
            pos += consumed;
            start = pos;
        }
        out.write_all(&bytes[start..])?;
        Ok(true)
    }
}
