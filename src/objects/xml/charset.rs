//! Character sets observed in stock's XML reader. Convert into a private bounded-memory spool.
use super::{ChildSink, Handling, Snapshot};
use encoding_rs::{DecoderResult, Encoding};
use quick_xml::{Reader, events::Event};
use std::io::{self, Write};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Charset {
    Utf8,
    Ascii,
    Latin1,
    Latin2,
    Windows1251,
    Windows1252,
    ShiftJis,
    Cp932,
    EucKr,
    Cp949,
}

impl Charset {
    pub(super) fn declaration(bytes: &[u8]) -> Option<Self> {
        let end = bytes[..bytes.len().min(1024)]
            .windows(2)
            .position(|s| s == b"?>")?
            + 2;
        let mut xml = Reader::from_reader(&bytes[..end]);
        let Event::Decl(decl) = xml.read_event().ok()? else {
            return None;
        };
        let Some(label) = decl.encoding() else {
            return Some(Self::Utf8);
        };
        let label = label.ok()?;
        if label.eq_ignore_ascii_case("utf-8") {
            return Some(Self::Utf8);
        }
        if label.len() > 40 {
            return None;
        }
        Some(match label.to_ascii_lowercase().as_str() {
            "utf8" => Self::Utf8,
            "ascii" | "us-ascii" => Self::Ascii,
            "iso-8859-1" | "iso8859-1" | "iso_8859-1" | "latin1" | "l1" | "cp819" => Self::Latin1,
            "iso-8859-2" | "iso8859-2" | "latin2" => Self::Latin2,
            "windows-1252" | "cp1252" => Self::Windows1252,
            "windows-1251" | "cp1251" => Self::Windows1251,
            "shift_jis" | "shift-jis" | "sjis" => Self::ShiftJis,
            "cp932" => Self::Cp932,
            "euc-kr" | "euckr" => Self::EucKr,
            "cp949" => Self::Cp949,
            _ => return None,
        })
    }

    pub(super) fn with_utf8(
        self,
        bytes: &[u8],
        sink: &mut dyn ChildSink,
        parse: impl FnOnce(&[u8], &mut dyn ChildSink, bool) -> io::Result<Handling>,
    ) -> io::Result<Handling> {
        if self == Self::Utf8 {
            return parse(bytes, sink, false);
        }
        let mut unchanged = true;
        for (i, chunk) in bytes.chunks(64 * 1024).enumerate() {
            sink.check()?;
            if !chunk.is_ascii() {
                if self == Self::Ascii {
                    let valid = i * 64 * 1024 + chunk.iter().position(|b| !b.is_ascii()).unwrap();
                    let end = committed_prefix(bytes.len(), valid);
                    return partial(parse(&bytes[..end], sink, true)?);
                }
                unchanged = false;
                break;
            }
            if self == Self::ShiftJis && chunk.iter().any(|b| matches!(b, b'\\' | b'~')) {
                unchanged = false;
                break;
            }
        }
        if unchanged {
            return parse(bytes, sink, false);
        }
        let mut file = Snapshot::new(sink.temporary_directory());
        if self == Self::Latin1 {
            let mut out = String::with_capacity(8192);
            for chunk in bytes.chunks(4096) {
                sink.check()?;
                out.clear();
                out.extend(chunk.iter().map(|&b| char::from(b)));
                file.write_all(out.as_bytes())?;
            }
        } else {
            let valid = self.convert(bytes, &mut file, sink)?;
            if valid < bytes.len() {
                let end = committed_prefix(bytes.len(), valid);
                if end < valid {
                    // A conversion failure in a final short block hides the whole block.
                    drop(file);
                    file = Snapshot::new(sink.temporary_directory());
                    self.convert(&bytes[..end], &mut file, sink)?;
                }
                return file.with_bytes(|data| partial(parse(data, sink, true)?));
            }
        }
        file.with_bytes(|data| parse(data, sink, false))
    }

    // Find the start of the reader's last source block when a later lexical error
    // prevents it from publishing that block. Only the error path requires this map.
    pub(super) fn earlier_block(
        self,
        utf8: &[u8],
        bom: usize,
        sink: &mut dyn ChildSink,
    ) -> io::Result<usize> {
        let single_byte = !matches!(
            self,
            Self::ShiftJis | Self::Cp932 | Self::EucKr | Self::Cp949
        );
        let back = if self == Self::Utf8 || self == Self::Ascii {
            return Ok(block_start(utf8.len() + bom).saturating_sub(bom));
        } else if single_byte {
            let mut count = bom;
            for part in utf8.chunks(64 * 1024) {
                sink.check()?;
                count += part.iter().filter(|b| **b & 0xc0 != 0x80).count();
            }
            count - block_start(count)
        } else {
            // A character in the multibyte source needs at least one input byte.
            512
        };
        if back == 0 {
            return Ok(utf8.len());
        }
        Ok(utf8
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, b)| **b & 0xc0 != 0x80)
            .map(|(n, _)| n)
            .nth(back.saturating_sub(1))
            .unwrap_or(0))
    }

    fn table(self) -> &'static Encoding {
        match self {
            Self::Windows1251 => encoding_rs::WINDOWS_1251,
            Self::Windows1252 => encoding_rs::WINDOWS_1252,
            Self::Latin2 => encoding_rs::ISO_8859_2,
            Self::ShiftJis | Self::Cp932 => encoding_rs::SHIFT_JIS,
            Self::EucKr | Self::Cp949 => encoding_rs::EUC_KR,
            _ => unreachable!("single-byte identity encodings use their direct path"),
        }
    }

    fn convert(
        self,
        bytes: &[u8],
        file: &mut Snapshot,
        sink: &mut dyn ChildSink,
    ) -> io::Result<usize> {
        let mut decoder = self.table().new_decoder_without_bom_handling();
        let mut buf = [0u8; 16 * 1024];
        let mut pos = 0;
        while pos < bytes.len() {
            sink.check()?;
            let mut start = pos;
            let mut used = 0;
            let end = bytes.len().min(pos + 4096);
            loop {
                let unit = if pos < end {
                    self.unit(&bytes[pos..])
                } else {
                    None
                };
                if let Some((width, None)) = unit {
                    pos += width;
                    continue;
                }
                let (status, read, written) = decoder.decode_to_utf8_without_replacement(
                    &bytes[start..pos],
                    &mut buf[used..],
                    false,
                );
                used += written;
                if let DecoderResult::Malformed(bad, after) = status {
                    file.write_all(&buf[..used])?;
                    return Ok(start + read - usize::from(bad) - usize::from(after));
                }
                debug_assert_eq!(status, DecoderResult::InputEmpty);
                if let Some((width, Some(c))) = unit {
                    used += c.encode_utf8(&mut buf[used..]).len();
                    pos += width;
                    start = pos;
                    continue;
                }
                file.write_all(&buf[..used])?;
                if pos < end {
                    return Ok(pos);
                }
                break;
            }
        }
        Ok(pos)
    }

    // The Linux XML reader distinguishes the original code pages from their Windows extensions.
    fn unit(self, bytes: &[u8]) -> Option<(usize, Option<char>)> {
        let b = bytes[0];
        if b.is_ascii() {
            let special = match (self, b) {
                (Self::ShiftJis, b'\\') => Some('¥'),
                (Self::ShiftJis, b'~') => Some('‾'),
                _ => None,
            };
            return Some((1, special));
        }
        let special = match self {
            Self::Windows1251 if b == 0x98 => return None,
            Self::Windows1252 if matches!(b, 0x81 | 0x8d | 0x8f | 0x90 | 0x9d) => return None,
            Self::EucKr if b <= 0x9f => return Some((1, Some(char::from(b)))),
            Self::EucKr => {
                let second = *bytes.get(1)?;
                if !(0xa1..=0xfe).contains(&b) || !(0xa1..=0xfe).contains(&second) {
                    return None;
                }
                (b == 0xa2 && second == 0xe8).then_some('㉾')
            }
            Self::Cp949 => {
                bytes.get(1)?;
                None
            }
            Self::ShiftJis | Self::Cp932 => {
                if (0xa1..=0xdf).contains(&b) {
                    return Some((1, None));
                }
                if !(0x81..=0x9f).contains(&b) && !(0xe0..=0xfc).contains(&b) {
                    return None;
                }
                let pair = u16::from_be_bytes([b, *bytes.get(1)?]);
                if self == Self::Cp932 {
                    None
                } else {
                    if matches!(b, 0x87 | 0xed | 0xee | 0xf0..=0xfc) {
                        return None;
                    }
                    match pair {
                        0x8160 => Some('〜'),
                        0x8161 => Some('‖'),
                        0x817c => Some('−'),
                        0x8191 => Some('¢'),
                        0x8192 => Some('£'),
                        0x81ca => Some('¬'),
                        _ => None,
                    }
                }
            }
            _ => return Some((1, None)),
        };
        Some((2, special))
    }
}

// The reference reader primes its input with four bytes, then pushes 512-byte blocks.
// Its initial conversion can expose valid text. Later short final blocks with conversion
// errors leave only earlier blocks available to the reader.
fn block_start(offset: usize) -> usize {
    if offset < 4 {
        0
    } else {
        4 + (offset - 4) / 512 * 512
    }
}

fn committed_prefix(size: usize, valid: usize) -> usize {
    let final_block = block_start(size);
    if final_block > 4 && valid >= final_block {
        final_block
    } else {
        valid
    }
}

fn partial(handling: Handling) -> io::Result<Handling> {
    Ok(if handling == Handling::Stopped {
        Handling::Stopped
    } else {
        Handling::Incomplete
    })
}
