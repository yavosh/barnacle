//! Typed streams produced by the stock HTML, script, and mail parsers.
use super::{ChildSink, Handling, ObjectBytes, Snapshot, classify::Parser};
use crate::body::Target;
use std::io::{self, Write};
use std::path::Path;

mod attachments;
mod html;
mod mail;
pub(super) use mail::{SavedLetters, base64_reader, valid_base64};

fn text_byte(b: u8) -> bool {
    matches!(b, 7..=10 | 12 | 13 | 27 | 0x20..=0x7e | 0x80..=0xff)
}

pub(super) fn file_type(bytes: &[u8]) -> &'static str {
    let head = &bytes[..bytes.len().min(1024)];
    if head.iter().copied().all(text_byte) {
        // Stock includes extended single-byte text and UTF-8 in this class.
        return "CL_TYPE_TEXT_ASCII";
    }
    let (pairs, _) = head.as_chunks::<2>();
    let Some((prefix, rest)) = pairs.split_first() else {
        return "CL_TYPE_BINARY_DATA";
    };
    let little = *prefix == [0xff, 0xfe];
    let marked = little || *prefix == [0xfe, 0xff];
    for &pair in rest {
        let point = if little {
            u16::from_le_bytes(pair)
        } else {
            u16::from_be_bytes(pair)
        };
        if point == 0xfffe || (!marked && point < 128 && !text_byte(point as u8)) {
            return "CL_TYPE_BINARY_DATA";
        }
    }
    if little {
        "CL_TYPE_TEXT_UTF16LE"
    } else {
        "CL_TYPE_TEXT_UTF16BE"
    }
}

pub(super) fn plain(bytes: &[u8]) -> bool {
    file_type(bytes) != "CL_TYPE_BINARY_DATA"
}

pub(super) fn parser(bytes: &[u8]) -> Option<Parser> {
    let head = &bytes[..bytes.len().min(1024)];
    if mail::recognizes(head) {
        return Some(Parser::Mail);
    }
    if plain(head) && html::recognizes(head) {
        return Some(Parser::Html { big_endian: false });
    }
    if !head.contains(&0) {
        return None;
    }
    let pairs = head.as_chunks::<2>().0;
    let mut projected = [0; 512];
    let sample = &mut projected[..pairs.len()];
    if pairs.contains(&[b'<', 0]) {
        for (dst, &pair) in sample.iter_mut().zip(pairs) {
            *dst = html_byte(pair);
        }
        if html::recognizes(sample) {
            return Some(Parser::Utf16Html);
        }
    }
    if head.starts_with(&[0xfe, 0xff]) {
        for (dst, &pair) in sample.iter_mut().zip(pairs) {
            *dst = if pair[0] == 0 { pair[1] } else { 0xff };
        }
        if html::recognizes(sample) {
            return Some(Parser::Html { big_endian: true });
        }
    }
    None
}

pub(super) fn container_type(bytes: &[u8]) -> Option<&'static str> {
    attachments::file_type(bytes)
}

pub(super) fn before_raw(
    parser: Parser,
    bytes: &[u8],
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    match parser {
        Parser::Tnef => attachments::tnef(bytes, sink),
        Parser::Uuencoded => attachments::uu(bytes, sink),
        Parser::Utf16Html => sink.utf16_html(bytes),
        Parser::Html { big_endian: true } => unicode_html(bytes, false, sink),
        Parser::Html { big_endian: false } => html::extract(bytes, sink, bytes.len(), true),
        Parser::Mail => mail::extract(bytes, sink),
        _ => Ok(Handling::Unrecognized),
    }
}

// ClamAV's little-endian HTML projection combines the upper byte at bit four.
fn html_byte(pair: [u8; 2]) -> u8 {
    pair[0].wrapping_add(pair[1] << 4)
}

pub(super) fn unicode_html(
    bytes: &[u8],
    little: bool,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let size = if little { bytes.len() / 2 } else { bytes.len() };
    if size as u64 > sink.text_limits().0 {
        return Ok(Handling::Complete);
    }
    let mut spool = super::Snapshot::new(sink.temporary_directory());
    // The reference fills 8,191 nonzero bytes, then rewinds the source by the
    // number of output bytes after the last space. These units differ for UTF-16BE.
    const BLOCK: usize = 8191;
    let byte = |at: usize| {
        if little {
            html_byte([bytes[2 * at], bytes[2 * at + 1]])
        } else {
            bytes[at]
        }
    };
    let mut buffer = Vec::with_capacity(BLOCK);
    let mut at = 0;
    while at < size {
        buffer.clear();
        while at < size && buffer.len() < BLOCK {
            sink.check()?;
            let end = (at + BLOCK).min(size);
            while at < end && buffer.len() < BLOCK {
                let b = byte(at);
                if b != 0 {
                    buffer.push(b);
                }
                at += 1;
            }
        }
        if at < size
            && !byte(at).is_ascii_whitespace()
            && let Some(space) = buffer.iter().rposition(u8::is_ascii_whitespace)
            && space > 0
        {
            at -= buffer.len() - space - 1;
            buffer.truncate(space + 1);
        }
        buffer.retain(|b| *b != b'\r');
        spool.write_all(buffer.trim_ascii_start())?;
    }
    spool.with_bytes(|data| html::extract(data, sink, size, false))
}

pub(super) struct NormalizedText<'a> {
    bytes: &'a [u8],
    space: bool,
}

impl<'a> NormalizedText<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            space: false,
        }
    }

    // Bound consumed input even if a whole block normalizes to zero bytes.
    fn next_block(&mut self, output: &mut [u8]) -> Option<usize> {
        if self.bytes.is_empty() || output.is_empty() {
            return None;
        }
        // Printable text with single spaces keeps its length. Lowercase it in bulk.
        let n = self.bytes.len().min(output.len());
        let (input, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        if n >= 64
            && !(self.space && input[0] == b' ')
            && input.iter().all(|b| (0x20..=0x7f).contains(b))
            && memchr::memmem::find(input, b"  ").is_none()
        {
            output[..n].copy_from_slice(input);
            output[..n].make_ascii_lowercase();
            self.space = input[n - 1] == b' ';
            return Some(n);
        }
        let mut written = 0;
        for &b in input {
            let b = match b {
                9..=13 | b' ' if !self.space => b' ',
                0x21..=0x7f => b.to_ascii_lowercase(),
                _ => continue,
            };
            self.space = b == b' ';
            output[written] = b;
            written += 1;
        }
        Some(written)
    }

    pub(super) fn size(mut self, check: &mut dyn FnMut() -> io::Result<()>) -> io::Result<u64> {
        let mut total = 0;
        let mut buf = [0; 8192];
        while let Some(n) = self.next_block(&mut buf) {
            check()?;
            total += n as u64;
        }
        Ok(total)
    }

    pub(super) fn into_bytes(
        mut self,
        directory: &Path,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<ObjectBytes<'a>> {
        let source = self.bytes;
        let mut prefix = 0;
        let mut spool = None;
        let mut buf = [0; 8192];
        while let Some(n) = self.next_block(&mut buf) {
            check()?;
            let part = &buf[..n];
            let file = match &mut spool {
                Some(file) => file,
                None if source[prefix..].starts_with(part) => {
                    prefix += n;
                    continue;
                }
                None => {
                    let mut file = Snapshot::new(directory);
                    for bytes in source[..prefix].chunks(64 * 1024) {
                        check()?;
                        file.write_all(bytes)?;
                    }
                    spool.insert(file)
                }
            };
            file.write_all(part)?;
        }
        match spool {
            Some(file) => file.into_bytes(),
            None => Ok(ObjectBytes::Borrowed(&source[..prefix])),
        }
    }
}

pub(super) fn after_raw(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if !plain(bytes) || parser(bytes).is_some() {
        return Ok(Handling::Unrecognized);
    }
    Ok(
        if bytes.len() as u64 <= sink.text_limits().2 && sink.script_view(bytes)? {
            Handling::Stopped
        } else {
            Handling::Complete
        },
    )
}

#[cfg(test)]
mod normalized_text_tests {
    use super::*;

    #[test]
    fn bulk_reads_keep_scalar_whitespace_state() -> io::Result<()> {
        let mut source = b"MiXeD-bOX ".repeat(900);
        source[8191..8193].fill(b' ');
        source.extend(0..=u8::MAX);
        source.extend(b" Warehouse note.".repeat(900));
        source.extend(b"\r\n  Tail\x7f  ");
        let mut expected = Vec::new();
        for &byte in &source {
            match byte {
                9..=13 | b' ' if expected.last() != Some(&b' ') => expected.push(b' '),
                0x21..=0x7f => expected.push(byte.to_ascii_lowercase()),
                _ => (),
            }
        }
        for size in [1, 2, 63, 64, 65, 257, 8191, 8192] {
            let mut reader = NormalizedText::new(&source);
            let mut actual = Vec::new();
            let mut buf = vec![0; size];
            while let Some(n) = reader.next_block(&mut buf) {
                actual.extend_from_slice(&buf[..n]);
            }
            assert_eq!(actual, expected, "read size {size}");
        }
        Ok(())
    }

    #[test]
    fn sparse_normalization_checks_input_and_preserves_a_late_change() -> io::Result<()> {
        let tmp = tempfile::tempdir()?;
        let input = vec![b' '; 128 * 1024];
        for count_only in [false, true] {
            let mut polls = 0;
            let mut interrupt = || {
                polls += 1;
                if polls == 3 {
                    Err(io::Error::other("cancelled"))
                } else {
                    Ok(())
                }
            };
            let text = NormalizedText::new(&input);
            let result = if count_only {
                text.size(&mut interrupt).map(|_| ())
            } else {
                text.into_bytes(tmp.path(), &mut interrupt).map(|_| ())
            };
            assert_eq!(result.unwrap_err().to_string(), "cancelled");
        }
        let mut input = b"paper order ".repeat(12_000);
        input.extend_from_slice(b"BOX\r\n");
        let bytes = NormalizedText::new(&input).into_bytes(tmp.path(), &mut || Ok(()))?;
        assert!(matches!(bytes, ObjectBytes::Mapped(_)));
        let prefix = input.len() - 5;
        assert_eq!(&bytes.as_ref()[..prefix], &input[..prefix]);
        assert_eq!(&bytes.as_ref()[prefix..], b"box ");
        Ok(())
    }
}
