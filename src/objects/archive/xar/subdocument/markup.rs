//! Write comments, processing instructions, and adjacent CDATA as stock libxml2 does.
use super::{ChildSink, ncname};
use quick_xml::events::BytesPI;
use std::io::{self, Write};

const MAX_NODE: usize = 10_000_000;

fn valid_text(text: &str, sink: &mut dyn ChildSink) -> io::Result<bool> {
    if text.len() > MAX_NODE {
        return Ok(false);
    }
    let mut rest = text;
    while !rest.is_empty() {
        sink.check()?;
        let n = rest.floor_char_boundary(rest.len().min(64 * 1024));
        let (chunk, tail) = rest.split_at(n);
        if chunk.chars().any(|c| {
            (c < ' ' && !matches!(c, '\t' | '\n' | '\r')) || matches!(c, '\u{fffe}' | '\u{ffff}')
        }) {
            return Ok(false);
        }
        rest = tail;
    }
    Ok(true)
}

fn normalized_lines(
    out: &mut impl Write,
    bytes: &[u8],
    sink: &mut dyn ChildSink,
) -> io::Result<()> {
    let mut after_cr = false;
    for chunk in bytes.chunks(64 * 1024) {
        sink.check()?;
        let mut part = if after_cr {
            chunk.strip_prefix(b"\n").unwrap_or(chunk)
        } else {
            chunk
        };
        after_cr = chunk.ends_with(b"\r");
        while let Some(i) = memchr::memchr(b'\r', part) {
            out.write_all(&part[..i])?;
            out.write_all(b"\n")?;
            part = &part[i + 1..];
            part = part.strip_prefix(b"\n").unwrap_or(part);
        }
        out.write_all(part)?;
    }
    Ok(())
}

pub(super) fn comment(
    text: &str,
    out: &mut impl Write,
    sink: &mut dyn ChildSink,
) -> io::Result<bool> {
    if !valid_text(text, sink)? || text.contains("--") || text.ends_with('-') {
        return Ok(false);
    }
    out.write_all(b"<!--")?;
    normalized_lines(out, text.as_bytes(), sink)?;
    out.write_all(b"-->")?;
    Ok(true)
}

pub(super) fn instruction(
    pi: &BytesPI<'_>,
    out: &mut impl Write,
    sink: &mut dyn ChildSink,
) -> io::Result<bool> {
    let target = pi.target();
    let data = pi.content();
    if target.len() > 1024
        || !target.split_once(':').map_or_else(
            || ncname(target),
            |(prefix, local)| ncname(prefix) && ncname(local),
        )
        || target.eq_ignore_ascii_case("xml")
        || !valid_text(data, sink)?
    {
        return Ok(false);
    }
    out.write_all(b"<?")?;
    out.write_all(target.as_bytes())?;
    if !data.is_empty() {
        out.write_all(b" ")?;
        normalized_lines(
            out,
            data.trim_start_matches([' ', '\t', '\r', '\n']).as_bytes(),
            sink,
        )?;
    }
    out.write_all(b"?>")?;
    Ok(true)
}

#[derive(Default)]
pub(super) struct Cdata {
    len: usize,
    brackets: usize,
}

impl Cdata {
    pub(super) fn append(
        &mut self,
        text: &str,
        out: &mut impl Write,
        sink: &mut dyn ChildSink,
    ) -> io::Result<bool> {
        self.len = self.len.saturating_add(text.len());
        if self.len > MAX_NODE || !valid_text(text, sink)? {
            return Ok(false);
        }
        let bytes = text.as_bytes();
        // A terminator can only form across two source sections. Split the merged
        // section before its '>', as libxml2 does. No section grows the source.
        let leading = bytes.iter().take(2).take_while(|&&b| b == b']').count();
        let tail = if self.brackets + leading >= 2 && bytes.get(leading) == Some(&b'>') {
            out.write_all(&bytes[..leading])?;
            out.write_all(b"]]><![CDATA[")?;
            &bytes[leading..]
        } else {
            bytes
        };
        for part in tail.chunks(64 * 1024) {
            sink.check()?;
            out.write_all(part)?;
        }
        let trailing = bytes
            .iter()
            .rev()
            .take(2)
            .take_while(|&&b| b == b']')
            .count();
        self.brackets = if trailing == bytes.len() {
            (self.brackets + trailing).min(2)
        } else {
            trailing
        };
        Ok(true)
    }
}
