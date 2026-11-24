//! Stream legacy mail attachment data without creating files from attachment names.
use super::{ChildSink, Handling};
use std::io::{self, Read};

pub(super) fn file_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x78, 0x9f, 0x3e, 0x22]) {
        Some("CL_TYPE_TNEF")
    } else if bytes.starts_with(b"begin ") {
        Some("CL_TYPE_UUENCODED")
    } else {
        None
    }
}

struct Attribute<'a> {
    level: u8,
    tag: u16,
    value: &'a [u8],
}

// TNEF lengths exclude the nine-byte header and two-byte checksum.
fn attribute<'a>(rest: &mut &'a [u8]) -> Option<Attribute<'a>> {
    let head = rest.get(..9)?;
    let len = i32::from_le_bytes(head[5..9].try_into().ok()?);
    let end = 9usize.checked_add(usize::try_from(len).ok()?)?;
    let attr = Attribute {
        level: head[0],
        tag: u16::from_le_bytes([head[1], head[2]]),
        value: rest.get(9..end)?,
    };
    *rest = rest.get(end.checked_add(2)?..)?;
    Some(attr)
}

struct Attachment<'a> {
    attrs: &'a [u8],
    data: &'a [u8],
}

impl Read for Attachment<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        while self.data.is_empty() {
            let Some(attr) = attribute(&mut self.attrs) else {
                return Ok(0);
            };
            if attr.level == 2 && attr.tag == 0x800f {
                self.data = attr.value;
            }
        }
        self.data.read(buffer)
    }
}

pub(super) fn tnef(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(attrs) = bytes.get(6..) else {
        return Ok(Handling::Incomplete);
    };
    let mut rest = attrs;
    // Stock extracts the directory before scanning its contents.
    while !rest.is_empty() && !rest.starts_with(&[0]) && !matches!(rest, b"\n" | b"\r") {
        sink.check()?;
        let Some(attr) = attribute(&mut rest) else {
            return Ok(Handling::Incomplete);
        };
        if !matches!(attr.level, 1 | 2) {
            return Ok(Handling::Incomplete);
        }
    }
    let mut rest = &attrs[..attrs.len() - rest.len()];
    while !rest.is_empty() {
        let group = rest;
        let mut title = None;
        let mut has_data = false;
        while !rest.is_empty() {
            let attr = attribute(&mut rest).expect("validated TNEF attribute");
            sink.check()?;
            match (attr.level, attr.tag) {
                (2, 0x8010) if title.is_none() => {
                    title = attr.value.split(|&b| b == 0).next();
                    if title.is_some_and(|name| name.len() > 255) {
                        return Ok(Handling::Incomplete);
                    }
                }
                (2, 0x800f) => {
                    has_data |= !attr.value.is_empty();
                }
                _ => (),
            }
            if rest.starts_with(&[1]) {
                break;
            }
        }
        // The final attachment receives a default title when the sender omitted it.
        if title.is_none() && rest.is_empty() {
            title = Some(b"tnef");
        }
        if has_data && title.is_some() {
            let mut reader = Attachment {
                attrs: &group[..group.len() - rest.len()],
                data: &[],
            };
            if sink.child(&mut reader, None, title)? {
                return Ok(Handling::Stopped);
            }
        }
    }
    Ok(Handling::Complete)
}

fn row(input: &[u8]) -> (&[u8], &[u8]) {
    let (line, rest) = input
        .iter()
        .position(|&b| b == b'\n')
        .map_or((input, &[][..]), |n| (&input[..n], &input[n + 1..]));
    (line.strip_suffix(b"\r").unwrap_or(line), rest)
}

struct Uu<'a> {
    input: &'a [u8],
    decoded: [u8; 63],
    start: usize,
    len: usize,
}

fn uu_length(line: &[u8]) -> io::Result<usize> {
    if line.is_empty() || line.eq_ignore_ascii_case(b"end") {
        return Ok(0);
    }
    let len = usize::from(line[0].wrapping_sub(b' ') & 63);
    if len == 0 || len > 62 {
        return Ok(0);
    }
    let body = &line[1..];
    if body.len() < (len * 8).div_ceil(6) || !body.iter().all(|b| (32..=96).contains(b)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid uuencoded line",
        ));
    }
    Ok(len)
}

impl Read for Uu<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.start == self.len {
            let (line, next) = row(self.input);
            self.input = next;
            let len = uu_length(line)?;
            if len == 0 {
                return Ok(0);
            }
            // The line length byte names the decoded length, including any short final group.
            let body = &line[1..];
            let mut acc = 0u16;
            let mut bits = 0;
            let mut pos = 0;
            for &b in body {
                acc = (acc << 6) | u16::from(b.wrapping_sub(32) & 63);
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    self.decoded[pos] = (acc >> bits) as u8;
                    pos += 1;
                    if pos == len {
                        break;
                    }
                }
            }
            self.start = 0;
            self.len = len;
        }
        let n = output.len().min(self.len - self.start);
        output[..n].copy_from_slice(&self.decoded[self.start..self.start + n]);
        self.start += n;
        Ok(n)
    }
}

fn uu_reader(bytes: &[u8]) -> Option<(Uu<'_>, &[u8])> {
    let (head, input) = row(bytes);
    let mut fields = head.split(|&c| c == b' ').filter(|s| !s.is_empty());
    let (Some(b"begin"), Some(mode), Some(name)) = (fields.next(), fields.next(), fields.next())
    else {
        return None;
    };
    if mode.len() != 3 || !mode.iter().all(|b| (b'0'..=b'7').contains(b)) || name.len() > 255 {
        return None;
    }
    let reader = Uu {
        input,
        decoded: [0; 63],
        start: 0,
        len: 0,
    };
    Some((reader, name))
}

pub(super) fn uu(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some((mut reader, name)) = uu_reader(bytes) else {
        return Ok(Handling::Incomplete);
    };
    Ok(if sink.child(&mut reader, None, Some(name))? {
        Handling::Stopped
    } else {
        Handling::Complete
    })
}

pub(super) struct RecoveredNote<'a> {
    reader: Uu<'a>,
    size: u64,
    pub(super) tail: &'a [u8],
}

pub(super) fn recovered_note<'a>(
    bytes: &'a [u8],
    sink: &mut dyn ChildSink,
) -> io::Result<Option<RecoveredNote<'a>>> {
    let Some((reader, _)) = uu_reader(bytes) else {
        return Ok(None);
    };
    let mut size = 0;
    let mut lines = reader.input;
    let tail = loop {
        sink.check()?;
        let (line, rest) = row(lines);
        match uu_length(line) {
            Ok(0) => {
                if !matches!(line, b"`" | b" ") || row(rest).0 != b"end" {
                    return Ok(None);
                }
                break rest;
            }
            Ok(n) => size += n as u64,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => return Ok(None),
            Err(e) => return Err(e),
        }
        lines = rest;
    };
    Ok(Some(RecoveredNote { reader, size, tail }))
}

impl RecoveredNote<'_> {
    pub(super) fn can_enter(&self, sink: &dyn ChildSink) -> bool {
        self.size > 5 && sink.size_limit(self.size).is_none() && sink.child_limit().is_none()
    }

    pub(super) fn submit(mut self, sink: &mut dyn ChildSink) -> io::Result<Handling> {
        if self.size <= 5 || sink.skip_declared_size(self.size) {
            return Ok(Handling::Complete);
        }
        // Stock assigns a private temporary filename, not the name in the begin line.
        Ok(if sink.child(&mut self.reader, None, None)? {
            Handling::Stopped
        } else {
            Handling::Complete
        })
    }
}
