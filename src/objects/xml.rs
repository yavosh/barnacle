//! Word 2003 XML, SpreadsheetML and HWPML attachment streams.
mod charset;
use super::{ChildSink, Handling, Snapshot, text};
use flate2::{Decompress, FlushDecompress, Status};
use quick_xml::{
    Reader,
    events::{BytesStart, Event},
};
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    ops::Range,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Format {
    Word,
    Excel,
    Hwp,
}

const DECL: &[u8] = b"<?xml version=\"1.0\"";
const DEPTH: usize = 20;
const MAX_TEXT: usize = 10_000_000;
const MAX_ATTRIBUTES: usize = 1024;

impl Format {
    pub(super) fn recognize(bytes: &[u8]) -> Option<Self> {
        let header = &bytes[..bytes.len().min(1024)];
        if let Some(rest) = header
            .strip_prefix(b"\xef\xbb\xbf")
            .and_then(|s| s.strip_prefix(DECL))
        {
            return rest.windows(6).any(|s| s == b"<HWPML").then_some(Self::Hwp);
        }
        let rest = header.strip_prefix(DECL)?;
        let mut word = rest
            .windows(b"progid=\"Word.Document\"?>".len())
            .any(|s| s == b"progid=\"Word.Document\"?>");
        for (i, _) in rest.iter().enumerate().filter(|(_, b)| **b == b'<') {
            let mut tag = &rest[i + 1..];
            if tag.get(1) == Some(&b':') {
                tag = &tag[2..];
            }
            if tag.starts_with(b"Workbook") {
                return Some(Self::Excel);
            }
            word |= tag.starts_with(b"wordDocument");
        }
        word.then_some(Self::Word)
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Word => "CL_TYPE_XML_WORD",
            Self::Excel => "CL_TYPE_XML_XL",
            Self::Hwp => "CL_TYPE_XML_HWP",
        }
    }

    pub(super) fn extract(self, bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
        let bom = usize::from(bytes.starts_with(b"\xef\xbb\xbf")) * 3;
        let bytes = &bytes[bom..];
        let Some(charset) = charset::Charset::declaration(bytes) else {
            return Ok(Handling::Incomplete);
        };
        charset.with_utf8(bytes, sink, |data, sink, partial| {
            self.parse(data, sink, partial, charset, bom)
        })
    }

    fn parse(
        self,
        bytes: &[u8],
        sink: &mut dyn ChildSink,
        partial: bool,
        charset: charset::Charset,
        bom: usize,
    ) -> io::Result<Handling> {
        // The reader borrows text and keeps open element names for end-tag validation.
        let mut xml = Reader::from_reader(bytes);
        let mut levels = Vec::with_capacity(DEPTH);
        let mut ignored = 0usize;
        let mut start = None;
        let mut pending: VecDeque<PendingText> = VecDeque::new();
        let mut root_seen = false;
        loop {
            sink.check()?;
            let at = xml.buffer_position() as usize;
            if let Some(tag) = bytes[at..].strip_prefix(b"<")
                && tag.first().is_some_and(|b| !b"!?/".contains(b))
                && (levels.len() + ignored >= 256
                    || tag.get(..1025).is_some_and(|s| {
                        !s.iter()
                            .any(|b| b.is_ascii_whitespace() || b"/>".contains(b))
                    }))
            {
                return Ok(Handling::Incomplete);
            }
            let (event, error) = match xml.read_event() {
                Ok(event) => {
                    let in_element = !levels.is_empty() || ignored != 0;
                    let error = lexical_error(&event, in_element, sink)?.map(|offset| at + offset);
                    (event, error)
                }
                Err(quick_xml::Error::Encoding(quick_xml::encoding::EncodingError::Utf8(
                    error,
                ))) => (Event::Eof, Some(at + error.valid_up_to())),
                Err(_) => return Ok(Handling::Incomplete),
            };
            let end = xml.buffer_position() as usize;
            let eof = matches!(event, Event::Eof);
            let finished = eof
                && error.is_none()
                && (partial || root_seen && levels.is_empty() && ignored == 0);
            // The reference validates a complete 512-byte source block before exposing its
            // nodes. Transcoding may expand one source byte into three UTF-8 bytes.
            let through = if finished {
                usize::MAX
            } else if let Some(offset) = error
                && !pending.is_empty()
            {
                charset.earlier_block(&bytes[..offset], bom, sink)?
            } else {
                end.saturating_sub(3 * 512 + 4)
            };
            if let Some(last) = pending.back_mut()
                && last.tag_end == at
            {
                // A closing tag on the block edge may still be the reader's last node.
                // Its next sibling or parent end tag commits it on malformed input.
                last.ready = (end + 1).min(at.saturating_add(3 * 512 + 4));
            }
            while pending.front().is_some_and(|item| item.ready <= through) {
                let item = pending.pop_front().unwrap();
                if let Some(result) = scan_text(Some(item.content), &bytes[item.range], sink)? {
                    return Ok(result);
                }
            }
            if error.is_some() {
                return Ok(Handling::Incomplete);
            }
            if matches!(event, Event::Text(_) | Event::GeneralRef(_)) {
                if levels.is_empty()
                    && ignored == 0
                    && !event.as_bytes().iter().all(u8::is_ascii_whitespace)
                {
                    return Ok(Handling::Incomplete);
                }
                start.get_or_insert(at);
                continue;
            }
            if let Some(from) = start.take() {
                let content = if ignored == 0 {
                    levels.last().copied().flatten()
                } else {
                    None
                };
                if let Some(content) = content {
                    if !eof && (!partial || end < bytes.len()) {
                        pending.push_back(PendingText {
                            tag_end: end,
                            ready: usize::MAX,
                            content,
                            range: from..at,
                        });
                    }
                } else if let Some(result) = scan_text(None, &bytes[from..at], sink)? {
                    return Ok(result);
                }
            }
            if matches!(event, Event::Start(_) | Event::Empty(_))
                && levels.is_empty()
                && ignored == 0
            {
                if root_seen {
                    return Ok(Handling::Incomplete);
                }
                root_seen = true;
            }
            match event {
                Event::Start(ref e) if ignored != 0 || levels.len() == DEPTH || self.ignore(e) => {
                    ignored += 1;
                }
                Event::Start(e) => levels.push(self.content(&e)),
                Event::End(_) if ignored != 0 => ignored -= 1,
                Event::End(_) => {
                    levels.pop();
                }
                Event::DocType(_) => return Ok(Handling::Incomplete),
                Event::Eof => {
                    return Ok(if levels.is_empty() && ignored == 0 {
                        Handling::Complete
                    } else {
                        Handling::Incomplete
                    });
                }
                _ => {}
            }
        }
    }

    fn ignore(self, tag: &BytesStart) -> bool {
        let tags: &[&[u8]] = if self == Self::Hwp {
            &[
                b"body",
                b"facenamelist",
                b"borderfilllist",
                b"charshapelist",
                b"tabdeflist",
                b"numberinglist",
                b"parashapelist",
                b"stylelist",
                b"compatibledocument",
            ]
        } else {
            &[b"fonts", b"styles"]
        };
        tags.iter()
            .any(|n| tag.local_name().as_ref().as_bytes().eq_ignore_ascii_case(n))
    }

    fn content(self, tag: &BytesStart) -> Option<Content> {
        let name = tag.local_name();
        let binary = name.as_ref().as_bytes().eq_ignore_ascii_case(b"bindata");
        if self != Self::Hwp {
            return binary.then_some(Content {
                base64: true,
                deflate: false,
            });
        }
        if !binary
            && ![b"scriptheader".as_slice(), b"scriptsource"]
                .iter()
                .any(|n| name.as_ref().as_bytes().eq_ignore_ascii_case(n))
        {
            return None;
        }
        let mut content = Content {
            base64: false,
            deflate: false,
        };
        for attr in tag.attributes().with_checks(false).take(20) {
            let attr = attr.ok()?;
            match attr.key.local_name().as_ref().as_bytes() {
                b"Encoding" if attr.value.as_ref().as_bytes() == b"Base64" => content.base64 = true,
                b"Encoding" => {
                    return Some(Content {
                        base64: false,
                        deflate: false,
                    });
                }
                b"Compress" => content.deflate = attr.value.as_ref().as_bytes() != b"false",
                _ => {}
            }
        }
        Some(content)
    }
}

struct PendingText {
    tag_end: usize,
    ready: usize,
    content: Content,
    range: Range<usize>,
}

fn lexical_error(
    event: &Event<'_>,
    in_element: bool,
    sink: &mut dyn ChildSink,
) -> io::Result<Option<usize>> {
    // quick-xml checks UTF-8 and tag matching. XML 1.0 further restricts text characters
    // and the five predefined entities, including content outside an attachment.
    let text: &str = event;
    for (block, chunk) in text.as_bytes().chunks(64 * 1024).enumerate() {
        if block != 0 {
            sink.check()?;
        }
        if let Some(pos) = chunk
            .iter()
            .position(|&b| b < 0x20 && !matches!(b, 9 | 10 | 13))
        {
            return Ok(Some(block * 64 * 1024 + pos));
        }
    }
    if text.as_bytes().contains(&0xef)
        && let Some(pos) = text.find(['\u{fffe}', '\u{ffff}'])
    {
        return Ok(Some(pos));
    }
    match event {
        // In element text an ampersand can start a valid reference. The parser
        // must read the following byte before rejecting it, possibly in a new block.
        Event::GeneralRef(reference) if entity(reference).is_none() => {
            return Ok(Some(usize::from(in_element)));
        }
        Event::Start(element) | Event::Empty(element) => {
            for (index, attribute) in element.attributes().enumerate() {
                if index == MAX_ATTRIBUTES {
                    return Ok(Some(0));
                }
                let Ok(attribute) = attribute else {
                    return Ok(Some(0));
                };
                let value = attribute.value.as_ref();
                if value.contains('<')
                    || value.split('&').skip(1).any(|tail| {
                        tail.split_once(';')
                            .and_then(|(key, _)| entity(key))
                            .is_none()
                    })
                {
                    return Ok(Some(0));
                }
            }
        }
        Event::Text(text) if text.contains("]]>") => return Ok(Some(0)),
        _ => {}
    }
    Ok(None)
}

#[derive(Clone, Copy)]
struct Content {
    base64: bool,
    deflate: bool,
}

fn scan_text(
    content: Option<Content>,
    bytes: &[u8],
    sink: &mut dyn ChildSink,
) -> io::Result<Option<Handling>> {
    if content.is_none() && bytes.len() <= MAX_TEXT {
        return Ok(None);
    }
    let scan = |value: &[u8], sink: &mut dyn ChildSink| {
        if value.len() > MAX_TEXT {
            return Ok(Some(Handling::Complete));
        }
        let Some(content) = content else {
            return Ok(None);
        };
        if value.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        let result = scan_value(content, value, sink)?;
        Ok((result != Handling::Complete).then_some(result))
    };
    if !bytes.iter().any(|&b| matches!(b, b'\r' | b'&')) {
        return scan(bytes, sink);
    }
    // Normalize XML line endings and character references before decoding the attachment.
    let mut temp = Snapshot::new(sink.temporary_directory());
    let mut rest = bytes;
    while let Some(at) = rest.iter().position(|&b| matches!(b, b'\r' | b'&')) {
        sink.check()?;
        temp.write_all(&rest[..at])?;
        rest = &rest[at..];
        if rest[0] == b'\r' {
            temp.write_all(b"\n")?;
            rest = rest[1..].strip_prefix(b"\n").unwrap_or(&rest[1..]);
        } else {
            let Some(end) = rest.iter().take(16).position(|b| *b == b';') else {
                return Ok(Some(Handling::Incomplete));
            };
            let Some(value) = std::str::from_utf8(&rest[1..end]).ok().and_then(entity) else {
                return Ok(Some(Handling::Incomplete));
            };
            temp.write_all(value.encode_utf8(&mut [0; 4]).as_bytes())?;
            rest = &rest[end + 1..];
        }
    }
    temp.write_all(rest)?;
    temp.with_bytes(|value| scan(value, sink))
}

pub(super) fn entity(key: &str) -> Option<char> {
    match key {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => if let Some(hex) = key.strip_prefix("#x") {
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit())
                .then(|| u32::from_str_radix(hex, 16).ok())
                .flatten()
        } else {
            let digits = key.strip_prefix('#')?;
            digits
                .bytes()
                .all(|b| b.is_ascii_digit())
                .then(|| digits.parse().ok())
                .flatten()
        }
        .and_then(char::from_u32)
        .filter(|c| {
            matches!(c, '\t' | '\n' | '\r') || *c >= ' ' && !matches!(c, '\u{fffe}' | '\u{ffff}')
        }),
    }
}

fn scan_value(content: Content, bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let mut raw = bytes;
    let mut decoded;
    let input: &mut dyn Read = if content.base64 {
        // The reference uses the OpenSSL MIME reader. A newline starts decoding.
        let Some(data) = mime_lines(bytes) else {
            return Ok(Handling::Complete);
        };
        if !text::valid_base64(data, sink)? {
            return Ok(Handling::Incomplete);
        }
        decoded = text::base64_reader(data);
        &mut decoded
    } else {
        &mut raw
    };
    let stop = if content.deflate {
        scan_deflated(input, sink)?
    } else if content.base64 {
        let mut first = [0; 6];
        match input.read_exact(&mut first) {
            Ok(()) => sink.child(&mut first.as_slice().chain(input), None, None)?,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => false,
            Err(e) => return Err(e),
        }
    } else if bytes.len() <= 5 {
        false
    } else {
        sink.child_bytes(bytes, None)?
    };
    Ok(if stop {
        Handling::Stopped
    } else {
        Handling::Complete
    })
}

pub(super) fn scan_deflated(input: &mut dyn Read, sink: &mut dyn ChildSink) -> io::Result<bool> {
    let (file, _) = inflate_hwp(input, sink)?;
    file.with_bytes(|bytes| {
        if bytes.len() > 5 {
            sink.child_bytes(bytes, None)
        } else {
            Ok(false)
        }
    })
}

// The boolean tells HWP3 whether to parse decompressed records or scan the partial output directly.
pub(super) fn inflate_hwp(
    input: &mut dyn Read,
    sink: &mut dyn ChildSink,
) -> io::Result<(Snapshot, bool)> {
    let mut partial = false;
    // The pinned HWP reader checks limits after each 8192-byte input or output block.
    // On reaching a limit it still scans the preceding complete output blocks.
    let mut source = [0; 8192];
    let mut output = [0; 8192];
    let mut file = Snapshot::new(sink.temporary_directory());
    let mut inflater = Decompress::new(false);
    let mut pending: &[u8] = &[];
    let mut size = 0;
    loop {
        sink.check()?;
        if pending.is_empty() {
            let n = input.read(&mut source)?;
            if n == 0 {
                break;
            }
            pending = &source[..n];
        }
        let (before, after) = (inflater.total_in(), inflater.total_out());
        let status = inflater.decompress(pending, &mut output, FlushDecompress::Sync);
        let read = (inflater.total_in() - before) as usize;
        let written = (inflater.total_out() - after) as usize;
        if sink.skip_declared_size(size + written as u64) {
            partial = true;
            break;
        }
        file.write_all(&output[..written])?;
        size += written as u64;
        pending = &pending[read..];
        partial = status.is_err();
        if status.is_err() || matches!(status, Ok(Status::StreamEnd)) || (read == 0 && written == 0)
        {
            break;
        }
    }
    Ok((file, partial))
}

fn mime_lines(mut data: &[u8]) -> Option<&[u8]> {
    while let Some(end) = data.iter().position(|b| *b == b'\n') {
        let line = &data[..end];
        if end < 1024
            && line.iter().all(|&c| {
                c.is_ascii_alphanumeric() || c.is_ascii_whitespace() || b"+/=".contains(&c)
            })
        {
            return Some(data);
        }
        data = &data[end + 1..];
    }
    None
}
