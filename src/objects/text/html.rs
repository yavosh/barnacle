mod data;
mod entities;
mod script;
mod value;
use super::{ChildSink, Handling, Target};
use std::io::{self, BufWriter, Seek, Write};
use tempfile::SpooledTempFile;

// Only the spellings recognized by the pinned stock magic database select target 3.
pub(super) fn recognizes(head: &[u8]) -> bool {
    const MAGIC: &[&[u8]] = &[
        b"<HTML>", b"<Html>", b"<html>", b"<HEAD>", b"<Head>", b"<head>", b"<IFRAME", b"<iframe",
        b"<IMG", b"<Img", b"<img", b"<OBJECT", b"<Object", b"<object", b"<SCRIPT", b"<Script",
        b"<script", b"<TABLE", b"<table",
    ];
    head.iter()
        .enumerate()
        .filter(|(_, b)| **b == b'<')
        .any(|(i, _)| {
            let tag = &head[i..];
            MAGIC.iter().any(|magic| tag.starts_with(magic))
                || ((tag.starts_with(b"<a ") || tag.starts_with(b"<A "))
                    && tag[3..].windows(4).any(|attr| {
                        attr[..2].eq_ignore_ascii_case(b"hr") && matches!(&attr[2..], b"ef" | b"EF")
                    }))
        })
}

struct View {
    out: BufWriter<SpooledTempFile>,
    limit: u64,
    count: u64,
    last_space: bool,
}

impl View {
    fn new(sink: &dyn ChildSink) -> Self {
        Self {
            out: BufWriter::new(tempfile::spooled_tempfile_in(
                64 * 1024,
                sink.temporary_directory(),
            )),
            limit: if sink.child_limit().is_none() {
                sink.remaining()
            } else {
                0
            },
            count: 0,
            last_space: false,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        let left = self.limit.saturating_sub(self.count);
        let keep = left.min(bytes.len() as u64) as usize;
        self.out.write_all(&bytes[..keep])?;
        self.count = self.count.saturating_add(bytes.len() as u64);
        if let Some(&b) = bytes.last() {
            self.last_space = b == b' ';
        }
        Ok(())
    }

    fn separate(&mut self) -> io::Result<()> {
        if !self.last_space {
            self.write(b" ")?;
        }
        Ok(())
    }

    fn submit(self, sink: &mut dyn ChildSink, name: &[u8], targets: &[Target]) -> io::Result<bool> {
        let mut file = self.out.into_inner().map_err(|e| e.into_error())?;
        for &target in targets {
            // Stock checks the normalized size before file count and recursion.
            if sink.skip_declared_size(self.count) || !sink.can_enter_child() {
                break;
            }
            file.rewind()?;
            if sink.child(&mut file, Some(target), Some(name))? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

// The reference retains the first 1024 URL bytes, including attribute quotes.
struct Url {
    bytes: [u8; 1024],
    len: usize,
}

impl Url {
    fn new(quoted: bool) -> Self {
        let mut url = Self {
            bytes: [0; 1024],
            len: 0,
        };
        if quoted {
            url.push(b"\"");
        }
        url
    }

    fn push(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(self.bytes.len() - self.len);
        self.bytes[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    fn submit(mut self, quoted: bool, text: &mut View) -> io::Result<()> {
        if quoted {
            self.push(b"\"");
        }
        let end = self.bytes[..self.len]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.len);
        let value = if quoted {
            self.bytes.get(1..end.saturating_sub(1)).unwrap_or_default()
        } else {
            &self.bytes[..end]
        };
        if !value.is_empty() {
            text.write(value)?;
            text.write(b" ")?;
        }
        Ok(())
    }
}

fn ws(bytes: &[u8]) -> &[u8] {
    bytes.trim_ascii_start()
}

fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.')
}

fn attribute_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t'..=b'\x0c')
}

// Pending high bytes belong to the document's attribute-value parser. They can
// resume in another tag, independently of intervening prose.
#[derive(Default)]
struct AttributeBytes {
    pending: [u8; 3],
    len: usize,
}

// Keep each quoted attribute within its tag and release it as soon as the tag ends.
fn tag<'a>(
    input: &'a [u8],
    full: &mut View,
    text: &mut View,
    urls: &mut data::DataUrls,
    attr_bytes: &mut AttributeBytes,
    chunks: &mut value::Blocks<'a>,
    sink: &mut dyn ChildSink,
) -> io::Result<Option<(usize, bool, bool)>> {
    let mut bytes = ws(&input[1..]);
    let close = bytes.starts_with(b"/");
    if close {
        bytes = &bytes[1..];
    }
    let len = bytes
        .iter()
        .take_while(|b| !b.is_ascii_whitespace() && **b != b'>')
        .count();
    if len == 0 {
        return Ok(None);
    }
    let name = &bytes[..len];
    let script = name.eq_ignore_ascii_case(b"script");
    full.write(if close { b"</" } else { b"<" })?;
    for &b in name {
        full.write(&[b.to_ascii_lowercase()])?;
    }
    bytes = &bytes[len..];
    text.separate()?;
    let mut attach_terminator = false;
    let mut after_data = false;
    let mut past_delimiter = false;
    let mut tag_check = bytes.len().saturating_sub(8192);
    loop {
        if bytes.len() <= tag_check {
            sink.check()?;
            tag_check = bytes.len().saturating_sub(8192);
        }
        let untrimmed = bytes;
        bytes = ws(bytes);
        if let Some(rest) = bytes.strip_prefix(b">") {
            full.write(b">")?;
            return Ok(Some((input.len() - rest.len(), script, close)));
        }
        if let [end, b'>', rest @ ..] = bytes
            && (*end == b'/' || (*end == b'?' && name.starts_with(b"?")))
        {
            if !after_data && (!attach_terminator || untrimmed.len() != bytes.len()) {
                full.write(b" ")?;
            }
            full.write(&[*end, b'>'])?;
            return Ok(Some((input.len() - rest.len(), false, close)));
        }
        let len = bytes
            .iter()
            .take(8193)
            .take_while(|&&b| name_byte(b) || (past_delimiter && matches!(b, b'<' | b'/')))
            .count();
        if close || len == 0 || len > 8192 {
            return Ok(None);
        }
        let attr = &bytes[..len];
        // Stock continues the previous attribute name after an inline data URL.
        let joined = after_data;
        after_data = false;
        if !joined {
            full.write(b" ")?;
        }
        for &b in attr {
            full.write(&[b.to_ascii_lowercase()])?;
        }
        bytes = &bytes[len..];
        let after_name = ws(bytes);
        if !after_name.starts_with(b"=") {
            attach_terminator = true;
            continue;
        }
        bytes = ws(&after_name[1..]);
        let Some(&first) = bytes.first() else {
            return Ok(None);
        };
        let quoted = matches!(first, b'"' | b'\'');
        if quoted {
            bytes = &bytes[1..];
        }
        let is_data = bytes.starts_with(b"data:");
        let delimiter = |b| {
            if quoted {
                b == first
            } else {
                attribute_space(b) || b == b'>'
            }
        };
        // Data URL locations refer to the unchanged source. Its payload is binary.
        let mut value = chunks.value(bytes, sink)?;
        let end = if is_data {
            let mut end = None;
            for (i, block) in bytes.chunks(8192).enumerate() {
                if i != 0 {
                    sink.check()?;
                }
                if let Some(n) = block.iter().position(|&b| delimiter(b)) {
                    end = Some(i * 8192 + n);
                    break;
                }
            }
            end
        } else {
            value.length(delimiter, sink)?
        };
        let Some(end) = end else { return Ok(None) };
        value.limit(end);
        bytes = &bytes[end + usize::from(quoted)..];
        let url = !joined
            && ((name.eq_ignore_ascii_case(b"a") && attr.eq_ignore_ascii_case(b"href"))
                || (name.eq_ignore_ascii_case(b"img") && attr.eq_ignore_ascii_case(b"src")));
        if is_data {
            if attr_bytes.len != 0 {
                return Ok(None);
            }
            after_data = true;
            urls.push(bytes.len() + usize::from(quoted), end)?;
            full.write(if quoted { b"=\"data\"" } else { b"=data" })?;
            if !quoted {
                // An unquoted data URL also consumes its delimiter.
                past_delimiter |= bytes[0] == b'>';
                bytes = &bytes[1..];
            }
            continue;
        }
        full.write(if quoted { b"=\"" } else { b"=" })?;
        let mut url = url.then(|| Url::new(quoted));
        if value.split_data(sink)? {
            // The data handler needs the scheme's original byte offsets.
            return Ok(None);
        }
        // Attribute values retain up to three high bytes until another ordinary
        // byte arrives. A reference can emit its spelling ahead of this group.
        let mut spaces = 0u8;
        let mut whitespace = false;
        while let Some(b) = value.next(sink)? {
            if attribute_space(b) {
                if whitespace {
                    continue;
                }
                whitespace = true;
                let markup = if spaces == 0 && b != b'\n' { b } else { b' ' };
                full.write(&[markup])?;
                if spaces < 2
                    && let Some(url) = &mut url
                {
                    url.push(&[if spaces == 0 { b' ' } else { 0 }]);
                }
                spaces = (spaces + 1).min(2);
                continue;
            }
            whitespace = false;
            // After the second run the URL ends. Stock copies subsequent text,
            // including character reference spellings, into the markup.
            if spaces == 2 {
                if b.is_ascii_control() || matches!(b, b'<' | b'>' | b'\'' | b'"') {
                    return Ok(None);
                }
                full.write(&[b.to_ascii_lowercase()])?;
                continue;
            }
            if b == b'&' {
                if !value.reference(full, url.as_mut(), sink)? {
                    return Ok(None);
                }
                continue;
            }
            if !b.is_ascii() && attr_bytes.len < attr_bytes.pending.len() {
                attr_bytes.pending[attr_bytes.len] = b;
                attr_bytes.len += 1;
                continue;
            }
            if attr_bytes.len != 0 {
                if matches!(b, b'<' | b'>' | b'\'' | b'"') {
                    return Ok(None);
                }
                let group = &attr_bytes.pending[..attr_bytes.len];
                let bytes = if is_dot(group) { b"." } else { group };
                full.write(bytes)?;
                if let Some(url) = &mut url {
                    url.push(bytes);
                }
                attr_bytes.len = 0;
                if !b.is_ascii() {
                    value.repeat_byte();
                    continue;
                }
            }
            if b.is_ascii_control() {
                return Ok(None);
            }
            full.write(&[b.to_ascii_lowercase()])?;
            if let Some(url) = &mut url {
                url.push(&[b]);
            }
        }
        *chunks = value.blocks;
        // Literal whitespace in a quoted value makes a directly following terminator
        // part of the same token. An entity that decodes to a space does not.
        attach_terminator = spaces > 0;
        if quoted {
            full.write(&[if spaces >= 2 { first } else { b'"' }])?;
        }
        if let Some(mut url) = url {
            if spaces == 1 && bytes.starts_with(b"/>") {
                // The slash follows the closing quote in the URL token.
                url.push(b"\"");
            }
            url.submit(quoted, text)?;
        }
    }
}

fn is_dot(group: &[u8]) -> bool {
    matches!(
        group,
        [0xe3, 0x80, 0x82] | [0xef, 0xbc, 0x8e] | [0xef, 0xb9, 0x92]
    )
}

pub(super) fn extract(
    bytes: &[u8],
    sink: &mut dyn ChildSink,
    input_size: usize,
    trim_blocks: bool,
) -> io::Result<Handling> {
    let (max_html, max_notags, _) = sink.text_limits();
    if input_size as u64 > max_html {
        return Ok(Handling::Complete);
    }
    let mut full = View::new(sink);
    let mut text = View::new(sink);
    let mut pending = false;
    let mut skip_space = true;
    let mut script = false;
    let mut javascript = View::new(sink);
    let mut urls = data::DataUrls::new(bytes.len(), sink);
    let mut attr_bytes = AttributeBytes::default();
    let mut chunks = value::Blocks::new(bytes, trim_blocks);
    let mut script_start = None;
    let mut unknown_script = false;
    let mut pos = 0;
    let mut next_check = 0;
    while pos < bytes.len() {
        if pos >= next_check {
            sink.check()?;
            next_check = pos.saturating_add(8192);
        }
        let tail = &bytes[pos..];
        let b = tail[0];
        if b == b'\r' {
            pos += 1;
            continue;
        }
        if b.is_ascii_whitespace() {
            if !script {
                pending = !skip_space;
                text.separate()?;
            }
            pos += 1;
            continue;
        }
        if pending {
            full.write(b" ")?;
            pending = false;
        }
        if b == b'<' {
            if tail.starts_with(b"<!--")
                || tail
                    .get(..9)
                    .is_some_and(|s| s.eq_ignore_ascii_case(b"<!doctype"))
            {
                if script {
                    return Ok(Handling::Incomplete);
                }
                let terminator: &[u8] = if tail.starts_with(b"<!--") {
                    b"-->"
                } else {
                    b">"
                };
                let Some(end) = tail.windows(terminator.len()).position(|w| w == terminator) else {
                    return Ok(Handling::Incomplete);
                };
                pos += end + terminator.len();
                text.separate()?;
            } else {
                let Some((used, is_script, close)) = tag(
                    tail,
                    &mut full,
                    &mut text,
                    &mut urls,
                    &mut attr_bytes,
                    &mut chunks,
                    sink,
                )?
                else {
                    return Ok(Handling::Incomplete);
                };
                if is_script {
                    script = !close;
                    if close {
                        if let Some(start) = script_start.take()
                            && !script::normalize(&bytes[start..pos], &mut javascript, sink)?
                        {
                            unknown_script = true;
                        }
                    } else if tail[..used].eq_ignore_ascii_case(b"<script>") {
                        script_start = Some(pos + used);
                    } else {
                        unknown_script = true;
                    }
                }
                pos += used;
            }
            skip_space = true;
            continue;
        }
        if !b.is_ascii() {
            let n = tail.iter().take(3).take_while(|b| !b.is_ascii()).count();
            let group = &tail[..n];
            // The HTML text extractor groups at most three high bytes. Its text
            // view ends each group with the preceding byte, or zero for a singleton.
            if is_dot(group) {
                full.write(b".")?;
                text.write(b".")?;
            } else {
                full.write(group)?;
                let space = text.last_space;
                text.write(&group[..n - 1])?;
                text.write(&[if n == 1 { 0 } else { group[n - 2] }])?;
                text.last_space = space;
            }
            skip_space = false;
            pos += n;
            continue;
        }
        if b == 0 {
            return Ok(Handling::Incomplete);
        }
        skip_space = false;
        if b == b'&' {
            let Some((reference, n)) = entities::parse(tail) else {
                return Ok(Handling::Incomplete);
            };
            if script && matches!(reference, entities::Reference::Literal(_)) {
                return Ok(Handling::Incomplete);
            }
            reference.write(&mut full, None)?;
            if !script {
                text.separate()?;
            }
            pos += n;
        } else {
            let c = if script && b == b'\'' {
                b'"'
            } else {
                b.to_ascii_lowercase()
            };
            full.write(&[c])?;
            if !script {
                if b < 0x20 {
                    text.separate()?;
                } else {
                    text.write(&[c])?;
                }
            }
            pos += 1;
        }
    }
    if full.submit(sink, b"nocomment.html", &[Target::Html])?
        || (input_size as u64 <= max_notags
            && text.submit(sink, b"notags.html", &[Target::Html])?)
    {
        return Ok(Handling::Stopped);
    }
    if unknown_script || script_start.is_some() {
        return Ok(Handling::Incomplete);
    }
    if javascript.count > 0
        && javascript.submit(sink, b"javascript", &[Target::Html, Target::Ascii])?
    {
        return Ok(Handling::Stopped);
    }
    urls.scan(bytes, sink)
}
