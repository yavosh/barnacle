//! Serialize each top-level subtree with the namespace bindings that it uses.
mod attribute;
mod markup;
use super::{ChildSink, Handling, MAX_DEPTH, MAX_TOC, Snapshot};
use quick_xml::{
    Reader,
    events::{BytesStart, Event},
};
use std::io::{self, Seek, SeekFrom, Write};

// Bound namespace state independently of the size of the catalogue.
const MAX_BINDINGS: usize = 256;
const MAX_ATTRIBUTES: usize = 256;
const XML_URI: &str = "http://www.w3.org/XML/1998/namespace";

struct Binding {
    prefix: String,
    uri: String,
    depth: usize,
}

#[derive(Default)]
pub(super) struct Namespaces {
    bindings: Vec<Binding>,
    pub(super) encoding: attribute::Encoding,
}

fn declaration(key: &str) -> Option<&str> {
    if key == "xmlns" {
        Some("")
    } else {
        key.strip_prefix("xmlns:")
    }
}

fn plain_value(value: &str) -> bool {
    !value
        .bytes()
        .any(|b| b < b' ' || matches!(b, b'&' | b'<' | b'>' | b'"'))
}

fn ncname(name: &str) -> bool {
    if let Some((&first, rest)) = name.as_bytes().split_first()
        && first.is_ascii_alphabetic()
        && rest.iter().all(u8::is_ascii_alphanumeric)
    {
        return true;
    }
    // XML 1.0 NameStartChar and NameChar, excluding the namespace separator.
    let start = |c: char| {
        matches!(
            c,
            'A'..='Z' | '_' | 'a'..='z'
                | '\u{c0}'..='\u{d6}' | '\u{d8}'..='\u{f6}' | '\u{f8}'..='\u{2ff}'
                | '\u{370}'..='\u{37d}' | '\u{37f}'..='\u{1fff}' | '\u{200c}'..='\u{200d}'
                | '\u{2070}'..='\u{218f}' | '\u{2c00}'..='\u{2fef}' | '\u{3001}'..='\u{d7ff}'
                | '\u{f900}'..='\u{fdcf}' | '\u{fdf0}'..='\u{fffd}' | '\u{10000}'..='\u{effff}'
        )
    };
    let mut chars = name.chars();
    chars.next().is_some_and(start)
        && chars.all(|c| {
            start(c) || matches!(c, '-' | '.' | '0'..='9' | '\u{b7}' | '\u{300}'..='\u{36f}' | '\u{203f}'..='\u{2040}')
        })
}

impl Namespaces {
    pub(super) fn enter(&mut self, tag: &BytesStart<'_>, depth: usize) -> bool {
        if tag.name().as_ref().len() > 1024 {
            return false;
        }
        if !tag.attributes_raw().contains("xmlns") {
            return true;
        }
        for (i, attr) in tag.attributes().enumerate() {
            let Ok(attr) = attr else { return false };
            if i == MAX_ATTRIBUTES || attr.key.as_ref().len() > 1024 {
                return false;
            }
            let Some(prefix) = declaration(attr.key.as_ref()) else {
                continue;
            };
            let uri = attr.value.as_ref();
            if attr.key.as_ref() == "xmlns:"
                || self.bindings.len() == MAX_BINDINGS
                || prefix.len() > 256
                || uri.len() > 2048
                || (!prefix.is_empty() && (!ncname(prefix) || uri.is_empty()))
                || uri.bytes().any(|b| b.is_ascii_whitespace())
                || !plain_value(uri)
                || matches!(prefix, "xml" | "xmlns")
                || matches!(uri, XML_URI | "http://www.w3.org/2000/xmlns/")
            {
                return false;
            }
            self.bindings.push(Binding {
                prefix: prefix.into(),
                uri: uri.into(),
                depth,
            });
        }
        true
    }

    pub(super) fn leave(&mut self, depth: usize) {
        while self.bindings.last().is_some_and(|b| b.depth >= depth) {
            self.bindings.pop();
        }
    }

    // Attribute names without a prefix have no namespace, even under a default binding.
    fn resolve<'a>(
        &'a self,
        name: &'a str,
        attribute: bool,
        inherited: usize,
        used: &mut Vec<usize>,
    ) -> Option<(&'a str, &'a str)> {
        if name.len() > 1024 {
            return None;
        }
        let (prefix, local) = name.split_once(':').unwrap_or(("", name));
        if !ncname(local) || (!prefix.is_empty() && !ncname(prefix)) || name.starts_with(':') {
            return None;
        }
        if prefix == "xml" {
            return Some((XML_URI, local));
        }
        if prefix.is_empty() && attribute {
            return Some(("", local));
        }
        let Some(n) = self.bindings.iter().rposition(|b| b.prefix == prefix) else {
            return prefix.is_empty().then_some(("", local));
        };
        if n < inherited && !self.bindings[n].uri.is_empty() && !used.contains(&n) {
            used.push(n);
        }
        Some((&self.bindings[n].uri, local))
    }

    // The XML reader rejects repeated lexical attribute names. Two different
    // prefixes may also resolve to the same attribute, which XML forbids.
    fn attributes(
        &self,
        tag: &BytesStart<'_>,
        inherited: usize,
        used: &mut Vec<usize>,
        out: &mut impl Write,
        sink: &mut dyn ChildSink,
    ) -> io::Result<bool> {
        if self
            .resolve(tag.name().as_ref(), false, inherited, used)
            .is_none()
        {
            return Ok(false);
        }
        let raw = tag.attributes_raw();
        if raw.is_empty() {
            return Ok(true);
        }
        // A single ordinary attribute in canonical spelling can be copied as a slice.
        // A second attribute introduces a quote inside value and takes the general path.
        if let Some((key, quoted)) = raw.strip_prefix(' ').and_then(|s| s.split_once('='))
            && let Some(value) = quoted.strip_prefix('"').and_then(|s| s.strip_suffix('"'))
            && key.len() <= 1024
            && key != "xmlns"
            && ncname(key)
            && attribute::plain(value)
        {
            out.write_all(raw.as_bytes())?;
            return Ok(true);
        }
        let mut first_qualified = None;
        let mut others = std::collections::HashSet::new();
        for (i, attr) in tag.attributes().enumerate() {
            let Ok(attr) = attr else { return Ok(false) };
            if i >= MAX_ATTRIBUTES {
                return Ok(false);
            }
            let key = attr.key.into_inner();
            if declaration(key).is_some() {
                continue;
            }
            let Some((uri, local)) = self.resolve(key, true, inherited, used) else {
                return Ok(false);
            };
            if !uri.is_empty() {
                if let Some(first) = first_qualified {
                    if first == (uri, local) || !others.insert((uri, local)) {
                        return Ok(false);
                    }
                } else {
                    first_qualified = Some((uri, local))
                }
            }
            out.write_all(b" ")?;
            out.write_all(key.as_bytes())?;
            out.write_all(b"=\"")?;
            if !self.encoding.write(&attr.value, out, sink)? {
                return Ok(false);
            }
            out.write_all(b"\"")?;
        }
        Ok(true)
    }
}

// Look ahead once within this subtree. Bindings declared in ancestors are copied
// onto its root in first-use order, after the root's own declarations.
fn inherited(
    reader: &Reader<&[u8]>,
    root: &BytesStart<'_>,
    empty: bool,
    scope: &mut Namespaces,
    level: usize,
    sink: &mut dyn ChildSink,
) -> io::Result<Option<Vec<usize>>> {
    let boundary = scope.bindings.len();
    let mut used = Vec::new();
    if !scope.enter(root, level)
        || !scope.attributes(root, boundary, &mut used, &mut io::sink(), sink)?
    {
        return Ok(None);
    }
    if !empty {
        let mut ahead = reader.clone();
        let mut depth = level;
        loop {
            sink.check()?;
            let Ok(event) = ahead.read_event() else {
                return Ok(None);
            };
            match event {
                Event::Start(ref tag) | Event::Empty(ref tag) => {
                    if depth >= MAX_DEPTH
                        || !scope.enter(tag, depth + 1)
                        || !scope.attributes(tag, boundary, &mut used, &mut io::sink(), sink)?
                    {
                        return Ok(None);
                    }
                    if matches!(event, Event::Empty(_)) {
                        scope.leave(depth + 1)
                    } else {
                        depth += 1
                    }
                }
                Event::End(_) if depth == level => break,
                Event::End(_) => {
                    scope.leave(depth);
                    depth -= 1;
                }
                Event::Eof | Event::DocType(_) => return Ok(None),
                _ => {}
            }
        }
    }
    scope.leave(level);
    Ok(Some(used))
}

fn binding(out: &mut impl Write, b: &Binding) -> io::Result<()> {
    out.write_all(b" xmlns")?;
    if !b.prefix.is_empty() {
        out.write_all(b":")?;
        out.write_all(b.prefix.as_bytes())?;
    }
    out.write_all(b"=\"")?;
    out.write_all(b.uri.as_bytes())?;
    out.write_all(b"\"")
}

fn serialize(
    reader: &mut Reader<&[u8]>,
    scope: &mut Namespaces,
    base: usize,
    out: &mut impl Write,
    sink: &mut dyn ChildSink,
) -> io::Result<bool> {
    let mut depth = base;
    let mut open = false;
    let mut cdata = None;
    loop {
        sink.check()?;
        let Ok(event) = reader.read_event() else {
            return Ok(false);
        };
        if !matches!(event, Event::CData(_)) && cdata.take().is_some() {
            out.write_all(b"]]>")?;
        }
        if let Event::End(ref end) = event
            && depth == base
        {
            return Ok(end.local_name().as_ref() == "subdoc");
        }
        if open && !matches!(event, Event::End(_)) {
            out.write_all(b">")?;
            open = false;
        }
        match event {
            Event::Start(ref tag) | Event::Empty(ref tag) => {
                let empty = matches!(event, Event::Empty(_));
                if depth >= MAX_DEPTH {
                    return Ok(false);
                }
                let extra = if depth == base && !scope.bindings.is_empty() {
                    let Some(extra) = inherited(reader, tag, empty, scope, depth + 1, sink)? else {
                        return Ok(false);
                    };
                    extra
                } else {
                    Vec::new()
                };
                let local = scope.bindings.len();
                if !scope.enter(tag, depth + 1) {
                    return Ok(false);
                }
                out.write_all(b"<")?;
                out.write_all(tag.name().as_ref().as_bytes())?;
                for b in &scope.bindings[local..] {
                    binding(out, b)?
                }
                for n in extra {
                    binding(out, &scope.bindings[n])?
                }
                if !scope.attributes(tag, 0, &mut Vec::new(), out, sink)? {
                    return Ok(false);
                }
                if empty {
                    out.write_all(b"/>")?;
                    scope.leave(depth + 1);
                } else {
                    open = true;
                    depth += 1
                }
            }
            Event::End(tag) => {
                scope.leave(depth);
                depth -= 1;
                if open {
                    out.write_all(b"/>")?;
                    open = false;
                } else {
                    out.write_all(b"</")?;
                    out.write_all(tag.name().as_ref().as_bytes())?;
                    out.write_all(b">")?;
                }
            }
            Event::Text(text)
                if !text
                    .as_bytes()
                    .iter()
                    .any(|&b| (b < 32 && b != 9 && b != 10) || b == b'>')
                    && (!text.as_bytes().contains(&0xef)
                        || !text.contains(['\u{fffe}', '\u{ffff}'])) =>
            {
                out.write_all(text.as_bytes())?
            }
            Event::GeneralRef(name) if name.len() <= 30 => {
                match crate::objects::xml::entity(&name) {
                    Some('&') => out.write_all(b"&amp;")?,
                    Some('<') => out.write_all(b"&lt;")?,
                    Some('>') => out.write_all(b"&gt;")?,
                    Some('\r') => out.write_all(b"&#13;")?,
                    Some(ch) => out.write_all(ch.encode_utf8(&mut [0; 4]).as_bytes())?,
                    None => return Ok(false),
                }
            }
            Event::CData(text) => {
                if cdata.is_none() {
                    out.write_all(b"<![CDATA[")?;
                }
                if !cdata
                    .get_or_insert_with(markup::Cdata::default)
                    .append(&text, out, sink)?
                {
                    return Ok(false);
                }
            }
            Event::Comment(text) if markup::comment(&text, out, sink)? => {}
            Event::PI(pi) if markup::instruction(&pi, out, sink)? => {}
            _ => return Ok(false),
        }
    }
}

// Count before creating scratch. Inherited bindings can make the output larger than its input.
struct Preview {
    size: u64,
    limit: u64,
    bytes: Option<Vec<u8>>,
}
impl Write for Preview {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.size = self.size.saturating_add(data.len() as u64);
        if self.size > self.limit {
            self.bytes = None
        } else if let Some(bytes) = &mut self.bytes {
            bytes.extend_from_slice(data);
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn scan(
    reader: &mut Reader<&[u8]>,
    scope: &mut Namespaces,
    depth: usize,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    // Without inherited bindings, the largest expansion is a literal quote to `&quot;`.
    // Other attributes, markup, and XML names also fit within this bound.
    let upper = (reader.get_ref().len() as u64).saturating_mul(6);
    if scope.bindings.is_empty()
        && sink.child_limit().is_none()
        && upper <= sink.remaining().min(MAX_TOC)
    {
        return spool(reader, scope, depth, sink);
    }
    let mut replay = reader.clone();
    let mut preview = Preview {
        size: 0,
        limit: sink.remaining().min(64 * 1024),
        bytes: sink.child_limit().is_none().then(Vec::new),
    };
    if !serialize(reader, scope, depth, &mut preview, sink)? {
        return Ok(Handling::Incomplete);
    }
    if sink.skip_declared_size(preview.size) || !sink.can_enter_child() {
        return Ok(Handling::Complete);
    }
    if let Some(bytes) = preview.bytes {
        return Ok(if sink.child_bytes(&bytes, None)? {
            Handling::Stopped
        } else {
            Handling::Complete
        });
    }
    if preview.size > MAX_TOC {
        return Ok(Handling::Incomplete);
    }
    spool(&mut replay, scope, depth, sink)
}

// Retain the borrowed source prefix as long as the serialized bytes match it.
// On the first difference, leave its space in the spool and append normally.
struct XmlOutput<'a> {
    source: &'a [u8],
    prefix: usize,
    changed: bool,
    spool: Snapshot,
}

impl Write for XmlOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.changed {
            if self.source[self.prefix..].starts_with(bytes) {
                self.prefix += bytes.len();
                return Ok(bytes.len());
            }
            self.spool.seek(SeekFrom::Start(self.prefix as u64))?;
            self.changed = true;
        }
        self.spool.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.spool.flush()
    }
}

fn spool(
    reader: &mut Reader<&[u8]>,
    scope: &mut Namespaces,
    depth: usize,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let mut output = XmlOutput {
        source: reader.get_ref(),
        prefix: 0,
        changed: false,
        spool: Snapshot::new(sink.temporary_directory()),
    };
    {
        let mut out = io::BufWriter::new(&mut output);
        if !serialize(reader, scope, depth, &mut out, sink)? {
            return Ok(Handling::Incomplete);
        }
        out.flush()?;
    }
    let prefix = &output.source[..output.prefix];
    if !output.changed {
        return Ok(if sink.child_bytes(prefix, None)? {
            Handling::Stopped
        } else {
            Handling::Complete
        });
    }
    if !prefix.is_empty() {
        output.spool.rewind()?;
        for chunk in prefix.chunks(64 * 1024) {
            sink.check()?;
            output.spool.write_all(chunk)?;
        }
    }
    output.spool.with_bytes(|b| {
        Ok(if sink.child_bytes(b, None)? {
            Handling::Stopped
        } else {
            Handling::Complete
        })
    })
}
