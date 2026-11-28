//! Scan PDF streams after the raw PDF matcher, in physical indirect-object order.
use super::{ChildSink, Handling, Limit, ObjectBytes, Snapshot};
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};

mod destination;
mod filters;
mod object_stream;
mod security;
use filters::{Filter, Output};

type Id = (usize, usize);
const MAX_OBJECTS: usize = 65_536;
const MAX_FILTERS: usize = 64;

#[derive(Clone)]
struct Tokens<'a> {
    data: &'a [u8],
    pos: usize,
}

fn white(b: u8) -> bool {
    b == 0 || b.is_ascii_whitespace()
}

fn delimiter(b: u8) -> bool {
    white(b) || b"()<>[]{}/%".contains(&b)
}

// Each chunk is borrowed from the PDF. Check within long tokens as well as
// between tokens, including skipped comments and nested literal strings.
const TOKEN_BLOCK: usize = 64 * 1024;

#[derive(Default)]
struct TokenBudget(usize);

impl TokenBudget {
    fn charge(
        &mut self,
        bytes: usize,
        check: &mut (impl FnMut() -> io::Result<()> + ?Sized),
    ) -> io::Result<()> {
        self.0 += bytes;
        if self.0 >= TOKEN_BLOCK {
            self.0 -= TOKEN_BLOCK;
            check()?;
        }
        Ok(())
    }
}

impl<'a> Tokens<'a> {
    fn skip_while(
        &mut self,
        mut predicate: impl FnMut(u8) -> bool,
        charge: &mut impl FnMut(usize) -> io::Result<()>,
    ) -> io::Result<()> {
        for chunk in self.data[self.pos..].chunks(TOKEN_BLOCK) {
            let n = chunk
                .iter()
                .position(|&b| !predicate(b))
                .unwrap_or(chunk.len());
            self.pos += n;
            charge(n)?;
            if n != chunk.len() {
                break;
            }
        }
        Ok(())
    }

    fn next_with(
        &mut self,
        charge: &mut impl FnMut(usize) -> io::Result<()>,
    ) -> io::Result<Option<&'a [u8]>> {
        while let Some(&b) = self.data.get(self.pos) {
            if b == b'%' {
                self.skip_while(|c| !matches!(c, b'\n' | b'\r'), charge)?;
            } else if white(b) {
                self.skip_while(white, charge)?;
            } else {
                break;
            }
        }
        let at = self.pos;
        let Some(&b) = self.data.get(at) else {
            return Ok(None);
        };
        self.pos += 1;
        charge(1)?;
        match b {
            b'(' => {
                let mut depth = 1usize;
                let mut escaped_at = None;
                'literal: for chunk in self.data[self.pos..].chunks(TOKEN_BLOCK) {
                    for i in memchr::memchr3_iter(b'(', b')', b'\\', chunk) {
                        let at = self.pos + i;
                        if escaped_at == Some(at) {
                            continue;
                        }
                        match chunk[i] {
                            b'\\' => escaped_at = Some(at + 1),
                            b'(' => depth += 1,
                            _ => {
                                depth -= 1;
                                if depth == 0 {
                                    self.pos = at + 1;
                                    charge(i + 1)?;
                                    break 'literal;
                                }
                            }
                        }
                    }
                    self.pos += chunk.len();
                    charge(chunk.len())?;
                }
            }
            b'<' | b'>' if self.data.get(self.pos) == Some(&b) => self.pos += 1,
            b'<' => {
                self.skip_while(|c| c != b'>', charge)?;
                self.pos += usize::from(self.pos < self.data.len());
            }
            b'>' | b'[' | b']' | b'{' | b'}' | b')' => (),
            _ => self.skip_while(|c| !delimiter(c), charge)?,
        }
        Ok(Some(&self.data[at..self.pos]))
    }

    fn next(&mut self) -> Option<&'a [u8]> {
        self.next_with(&mut |_| Ok(()))
            .expect("unchecked PDF token")
    }

    fn next_checked(
        &mut self,
        budget: &mut TokenBudget,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Option<&'a [u8]>> {
        self.next_with(&mut |n| budget.charge(n, &mut || sink.check()))
    }

    fn integer_checked(
        &mut self,
        budget: &mut TokenBudget,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Option<usize>> {
        let Some(token) = self.next_checked(budget, sink)? else {
            return Ok(None);
        };
        number_with(token, &mut |n| budget.charge(n, &mut || sink.check()))
    }

    fn reference_checked(
        &self,
        budget: &mut TokenBudget,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Option<Id>> {
        let mut copy = self.clone();
        let Some(id) = copy.integer_checked(budget, sink)? else {
            return Ok(None);
        };
        let Some(generation) = copy.integer_checked(budget, sink)? else {
            return Ok(None);
        };
        Ok((copy.next_checked(budget, sink)? == Some(b"R")).then_some((id, generation)))
    }

    fn reference(&self) -> Option<Id> {
        let mut input = self.clone();
        let id = (number(input.next()?)?, number(input.next()?)?);
        (input.next()? == b"R").then_some(id)
    }

    fn skip_value(&mut self) -> bool {
        let Some(token) = self.next() else {
            return false;
        };
        let mut depth = usize::from(matches!(token, b"[" | b"<<"));
        while depth != 0 {
            match self.next() {
                Some(b"[" | b"<<") => depth += 1,
                Some(b"]" | b">>") => depth -= 1,
                Some(_) => (),
                None => return false,
            }
        }
        true
    }
}

fn number_with(
    token: &[u8],
    charge: &mut impl FnMut(usize) -> io::Result<()>,
) -> io::Result<Option<usize>> {
    if !token.first().is_some_and(u8::is_ascii_digit) {
        return Ok(None);
    }
    let mut value = 0usize;
    for chunk in token.chunks(TOKEN_BLOCK) {
        charge(chunk.len())?;
        for &b in chunk {
            if !b.is_ascii_digit() {
                return Ok(None);
            }
            let Some(n) = value
                .checked_mul(10)
                .and_then(|n| n.checked_add((b - b'0') as usize))
            else {
                return Ok(None);
            };
            value = n;
        }
    }
    Ok(Some(value))
}

fn number(token: &[u8]) -> Option<usize> {
    number_with(token, &mut |_| Ok(())).expect("unchecked PDF integer")
}

#[derive(Default)]
struct Object<'a> {
    id: Id,
    start: usize,
    length: Option<usize>,
    length_ref: Option<Id>,
    raw_destination: bool,
    encoded: Option<&'a [u8]>,
    filters: Vec<Filter>,
    image: bool,
    embedded: bool,
    metadata: bool,
    object_stream: bool,
    xref: bool,
    directory: Option<object_stream::Directory>,
    unsupported: bool,
}

struct Pdf<'a> {
    objects: Vec<Object<'a>>,
    count: usize,
    lengths: HashMap<Id, usize>,
    contents: HashSet<Id>,
    security: Option<security::Security>,
    /// Stock reads a locked document's streams without decrypting them.
    locked: bool,
}

fn stream_start(input: &mut Tokens<'_>) -> Option<usize> {
    while matches!(input.data.get(input.pos), Some(b' ' | b'\t')) {
        input.pos += 1;
    }
    match input.data.get(input.pos..)? {
        [b'\r', b'\n', ..] => Some(input.pos + 2),
        [b'\n' | b'\r', ..] => Some(input.pos + 1),
        _ => None,
    }
}

fn read_stream<'a>(
    input: &mut Tokens<'a>,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<Option<&'a [u8]>> {
    let Some(start) = stream_start(input) else {
        return Ok(None);
    };
    let rest = &input.data[start..];
    let marker = b"endstream";
    let finder = memchr::memmem::Finder::new(marker);
    for at in (0..rest.len()).step_by(TOKEN_BLOCK) {
        check()?;
        let end = rest
            .len()
            .min(at.saturating_add(TOKEN_BLOCK + marker.len() - 1));
        if let Some(offset) = finder.find(&rest[at..end]) {
            let position = at + offset;
            input.pos = start + position + marker.len();
            return Ok(Some(&rest[..position]));
        }
    }
    Ok(None)
}

// Stock reads every `/` in a dictionary through a small name state machine.
// `/EmbeddedFile` sets its flag only in the idle state. `/Filter` keeps the
// filter state until `/Length` or `/Crypt`, so a later type name is ignored.
fn embedded_flag(dict: &[u8]) -> bool {
    #[derive(PartialEq)]
    enum State {
        Idle,
        S,
        Filter,
        Launch,
    }
    const IDLE_NAMES: &[&[u8]] = &[
        b"EmbeddedFile",
        b"Image",
        b"Type",
        b"Page",
        b"Author",
        b"Producer",
        b"CreationDate",
        b"ModDate",
        b"Creator",
        b"Title",
        b"Keywords",
        b"Subject",
        b"Pages",
        b"Colors",
        b"RichMedia",
        b"AcroForm",
        b"XFA",
        b"Linearized",
        b"Contents",
        b"S",
    ];
    const FILTER_NAMES: &[&[u8]] = &[
        b"ASCIIHexDecode",
        b"ASCII85Decode",
        b"A85",
        b"AHx",
        b"FlateDecode",
        b"Fl",
        b"LZWDecode",
        b"LZW",
        b"RunLengthDecode",
        b"RL",
        b"CCITTFaxDecode",
        b"CCF",
        b"JBIG2Decode",
        b"DCTDecode",
        b"DCT",
        b"JPXDecode",
        b"Standard",
        b"Crypt",
        b"Length",
    ];
    let mut state = State::Idle;
    let mut flag = false;
    let mut at = 0;
    let mut name = Vec::with_capacity(63);
    while let Some(slash) = memchr::memchr(b'/', &dict[at..]) {
        at += slash + 1;
        name.clear();
        // The reference keeps at most 63 bytes and decodes `#xx` escapes.
        while name.len() < 63 && at < dict.len() {
            let b = dict[at];
            if b == b'#' {
                let Some(byte) = dict
                    .get(at + 1..at + 3)
                    .and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok())
                else {
                    break;
                };
                name.push(byte);
                at += 3;
                continue;
            }
            if b" \t\r\n/>[]<(".contains(&b) {
                break;
            }
            name.push(b);
            at += 1;
        }
        let name = name.as_slice();
        state = match name {
            b"Filter" => State::Filter,
            b"Launch" => State::Launch,
            b"Sig" | b"V" | b"R" | b"JavaScript" | b"OpenAction" => State::Idle,
            _ if IDLE_NAMES.contains(&name) && state == State::Idle => {
                flag |= name == b"EmbeddedFile";
                if name == b"S" { State::S } else { State::Idle }
            }
            _ if FILTER_NAMES.contains(&name) && state == State::Filter => {
                if matches!(name, b"Crypt" | b"Length") {
                    State::Idle
                } else {
                    State::Filter
                }
            }
            // A known name from another state resets only the `/S` state.
            _ if (IDLE_NAMES.contains(&name) || FILTER_NAMES.contains(&name))
                && state == State::S =>
            {
                State::Idle
            }
            _ => state,
        };
    }
    flag
}

fn trim_eol(bytes: &[u8]) -> &[u8] {
    bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .or_else(|| bytes.strip_suffix(b"\r"))
        .unwrap_or(bytes)
}

fn parse<'a>(data: &'a [u8], sink: &mut dyn ChildSink) -> io::Result<Option<Pdf<'a>>> {
    let mut input = Tokens { data, pos: 0 };
    let mut token_budget = TokenBudget::default();
    let mut pdf = Pdf {
        objects: Vec::new(),
        count: 0,
        lengths: HashMap::new(),
        contents: HashSet::new(),
        security: None,
        locked: false,
    };
    let mut trailer = None;
    let mut standard = None;
    let mut encrypted = false;
    let mut ambiguous = false;
    let mut requests = Vec::new();
    let mut count = 0usize;
    let mut last = [None, None];
    while let Some(tok) = input.next_checked(&mut token_budget, sink)? {
        if tok == b"trailer" {
            ambiguous |= trailer.replace(input.pos).is_some();
        } else if tok == b"/Encrypt" {
            if trailer.is_none() || encrypted {
                return Ok(None);
            }
            encrypted = true;
        }
        if tok != b"obj" {
            last = [last[1], number(tok)];
            continue;
        }
        sink.check()?;
        count += 1;
        if count > MAX_OBJECTS {
            return Ok(None);
        }
        let [Some(id), Some(gen_id)] = last else {
            return Ok(None);
        };
        let mut obj = Object {
            id: (id, gen_id),
            start: input.pos,
            ..Object::default()
        };
        let mut has_opening = false;
        let mut standard_filter = false;
        let mut escaped_name = None;
        let mut encrypt_entry = false;
        let mut copy = input.clone();
        if let Some(n) = copy.next_checked(&mut token_budget, sink)?.and_then(number)
            && copy.next_checked(&mut token_budget, sink)? == Some(b"endobj".as_slice())
        {
            pdf.lengths.insert(obj.id, n);
        }
        loop {
            let Some(tok) = input.next_checked(&mut token_budget, sink)? else {
                return Ok(None);
            };
            match tok {
                b"endobj" => {
                    if let Some(name) = escaped_name {
                        obj.unsupported |= obj.encoded.is_none()
                            || !security::embedded_mime(&data[obj.start..input.pos], name);
                    }
                    if standard_filter {
                        let body = &data[obj.start..input.pos - 6];
                        ambiguous |= standard.replace((obj.id, body)).is_some();
                    }
                    if has_opening {
                        let body = &data[obj.start..input.pos - 6];
                        match destination::catalog(body, &mut || sink.check())? {
                            Some(destination::Destination::Inline) if obj.encoded.is_none() => {
                                obj.raw_destination = true;
                                obj.encoded = Some(body);
                            }
                            Some(value) if obj.encoded.is_none() => {
                                requests.push((pdf.objects.len(), value))
                            }
                            _ => obj.unsupported = true,
                        }
                    }
                    break;
                }
                b"stream" => {
                    obj.embedded = embedded_flag(&data[obj.start..input.pos]);
                    obj.directory = object_stream::Directory::read(&data[obj.start..input.pos]);
                    let Some(encoded) = read_stream(&mut input, &mut || sink.check())? else {
                        return Ok(None);
                    };
                    obj.encoded = Some(encoded);
                }
                b"/Contents" => {
                    if let Some(id) = input.reference() {
                        pdf.contents.insert(id);
                        if pdf.contents.len() > MAX_OBJECTS {
                            return Ok(None);
                        }
                    }
                }
                b"/Length" => {
                    obj.length_ref = input.reference();
                    let mut look = input.clone();
                    let candidate = look.next().and_then(number);
                    if input.data.get(look.pos) != Some(&b' ') {
                        obj.length = candidate;
                    }
                }
                b"/Filter" => {
                    if !obj.filters.is_empty() {
                        return Ok(None);
                    }
                    let Some(first) = input.next() else {
                        return Ok(None);
                    };
                    standard_filter |= first == b"/Standard";
                    if first == b"[" {
                        loop {
                            let Some(name) = input.next() else {
                                return Ok(None);
                            };
                            if name == b"]" {
                                break;
                            }
                            if obj.filters.len() >= MAX_FILTERS {
                                return Ok(None);
                            }
                            obj.filters.push(Filter::parse(name));
                        }
                    } else {
                        obj.filters.push(Filter::parse(first));
                    }
                }
                b"/Image" => obj.image = true,
                b"/Metadata" => obj.metadata = true,
                b"/ObjStm" => obj.object_stream = true,
                b"/XRef" => obj.xref = true,
                b"/OpenAction" => {
                    obj.unsupported |= has_opening;
                    has_opening = true;
                }
                b"/JS" | b"/JavaScript" | b"/Launch" => obj.unsupported = true,
                // The sampled filters use their defaults even with explicit decode parameters.
                b"/DecodeParms" | b"/DP" => {
                    if !input.skip_value() {
                        return Ok(None);
                    }
                }
                b"/Encrypt" if !encrypt_entry => encrypt_entry = true,
                b"/Encrypt" => return Ok(None),
                n if n.first() == Some(&b'/') && n.contains(&b'#') => {
                    obj.unsupported |= escaped_name.replace(n).is_some();
                }
                _ => (),
            }
        }
        if encrypt_entry {
            // A cross-reference stream dictionary holds the trailer entries.
            if !obj.xref || encrypted {
                return Ok(None);
            }
            encrypted = true;
            ambiguous |= trailer.replace(obj.start).is_some();
        }
        if obj.encoded.is_some() || obj.unsupported || has_opening {
            pdf.objects.push(obj);
        }
        last = [None, None];
    }
    if encrypted {
        let (Some(at), Some((id, dict))) = (trailer, standard) else {
            return Ok(None);
        };
        if ambiguous
            || dict.len() > security::MAX_METADATA
            || !requests.is_empty()
            || pdf.objects.iter().any(|o| o.raw_destination)
        {
            return Ok(None);
        }
        match security::Security::open(id, dict, &data[at..]) {
            Some(security::Access::Open(handler)) => pdf.security = Some(*handler),
            Some(security::Access::Locked) => pdf.locked = true,
            None => return Ok(None),
        }
    }
    if !destination::resolve(data, &mut pdf.objects, &requests, sink)? {
        return Ok(None);
    }
    pdf.count = count;
    Ok(Some(pdf))
}

pub(super) fn header_type(data: &[u8]) -> bool {
    data[..data.len().min(1024)]
        .windows(7)
        .any(|w| (w.starts_with(b"%PDF-") || w.starts_with(b"%pdf-")) && w[6] == b'.')
}

pub(super) fn extract(
    data: &[u8],
    alert_encrypted_doc: bool,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let Some(start) = data[..data.len().min(1032)]
        .windows(5)
        .position(|w| w == b"%PDF-")
    else {
        return Ok(Handling::Complete);
    };
    let data = &data[start..];
    let Some(mut pdf) = parse(data, sink)? else {
        return Ok(Handling::Incomplete);
    };
    sink.check()?;
    if pdf.locked && alert_encrypted_doc && sink.report_heuristic("Heuristics.Encrypted.PDF") {
        return Ok(Handling::Stopped);
    }
    let directories = pdf
        .objects
        .iter()
        .filter(|obj| obj.directory.is_some())
        .take(2)
        .count();
    let mut retained = None;
    let locked = pdf.locked;
    let mut packed = (directories != 0).then(|| {
        object_stream::Packed::new(
            sink.temporary_directory(),
            sink.remaining(),
            pdf.count,
            pdf.objects
                .iter()
                .filter(|obj| obj.unsupported || obj.encoded.is_some() && !obj.raw_destination)
                .map(|obj| obj.id),
        )
    });
    'objects: for mut obj in pdf.objects {
        sink.check()?;
        if obj.unsupported {
            return Ok(Handling::Incomplete);
        }
        let Some(bytes) = obj.encoded else { continue };
        if obj.raw_destination {
            // Stock checks file count, then dictionary bytes, then recursion.
            if sink.child_limit() != Some(Limit::MaxFiles)
                && sink.skip_declared_size(bytes.len() as u64)
            {
                continue;
            }
            if sink.child_bytes(bytes, None)? {
                return Ok(Handling::Stopped);
            }
            continue;
        }
        let content = pdf.contents.contains(&obj.id);
        if obj.image && !obj.filters.contains(&Filter::Jpeg) {
            continue;
        }
        if !obj.filters.is_empty()
            && !obj.embedded
            && !content
            && !obj.filters.iter().any(Filter::dumped)
        {
            continue;
        }
        if obj.filters.contains(&Filter::Unsupported) {
            return Ok(Handling::Incomplete);
        }
        // Stock leaves cross-reference streams unencrypted.
        let encrypted = if let Some(handler) = &pdf.security
            && !obj.xref
        {
            let Some(stream) = security::ciphertext(&data[obj.start..], bytes, &pdf.lengths) else {
                return Ok(Handling::Incomplete);
            };
            // The pinned stream parser stops collecting filters at the first closing dictionary.
            if !stream.filters_visible {
                obj.filters.clear();
            }
            Some((handler, stream))
        } else {
            None
        };
        let length = obj
            .length_ref
            .and_then(|id| pdf.lengths.get(&id).copied())
            .or(obj.length)
            .unwrap_or(0)
            .min(bytes.len());
        // The pinned fallback determines EOL width relative to the indirect object header.
        let visible_flate =
            obj.filters.first() != Some(&Filter::Crypt) && obj.filters.contains(&Filter::Flate);
        let end = if length == 0 && !visible_flate {
            trim_eol(&data[obj.start..obj.start + bytes.len()]).len()
        } else if bytes.len().saturating_sub(length) > 2 {
            bytes.len()
        } else {
            length
        };
        let mut decoded: Option<Snapshot> = None;
        if let Some((handler, stream)) = encrypted {
            let mut name = None;
            if obj.filters.first() == Some(&Filter::Crypt) {
                // Stock's explicit Crypt stage consumes the stream without running subsequent filters.
                obj.filters.clear();
                name = stream.explicit.filter(|v| *v != b"Identity");
            }
            // A leading DCT stage stops stock's chain before the decrypted bytes are kept.
            if name.is_none() && matches!(obj.filters.as_slice(), [] | [Filter::Jpeg]) {
                if physical_stream(&bytes[..end], content, sink)? {
                    return Ok(Handling::Stopped);
                }
                continue;
            }
            if !obj.filters.iter().all(|f| {
                matches!(
                    f,
                    Filter::Flate | Filter::Hex | Filter::Ascii85 | Filter::RunLength | Filter::Lzw
                )
            }) {
                return Ok(Handling::Incomplete);
            }
            if obj.directory.is_some() {
                // Only the sampled carrier layouts keep output past the scan budget.
                if !matches!(obj.filters.as_slice(), [] | [Filter::Flate]) {
                    return Ok(Handling::Incomplete);
                }
                // The decoded carrier continues through the unencrypted object-stream path.
                match handler.decode(&obj, name, stream.bytes, filters::Retain::Carrier, sink)? {
                    Output::Decoded(file) => decoded = Some(file),
                    Output::StageLimit(0, required) => {
                        sink.skip_declared_size(required);
                        if physical_stream(&bytes[..end], content, sink)? {
                            return Ok(Handling::Stopped);
                        }
                        continue;
                    }
                    _ => return Ok(Handling::Incomplete),
                }
                obj.filters.clear();
            } else if obj.filters.contains(&Filter::Lzw) {
                // Decrypt first, then decode the plaintext with the unencrypted LZW rules.
                let chain = std::mem::take(&mut obj.filters);
                let plain =
                    handler.decode(&obj, name, stream.bytes, filters::Retain::Carrier, sink)?;
                obj.filters = chain;
                let Output::Decoded(plain) = plain else {
                    return Ok(Handling::Incomplete);
                };
                decoded = Some(plain);
            } else {
                let mut retain = if sink.child_limit().is_some() {
                    filters::Retain::Count
                } else {
                    filters::Retain::Verify
                };
                loop {
                    match handler.decode(&obj, name, stream.bytes, retain, sink)? {
                        Output::Decoded(file) => {
                            if file.with_bytes(|b| visit_stream(b, content, sink))? {
                                return Ok(Handling::Stopped);
                            }
                        }
                        Output::Counted(_) if retain == filters::Retain::Verify => {
                            retain = filters::Retain::Keep;
                            continue;
                        }
                        Output::Counted(size) => record_child_limit(size, sink),
                        Output::TooLarge(size) => {
                            sink.skip_declared_size(size);
                        }
                        Output::StageLimit(index, required) => {
                            sink.skip_declared_size(required);
                            if index == 0 {
                                if physical_stream(&bytes[..end], content, sink)? {
                                    return Ok(Handling::Stopped);
                                }
                            } else {
                                // The last successful filter output becomes the child on an allocation failure.
                                obj.filters.truncate(index);
                                continue;
                            }
                        }
                        Output::Malformed | Output::UseInput => return Ok(Handling::Incomplete),
                    }
                    break;
                }
                continue;
            }
        }
        if obj.filters.contains(&Filter::Crypt) {
            return Ok(Handling::Incomplete);
        }
        let input_bytes = ObjectBytes::Borrowed(&bytes[..end]);
        let mut directory = obj.directory;
        let mut filters = obj
            .filters
            .into_iter()
            .take_while(|f| *f != Filter::Jpeg)
            .peekable();
        while let Some(filter) = filters.next() {
            let retain =
                filters.peek().is_some() || directory.is_some() || sink.child_limit().is_none();
            let first_stage = decoded.is_none();
            let limit = if obj.object_stream && filter == Filter::Flate {
                // Stock inflates the first 256 KiB before checking its next allocation.
                (sink.remaining() / (256 << 10)).max(1) * (256 << 10)
            } else if matches!(filter, Filter::Hex | Filter::Ascii85) && filters.peek().is_some() {
                // These stock decoders check no limit. Only the final output is counted.
                u64::MAX
            } else {
                sink.remaining()
            };
            let mut input_verdict = None;
            let mut next = |data: &[u8]| {
                let result = match filter.decode(data, limit, retain, sink)? {
                    // Ciphertext fails stock's Flate stage before any output.
                    Output::Malformed
                        if locked
                            && first_stage
                            && filter == Filter::Flate
                            && filters::flate_fails_at_start(data) =>
                    {
                        Output::UseInput
                    }
                    result => result,
                };
                if let Output::UseInput = result {
                    // The current stage still owns this borrowed input, including earlier filters' output.
                    input_verdict = Some(visit_stream(data, content, sink)?);
                }
                Ok(result)
            };
            let result = match decoded.take() {
                Some(last) => last.with_bytes(next),
                None => next(input_bytes.as_ref()),
            };
            match result? {
                Output::Counted(size) => {
                    record_child_limit(size, sink);
                    continue 'objects;
                }
                Output::Malformed | Output::StageLimit(_, _) => return Ok(Handling::Incomplete),
                Output::Decoded(output) => decoded = Some(output),
                Output::UseInput => {
                    if input_verdict.expect("fallback visited the input") {
                        return Ok(Handling::Stopped);
                    }
                    continue 'objects;
                }
                Output::TooLarge(required) => {
                    sink.skip_declared_size(required);
                    if obj.object_stream && filter == Filter::Flate && first_stage {
                        directory = None;
                        break;
                    }
                    continue 'objects;
                }
            }
        }
        let source = match decoded {
            Some(s) => s.into_bytes()?,
            None => input_bytes,
        };
        let data = source.as_ref();
        let (retain, skipped) =
            if let (Some(directory), Some(packed)) = (directory, packed.as_mut()) {
                let retain = packed.inspect(
                    directory,
                    directories == 1,
                    &source,
                    &mut pdf.lengths,
                    &mut pdf.contents,
                    sink,
                )?;
                (retain, sink.skip_declared_size(data.len() as u64))
            } else {
                (false, false)
            };
        if !skipped && visit_stream(data, content, sink)? {
            return Ok(Handling::Stopped);
        }
        if retain {
            retained = Some(source);
        }
    }
    packed.map_or(Ok(Handling::Complete), |packed| {
        packed.finish(retained.as_ref().map(AsRef::as_ref), sink)
    })
}

fn physical_stream(data: &[u8], content: bool, sink: &mut dyn ChildSink) -> io::Result<bool> {
    if sink.skip_declared_size(data.len() as u64) {
        return Ok(false);
    }
    visit_stream(data, content, sink)
}

fn record_child_limit(size: u64, sink: &mut dyn ChildSink) {
    if size > 5 || sink.child_limit() == Some(Limit::MaxFiles) {
        sink.can_enter_child();
    }
}

fn visit_stream(data: &[u8], content: bool, sink: &mut dyn ChildSink) -> io::Result<bool> {
    if sink.child_limit().is_some() {
        record_child_limit(data.len() as u64, sink);
        return Ok(false);
    }
    if sink.child_bytes(data, None)? {
        return Ok(true);
    }
    if content {
        return scan_page_text(data, sink);
    }
    Ok(false)
}

// The normalized text cannot be longer than its source. When that bound fits,
// an admitted child needs only one pass. Otherwise count before opening a spool.
fn scan_page_text(data: &[u8], sink: &mut dyn ChildSink) -> io::Result<bool> {
    let remaining = sink.remaining();
    let denied = sink.child_limit().is_some();
    let may_exceed_size = data.len() as u64 > remaining;
    if denied || may_exceed_size {
        let stop_after = if may_exceed_size { remaining.max(5) } else { 5 };
        let size = page_text(data, sink, None, stop_after)?;
        if size <= 5 || sink.skip_declared_size(size) || !sink.can_enter_child() {
            return Ok(false);
        }
    }
    let mut snapshot = Snapshot::new(sink.temporary_directory());
    let size = page_text(data, sink, Some(&mut snapshot), u64::MAX)?;
    if size <= 5 {
        return Ok(false);
    }
    sink.visit_snapshot(snapshot, None, None)
}

// The pinned contents pass reads parenthesized strings from arrays starting a line.
fn page_text(
    data: &[u8],
    sink: &mut dyn ChildSink,
    mut snapshot: Option<&mut Snapshot>,
    stop_after: u64,
) -> io::Result<u64> {
    let mut written = 0u64;
    let mut at_line_start = true;
    let mut array = false;
    let mut literal = false;
    let mut space = false;
    let mut out = [0; 8192];
    let mut used = 0;
    for chunk in data.chunks(out.len()) {
        sink.check()?;
        for &b in chunk {
            if !array {
                array = at_line_start && b == b'[';
                at_line_start = b == b'\n';
            } else if !literal {
                literal = b == b'(';
            } else if b == b')' {
                literal = false;
            } else if used == out.len() {
                // Stock consumes this literal byte while flushing the full block.
                // Whitespace state starts fresh in the next output block.
                if let Some(file) = &mut snapshot {
                    file.write_all(&out)?;
                }
                written += used as u64;
                used = 0;
                space = false;
            } else {
                let normalized = match b {
                    9..=13 | b' ' if !space => b' ',
                    0x21..=0x7f => b.to_ascii_lowercase(),
                    _ => continue,
                };
                space = normalized == b' ';
                out[used] = normalized;
                used += 1;
            }
        }
        if written + used as u64 > stop_after {
            return Ok(written + used as u64);
        }
    }
    if let Some(file) = snapshot {
        file.write_all(&out[..used])?;
    }
    Ok(written + used as u64)
}

#[cfg(test)]
mod token_tests {
    use super::*;

    #[test]
    fn stream_terminator_across_chunks_and_cancellation() -> io::Result<()> {
        for size in TOKEN_BLOCK - 9..TOKEN_BLOCK + 2 {
            let mut stream = vec![b'x'; size + 1];
            stream[0] = b'\n';
            stream.extend_from_slice(b"endstream endobj");
            let mut tokens = Tokens {
                data: &stream,
                pos: 0,
            };
            assert_eq!(
                read_stream(&mut tokens, &mut || Ok(()))?,
                Some(&stream[1..size + 1])
            );
            assert_eq!(tokens.next(), Some(b"endobj".as_slice()));
        }
        let mut stream = vec![0; 16 << 20];
        stream[0] = b'\n';
        let mut tokens = Tokens {
            data: &stream,
            pos: 0,
        };
        let mut checks = 0;
        let error = read_stream(&mut tokens, &mut || {
            checks += 1;
            if checks == 3 {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "cancel stream"));
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(checks, 3);
        Ok(())
    }

    #[test]
    fn literal_escapes_across_chunks() -> io::Result<()> {
        for prefix in [0, 3, TOKEN_BLOCK - 2, TOKEN_BLOCK - 1, TOKEN_BLOCK] {
            let mut data = vec![b'('];
            data.resize(1 + prefix, b'a');
            data.extend_from_slice(br"\)\(\\(nested) tail)");
            let end = data.len();
            data.extend_from_slice(b" /Next");
            let mut tokens = Tokens {
                data: &data,
                pos: 0,
            };
            assert_eq!(tokens.next(), Some(&data[..end]));
            assert_eq!(tokens.next(), Some(b"/Next".as_slice()));
        }
        // Report a cancellation from the middle of a single large string.
        let mut data = vec![b'x'; 4 * TOKEN_BLOCK];
        data[0] = b'(';
        *data.last_mut().unwrap() = b')';
        let mut tokens = Tokens {
            data: &data,
            pos: 0,
        };
        let mut budget = TokenBudget::default();
        let error = tokens
            .next_with(&mut |n| {
                budget.charge(n, &mut || Err(io::Error::other("receipt scan cancelled")))
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "receipt scan cancelled");
        assert_eq!(tokens.pos, 1 + TOKEN_BLOCK);
        Ok(())
    }
}
