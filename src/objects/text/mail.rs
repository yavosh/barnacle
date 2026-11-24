mod mbox;
use super::{ChildSink, Handling};
pub(in crate::objects) use mbox::SavedLetters;
use std::io::{self, Read};

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    const START: &[&[u8]] = &[
        b"From: ",
        b"From ",
        b">From ",
        b"Received: ",
        b"Subject: ",
        b"Date: ",
        b"To: ",
        b"Message-ID: ",
        b"Message-Id: ",
        b"Return-Path: ",
        b"Return-path: ",
        b"Delivered-To: ",
        b"Delivery-date: ",
        b"Envelope-to: ",
        b"Received-SPF: ",
        b"X-Original-To: ",
    ];
    START.iter().any(|s| bytes.starts_with(s))
        || (bytes
            .get(..13)
            .is_some_and(|s| s.eq_ignore_ascii_case(b"MIME-Version:"))
            && bytes
                .windows(14)
                .any(|s| s.eq_ignore_ascii_case(b"\nContent-Type:")))
}

struct Part<'a> {
    kind: Vec<u8>,
    disposition: Vec<u8>,
    encoding: Vec<u8>,
    body: &'a [u8],
}

impl Part<'_> {
    fn media_type(&self) -> &[u8] {
        self.kind
            .split(|&b| b == b';')
            .next()
            .unwrap_or_default()
            .trim_ascii()
    }
    fn direct_encoding(&self) -> bool {
        [
            b"base64".as_slice(),
            b"quoted-printable",
            b"8bit",
            b"binary",
        ]
        .iter()
        .any(|name| self.encoding.eq_ignore_ascii_case(name))
    }

    fn named_attachment(&self) -> bool {
        self.disposition
            .split(|&b| b == b';')
            .next()
            .unwrap_or_default()
            .trim_ascii()
            .eq_ignore_ascii_case(b"attachment")
            && parameter(&self.disposition, b"filename").is_some_and(|name| !name.is_empty())
    }
}

fn mailbox_media(mime: &[u8]) -> bool {
    let Some(slash) = mime.iter().position(|&b| b == b'/') else {
        return false;
    };
    slash + 1 < mime.len()
        && [
            b"application".as_slice(),
            b"audio",
            b"image",
            b"text",
            b"video",
        ]
        .iter()
        .any(|family| mime[..slash].eq_ignore_ascii_case(family))
}

fn line(input: &[u8]) -> (&[u8], &[u8]) {
    let (text, rest) = input
        .iter()
        .position(|&b| b == b'\n')
        .map_or((input, &[][..]), |i| (&input[..i], &input[i + 1..]));
    (text.strip_suffix(b"\r").unwrap_or(text), rest)
}

fn headers(mut input: &[u8]) -> Option<Part<'_>> {
    let mut part = Part {
        kind: vec![],
        disposition: vec![],
        encoding: vec![],
        body: &[],
    };
    let mut last = None;
    let original_len = input.len();
    while !input.is_empty() && original_len - input.len() <= 64 * 1024 {
        let (row, rest) = line(input);
        input = rest;
        if row.is_empty() {
            part.body = input;
            return Some(part);
        }
        let continuation = row.starts_with(b" ") || row.starts_with(b"\t");
        let value = if continuation {
            row.trim_ascii()
        } else {
            let colon = row.iter().position(|b| *b == b':')?;
            let name = &row[..colon];
            last = if name.eq_ignore_ascii_case(b"Content-Type") {
                Some(0)
            } else if name.eq_ignore_ascii_case(b"Content-Disposition") {
                Some(1)
            } else if name.eq_ignore_ascii_case(b"Content-Transfer-Encoding") {
                Some(2)
            } else {
                None
            };
            row[colon + 1..].trim_ascii()
        };
        if value.len() > 8192 {
            return None;
        }
        let field = match last {
            Some(0) => &mut part.kind,
            Some(1) => &mut part.disposition,
            Some(2) => &mut part.encoding,
            _ => continue,
        };
        if !field.is_empty() {
            if !continuation {
                return None;
            }
            field.push(b' ');
        }
        field.extend_from_slice(value);
    }
    None
}

fn parameter<'a>(value: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    value.split(|c| *c == b';').skip(1).find_map(|field| {
        let eq = field.iter().position(|&c| c == b'=')?;
        if !field[..eq].trim_ascii().eq_ignore_ascii_case(name) {
            return None;
        }
        let v = field[eq + 1..].trim_ascii();
        Some(
            v.strip_prefix(b"\"")
                .and_then(|s| s.strip_suffix(b"\""))
                .unwrap_or(v),
        )
    })
}

const BASE64: [u8; 256] = {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [u8::MAX; 256];
    let mut i = 0;
    while i < alphabet.len() {
        table[alphabet[i] as usize] = i as u8;
        i += 1;
    }
    table
};

fn b64(b: u8) -> Option<u8> {
    let value = BASE64[b as usize];
    (value != u8::MAX).then_some(value)
}

#[derive(Clone, Copy)]
enum Encoding {
    Plain,
    Base64,
    Quoted,
}

struct Body<'a> {
    data: &'a [u8],
    mode: Encoding,
    code: u16,
    bits: u8,
    final_lf: bool,
}

pub(in crate::objects) fn valid_base64(data: &[u8], sink: &mut dyn ChildSink) -> io::Result<bool> {
    let mut digits = 0;
    let mut pads = 0;
    for block in data.chunks(8192) {
        sink.check()?;
        for &b in block {
            if b.is_ascii_whitespace() {
                continue;
            }
            if b == b'=' && pads < 2 {
                pads += 1;
            } else if pads == 0 && b64(b).is_some() {
                digits += 1;
            } else {
                return Ok(false);
            }
        }
    }
    if digits % 4 == 1 || (pads != 0 && (digits + pads) % 4 != 0) {
        return Ok(false);
    }
    Ok(true)
}

pub(in crate::objects) fn base64_reader(data: &[u8]) -> impl Read + '_ {
    Body::new(data, Encoding::Base64)
}

impl<'a> Body<'a> {
    fn new(data: &'a [u8], mode: Encoding) -> Self {
        Self {
            data,
            mode,
            code: 0,
            bits: 0,
            final_lf: !data.is_empty()
                && !data.ends_with(b"\n")
                && !matches!(mode, Encoding::Base64),
        }
    }

    // Both read paths call this for individual bytes. An out-of-line call here
    // reduced throughput even for messages with no Base64 content.
    #[inline(always)]
    fn next_byte(&mut self) -> io::Result<Option<u8>> {
        while let Some((&b, rest)) = self.data.split_first() {
            self.data = rest;
            match self.mode {
                Encoding::Base64 => {
                    if b.is_ascii_whitespace() || b == b'=' {
                        continue;
                    }
                    let six = b64(b).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid base64 mail part")
                    })?;
                    self.code = (self.code << 6) | u16::from(six);
                    self.bits += 6;
                    if self.bits < 8 {
                        continue;
                    }
                    self.bits -= 8;
                    return Ok(Some((self.code >> self.bits) as u8));
                }
                Encoding::Quoted if b == b'=' => {
                    if let Some(next) = rest
                        .strip_prefix(b"\r\n")
                        .or_else(|| rest.strip_prefix(b"\n"))
                    {
                        self.data = next;
                        continue;
                    }
                    if let Some(hex) = rest
                        .get(..2)
                        .and_then(|s| std::str::from_utf8(s).ok())
                        .and_then(|s| u8::from_str_radix(s, 16).ok())
                    {
                        self.data = &rest[2..];
                        return Ok(Some(hex));
                    }
                }
                _ => (),
            }
            if b == b'\r' && rest.starts_with(b"\n") {
                continue;
            }
            return Ok(Some(b));
        }
        Ok(std::mem::take(&mut self.final_lf).then_some(b'\n'))
    }

    fn read_base64(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < output.len() {
            // A complete quartet has no residual bits. Whitespace, padding, and
            // split quartets still go through the streaming decoder.
            if self.bits == 0 {
                let groups = self.data.as_chunks::<4>().0;
                for (&group, dst) in groups.iter().zip(output[written..].as_chunks_mut::<3>().0) {
                    let [a, b, c, d] = group.map(|byte| BASE64[byte as usize]);
                    if a | b | c | d == u8::MAX {
                        break;
                    }
                    dst.copy_from_slice(&[a << 2 | b >> 4, b << 4 | c >> 2, c << 6 | d]);
                    self.data = &self.data[4..];
                    written += 3;
                }
                if written == output.len() {
                    break;
                }
            }
            let Some(b) = self.next_byte()? else { break };
            output[written] = b;
            written += 1;
        }
        Ok(written)
    }
}

impl Read for Body<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if matches!(self.mode, Encoding::Base64) {
            return self.read_base64(output);
        }
        for (i, dest) in output.iter_mut().enumerate() {
            let Some(b) = self.next_byte()? else {
                return Ok(i);
            };
            *dest = b;
        }
        Ok(output.len())
    }
}

fn decoded_size(mut data: impl Read, stop_after: u64, sink: &mut dyn ChildSink) -> io::Result<u64> {
    let mut size = 0;
    let mut block = [0; 8192];
    while size <= stop_after {
        sink.check()?;
        let n = data.read(&mut block)?;
        if n == 0 {
            break;
        }
        size += n as u64;
    }
    Ok(size)
}

fn submit(
    bytes: &[u8],
    mode: Encoding,
    filename: Option<&[u8]>,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    submit_parts(&[], bytes, mode, filename, sink)
}

fn submit_parts(
    prefix: &[u8],
    bytes: &[u8],
    mode: Encoding,
    filename: Option<&[u8]>,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let body = Body::new(bytes, mode);
    let bound = (prefix.len() + bytes.len()) as u64 + u64::from(body.final_lf);
    // A nonempty prefix ends on the LF immediately before the removed begin line.
    let mut data = Body::new(prefix, Encoding::Plain).chain(body);
    if sink.child_limit().is_some() {
        // Stock checks the decoded byte count before the file and map limits.
        if bound > sink.remaining() {
            let total = decoded_size(&mut data, u64::MAX, sink)?;
            if sink.skip_declared_size(total) {
                return Ok(Handling::Complete);
            }
        }
        sink.can_enter_child();
        return Ok(Handling::Complete);
    }
    Ok(if sink.child(&mut data, None, filename)? {
        Handling::Stopped
    } else {
        Handling::Complete
    })
}

#[derive(Default)]
struct ForwardFiles<'a> {
    transfer: bool,
    note: Option<&'a [u8]>,
    multiple_notes: bool,
}

fn transfer_line(row: &[u8]) -> bool {
    const MARKER: &[u8] = b"Content-Transfer-Encoding";
    // Stock checks this case-insensitive prefix even in prose, without a colon.
    row.split_at_checked(MARKER.len())
        .is_some_and(|(name, rest)| {
            name.eq_ignore_ascii_case(MARKER) && !rest.windows(4).any(|w| w == b"7bit")
        })
}

fn uu_begin(row: &[u8]) -> bool {
    row.starts_with(b"b")
        && row
            .get(..6)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"begin "))
        && row
            .get(6..9)
            .is_some_and(|p| p.iter().all(u8::is_ascii_digit))
        && row.get(9) == Some(&b' ')
}

fn forward_files<'a>(
    mut body: &'a [u8],
    mut check: impl FnMut() -> io::Result<()>,
    next_line: impl Fn(&[u8]) -> (&[u8], &[u8]),
) -> io::Result<ForwardFiles<'a>> {
    let mut files = ForwardFiles::default();
    while !body.is_empty() {
        check()?;
        let (row, next) = next_line(body);
        if transfer_line(row) {
            files.transfer = true;
        }
        if uu_begin(row) {
            files.multiple_notes |= files.note.is_some();
            files.note.get_or_insert(body);
        }
        body = next;
    }
    Ok(files)
}

enum Saved<'a> {
    Forward(&'a [u8]),
    Uuencoded(Option<super::attachments::RecoveredNote<'a>>),
}

#[derive(Default)]
struct Deferred<'a> {
    first: Option<Saved<'a>>,
    copies: usize,
    uncertain: bool,
    max_bytes: u64,
    prior_limit: bool,
    has_uu: bool,
    oversized_mixed: bool,
    direct_members: usize,
    mbox: bool,
    rejected_direct: bool,
}

// Identical saved messages have the same children and scan cost in either directory order.
fn identical_forward(left: &[u8], right: &[u8], sink: &mut dyn ChildSink) -> io::Result<bool> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (a, b) in left.chunks(8192).zip(right.chunks(8192)) {
        sink.check()?;
        if a != b {
            return Ok(false);
        }
    }
    Ok(true)
}

impl<'a> Deferred<'a> {
    fn add(&mut self, file: Saved<'a>, bound: u64, uncertain: bool) {
        self.uncertain |= self.first.is_some() || uncertain;
        self.has_uu |= matches!(file, Saved::Uuencoded(_));
        self.max_bytes = self.max_bytes.max(bound);
        self.first.get_or_insert(file);
    }

    fn add_forward(
        &mut self,
        body: &'a [u8],
        extra: bool,
        sink: &mut dyn ChildSink,
    ) -> io::Result<()> {
        if !self.uncertain
            && !extra
            && let Some(Saved::Forward(first)) = &self.first
            && identical_forward(first, body, sink)?
        {
            self.copies += 1;
        } else {
            let bound = body.len() as u64 + u64::from(!body.ends_with(b"\n"));
            self.add(Saved::Forward(body), bound, extra);
        }
        Ok(())
    }
}

fn part<'a>(
    input: &'a [u8],
    sink: &mut dyn ChildSink,
    depth: usize,
    multipart_member: bool,
    deferred: &mut Deferred<'a>,
) -> io::Result<Handling> {
    if depth >= 16 {
        return Ok(Handling::Incomplete);
    }
    let Some(p) = headers(input) else {
        return Ok(Handling::Incomplete);
    };
    let mime = p.media_type();
    if deferred.mbox && multipart_member {
        // In ordinary mixed mail, stock directly scans the text cover and decoded attachments.
        let cover = mime.eq_ignore_ascii_case(b"text/plain") && p.encoding.is_empty();
        let attachment = mailbox_media(mime)
            && (p.direct_encoding() || p.encoding.is_empty() && p.named_attachment());
        if depth != 1 || !(cover || attachment) {
            return Ok(Handling::Incomplete);
        }
    }
    if mime
        .get(..10)
        .is_some_and(|v| v.eq_ignore_ascii_case(b"multipart/"))
    {
        let Some(boundary) = parameter(&p.kind, b"boundary") else {
            return Ok(Handling::Incomplete);
        };
        if boundary.is_empty() || boundary.len() > 200 {
            return Ok(Handling::Incomplete);
        }
        let mut data = p.body;
        let mut start = None;
        while !data.is_empty() {
            sink.check()?;
            let (row, next) = line(data);
            let offset = p.body.len() - data.len();
            let ending = row
                .strip_prefix(b"--")
                .and_then(|s| s.strip_prefix(boundary))
                .map(<[u8]>::trim_ascii_end);
            if let Some(suffix @ (b"" | b"--")) = ending {
                if let Some(at) = start {
                    let result = part(&p.body[at..offset], sink, depth + 1, true, deferred)?;
                    if result != Handling::Complete {
                        return Ok(result);
                    }
                }
                if suffix == b"--" {
                    return Ok(Handling::Complete);
                }
                start = Some(p.body.len() - next.len());
            }
            data = next;
        }
        return Ok(Handling::Incomplete);
    }
    if mime.eq_ignore_ascii_case(b"message/partial") {
        return Ok(Handling::Incomplete);
    }
    let enc = p.encoding.trim_ascii();
    if [b"x-uuencode".as_slice(), b"uuencode", b"uue"]
        .iter()
        .any(|e| enc.eq_ignore_ascii_case(e))
    {
        deferred.direct_members += 1;
        return super::attachments::uu(p.body, sink);
    }
    let mode = if enc.eq_ignore_ascii_case(b"base64") {
        Encoding::Base64
    } else if enc.eq_ignore_ascii_case(b"quoted-printable") {
        Encoding::Quoted
    } else if enc.is_empty()
        || [b"7bit".as_slice(), b"8bit", b"binary"]
            .iter()
            .any(|s| enc.eq_ignore_ascii_case(s))
    {
        Encoding::Plain
    } else {
        return Ok(Handling::Incomplete);
    };
    let forwarded = mime.eq_ignore_ascii_case(b"message/rfc822");
    if forwarded && !multipart_member {
        return match mode {
            Encoding::Plain => part(p.body, sink, depth + 1, false, deferred),
            // A standalone message is parsed for literal message headers. Its wrapping
            // transport declaration does not decode a fresh child as it does in multipart.
            Encoding::Base64 if valid_base64(p.body, sink)? => Ok(Handling::Complete),
            Encoding::Quoted => {
                let Some(inner) = headers(p.body) else {
                    return Ok(Handling::Incomplete);
                };
                let kind = inner.kind.strip_prefix(b"=20").unwrap_or(&inner.kind);
                if inner.encoding.is_empty()
                    && inner.disposition.is_empty()
                    && kind.eq_ignore_ascii_case(b"text/plain")
                {
                    submit(inner.body, Encoding::Plain, None, sink)
                } else {
                    Ok(Handling::Incomplete)
                }
            }
            _ => Ok(Handling::Incomplete),
        };
    }
    let mut prefix = &[][..];
    let mut body = p.body;
    if forwarded && matches!(mode, Encoding::Plain) {
        let files = forward_files(p.body, || sink.check(), line)?;
        if let Some(encoded) = files.note {
            let delayed = enc.is_empty() || enc.eq_ignore_ascii_case(b"7bit");
            let note = super::attachments::recovered_note(encoded, sink)?;
            if files.transfer && !delayed {
                let Some(note) = note.filter(|_| !files.multiple_notes) else {
                    return Ok(Handling::Incomplete);
                };
                // The reference removes the begin line, data and zero line. The end
                // line stays in the forward that it submits before direct siblings.
                prefix = &p.body[..p.body.len() - encoded.len()];
                body = note.tail;
                let remaining = sink.remaining();
                let upper = (prefix.len() + body.len()) as u64 + u64::from(!body.ends_with(b"\n"));
                if upper > remaining {
                    // Only CRLF normalization can shrink this forward below its wire length.
                    let file =
                        Body::new(prefix, Encoding::Plain).chain(Body::new(body, Encoding::Plain));
                    deferred.oversized_mixed |= decoded_size(file, remaining, sink)? > remaining;
                }
                deferred.add(Saved::Uuencoded(Some(note)), encoded.len() as u64, false);
            } else {
                deferred.add(
                    Saved::Uuencoded(note),
                    encoded.len() as u64,
                    files.multiple_notes || files.transfer,
                );
                return Ok(Handling::Complete);
            }
        }
        if !files.transfer {
            return Ok(Handling::Complete);
        }
        if enc.is_empty() || enc.eq_ignore_ascii_case(b"7bit") {
            // These saved messages follow directly scanned attachments. With explicit
            // 7bit the reference also writes a second transfer-decoding recovery file.
            deferred.add_forward(p.body, enc.eq_ignore_ascii_case(b"7bit"), sink)?;
            return Ok(Handling::Complete);
        }
    }
    if matches!(mode, Encoding::Base64) && !valid_base64(p.body, sink)? {
        return Ok(Handling::Incomplete);
    }
    let filename = parameter(&p.disposition, b"filename")
        .or_else(|| parameter(&p.kind, b"name"))
        .or(forwarded.then_some(b"textportion".as_slice()));
    deferred.direct_members += 1;
    if deferred.mbox && body.len() as u64 + 1 > sink.remaining() {
        let remaining = sink.remaining();
        deferred.rejected_direct |=
            decoded_size(Body::new(body, mode), remaining, sink)? > remaining;
    }
    deferred.prior_limit |= sink.child_limit().is_some();
    submit_parts(prefix, body, mode, filename, sink)
}

fn parse_message(bytes: &[u8], standalone: bool, sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let mut deferred = Deferred::default();
    let result = part(bytes, sink, 0, false, &mut deferred)?;
    if result != Handling::Complete {
        return Ok(result);
    }
    let Some(saved) = deferred.first else {
        return Ok(Handling::Complete);
    };
    if deferred.uncertain {
        // A recovered note may be too short to consume any file or scan budget.
        if deferred.has_uu {
            return Ok(Handling::Incomplete);
        }
        if sink.child_limit().is_some() {
            // The reference scans these generated files in filesystem order.
            // Return a limit only when it was recorded earlier or every possible file fits.
            if deferred.prior_limit || deferred.max_bytes <= sink.remaining() {
                sink.can_enter_child();
                return Ok(Handling::Complete);
            }
            if sink.remaining() == 0 {
                sink.skip_declared_size(1);
                return Ok(Handling::Complete);
            }
        }
        return Ok(Handling::Incomplete);
    }
    match saved {
        Saved::Forward(body) => {
            for _ in 0..=deferred.copies {
                sink.check()?;
                let result = submit(body, Encoding::Plain, None, sink)?;
                if result != Handling::Complete {
                    return Ok(result);
                }
            }
            Ok(Handling::Complete)
        }
        Saved::Uuencoded(Some(note)) if deferred.oversized_mixed && note.can_enter(sink) => {
            // The rejected forward remains beside the note. Directory traversal may stop
            // at the forward before reaching the note. A later map could see either budget.
            if !standalone || !sink.at_root() || deferred.direct_members != 1 {
                return Ok(Handling::Incomplete);
            }
            if !printable(bytes, sink)? {
                return Ok(Handling::Incomplete);
            }
            // Printable top-level mail has no subsequent embedded map. A note miss leaves
            // the outer raw matcher and the already recorded size limit identical in both orders.
            Ok(if note.submit(sink)? == Handling::Complete {
                Handling::Complete
            } else {
                Handling::Incomplete
            })
        }
        Saved::Uuencoded(Some(note)) => note.submit(sink),
        Saved::Uuencoded(None) => Ok(Handling::Incomplete),
    }
}

fn printable(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<bool> {
    for block in bytes.chunks(8192) {
        sink.check()?;
        if !block
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if bytes.starts_with(b">From ") {
        return Ok(Handling::Incomplete);
    }
    if bytes.starts_with(b"From ") {
        return mbox::extract(bytes, sink);
    }
    parse_message(bytes, true, sink)
}

#[cfg(test)]
mod base64_tests {
    use super::*;

    #[test]
    fn base64_output_across_read_boundaries() -> io::Result<()> {
        let cases: &[(&[u8], &[u8])] = &[
            (b"", b""),
            (b"Zg==", b"f"),
            (b"Zm8=", b"fo"),
            (b"Zm9vYmFy", b"foobar"),
            (b"Zm9vYmE", b"fooba"),
            (b"Zm9vYg", b"foob"),
            (b" Zm\r\n9v\tY mFy\n", b"foobar"),
            (b"AAECA/7/\nZm9vOg= =", b"\x00\x01\x02\x03\xfe\xfffoo:"),
        ];
        for &(encoded, expected) in cases {
            for size in 1..=13 {
                let mut reader = base64_reader(encoded);
                let mut decoded = Vec::new();
                let mut block = [0; 13];
                loop {
                    assert_eq!(reader.read(&mut [])?, 0);
                    let n = reader.read(&mut block[..size])?;
                    if n == 0 {
                        break;
                    }
                    decoded.extend_from_slice(&block[..n]);
                }
                assert_eq!(decoded, expected, "input {encoded:?}, read size {size}");
            }
        }
        Ok(())
    }

    #[test]
    fn base64_errors_preserve_scalar_read_progress() {
        let text = b"Zm9vYmFyAAECA/7/";
        for at in 0..text.len() {
            for invalid in [b'!', 0xff] {
                let mut encoded = text.to_vec();
                encoded[at] = invalid;
                for size in 1..=9 {
                    let mut reader = base64_reader(&encoded);
                    let mut scalar = Body::new(&encoded, Encoding::Base64);
                    loop {
                        let mut actual = [0; 9];
                        let mut expected = actual;
                        let reference = (|| {
                            for (i, dst) in expected[..size].iter_mut().enumerate() {
                                let Some(byte) = scalar.next_byte()? else {
                                    return Ok(i);
                                };
                                *dst = byte;
                            }
                            Ok(size)
                        })();
                        let result = reader.read(&mut actual[..size]).map_err(|e| e.kind());
                        assert_eq!(result, reference.map_err(|e: io::Error| e.kind()));
                        assert_eq!(actual, expected, "invalid byte at {at}, read size {size}");
                        if result == Ok(0) {
                            break;
                        }
                    }
                }
            }
        }
    }
}
