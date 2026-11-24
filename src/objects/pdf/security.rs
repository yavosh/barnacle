//! Open standard-security PDF streams using the empty user credential.
use super::filters::Retain;
use super::{ChildSink, Filter, Id, Output, Snapshot, Tokens};
use aes::cipher::{Block, BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7, consts::U16};
use flate2::{Decompress, FlushDecompress, Status};
use lopdf::encryption::crypt_filters::{CryptFilter, IdentityCryptFilter, Rc4CryptFilter};
use lopdf::{Dictionary, Document, EncryptionState, Object, ObjectId, StringFormat};
use std::io::{self, Read, Write};
use std::sync::Arc;

pub(super) const MAX_METADATA: usize = 16 * 1024;

// Only bounded direct metadata enters the security library. PDF bodies keep
// their original offsets and physical order in the existing scanner.
fn value(input: &mut Tokens<'_>, token: &[u8], depth: usize) -> Option<Object> {
    if depth > 4 {
        return None;
    }
    match token {
        b"<<" => {
            let mut dict = Dictionary::new();
            loop {
                let key = input.next()?;
                if key == b">>" {
                    return Some(Object::Dictionary(dict));
                }
                let key = key.strip_prefix(b"/")?;
                if key.is_empty() || key.len() > 64 || dict.len() >= 32 || dict.has(key) {
                    return None;
                }
                let token = input.next()?;
                dict.set(key, value(input, token, depth + 1)?);
            }
        }
        b"[" => {
            let mut array = Vec::new();
            loop {
                let item = input.next()?;
                if item == b"]" {
                    return Some(Object::Array(array));
                }
                if array.len() == 8 {
                    return None;
                }
                array.push(value(input, item, depth + 1)?);
            }
        }
        b"true" => Some(Object::Boolean(true)),
        b"false" => Some(Object::Boolean(false)),
        [b'/', name @ ..] if !name.is_empty() && name.len() <= 64 => {
            Some(Object::Name(name.to_vec()))
        }
        [b'<', hex @ .., b'>'] if hex.len() <= 256 && hex.len().is_multiple_of(2) => {
            let bytes = hex
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
                .collect::<Option<_>>()?;
            Some(Object::String(bytes, StringFormat::Hexadecimal))
        }
        _ => {
            let number = std::str::from_utf8(token).ok()?.parse::<i64>().ok()?;
            let mut look = input.clone();
            if let Some(generation) = look.next().and_then(super::number)
                && look.next() == Some(b"R")
            {
                *input = look;
                return Some(Object::Reference((
                    number.try_into().ok()?,
                    generation.try_into().ok()?,
                )));
            }
            Some(Object::Integer(number))
        }
    }
}

fn dictionary(bytes: &[u8]) -> Option<Dictionary> {
    let mut input = Tokens {
        data: &bytes[..bytes.len().min(MAX_METADATA)],
        pos: 0,
    };
    let token = input.next()?;
    let Object::Dictionary(dictionary) = value(&mut input, token, 0)? else {
        return None;
    };
    Some(dictionary)
}

// The only escaped name sampled here is a direct EmbeddedFile MIME subtype.
// Other name escapes can change a PDF type, filter or action.
pub(super) fn embedded_mime(header: &[u8], escaped: &[u8]) -> bool {
    let mut input = Tokens {
        data: &header[..header.len().min(MAX_METADATA)],
        pos: 0,
    };
    if input.next() != Some(b"<<") {
        return false;
    }
    let mut embedded = None;
    let mut subtype = None;
    let mut depth = 1;
    while let Some(token) = input.next() {
        match token {
            b"<<" | b"[" => depth += 1,
            b">>" | b"]" => {
                depth -= 1;
                if depth == 0 {
                    return embedded == Some(true) && subtype == Some(true);
                }
            }
            b"/Type" if depth == 1 && embedded.is_none() => {
                embedded = Some(input.next() == Some(b"/EmbeddedFile"));
            }
            b"/Subtype" if depth == 1 && subtype.is_none() => {
                subtype = Some(
                    input
                        .next()
                        .is_some_and(|v| std::ptr::eq(v, escaped) && mime_name(v)),
                );
            }
            b"/Type" | b"/Subtype" if depth == 1 => return false,
            _ => (),
        }
    }
    false
}

fn mime_name(token: &[u8]) -> bool {
    let Some(name) = token.strip_prefix(b"/") else {
        return false;
    };
    let Some(index) = name.iter().position(|b| *b == b'#') else {
        return false;
    };
    let (kind, rest) = name.split_at(index);
    let Some(subtype) = rest
        .strip_prefix(b"#2f")
        .or_else(|| rest.strip_prefix(b"#2F"))
    else {
        return false;
    };
    [kind, subtype].iter().all(|part| {
        part.len() <= 127
            && part.first().is_some_and(u8::is_ascii_alphanumeric)
            && part.iter().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, b'!' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+')
            })
    })
}

pub(super) struct Stream<'a> {
    pub bytes: &'a [u8],
    pub filters_visible: bool,
    pub explicit: Option<&'a [u8]>,
}

pub(super) fn ciphertext<'a>(
    header: &'a [u8],
    stream: &'a [u8],
    lengths: &std::collections::HashMap<Id, usize>,
) -> Option<Stream<'a>> {
    let mut input = Tokens {
        data: &header[..header.len().min(MAX_METADATA)],
        pos: 0,
    };
    if input.next()? != b"<<" {
        return None;
    }
    let mut depth = 1;
    let mut length = None;
    let mut explicit = None;
    let mut filter_visible = false;
    let mut closed_dictionary = false;
    while depth != 0 {
        match input.next()? {
            b"<<" | b"[" => depth += 1,
            b">>" => {
                closed_dictionary = true;
                depth -= 1;
            }
            b"]" => depth -= 1,
            b"/Filter" if depth == 1 => filter_visible = !closed_dictionary,
            b"/Filter" => return None,
            b"/DecodeParms" if depth == 1 => {
                let rest = &input.data[input.pos..];
                let dict = rest.strip_prefix(b"[").unwrap_or(rest);
                if let Some(val) = dict.strip_prefix(b"<</Name/") {
                    let n = val
                        .iter()
                        .position(|&b| super::white(b) || b"<>/[]()".contains(&b))?;
                    explicit = Some(&val[..n]);
                }
            }
            b"/Length" if depth == 1 => {
                if length.is_some() {
                    return None;
                }
                length = Some(match input.reference() {
                    Some(id) => *lengths.get(&id)?,
                    None => super::number(input.next()?)?,
                });
            }
            _ => (),
        }
    }
    let (cipher, rest) = stream.split_at_checked(length?)?;
    matches!(rest, b"" | b"\n" | b"\r" | b"\r\n").then_some(Stream {
        bytes: cipher,
        filters_visible: filter_visible,
        explicit,
    })
}

/// A standard handler either opens with the empty user password or stays locked.
pub(super) enum Access {
    Open(Box<Security>),
    Locked,
}

pub(super) struct Security {
    state: EncryptionState,
    streams: Arc<dyn CryptFilter>,
    attachments: Arc<dyn CryptFilter>,
}

impl Security {
    pub(super) fn open(id: Id, metadata: &[u8], trailer: &[u8]) -> Option<Access> {
        let id: ObjectId = (id.0.try_into().ok()?, id.1.try_into().ok()?);
        let trailer = dictionary(trailer)?;
        if trailer.get(b"Encrypt").ok()?.as_reference().ok()? != id
            || trailer.has(b"Prev")
            || trailer.has(b"XRefStm")
        {
            return None;
        }
        let dict = dictionary(metadata)?;
        let revision = dict.get(b"R").ok()?.as_i64().ok()?;
        let version = dict.get(b"V").ok()?.as_i64().ok()?;
        let length = dict
            .get(b"Length")
            .ok()
            .map(Object::as_i64)
            .transpose()
            .ok()?
            .unwrap_or(40);
        if dict.get(b"Filter").ok()?.as_name().ok()? != b"Standard"
            || !matches!(
                (revision, version, length),
                (2, 1, 40) | (3, 2, 128) | (4, 4, 128) | (5 | 6, 5, 256)
            )
        {
            return None;
        }
        let mut doc = Document::new();
        doc.trailer.set("ID", trailer.get(b"ID").ok()?.clone());
        doc.trailer.set("Encrypt", Object::Reference(id));
        doc.objects.insert(id, Object::Dictionary(dict));
        if doc.authenticate_raw_user_password(b"").is_err() {
            return Some(Access::Locked);
        }
        let state = EncryptionState::decode(&doc, b"").ok()?;
        let dict = doc.get_encrypted().ok()?;
        let selected = |name: &[u8]| -> Option<Arc<dyn CryptFilter>> {
            if revision < 4 {
                return Some(Arc::new(Rc4CryptFilter));
            }
            if name == b"Identity" || name.is_empty() {
                return Some(Arc::new(IdentityCryptFilter));
            }
            let cf = dict
                .get(b"CF")
                .ok()?
                .as_dict()
                .ok()?
                .get(name)
                .ok()?
                .as_dict()
                .ok()?;
            let method = cf.get(b"CFM").ok()?.as_name().ok()?;
            if !matches!(
                (revision, method),
                (4, b"AESV2" | b"V2") | (5 | 6, b"AESV3")
            ) || cf
                .get(b"Length")
                .is_ok_and(|n| n.as_i64().ok() != Some(length / 8))
                || cf
                    .get(b"AuthEvent")
                    .is_ok_and(|v| !matches!(v.as_name(), Ok(b"DocOpen" | b"EFOpen")))
            {
                return None;
            }
            state
                .crypt_filters()
                .get(name)
                .filter(|f| f.method() == method)
                .cloned()
        };
        let stream_name = dict
            .get(b"StmF")
            .ok()
            .map(Object::as_name)
            .transpose()
            .ok()?
            .unwrap_or(b"Identity");
        let streams = selected(stream_name)?;
        let attachments = match dict.get(b"EFF") {
            Ok(name) => selected(name.as_name().ok()?)?,
            Err(_) => streams.clone(),
        };
        Some(Access::Open(Box::new(Self {
            state,
            streams,
            attachments,
        })))
    }

    pub(super) fn decode(
        &self,
        obj: &super::Object,
        explicit: Option<&[u8]>,
        bytes: &[u8],
        retain: Retain,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Output> {
        let filters = &obj.filters;
        let id = obj.id;
        let filter = if let Some(name) = explicit {
            let Some(filter) = self.state.crypt_filters().get(name) else {
                return Ok(Output::Malformed);
            };
            filter
        } else if obj.embedded {
            &self.attachments
        } else {
            &self.streams
        };
        if filter.method() == b"Identity" || obj.metadata && !self.state.encrypt_metadata() {
            return super::filters::chain(bytes, filters, retain, sink);
        }
        let (Ok(n), Ok(generation)) = (id.0.try_into(), id.1.try_into()) else {
            return Ok(Output::Malformed);
        };
        let Ok(key) = filter.compute_key(self.state.file_encryption_key(), (n, generation)) else {
            return Ok(Output::Malformed);
        };
        match filter.method() {
            b"AESV2" => {
                aes_filters::<cbc::Decryptor<aes::Aes128>>(&key, bytes, filters, retain, sink)
            }
            b"AESV3" => {
                aes_filters::<cbc::Decryptor<aes::Aes256>>(&key, bytes, filters, retain, sink)
            }
            b"V2" => super::filters::chain(Rc4Input::new(bytes, &key), filters, retain, sink),
            _ => Ok(Output::Malformed),
        }
    }
}

struct Rc4Input<'a> {
    data: &'a [u8],
    state: [u8; 256],
    i: u8,
    j: u8,
}
impl<'a> Rc4Input<'a> {
    fn new(data: &'a [u8], key: &[u8]) -> Self {
        let mut state = std::array::from_fn(|i| i as u8);
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, usize::from(j));
        }
        Self {
            data,
            state,
            i: 0,
            j: 0,
        }
    }
}
impl Read for Rc4Input<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let len = self.data.len().min(out.len()).min(8192);
        for (plain, &cipher) in out[..len].iter_mut().zip(self.data) {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[usize::from(self.i)]);
            self.state.swap(usize::from(self.i), usize::from(self.j));
            let t = self.state[usize::from(self.i)].wrapping_add(self.state[usize::from(self.j)]);
            *plain = cipher ^ self.state[usize::from(t)];
        }
        self.data = &self.data[len..];
        Ok(len)
    }
}

struct AesInput<'a, D> {
    decoder: D,
    data: &'a [u8],
    buf: [u8; 8192],
    start: usize,
    end: usize,
    padding: usize,
}
impl<D: BlockModeDecrypt<BlockSize = U16>> Read for AesInput<'_, D> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.start == self.end {
            let n = self.data.len().min(self.buf.len());
            if n == 0 {
                return Ok(0);
            }
            let (chunk, rest) = self.data.split_at(n);
            self.data = rest;
            self.buf[..n].copy_from_slice(chunk);
            self.decoder
                .decrypt_blocks(Block::<D>::slice_as_chunks_mut(&mut self.buf[..n]).0);
            self.start = 0;
            self.end = if rest.is_empty() { n - self.padding } else { n };
        }
        let n = (self.end - self.start).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
        self.start += n;
        Ok(n)
    }
}

// Verify the final padding before accepting a zlib member that ends early.
fn aes_filters<D: BlockModeDecrypt<BlockSize = U16> + KeyIvInit>(
    key: &[u8],
    bytes: &[u8],
    filters: &[Filter],
    retain: Retain,
    sink: &mut dyn ChildSink,
) -> io::Result<Output> {
    if bytes.len() < 32 || !bytes.len().is_multiple_of(16) {
        return Ok(Output::Malformed);
    }
    let end = bytes.len();
    let Ok(last) = D::new_from_slices(key, &bytes[end - 32..end - 16]) else {
        return Ok(Output::Malformed);
    };
    let mut final_block: [u8; 16] = bytes[end - 16..].try_into().expect("one AES block");
    let Ok(tail) = last.decrypt_padded::<Pkcs7>(&mut final_block) else {
        return Ok(Output::Malformed);
    };
    let padding = 16 - tail.len();
    let mut decoder = D::new_from_slices(key, &bytes[..16]).expect("validated key and IV");
    if filters != [Filter::Flate] {
        return super::filters::chain(
            AesInput {
                decoder,
                data: &bytes[16..],
                buf: [0; 8192],
                start: 0,
                end: 0,
                padding,
            },
            filters,
            retain,
            sink,
        );
    }
    let mut zlib = Decompress::new(true);
    let mut compressed = [0; 8192];
    let mut plain = [0; 8192];
    let limit = sink.remaining();
    let mut output = retain.output(limit, sink.temporary_directory());
    let carrier = retain == Retain::Carrier;
    let capacity = super::filters::flate_capacity(limit);
    let mut chunks = bytes[16..].chunks(compressed.len()).peekable();
    while let Some(chunk) = chunks.next() {
        let final_chunk = chunks.peek().is_none();
        let data = &mut compressed[..chunk.len()];
        data.copy_from_slice(chunk);
        decoder.decrypt_blocks(Block::<D>::slice_as_chunks_mut(data).0);
        let mut input = &data[..data.len() - if final_chunk { padding } else { 0 }];
        loop {
            sink.check()?;
            let before_in = zlib.total_in();
            let before_out = zlib.total_out();
            let flush = if final_chunk && input.is_empty() {
                FlushDecompress::Finish
            } else {
                FlushDecompress::None
            };
            let Ok(status) = zlib.decompress(input, &mut plain, flush) else {
                return Ok(Output::Malformed);
            };
            if zlib.total_out() > capacity {
                return Ok(Output::StageLimit(0, capacity.saturating_add(256 * 1024)));
            }
            if zlib.total_out() > limit && !carrier {
                output = None;
            }
            if retain == Retain::Verify && zlib.total_out() > Snapshot::MEMORY_LIMIT as u64 {
                // Each remaining DEFLATE bit can produce at most 129 bytes. Include a pending match.
                let upper = zlib
                    .total_out()
                    .saturating_add(258)
                    .saturating_add((bytes.len() as u64 - zlib.total_in()).saturating_mul(1032));
                if upper > limit {
                    output = None;
                }
            }
            let written = (zlib.total_out() - before_out) as usize;
            if let Some(output) = &mut output {
                output.write_all(&plain[..written])?;
            }
            if status == Status::StreamEnd {
                if zlib.total_out() > limit && !carrier {
                    return Ok(Output::TooLarge(zlib.total_out()));
                }
                return Ok(output.map_or(Output::Counted(zlib.total_out()), Output::Decoded));
            }
            let used = (zlib.total_in() - before_in) as usize;
            input = &input[used..];
            if input.is_empty() && !final_chunk {
                break;
            }
            if written == 0 && used == 0 {
                return Ok(Output::Malformed);
            }
        }
    }
    Ok(Output::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accept_only_direct_embedded_file_mime_subtypes() {
        for (header, expected) in [
            ("<< /Type /EmbeddedFile /Subtype /text#2fplain >>", true),
            (
                "<< /Subtype /application#2Fvnd.openxmlformats-officedocument /Type /EmbeddedFile >>",
                true,
            ),
            ("<< /Type /XObject /Subtype /text#2fplain >>", false),
            (
                "<< /Type /EmbeddedFile /Params << /Subtype /text#2fplain >> >>",
                false,
            ),
            ("<< /Type /EmbeddedFile /Filter /text#2fplain >>", false),
            ("<< /Type /EmbeddedFile /Subtype /text#2fplain#00 >>", false),
            (
                "<< /Type /EmbeddedFile /Subtype /text#2fplain /Subtype /other >>",
                false,
            ),
        ] {
            let bytes = header.as_bytes();
            let mut tokens = Tokens {
                data: bytes,
                pos: 0,
            };
            let name = std::iter::from_fn(|| tokens.next())
                .find(|token| token.contains(&b'#'))
                .unwrap();
            assert_eq!(embedded_mime(bytes, name), expected, "{header}");
        }
    }
}
