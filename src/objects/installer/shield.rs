use super::{ChildSink, Copied, Handling, ISHIELD_MAGIC, Snapshot, copy, is_ishield, le32};
use flate2::bufread::ZlibDecoder;
use std::io::{self, BufReader, Read};

struct Resource<'a> {
    bytes: &'a [u8],
    name: &'a [u8],
    index: usize,
}

impl Read for Resource<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let size = out.len().min(self.bytes.len());
        let (part, rest) = self.bytes.split_at(size);
        for (out, &encoded) in out.iter_mut().zip(part) {
            let index = self.index % self.name.len();
            let key = self.name[index] ^ [0xec, 0xca, 0x79, 0xf8][index % 4];
            *out = encoded.rotate_right(4) ^ key;
            self.index = (self.index + 1) % 1024;
        }
        self.bytes = rest;
        Ok(size)
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if !is_ishield(bytes) {
        return Ok(Handling::Unrecognized);
    }
    let head = &bytes[ISHIELD_MAGIC.len()..];
    if head[8..32].iter().any(|&byte| byte != 0) {
        return Ok(Handling::Incomplete);
    }
    let mut records = &head[32..];
    for _ in 0..le32(head).expect("validated header") {
        sink.check()?;
        let Some((record, tail)) = records.split_at_checked(312) else {
            return Ok(Handling::Incomplete);
        };
        let name = &record[..259];
        let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
        if name.is_empty() {
            return Ok(Handling::Incomplete);
        }
        let length = u64::from_le_bytes(record[268..276].try_into().expect("fixed record"));
        let Ok(length) = usize::try_from(length) else {
            return Ok(Handling::Incomplete);
        };
        let Some((encoded, rest)) = tail.split_at_checked(length) else {
            return Ok(Handling::Incomplete);
        };
        records = rest;
        if length as u64 > sink.max_file_size() {
            continue;
        }
        let input = Resource {
            bytes: encoded,
            name,
            index: 0,
        };
        let mut reader = ZlibDecoder::new(BufReader::new(input));
        let mut decoded = Snapshot::new(sink.temporary_directory());
        let limit = sink.remaining();
        match copy(&mut reader, &mut decoded, limit, sink)? {
            Copied::Complete(_) => {
                if decoded.with_bytes(|bytes| sink.child_bytes(bytes, Some(name)))? {
                    return Ok(Handling::Stopped);
                }
            }
            Copied::Invalid => return Ok(Handling::Incomplete),
            Copied::Limit => {
                sink.skip_declared_size(limit.saturating_add(1));
            }
        }
    }
    Ok(Handling::Complete)
}

fn text_field<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
    let end = bytes
        .get(..bytes.len().min(2048))?
        .iter()
        .position(|&b| b == 0)?;
    let (value, tail) = bytes.split_at(end);
    *bytes = &tail[1..];
    Some(value)
}

fn record(bytes: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let mut tail = bytes;
    let name = text_field(&mut tail)?;
    text_field(&mut tail)?;
    text_field(&mut tail)?;
    let length = std::str::from_utf8(text_field(&mut tail)?)
        .ok()?
        .parse::<usize>()
        .ok()?;
    // This resource format leaves a terminator after the last file.
    if name.is_empty() || length >= tail.len() {
        return None;
    }
    let (data, next) = tail.split_at(length);
    Some((name, data, next))
}

fn cabinet_number(name: &[u8]) -> Option<u16> {
    if name.len() < 9
        || !name[..4].eq_ignore_ascii_case(b"data")
        || !name[name.len() - 4..].eq_ignore_ascii_case(b".cab")
    {
        return None;
    }
    let number: u16 = std::str::from_utf8(&name[4..name.len() - 4])
        .ok()?
        .parse()
        .ok()?;
    (number != 0).then_some(number)
}

pub(in crate::objects) fn legacy(
    mut bytes: &[u8],
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let mut header = None;
    let mut cabinets = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut found = false;
    while let Some((name, data, next)) = record(bytes) {
        sink.check()?;
        found = true;
        bytes = next;
        if name.eq_ignore_ascii_case(b"data1.hdr") && header.is_none() {
            header = Some(data);
        } else if let Some(number) = cabinet_number(name)
            && seen.insert(number)
        {
            cabinets.push(data);
        } else if sink.child_bytes(data, None)? {
            return Ok(Handling::Stopped);
        }
    }
    if !found {
        return Ok(Handling::Unrecognized);
    }
    if header.is_some_and(|h| h.starts_with(b"ISc(")) && !cabinets.is_empty() {
        // Members described by this separate InstallShield cabinet directory
        // precede any raw cabinet scan.
        return Ok(Handling::Incomplete);
    }
    for data in header.into_iter().chain(cabinets) {
        if sink.child_bytes(data, None)? {
            return Ok(Handling::Stopped);
        }
    }
    Ok(Handling::Complete)
}
