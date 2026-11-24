//! Extract the native data of objects embedded in rich text.
use super::{ChildSink, Handling, Snapshot};
use std::io::{self, Write};

fn number(input: &mut &[u8]) -> Option<usize> {
    let (field, rest) = input.split_first_chunk::<4>()?;
    *input = rest;
    Some(u32::from_le_bytes(*field) as usize)
}

fn skip_string(input: &mut &[u8]) -> Option<()> {
    let end = input.iter().position(|&b| b == 0)?;
    *input = &input[end + 1..];
    Some(())
}

fn native_data(mut data: &[u8]) -> Option<&[u8]> {
    if data.starts_with(&[0xd0, 0xcf]) {
        return Some(data);
    }
    // A Package has a type, two names, an eight-byte field and a source path
    // before the attachment length. All paths remain metadata.
    data = data.get(2..)?;
    skip_string(&mut data)?;
    skip_string(&mut data)?;
    data = data.get(8..)?;
    skip_string(&mut data)?;
    let length = number(&mut data)?;
    Some(&data[..length.min(data.len())])
}

fn visit_data(mut bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    while !bytes.is_empty() {
        sink.check()?;
        let Some(mut record) = bytes.strip_prefix(b"\x01\x05\0\0\x02\0\0\0") else {
            return Ok(Handling::Incomplete);
        };
        let Some(mut record) = number(&mut record).and_then(|n| record.get(n.checked_add(8)?..))
        else {
            return Ok(Handling::Incomplete);
        };
        let Some(n) = number(&mut record) else {
            return Ok(Handling::Incomplete);
        };
        let (data, rest) = record.split_at(n.min(record.len()));
        let Some(mut child) = native_data(data) else {
            return Ok(Handling::Incomplete);
        };
        if sink.child(&mut child, None, None)? {
            return Ok(Handling::Stopped);
        }
        if data.len() < n {
            return Ok(Handling::Incomplete);
        }
        bytes = rest;
    }
    Ok(Handling::Complete)
}

fn decode(hex: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let mut snapshot = Snapshot::new(sink.temporary_directory());
    let mut high = None;
    {
        let mut out = io::BufWriter::new(&mut snapshot);
        for chunk in hex.chunks(8192) {
            sink.check()?;
            for &b in chunk {
                if b.is_ascii_whitespace() {
                    continue;
                }
                let Some(n) = char::from(b).to_digit(16) else {
                    return Ok(Handling::Incomplete);
                };
                if let Some(first) = high.take() {
                    out.write_all(&[first | n as u8])?;
                } else {
                    high = Some((n as u8) << 4);
                }
            }
        }
        out.flush()?;
    }
    snapshot.with_bytes(|bytes| visit_data(bytes, sink))
}

pub(super) fn extract(input: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let (mut pos, mut depth, mut next_check) = (0usize, 0usize, 0usize);
    let mut object_depth = None;
    while pos < input.len() {
        if pos >= next_check {
            sink.check()?;
            next_check = pos + 8192;
        }
        match input[pos] {
            b'{' => depth += 1,
            b'}' => {
                if object_depth == Some(depth) {
                    object_depth = None;
                }
                let Some(parent) = depth.checked_sub(1) else {
                    return Ok(Handling::Incomplete);
                };
                depth = parent;
            }
            b'\\' => {
                pos += 1;
                let start = pos;
                while input.get(pos).is_some_and(u8::is_ascii_alphabetic) {
                    pos += 1;
                }
                match &input[start..pos] {
                    b"bin" => return Ok(Handling::Incomplete),
                    b"object" if object_depth.is_none() => object_depth = Some(depth),
                    b"objdata" if object_depth.is_some() && input.get(pos) == Some(&b' ') => {
                        let start = pos + 1;
                        let mut end = start;
                        for chunk in input[start..].chunks(8192) {
                            sink.check()?;
                            let take = chunk
                                .iter()
                                .position(|b| matches!(b, b'{' | b'}' | b'\\'))
                                .unwrap_or(chunk.len());
                            end += take;
                            if take < chunk.len() {
                                break;
                            }
                        }
                        if input.get(end) != Some(&b'}') {
                            return Ok(Handling::Incomplete);
                        }
                        let result = decode(&input[start..end], sink)?;
                        if result != Handling::Complete {
                            return Ok(result);
                        }
                        pos = end;
                        continue;
                    }
                    _ => {}
                }
                if start < pos {
                    continue;
                }
                // An escaped brace, backslash, or control symbol is literal here.
            }
            _ => {}
        }
        pos += 1;
    }
    Ok(if depth == 0 {
        Handling::Complete
    } else {
        Handling::Incomplete
    })
}
