//! Parse ordinary HWP3 paragraph contents and trailing information records.
use super::{ChildSink, Handling, xml};
use std::io;

fn take<'a>(input: &mut &'a [u8], length: usize) -> io::Result<&'a [u8]> {
    input
        .split_off(..length)
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
}
fn u16le(bytes: &[u8], at: usize) -> usize {
    u16::from_le_bytes([bytes[at], bytes[at + 1]]) as usize
}
fn word(input: &mut &[u8]) -> io::Result<u32> {
    Ok(u32::from_le_bytes(take(input, 4)?.try_into().unwrap()))
}

fn paragraphs(input: &mut &[u8], sink: &mut dyn ChildSink) -> io::Result<()> {
    loop {
        sink.check()?;
        let header = take(input, 43)?;
        let chars = u16le(header, 1);
        if chars == 0 {
            return Ok(());
        }
        if header[0] == 0 {
            take(input, 230 - 43)?;
        }
        take(input, u16le(header, 3) * 14)?;
        if header[5] != 0 {
            for _ in 0..chars {
                match take(input, 1)?[0] {
                    0 => {
                        take(input, 31)?;
                    }
                    1 => {}
                    _ => return Err(io::ErrorKind::InvalidData.into()),
                }
            }
        }
        let mut n = 0usize;
        loop {
            if n.is_multiple_of(4096) {
                sink.check()?;
            }
            n += 1;
            let code = u16le(take(input, 2)?, 0);
            match code {
                13 => break,
                9 => {
                    take(input, 6)?;
                }
                32.. => {}
                _ => return Err(io::ErrorKind::Unsupported.into()),
            }
        }
    }
}

fn visit(sink: &mut dyn ChildSink, bytes: &[u8]) -> io::Result<Option<Handling>> {
    if bytes.len() <= 5 {
        return Ok(None);
    }
    if sink.skip_declared_size(bytes.len() as u64) {
        return Ok(Some(Handling::Complete));
    }
    Ok(sink.child_bytes(bytes, None)?.then_some(Handling::Stopped))
}

fn body(all: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let mut rest = all;
    for stride in [40, 40, 40, 40, 40, 40, 40, 238] {
        let n = u16le(take(&mut rest, 2)?, 0);
        take(&mut rest, n * stride)?;
    }
    paragraphs(&mut rest, sink)?;
    loop {
        sink.check()?;
        let kind = word(&mut rest)?;
        if kind == 5 {
            continue;
        }
        let len = word(&mut rest)? as usize;
        let bytes = take(&mut rest, len)?;
        let data = match kind {
            0 if len == 0 => break,
            0 => return Ok(Handling::Complete),
            1 => bytes.get(32..),
            2 => Some(bytes),
            3 => {
                let (items, tail) = bytes.as_chunks::<617>();
                if !tail.is_empty() {
                    return Ok(Handling::Complete);
                }
                for item in items {
                    if let Some(result) = visit(sink, &item[288..613])? {
                        return Ok(result);
                    }
                }
                None
            }
            4 | 0x100 | 0x101 => None,
            6 => bytes.get(324..),
            _ => Some(bytes),
        };
        if let Some(data) = data
            && let Some(result) = visit(sink, data)?
        {
            return Ok(result);
        }
    }
    Ok(visit(sink, &all[..all.len() - rest.len()])?.unwrap_or(Handling::Complete))
}

pub(super) fn extract(
    bytes: &[u8],
    max_recursion: usize,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let Some(info) = bytes.get(30..158) else {
        return Ok(Handling::Complete);
    };
    if u16le(info, 96) != 0 {
        return Ok(Handling::Incomplete);
    }
    if max_recursion == 0 {
        return Ok(Handling::Complete);
    }
    let Some(mut content) = bytes.get(1166 + u16le(info, 126)..) else {
        return Ok(Handling::Complete);
    };
    let result = if info[124] == 0 {
        body(content, sink)
    } else {
        let (data, partial) = xml::inflate_hwp(&mut content, sink)?;
        data.with_bytes(|b| {
            if partial {
                Ok(visit(sink, b)?.unwrap_or(Handling::Complete))
            } else {
                body(b, sink)
            }
        })
    };
    match result {
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData
            ) =>
        {
            Ok(Handling::Complete)
        }
        Err(e) if e.kind() == io::ErrorKind::Unsupported => Ok(Handling::Incomplete),
        other => other,
    }
}
