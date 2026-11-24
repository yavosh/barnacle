use super::{ChildSink, Handling, decoded};
use bzip2::read::BzDecoder;
use flate2::read::DeflateDecoder;
use std::io::{self, Read};

struct Member<'a> {
    attributes: u8,
    flags: u8,
    method: u8,
    size: u64,
    name: &'a [u8],
    data: &'a [u8],
}

fn take<'a>(input: &mut &'a [u8], size: usize) -> Result<&'a [u8], ()> {
    input.split_off(..size).ok_or(())
}

fn size(bytes: &[u8]) -> u64 {
    let mut word = [0; 8];
    word[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(word)
}

fn next<'a>(input: &mut &'a [u8]) -> Result<Option<Member<'a>>, ()> {
    while !input.is_empty() {
        match take(input, 4)? {
            b"CLZ\x02" => return Ok(None),
            b"CLZ\x01" => {
                take(input, 8)?;
                continue;
            }
            b"BLZ\x01" => {}
            _ => return Err(()),
        }
        let head = take(input, 9)?;
        let name_len = u16::from_le_bytes([head[0], head[1]]);
        let flags = head[7];
        let width = usize::from(flags >> 4);
        if name_len == 0 || !matches!(width, 0 | 1 | 2 | 4 | 8) {
            return Err(());
        }
        let (method, packed, unpacked) = if width == 0 {
            (0, 0, 0)
        } else {
            let method = take(input, 6)?[0];
            (method, size(take(input, width)?), size(take(input, width)?))
        };
        let name = take(input, usize::from(name_len))?;
        if flags & 1 != 0 {
            take(input, 12)?;
        }
        let data = take(input, usize::try_from(packed).map_err(|_| ())?)?;
        return Ok(Some(Member {
            attributes: head[2],
            flags,
            method,
            size: unpacked,
            name,
            data,
        }));
    }
    Ok(None)
}

struct ExactBzip<'a>(io::Take<BzDecoder<&'a [u8]>>);

impl Read for ExactBzip<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.0.read(out)?;
        if n == 0 && !out.is_empty() && self.0.limit() != 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(n)
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(mut records) = bytes.get(8..) else {
        return Ok(Handling::Incomplete);
    };
    // Stock finishes parsing the record sequence before it scans the first file.
    // Validate the sequence first without retaining an index or expanded members.
    let mut check = records;
    loop {
        sink.check()?;
        match next(&mut check) {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(()) => return Ok(Handling::Incomplete),
        }
    }

    let mut result = Handling::Complete;
    while let Ok(Some(file)) = next(&mut records) {
        sink.check()?;
        if file.flags & 9 != 0 || file.method > 2 {
            result = Handling::Incomplete;
            continue;
        }
        if file.attributes & 0x10 != 0 || file.data.is_empty() {
            continue;
        }
        let name = String::from_utf8_lossy(file.name);
        let name = Some(name.as_bytes());
        let scanned = match file.method {
            0 => {
                let mut contents = file.data.take(file.size);
                if contents.limit() == 0 {
                    continue;
                }
                decoded(&mut contents, name, false, sink)?
            }
            1 if file.size == 0 => continue,
            1 => decoded(
                ExactBzip(BzDecoder::new(file.data).take(file.size)),
                name,
                false,
                sink,
            )?,
            2 if records.is_empty() => Handling::Incomplete,
            2 => decoded(DeflateDecoder::new(file.data), name, false, sink)?,
            _ => unreachable!(),
        };
        match scanned {
            Handling::Stopped => return Ok(scanned),
            Handling::Incomplete => result = scanned,
            _ => {}
        }
    }
    Ok(result)
}
