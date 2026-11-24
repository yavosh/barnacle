use super::{ChildSink, Handling, decoded};
use std::io::{self, Read};

const ALPHABET: &[u8; 64] = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[\x60abcdefhijklmpqr";
const VALUES: [u8; 128] = {
    let mut values = [255; 128];
    let mut i = 0;
    while i < ALPHABET.len() {
        values[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    values
};

#[derive(Default)]
struct Decoder<'a> {
    encoded: &'a [u8],
    bits: u16,
    bit_count: u8,
    last: u8,
    run: u8,
}

impl Decoder<'_> {
    fn octet(&mut self) -> io::Result<Option<u8>> {
        while self.bit_count < 8 {
            let Some((&c, rest)) = self.encoded.split_first() else {
                return Ok(None);
            };
            self.encoded = rest;
            if matches!(c, b':' | b'\r' | b'\n') {
                continue;
            }
            let value = VALUES.get(usize::from(c)).copied().unwrap_or(255);
            if value == 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid BinHex character",
                ));
            }
            self.bits = (self.bits << 6) | u16::from(value);
            self.bit_count += 6;
        }
        self.bit_count -= 8;
        Ok(Some((self.bits >> self.bit_count) as u8))
    }
}

impl Read for Decoder<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < out.len() {
            if self.run == 0 {
                let Some(value) = self.octet()? else { break };
                if value == 0x90 {
                    match self.octet()? {
                        None => return Err(io::ErrorKind::UnexpectedEof.into()),
                        Some(0) => {}
                        Some(count) => {
                            self.run = count - 1;
                            continue;
                        }
                    }
                }
                self.last = value;
                self.run = 1;
            }
            let take = usize::from(self.run).min(out.len() - n);
            out[n..n + take].fill(self.last);
            n += take;
            self.run -= take as u8;
        }
        Ok(n)
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(line_end) = bytes.iter().position(|&b| matches!(b, b'\n' | b'\r')) else {
        return Ok(Handling::Incomplete);
    };
    let start = bytes[line_end..]
        .iter()
        .position(|&b| !matches!(b, b'\n' | b'\r'));
    let Some(encoded) = start.and_then(|i| bytes[line_end + i..].strip_prefix(b":")) else {
        return Ok(Handling::Incomplete);
    };
    let mut input = Decoder {
        encoded,
        ..Default::default()
    };
    let mut header = [0; 255 + 21];
    let mut length = [0; 1];
    if input.read_exact(&mut length).is_err() {
        return Ok(Handling::Incomplete);
    }
    let name_len = usize::from(length[0]);
    if input.read_exact(&mut header[..name_len + 21]).is_err() {
        return Ok(Handling::Incomplete);
    }
    // The Finder metadata ends with both fork sizes and the two-byte header CRC.
    let sizes = &header[name_len + 11..name_len + 19];
    let data = u32::from_be_bytes(sizes[..4].try_into().unwrap());
    let resource = u32::from_be_bytes(sizes[4..].try_into().unwrap());
    if sink.skip_declared_size(u64::from(data)) {
        return Ok(Handling::Complete);
    }
    let skip_resource = sink.skip_declared_size(u64::from(resource));
    let mut fork = (&mut input).take(u64::from(data));
    let result = decoded(&mut fork, None, false, sink)?;
    if result != Handling::Complete {
        return Ok(result);
    }
    if fork.limit() != 0 {
        return Ok(Handling::Incomplete);
    }
    if skip_resource || resource < 5 {
        return Ok(Handling::Complete);
    }
    if input.read_exact(&mut [0; 2]).is_err() {
        return Ok(Handling::Incomplete);
    }
    let mut fork = input.take(u64::from(resource));
    let result = decoded(&mut fork, None, false, sink)?;
    if result == Handling::Complete && fork.limit() != 0 {
        return Ok(Handling::Incomplete);
    }
    Ok(result)
}
