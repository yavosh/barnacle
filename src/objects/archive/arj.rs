use super::{ChildSink, Handling, decoded};
use delharc::decode::{Decoder, Lh7Decoder};
use std::io::{self, Read};

fn header<'a>(input: &mut &'a [u8]) -> Result<Option<&'a [u8]>, ()> {
    if input.split_off(..2) != Some(&[0x60, 0xea]) {
        return Err(());
    }
    let len = |bytes: &mut &[u8]| {
        let field: [u8; 2] = bytes.split_off(..2)?.try_into().ok()?;
        Some(usize::from(u16::from_le_bytes(field)))
    };
    let size = len(input).ok_or(())?;
    if size == 0 {
        return Ok(None);
    }
    if !(30..=2600).contains(&size) {
        return Err(());
    }
    let data = input.split_off(..size).ok_or(())?;
    let fixed = usize::from(data[0]);
    if !(30..=size).contains(&fixed) || !data[fixed..].contains(&0) {
        return Err(());
    }
    input.split_off(..4).ok_or(())?; // Header CRC.
    loop {
        let extra = len(input).ok_or(())?;
        if extra == 0 {
            return Ok(Some(data));
        }
        input.split_off(..extra + 4).ok_or(())?;
    }
}

struct Huffman<'a>(Lh7Decoder<&'a [u8]>);

impl Read for Huffman<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.0.fill_buffer(out)?;
        Ok(out.len())
    }
}

// Method 4 encodes literals and backward copies using variable-width integers.
struct Fastest<'a> {
    input: &'a [u8],
    byte: u8,
    bits: u8,
    history: Box<[u8]>,
    position: usize,
    distance: usize,
    count: usize,
}

impl Fastest<'_> {
    fn number(&mut self, width: u8) -> io::Result<usize> {
        let mut result = 0;
        for _ in 0..width {
            if self.bits == 0 {
                self.byte = *self
                    .input
                    .split_off_first()
                    .ok_or(io::ErrorKind::UnexpectedEof)?;
                self.bits = 8;
            }
            self.bits -= 1;
            result = (result << 1) | usize::from((self.byte >> self.bits) & 1);
        }
        Ok(result)
    }

    fn code(&mut self, first: u8, last: u8) -> io::Result<usize> {
        let mut width = first;
        while width < last && self.number(1)? != 0 {
            width += 1;
        }
        Ok((1 << width) - (1 << first) + self.number(width)?)
    }
}

impl Read for Fastest<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let size = self.history.len();
        for dst in out.iter_mut() {
            if self.count == 0 {
                let len = self.code(0, 7)?;
                if len == 0 {
                    *dst = self.number(8)? as u8;
                } else {
                    self.count = len + 2;
                    self.distance = self.code(9, 13)? + 1;
                }
            }
            if self.count != 0 {
                *dst = self.history[(self.position + size - self.distance) % size];
                self.count -= 1;
            }
            self.history[self.position] = *dst;
            self.position = (self.position + 1) % size;
        }
        Ok(out.len())
    }
}

pub(super) fn extract(mut bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if !matches!(header(&mut bytes), Ok(Some(_))) {
        return Ok(Handling::Incomplete);
    }
    let mut result = Handling::Complete;
    loop {
        sink.check()?;
        let head = match header(&mut bytes) {
            Ok(Some(head)) => head,
            Ok(None) => return Ok(result),
            Err(()) => return Ok(Handling::Incomplete),
        };
        let packed = u32::from_le_bytes(head[12..16].try_into().unwrap());
        let unpacked = u32::from_le_bytes(head[16..20].try_into().unwrap());
        let Some(data) = bytes.split_off(..packed as usize) else {
            return Ok(Handling::Incomplete);
        };
        if sink.skip_declared_size(u64::from(unpacked.max(packed))) {
            // The pinned scanner stops at the rejected member's data.
            return Ok(result);
        }
        if head[4] & 1 != 0 || head[5] > 4 {
            result = Handling::Incomplete;
            continue;
        }
        let name = head[usize::from(head[0])..].split(|&b| b == 0).next();
        let scanned = match head[5] {
            0 => decoded(data, name, false, sink)?,
            1..=3 => decoded(
                Huffman(Lh7Decoder::new(data)).take(u64::from(unpacked)),
                name,
                false,
                sink,
            )?,
            4 => {
                let stream = Fastest {
                    input: data,
                    byte: 0,
                    bits: 0,
                    history: vec![0; 26624].into_boxed_slice(),
                    position: 0,
                    distance: 0,
                    count: 0,
                };
                decoded(stream.take(u64::from(unpacked)), name, false, sink)?
            }
            _ => unreachable!(),
        };
        if scanned != Handling::Complete {
            return Ok(scanned);
        }
    }
}
