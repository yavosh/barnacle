use super::{ChildSink, Handling, decoded};
use std::io::{self, Read};

/// LZSS tokens share a 4 KiB sliding window. Bits run from low to high in each flag byte.
struct Szdd<'a> {
    input: &'a [u8],
    window: [u8; 4096],
    written: usize,
    flags: u16,
    copy_from: usize,
    copy_left: usize,
}

impl Read for Szdd<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < output.len() {
            if self.copy_left == 0 {
                if self.flags <= 1 {
                    let Some((&byte, tail)) = self.input.split_first() else {
                        break;
                    };
                    self.flags = 0x100 | u16::from(byte);
                    self.input = tail;
                }
                if self.input.is_empty() {
                    break;
                }
                let literal = self.flags & 1 != 0;
                self.flags >>= 1;
                if literal {
                    let byte = self.input[0];
                    self.input = &self.input[1..];
                    self.window[self.written] = byte;
                } else {
                    let (pair, tail) = self
                        .input
                        .split_at_checked(2)
                        .ok_or(io::ErrorKind::UnexpectedEof)?;
                    self.input = tail;
                    self.copy_from = usize::from(pair[0]) | (usize::from(pair[1] & 0xf0) << 4);
                    self.copy_left = usize::from(pair[1] & 15) + 3;
                }
            }
            if self.copy_left > 0 {
                self.window[self.written] = self.window[self.copy_from];
                self.copy_from = (self.copy_from + 1) % self.window.len();
                self.copy_left -= 1;
            }
            output[n] = self.window[self.written];
            self.written = (self.written + 1) % self.window.len();
            n += 1;
        }
        Ok(n)
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some((header, input)) = bytes.split_at_checked(14) else {
        return Ok(Handling::Incomplete);
    };
    if &header[..10] != b"SZDD\x88\xf0\x27\x33A\0" {
        return Ok(Handling::Incomplete);
    }
    let size = u64::from(u32::from_le_bytes(header[10..14].try_into().unwrap()));
    if sink.skip_declared_size(size) {
        return Ok(Handling::Complete);
    }
    let reader = Szdd {
        input,
        window: [0; 4096],
        written: 4080,
        flags: 0,
        copy_from: 0,
        copy_left: 0,
    };
    // The reference flushes 2048-byte batches before checking the declared size.
    decoded(
        reader.take(size.max(1).next_multiple_of(2048)),
        None,
        false,
        sink,
    )
}
