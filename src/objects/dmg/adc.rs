//! Apple Data Compression uses a 64 KiB history and three token forms.
use std::io::{self, Read};

pub(super) struct Decoder<'a> {
    input: &'a [u8],
    history: Box<[u8]>,
    position: usize,
    pending: usize,
    distance: usize,
}
impl<'a> Decoder<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            history: vec![0; 65536].into_boxed_slice(),
            position: 0,
            pending: 0,
            distance: 0,
        }
    }
    fn byte(&mut self) -> io::Result<u8> {
        let Some((&b, rest)) = self.input.split_first() else {
            return Err(io::ErrorKind::UnexpectedEof.into());
        };
        self.input = rest;
        Ok(b)
    }
    fn token(&mut self) -> io::Result<()> {
        let code = self.byte()? as usize;
        (self.pending, self.distance) = if code & 128 != 0 {
            (1 + (code & 127), 0)
        } else if code & 64 != 0 {
            let dist = u16::from_be_bytes([self.byte()?, self.byte()?]);
            (4 + (code & 63), 1 + usize::from(dist))
        } else {
            (
                3 + (code >> 2),
                1 + ((code & 3) << 8) + usize::from(self.byte()?),
            )
        };
        if self.distance > self.position {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
}
impl Read for Decoder<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < out.len() {
            if self.pending == 0 {
                if self.input.is_empty() {
                    break;
                }
                self.token()?;
            }
            let byte = if self.distance == 0 {
                self.byte()?
            } else {
                self.history[(self.position - self.distance) % 65536]
            };
            out[n] = byte;
            self.history[self.position % 65536] = byte;
            self.position += 1;
            self.pending -= 1;
            n += 1;
        }
        Ok(n)
    }
}
