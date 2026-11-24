//! Retain the compressed-input boundaries used to check a Flash movie's expanded size.
use lzma_rust2::LzmaReader;
use std::io::{self, Read};

struct Source<'a> {
    bytes: &'a [u8],
    position: usize,
    end: usize,
}

impl Read for Source<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.position == self.end {
            self.end += 8192.min(self.bytes.len() - self.end);
        }
        // Keep lookahead near the block edge small. The caller uses the unread
        // compressed byte count to choose fast bulk output reads.
        let left = self.end - self.position;
        let n = if self.end == self.bytes.len() {
            out.len().min(left)
        } else {
            out.len().min(left).min(512)
        };
        out[..n].copy_from_slice(&self.bytes[self.position..self.position + n]);
        self.position += n;
        Ok(n)
    }
}

pub(super) struct Blocks<'a> {
    decoder: LzmaReader<Source<'a>>,
    next_byte: Option<u8>,
    error: Option<io::Error>,
}

impl<'a> Blocks<'a> {
    pub fn new(bytes: &'a [u8], first: usize, properties: u8, history: u32) -> io::Result<Self> {
        let input = Source {
            bytes,
            position: 0,
            end: bytes.len().min(first),
        };
        let mut decoder = LzmaReader::new_with_props(input, u64::MAX, properties, history, None)?;
        decoder.set_defer_errors(true);
        Ok(Self {
            decoder,
            next_byte: None,
            error: None,
        })
    }
}

impl Read for Blocks<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        let mut written = 0;
        if let Some(byte) = self.next_byte.take() {
            out[0] = byte;
            written = 1;
        }
        while written < out.len() {
            let input = self.decoder.inner();
            let boundary = input.end;
            // One LZMA symbol needs at most 20 input bytes. Bulk reads inside a
            // block are safe. At its edge, assign the first byte requiring new
            // compressed input to the next output block.
            let room = if boundary == input.bytes.len() {
                out.len() - written
            } else {
                (out.len() - written).min(((boundary - input.position) / 32).max(1))
            };
            let n = match self.decoder.read(&mut out[written..written + room]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if written == 0 => return Err(e),
                Err(e) => {
                    self.error = Some(e);
                    break;
                }
            };
            if self.decoder.inner().end != boundary {
                debug_assert_eq!(n, 1);
                if written > 0 {
                    self.next_byte = Some(out[written]);
                    break;
                }
            }
            written += n;
        }
        Ok(written)
    }
}
