//! Record data attribute locations while normalizing. Stock scans them after the HTML views.
use super::{ChildSink, Handling};
use std::io::{self, Cursor, Read, Seek, Write};

pub(super) struct DataUrls {
    offsets: tempfile::SpooledTempFile,
    input_len: usize,
}

impl DataUrls {
    pub(super) fn new(size: usize, sink: &dyn ChildSink) -> Self {
        Self {
            offsets: tempfile::spooled_tempfile_in(4096, sink.temporary_directory()),
            input_len: size,
        }
    }
    pub(super) fn push(&mut self, tail_after_value: usize, value_len: usize) -> io::Result<()> {
        let end = self.input_len - tail_after_value;
        let start = end - value_len;
        self.offsets.write_all(&(start as u64).to_le_bytes())?;
        self.offsets.write_all(&(end as u64).to_le_bytes())
    }
    pub(super) fn scan(mut self, input: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
        let count = self.offsets.stream_position()? / 16;
        self.offsets.rewind()?;
        for _ in 0..count {
            sink.check()?;
            let mut pair = [0; 16];
            self.offsets.read_exact(&mut pair)?;
            let start = u64::from_le_bytes(pair[..8].try_into().unwrap()) as usize;
            let end = u64::from_le_bytes(pair[8..].try_into().unwrap()) as usize;
            let value = &input[start + 5..end];
            let Some(comma) = value.iter().take(1024).position(|&b| b == b',') else {
                return Ok(Handling::Incomplete);
            };
            let media = &value[..comma];
            if media.iter().any(|c| !c.is_ascii_graphic()) {
                return Ok(Handling::Incomplete);
            }
            let mut header = b"From html-normalise\nContent-type: ".to_vec();
            header.extend(media.iter().map(u8::to_ascii_lowercase));
            header.push(b'\n');
            if media.windows(7).any(|s| s.eq_ignore_ascii_case(b";base64")) {
                header.extend_from_slice(b"Content-transfer-encoding: base64\n");
            }
            header.push(b'\n');
            let mut child = Cursor::new(header).chain(Decoded(&value[comma + 1..]));
            if sink.child(&mut child, None, None)? {
                return Ok(Handling::Stopped);
            }
        }
        Ok(Handling::Complete)
    }
}

struct Decoded<'a>(&'a [u8]);

impl Read for Decoded<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        for (i, out) in buf.iter_mut().enumerate() {
            let Some((&b, rest)) = self.0.split_first() else {
                return Ok(i);
            };
            if b == b'%' {
                let hex = rest
                    .get(..2)
                    .and_then(|v| std::str::from_utf8(v).ok())
                    .and_then(|v| u8::from_str_radix(v, 16).ok());
                *out = hex.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid HTML data URL percent encoding",
                    )
                })?;
                self.0 = &rest[2..];
            } else {
                *out = b;
                self.0 = rest;
            }
        }
        Ok(buf.len())
    }
}
