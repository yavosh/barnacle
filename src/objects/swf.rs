//! A compressed Flash movie produces one child with its original eight-byte FWS header.
use super::{ChildSink, Handling};
use flate2::{Decompress, FlushDecompress, Status};
mod lzma;
use std::io::{self, Read};

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(header) = bytes.get(..8) else {
        return Ok(Handling::Complete);
    };
    let mut fws: [u8; 8] = header.try_into().expect("eight-byte Flash header");
    fws[0] = b'F';
    let declared = u32::from_le_bytes(fws[4..].try_into().expect("Flash file length"));
    match &header[..3] {
        b"FWS" => Ok(Handling::Complete),
        b"CWS" => scan(fws, ZlibBlocks::new(&bytes[8..]), sink),
        b"ZWS" => {
            let Some(properties) = bytes.get(12..17) else {
                return Ok(Handling::Incomplete);
            };
            let dict = u32::from_le_bytes(properties[1..].try_into().expect("dictionary length"));
            // Stock caps an individual allocation at 1 GiB. Only the output prefix
            // that can reach the scanner needs to be retained as decoder history.
            if dict > 1 << 30 {
                return Ok(Handling::Incomplete);
            }
            let (max_output, header_end) = if declared == 0 {
                let Some(size) = bytes.get(17..25) else {
                    return Ok(Handling::Incomplete);
                };
                (
                    u64::from_le_bytes(size.try_into().expect("LZMA length")),
                    25,
                )
            } else {
                (u64::from(declared), 17)
            };
            let history = u64::from(dict)
                .min(max_output)
                .min(sink.remaining().saturating_add(8192)) as u32;
            // A valid end marker can occur before the declared size, which includes the header.
            match lzma::Blocks::new(
                &bytes[header_end..],
                8192 - (header_end - 12),
                properties[0],
                history,
            ) {
                Ok(decoder) => scan(fws, decoder.take(max_output), sink),
                Err(_) => Ok(Handling::Incomplete),
            }
        }
        _ => Ok(Handling::Unrecognized),
    }
}

struct ZlibBlocks<'a> {
    bytes: &'a [u8],
    decoder: Decompress,
    done: bool,
    failed: bool,
}

impl<'a> ZlibBlocks<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            decoder: Decompress::new(true),
            done: false,
            failed: false,
        }
    }
}

impl Read for ZlibBlocks<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while !self.done && !out.is_empty() {
            if self.failed {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid compressed Flash stream",
                ));
            }
            let before = self.decoder.total_in() as usize;
            let input = &self.bytes[before..];
            if input.is_empty() {
                break;
            }
            let n = input.len().min(8192 - before % 8192);
            let start = self.decoder.total_out();
            let status = self
                .decoder
                .decompress(&input[..n], out, FlushDecompress::Sync);
            self.done = matches!(status, Ok(Status::StreamEnd));
            let written = (self.decoder.total_out() - start) as usize;
            self.failed =
                status.is_err() || self.decoder.total_in() as usize == before && written == 0;
            if written != 0 {
                return Ok(written);
            }
        }
        Ok(0)
    }
}

// Stock checks each block of inflated output before admitting the entire block.
// Earlier blocks remain available for scanning when the next block exceeds a limit.
struct Blocks<R> {
    decoder: R,
    block: [u8; 8192],
    start: usize,
    end: usize,
    size: u64,
    limit: u64,
    rejected_size: Option<u64>,
    failed: bool,
}

impl<R: Read> Blocks<R> {
    fn next(&mut self) {
        self.start = 0;
        self.end = 0;
        match self.decoder.read(&mut self.block) {
            Ok(n) if self.size + n as u64 <= self.limit => {
                self.end = n;
                self.size += n as u64;
            }
            Ok(n) => self.rejected_size = Some(self.size + n as u64),
            Err(_) => self.failed = true,
        }
    }
}

impl<R: Read> Read for Blocks<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.rejected_size.is_some() || self.failed {
            return Ok(0);
        }
        if self.start == self.end {
            self.next();
        }
        let n = out.len().min(self.end - self.start);
        out[..n].copy_from_slice(&self.block[self.start..self.start + n]);
        self.start += n;
        Ok(n)
    }
}

fn scan<R: Read>(header: [u8; 8], decoder: R, sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let limit = sink.remaining();
    let mut body = Blocks {
        decoder,
        block: [0; 8192],
        start: 0,
        end: 0,
        size: 8,
        limit,
        rejected_size: None,
        failed: false,
    };
    body.next();
    if body.failed {
        return Ok(Handling::Incomplete);
    }
    let child = sink.read_child(&mut header.as_slice().chain(&mut body))?;
    if let Some(size) = body.rejected_size {
        sink.skip_declared_size(size);
    }
    let failed = body.failed;
    drop(body);
    let stopped = match child {
        Some(child) => sink.visit_snapshot(child, None, None)?,
        None => false,
    };
    Ok(if stopped {
        Handling::Stopped
    } else if failed {
        Handling::Incomplete
    } else {
        Handling::Complete
    })
}
