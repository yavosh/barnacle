//! Bounded readers for sampled PDF stream filters.
mod lzw;
use crate::objects::{ChildSink, Snapshot};
use flate2::read::ZlibDecoder;
use std::io::{self, Read, Write};
#[derive(Clone, Copy, PartialEq)]
pub(super) enum Filter {
    Flate,
    Lzw,
    Hex,
    Ascii85,
    RunLength,
    Jpeg,
    Crypt,
    Unsupported,
}
pub(super) enum Output {
    Decoded(Snapshot),
    TooLarge(u64),
    StageLimit(usize, u64),
    UseInput,
    Counted(u64),
    Malformed,
}

impl Filter {
    pub(super) fn parse(name: &[u8]) -> Self {
        match name {
            b"/Crypt" => Self::Crypt,
            b"/LZWDecode" | b"/LZW" => Self::Lzw,
            b"/FlateDecode" | b"/Fl" => Self::Flate,
            b"/ASCIIHexDecode" | b"/AHx" => Self::Hex,
            b"/ASCII85Decode" | b"/A85" => Self::Ascii85,
            b"/RunLengthDecode" | b"/RL" => Self::RunLength,
            b"/DCTDecode" | b"/DCT" => Self::Jpeg,
            _ => Self::Unsupported,
        }
    }
    pub(super) fn dumped(&self) -> bool {
        matches!(self, Self::Flate | Self::Hex | Self::Ascii85 | Self::Jpeg)
    }
    pub(super) fn decode(
        self,
        data: &[u8],
        limit: u64,
        retain: bool,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Output> {
        if self == Self::Lzw {
            return lzw::decode(data, limit, retain, sink);
        }
        let source = self.reader(data)?;
        let mut source = source.take(limit.saturating_add(1));
        let mut snapshot = retain.then(|| Snapshot::new(sink.temporary_directory()));
        let mut buf = [0; 8192];
        let mut size = 0;
        loop {
            sink.check()?;
            let n = match source.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                // The filter reads only the immutable PDF bytes. Check and scratch
                // errors arise separately and retain their original error kinds.
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::InvalidData
                            | io::ErrorKind::InvalidInput
                            | io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    return Ok(Output::Malformed);
                }
                Err(e) => return Err(e),
            };
            size += n as u64;
            if size > limit {
                return Ok(Output::TooLarge(size));
            }
            if let Some(file) = &mut snapshot {
                file.write_all(&buf[..n])?;
            }
        }
        Ok(snapshot.map_or(Output::Counted(size), Output::Decoded))
    }
    fn reader<'a>(self, data: impl Source + 'a) -> io::Result<Box<dyn Read + 'a>> {
        Ok(match self {
            Self::Flate => Box::new(ZlibDecoder::new(data)),
            Self::Hex => Box::new(Hex(data)),
            Self::Ascii85 => Box::new(Ascii85 {
                input: data,
                next: [0; 4],
                cursor: 0,
                len: 0,
                done: false,
            }),
            Self::RunLength => Box::new(Runs {
                input: data,
                done: false,
                repeat: None,
                left: 0,
            }),
            _ => return Err(invalid()),
        })
    }
}
// Stock skips one leading CR. When inflation writes nothing, it retries once
// after the next line break and otherwise keeps the stream bytes. Report only
// inputs whose zlib headers fail at both points before producing output.
pub(super) fn flate_fails_at_start(data: &[u8]) -> bool {
    let header_fails = |d: &[u8]| match d {
        [cmf, flg, ..] => {
            (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 != 0 || cmf & 0x0f != 8 || cmf >> 4 > 7
        }
        _ => false,
    };
    let data = data.strip_prefix(b"\r").unwrap_or(data);
    if !header_fails(data) {
        return false;
    }
    let line = |b: &u8| matches!(b, b'\n' | b'\r');
    let Some(at) = data.iter().position(line) else {
        return true;
    };
    let retry = &data[at..];
    let retry = &retry[retry.iter().position(|b| !line(b)).unwrap_or(retry.len())..];
    retry.is_empty() || header_fails(retry)
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid PDF filter data")
}
struct Hex<S>(S);
impl<S: Source> Read for Hex<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut used = 0;
        while used < out.len() {
            let input = self.0.look(4)?;
            if input.len() < 2 || input[0] == b'>' {
                break;
            }
            if input[0] == b' ' {
                self.0.advance(1);
                continue;
            }
            match (
                char::from(input[0]).to_digit(16),
                char::from(input[1]).to_digit(16),
            ) {
                (Some(a), Some(b)) => {
                    out[used] = (a * 16 + b) as u8;
                    used += 1;
                    self.0.advance(2);
                }
                _ if input.len() < 4 => self.0.advance(1),
                _ => return Err(invalid()),
            }
        }
        Ok(used)
    }
}
struct Ascii85<S> {
    input: S,
    next: [u8; 4],
    cursor: usize,
    len: usize,
    done: bool,
}
impl<S: Source> Ascii85<S> {
    fn group(&mut self) -> io::Result<()> {
        let mut value = 0u64;
        let mut n = 0usize;
        self.cursor = 0;
        while let Some(b) = self.input.byte()? {
            match b {
                b'~' => {
                    if self.input.byte()? != Some(b'>') {
                        return Err(invalid());
                    }
                    self.done = true;
                    break;
                }
                b'z' if n == 0 => {
                    self.next = [0; 4];
                    self.len = 4;
                    return Ok(());
                }
                b'!'..=b'u' => {
                    value = value * 85 + u64::from(b - b'!');
                    n += 1;
                    if n == 5 {
                        break;
                    }
                }
                b if b.is_ascii_whitespace() || b == 0 => (),
                _ => return Err(invalid()),
            }
        }
        if n < 5 {
            self.done = true;
        }
        if n == 0 {
            self.len = 0;
            return Ok(());
        }
        if n == 1 {
            return Err(invalid());
        }
        self.len = n.saturating_sub(1);
        for _ in n..5 {
            value = value * 85 + 84;
        }
        self.next = u32::try_from(value).map_err(|_| invalid())?.to_be_bytes();
        Ok(())
    }
}
impl<S: Source> Read for Ascii85<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < out.len() {
            if self.cursor == self.len {
                if self.done {
                    break;
                }
                self.group()?;
                if self.len == 0 {
                    break;
                }
            }
            let size = (out.len() - n).min(self.len - self.cursor);
            out[n..n + size].copy_from_slice(&self.next[self.cursor..self.cursor + size]);
            n += size;
            self.cursor += size;
        }
        Ok(n)
    }
}
struct Runs<S> {
    input: S,
    done: bool,
    repeat: Option<u8>,
    left: usize,
}
impl<S: Source> Read for Runs<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut used = 0;
        while !self.done && used < out.len() {
            if self.left == 0 {
                let Some(first) = self.input.byte()? else {
                    break;
                };
                match first {
                    128 => {
                        self.done = true;
                        break;
                    }
                    0..=127 => {
                        self.left = usize::from(first) + 1;
                        self.repeat = None;
                    }
                    other => {
                        let Some(byte) = self.input.byte()? else {
                            return Err(invalid());
                        };
                        self.left = 257 - usize::from(other);
                        self.repeat = Some(byte);
                    }
                }
            }
            let n = self.left.min(out.len() - used);
            if let Some(v) = self.repeat {
                out[used..used + n].fill(v);
            } else {
                let src = self.input.look(n)?.get(..n).ok_or_else(invalid)?;
                out[used..used + n].copy_from_slice(src);
                self.input.advance(n);
            }
            used += n;
            self.left -= n;
        }
        Ok(used)
    }
}

trait Source: Read {
    fn look(&mut self, n: usize) -> io::Result<&[u8]>;
    fn advance(&mut self, n: usize);
    fn byte(&mut self) -> io::Result<Option<u8>> {
        let byte = self.look(1)?.first().copied();
        if byte.is_some() {
            self.advance(1);
        }
        Ok(byte)
    }
}

impl Source for &[u8] {
    fn look(&mut self, _: usize) -> io::Result<&[u8]> {
        Ok(self)
    }
    fn advance(&mut self, n: usize) {
        *self = &self[n..];
    }
}

// Non-Flate filters need at most 128 bytes of lookahead across a reader boundary.
struct Buffered<R> {
    reader: R,
    buf: [u8; 8192],
    at: usize,
    end: usize,
}

impl<R: Read> Source for Buffered<R> {
    fn look(&mut self, n: usize) -> io::Result<&[u8]> {
        if self.end - self.at < n {
            self.buf.copy_within(self.at..self.end, 0);
            self.end -= self.at;
            self.at = 0;
            while self.end < n {
                let got = self.reader.read(&mut self.buf[self.end..])?;
                if got == 0 {
                    break;
                }
                self.end += got;
            }
        }
        Ok(&self.buf[self.at..self.end])
    }
    fn advance(&mut self, n: usize) {
        self.at += n;
    }
}
impl<R: Read> Read for Buffered<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at == self.end {
            return self.reader.read(out);
        }
        let n = out.len().min(self.end - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

struct Checked<'a, R>(R, &'a dyn Fn() -> io::Result<()>);
impl<R: Read> Read for Checked<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.1()?;
        self.0.read(out)
    }
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Retain {
    Count,
    Verify,
    Keep,
    /// Keep an object stream past the scan budget so its directory can still be read.
    Carrier,
}

impl Retain {
    // Output beyond a scan budget of `limit` bytes also fits the first Flate
    // allocation. That happens only below 256 KiB, so a carrier stays in memory.
    pub(super) fn output(self, limit: u64, directory: &std::path::Path) -> Option<Snapshot> {
        match self {
            Self::Count => None,
            Self::Carrier if limit < FLATE_STEP => {
                Some(Snapshot::with_memory(FLATE_STEP as usize, directory))
            }
            _ => Some(Snapshot::new(directory)),
        }
    }
}

const FLATE_STEP: u64 = 256 * 1024;

pub(super) fn flate_capacity(limit: u64) -> u64 {
    (limit / FLATE_STEP).max(1) * FLATE_STEP
}

struct FlateStage<'a, R> {
    reader: R,
    index: usize,
    size: u64,
    capacity: u64,
    failure: &'a std::cell::Cell<Option<(usize, u64)>>,
}
impl<R: Read> Read for FlateStage<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(out)?;
        self.size += n as u64;
        if self.size > self.capacity {
            self.failure
                .set(Some((self.index, self.capacity.saturating_add(FLATE_STEP))));
            return Err(io::Error::other(
                "PDF Flate stage exceeded allocation limit",
            ));
        }
        Ok(n)
    }
}

// Poll on each input and intermediate read. Only the final stream consumes scan bytes.
pub(super) fn chain(
    source: impl Read,
    filters: &[Filter],
    retain: Retain,
    sink: &mut dyn ChildSink,
) -> io::Result<Output> {
    use std::cell::RefCell;
    let limit = sink.remaining();
    let mut output = retain.output(limit, sink.temporary_directory());
    let sink = RefCell::new(sink);
    let interrupted = RefCell::new(None);
    let poll = || {
        sink.borrow_mut().check().map_err(|e| {
            interrupted.replace(Some(e));
            io::Error::other("PDF scan interrupted")
        })
    };
    let reader: Box<dyn Read + '_> = Box::new(source);
    let stage_limit = std::cell::Cell::new(None);
    let mut reader = reader;
    for (index, filter) in filters.iter().enumerate() {
        let checked = Checked(reader, &poll);
        reader = if *filter == Filter::Flate {
            Box::new(FlateStage {
                reader: ZlibDecoder::new(checked),
                index,
                size: 0,
                capacity: flate_capacity(limit),
                failure: &stage_limit,
            })
        } else {
            filter.reader(Buffered {
                reader: checked,
                buf: [0; 8192],
                at: 0,
                end: 0,
            })?
        };
    }
    let mut size = 0u64;
    let mut buf = [0; 8192];
    loop {
        sink.borrow_mut().check()?;
        let read = reader.read(&mut buf);
        if let Some(e) = interrupted.take() {
            return Err(e);
        }
        if let Some((index, required)) = stage_limit.take() {
            return Ok(Output::StageLimit(index, required));
        }
        let n = match read {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return Ok(Output::Malformed),
        };
        size += n as u64;
        if size > limit {
            if !filters.contains(&Filter::Flate) {
                return Ok(Output::TooLarge(size));
            }
            if retain != Retain::Carrier {
                output = None;
            }
        }
        if retain == Retain::Verify && size > Snapshot::MEMORY_LIMIT as u64 {
            output = None;
        }
        if let Some(out) = &mut output {
            out.write_all(&buf[..n])?;
        }
    }
    if size > limit && retain != Retain::Carrier {
        return Ok(Output::TooLarge(size));
    }
    Ok(output.map_or(Output::Counted(size), Output::Decoded))
}

#[cfg(test)]
mod tests {
    use super::flate_fails_at_start;

    #[test]
    fn flate_failure_follows_the_reference_retry() {
        // 0x78 0x9c is a valid zlib header. 0x78 0x00 fails the header checksum.
        assert!(flate_fails_at_start(b"\x78\x00garbage"));
        assert!(flate_fails_at_start(b"\r\x78\x00garbage"));
        assert!(!flate_fails_at_start(b"\x78\x9cdata"));
        assert!(!flate_fails_at_start(b"\r\x78\x9cdata"));
        assert!(!flate_fails_at_start(b"x"));
        // Stock retries after the first run of line breaks.
        assert!(flate_fails_at_start(b"\x78\x00bad\r\n\x78\x00bad"));
        assert!(!flate_fails_at_start(b"\x78\x00bad\r\n\x78\x9cdata"));
        assert!(flate_fails_at_start(b"\x78\x00bad\n\n"));
        // A lone byte after the line break can still be consumed as a partial header.
        assert!(!flate_fails_at_start(b"\x78\x00bad\nx"));
    }
}
