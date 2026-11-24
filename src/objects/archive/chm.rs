use super::{ChildSink, Handling, decoded};
use lzxd::{Lzxd, WindowSize};
use std::io::{self, Read};

const FRAME: usize = 32768;
const CONTENT: &[u8] = b"::DataSpace/Storage/MSCompressed/Content";
const CONTROL: &[u8] = b"::DataSpace/Storage/MSCompressed/ControlData";
const RESET: &[u8] = b"::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable";

fn word(bytes: &[u8], pos: usize) -> Option<usize> {
    Some(u32::from_le_bytes(bytes.get(pos..)?.first_chunk()?.to_owned()) as usize)
}

fn long(bytes: &[u8], pos: usize) -> Option<usize> {
    usize::try_from(u64::from_le_bytes(*bytes.get(pos..)?.first_chunk()?)).ok()
}

fn integer(bytes: &mut &[u8]) -> Option<usize> {
    let mut result = 0usize;
    loop {
        let byte = *bytes.split_off_first()?;
        result = result
            .checked_mul(128)?
            .checked_add(usize::from(byte & 127))?;
        if byte & 128 == 0 {
            return Some(result);
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid CHM archive")
}

struct Entry<'a> {
    name: &'a [u8],
    section: usize,
    start: usize,
    len: usize,
}

struct Directory<'a> {
    pages: &'a [u8],
    page_size: usize,
    data: &'a [u8],
}

impl<'a> Directory<'a> {
    fn new(bytes: &'a [u8]) -> Option<Self> {
        const GUIDS: &[u8; 32] = &[
            16, 253, 1, 124, 170, 123, 208, 17, 158, 12, 0, 160, 201, 34, 230, 236, 17, 253, 1,
            124, 170, 123, 208, 17, 158, 12, 0, 160, 201, 34, 230, 236,
        ];
        if bytes.get(24..56)? != GUIDS {
            return None;
        }
        let h = bytes.get(long(bytes, 72)?..)?;
        let page_size = word(h, 16)?;
        let first = word(h, 32)?;
        let last = word(h, 36)?;
        let count = word(h, 44)?;
        if !(22..=8192).contains(&page_size) || count > 100_000 || last >= count || first > last {
            return None;
        }
        let data = if word(bytes, 4)? < 3 {
            h.get(84 + count * page_size..)?
        } else {
            bytes.get(long(bytes, 88)?..)?
        };
        Some(Self {
            pages: h.get(84 + first * page_size..84 + (last + 1) * page_size)?,
            page_size,
            data,
        })
    }

    fn entries(&self, mut visit: impl FnMut(Entry<'a>) -> io::Result<bool>) -> io::Result<bool> {
        for page in self.pages.chunks_exact(self.page_size) {
            if !page.starts_with(b"PMGL") {
                continue;
            }
            let end = page.len() - 2;
            let count = u16::from_le_bytes(page[end..].try_into().unwrap());
            let mut bytes = &page[20..end];
            for _ in 0..count {
                let n = integer(&mut bytes).ok_or_else(invalid)?;
                let name = bytes.split_off(..n).ok_or_else(invalid)?;
                let section = integer(&mut bytes).ok_or_else(invalid)?;
                let start = integer(&mut bytes).ok_or_else(invalid)?;
                let len = integer(&mut bytes).ok_or_else(invalid)?;
                if name.len() >= 2
                    && name[0] != 0
                    && name[1] != 0
                    && section <= 1
                    && !(start == 0 && len == 0 && name.ends_with(b"/"))
                    && visit(Entry {
                        name,
                        section,
                        start,
                        len,
                    })?
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

#[derive(Default)]
struct Streams<'a> {
    content: &'a [u8],
    control: &'a [u8],
    reset: &'a [u8],
}

struct Frames<'a> {
    streams: Streams<'a>,
    reset_frames: usize,
    window: WindowSize,
    offsets: &'a [u8],
    width: usize,
    decoded_len: usize,
    decoder: Option<Lzxd>,
    frame: Vec<u8>,
    next: usize,
    offset: usize,
}

impl<'a> Frames<'a> {
    fn new(s: Streams<'a>) -> Option<Self> {
        if s.control.get(4..8)? != b"LZXC" || long(s.reset, 32)? != FRAME {
            return None;
        }
        let scale = match word(s.control, 8)? {
            1 => 1,
            2 => FRAME,
            _ => return None,
        };
        let interval = word(s.control, 12)?.checked_mul(scale)?;
        if interval == 0 || interval % FRAME != 0 {
            return None;
        }
        let window = match word(s.control, 16)?.checked_mul(scale)? {
            32768 => WindowSize::KB32,
            65536 => WindowSize::KB64,
            131072 => WindowSize::KB128,
            262144 => WindowSize::KB256,
            524288 => WindowSize::KB512,
            1048576 => WindowSize::MB1,
            2097152 => WindowSize::MB2,
            _ => return None,
        };
        let width = word(s.reset, 8)?;
        if !matches!(width, 4 | 8) {
            return None;
        }
        let count = word(s.reset, 4)?;
        let offsets = s
            .reset
            .get(word(s.reset, 12)?..)?
            .get(..count.checked_mul(width)?)?;
        let decoded_len = long(s.reset, 16)?;
        Some(Self {
            streams: s,
            reset_frames: interval / FRAME,
            window,
            offsets,
            width,
            decoded_len,
            decoder: None,
            frame: Vec::new(),
            next: 0,
            offset: 0,
        })
    }

    fn boundary(&self, frame: usize) -> Option<usize> {
        if frame == self.offsets.len() / self.width {
            return Some(self.streams.content.len());
        }
        let at = frame.checked_mul(self.width)?;
        if self.width == 4 {
            word(self.offsets, at)
        } else {
            long(self.offsets, at)
        }
    }

    fn advance(&mut self) -> io::Result<()> {
        let start = self.boundary(self.next).ok_or_else(invalid)?;
        let end = self.boundary(self.next + 1).ok_or_else(invalid)?;
        let packed = self.streams.content.get(start..end).ok_or_else(invalid)?;
        if self.next.is_multiple_of(self.reset_frames) || self.decoder.is_none() {
            self.decoder = Some(Lzxd::new(self.window));
        }
        let output = self
            .decoder
            .as_mut()
            .unwrap()
            .decompress_next(packed, FRAME)
            .map_err(|_| invalid())?;
        self.frame.clear();
        self.frame.extend_from_slice(output);
        self.next += 1;
        self.offset = 0;
        Ok(())
    }

    fn seek(&mut self, position: usize, sink: &mut dyn ChildSink) -> io::Result<bool> {
        let target = position / FRAME;
        if self.next != target + 1 {
            let restart = target / self.reset_frames * self.reset_frames;
            if self.next > target || self.next < restart {
                self.next = restart;
            }
            while self.next <= target {
                sink.check()?;
                if self.advance().is_err() {
                    return Ok(false);
                }
            }
        }
        self.offset = position % FRAME;
        Ok(true)
    }
}

impl Read for Frames<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.offset == self.frame.len() {
            self.advance()?;
        }
        let n = (&self.frame[self.offset..]).read(out)?;
        self.offset += n;
        Ok(n)
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(dir) = Directory::new(bytes) else {
        return Ok(Handling::Incomplete);
    };
    let mut system = Streams::default();
    let mut check_error = None;
    let index = dir.entries(|entry| {
        if let Err(e) = sink.check() {
            check_error = Some(e);
            return Ok(true);
        }
        if entry.section == 0 {
            let slot = match entry.name {
                CONTENT => &mut system.content,
                CONTROL => &mut system.control,
                RESET => &mut system.reset,
                _ => return Ok(false),
            };
            *slot = dir
                .data
                .get(entry.start..)
                .and_then(|b| b.get(..entry.len))
                .ok_or_else(invalid)?;
        }
        Ok(false)
    });
    if let Some(e) = check_error {
        return Err(e);
    }
    if index.is_err() {
        return Ok(Handling::Incomplete);
    }
    let mut frames = Frames::new(system);
    let mut result = Handling::Complete;
    dir.entries(|entry| {
        sink.check()?;
        if entry.name.starts_with(b"::") || entry.len == 0 {
            return Ok(false);
        }
        let name = entry.name.split(|&b| b == 0).next();
        let len = (entry.len as u64)
            .min(sink.remaining())
            .min(u64::from(u32::MAX));
        let scanned = if entry.section == 0 {
            let Some(data) = dir
                .data
                .get(entry.start..)
                .and_then(|b| b.get(..len as usize))
            else {
                result = Handling::Incomplete;
                return Ok(false);
            };
            decoded(data, name, false, sink)?
        } else if let Some(frames) = &mut frames {
            if entry
                .start
                .checked_add(len as usize)
                .is_none_or(|n| n > frames.decoded_len)
                || !frames.seek(entry.start, sink)?
            {
                result = Handling::Incomplete;
                return Ok(false);
            }
            decoded(frames.take(len), name, false, sink)?
        } else {
            Handling::Incomplete
        };
        if scanned != Handling::Complete {
            result = scanned;
        }
        Ok(scanned == Handling::Stopped)
    })?;
    Ok(result)
}
