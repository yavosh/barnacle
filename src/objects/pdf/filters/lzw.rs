//! PDF LZW codes use most-significant-bit-first packing and a 12-bit dictionary.
use super::Output;
use crate::objects::{ChildSink, Snapshot};
use std::io::{self, BufWriter, Write};

const CLEAR: usize = 256;
const END: usize = 257;
const FIRST: usize = 258;
const CODES: usize = 4096;
const TAIL: usize = 4;

struct Bits<'a> {
    input: &'a [u8],
    pending: u32,
    count: u8,
}

impl Bits<'_> {
    fn code(&mut self, width: u8) -> Option<usize> {
        while self.count < width {
            let (&byte, rest) = self.input.split_first()?;
            self.input = rest;
            self.pending = self.pending << 8 | u32::from(byte);
            self.count += 8;
        }
        self.count -= width;
        Some(((self.pending >> self.count) & ((1 << width) - 1)) as usize)
    }
}

#[derive(Clone, Copy, Default)]
struct Entry {
    // Removing the final one to four bytes leaves the word named by this prefix.
    prefix: u16,
    len: u16,
    first: u8,
    tail: [u8; TAIL],
}

impl Entry {
    fn append(mut self, prefix: usize, byte: u8) -> Self {
        let at = usize::from(self.len) % self.tail.len();
        if at == 0 {
            self.prefix = prefix as u16;
        }
        self.tail[at] = byte;
        self.len += 1;
        self
    }

    fn write(self, table: &[Self], word: &mut [u8; CODES], out: &mut impl Write) -> io::Result<()> {
        let len = usize::from(self.len);
        let tail_len = (len - 1) % self.tail.len() + 1;
        if len == tail_len {
            return out.write_all(&self.tail[..len]);
        }
        let (prefix, tail) = word[..len].split_at_mut(len - tail_len);
        tail.copy_from_slice(&self.tail[..tail_len]);
        let mut older = self.prefix;
        for chunk in prefix.rchunks_exact_mut(TAIL) {
            let entry = &table[usize::from(older)];
            chunk.copy_from_slice(&entry.tail);
            older = entry.prefix;
        }
        out.write_all(&word[..len])
    }
}

pub(super) fn decode(
    data: &[u8],
    limit: u64,
    retain: bool,
    sink: &mut dyn ChildSink,
) -> io::Result<Output> {
    const STEP: u64 = 256 * 1024;
    let capacity = (limit / STEP).max(1) * STEP;
    let mut bits = Bits {
        input: data,
        pending: 0,
        count: 0,
    };
    let mut table = [Entry::default(); CODES];
    for (byte, entry) in (0u8..=255).zip(&mut table) {
        entry.len = 1;
        entry.first = byte;
        entry.tail[0] = byte;
    }
    let mut word = [0u8; CODES];
    let mut out = retain.then(|| BufWriter::new(Snapshot::new(sink.temporary_directory())));
    let mut width = 9;
    let mut next = FIRST;
    let mut previous: Option<usize> = None;
    let mut size = 0u64;
    let mut codes = 0usize;
    while let Some(code) = bits.code(width) {
        if codes.is_multiple_of(256) {
            sink.check()?;
        }
        codes += 1;
        if code == CLEAR {
            width = 9;
            next = FIRST;
            previous = None;
            continue;
        }
        if code == END || code > next {
            break;
        }
        // The next dictionary entry can name the previous word followed by its first byte.
        let entry = if code == next {
            let Some(old) = previous else {
                break;
            };
            table[old].append(old, table[old].first)
        } else {
            table[code]
        };
        size += u64::from(entry.len);
        // Filling the reference buffer requests another whole block, even if EOD follows.
        if size >= capacity {
            sink.skip_declared_size(capacity.saturating_add(STEP));
            return Ok(Output::UseInput);
        }
        // Count up to that boundary without expanding the private spool past its byte budget.
        if size <= limit
            && let Some(out) = &mut out
        {
            entry.write(&table, &mut word, out)?;
        }
        if let Some(old) = previous
            && next < CODES
        {
            table[next] = table[old].append(old, entry.first);
            next += 1;
            // The pinned scanner uses EarlyChange=1 even when the dictionary requests zero.
            if width < 12 && next + 1 == 1 << width {
                width += 1;
            }
        }
        previous = Some(code);
    }
    Ok(if size == 0 {
        Output::UseInput
    } else if size > limit {
        Output::TooLarge(size)
    } else if let Some(out) = out {
        Output::Decoded(out.into_inner().map_err(|e| e.into_error())?)
    } else {
        Output::Counted(size)
    })
}
