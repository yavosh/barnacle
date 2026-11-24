//! EA05 and EA06 records from compiled AutoIt archives. Each record owns a separate keystream.
mod legacy;
mod packed;
mod script;

use super::{ChildSink, Handling, Limit, Snapshot};
use std::io::{self, BufReader, Read, Write};

pub(super) const MAGIC: &[u8] =
    b"\xa3\x48\x4b\xbe\x98\x6c\x4a\xa9\x99\x4c\x53\x0a\x86\xd6\x48\x7dAU3!EA0";
pub(super) fn recognized(bytes: &[u8]) -> bool {
    bytes
        .strip_prefix(MAGIC)
        .is_some_and(|rest| matches!(rest.first(), Some(b'5' | b'6')))
}

#[derive(Clone, Copy)]
enum Format {
    Ea05 { data_seed: u32 },
    Ea06,
}

impl Format {
    fn marker(self) -> &'static [u8] {
        match self {
            Self::Ea05 { .. } => &[0xff, 0x6d, 0xb0, 0xce],
            Self::Ea06 => &[0x6b, 0x43, 0xca, 0x52],
        }
    }

    fn key(self) -> Key {
        match self {
            Self::Ea05 { data_seed } => Key::Legacy(legacy::Stream::new(data_seed)),
            Self::Ea06 => Key::Current(Ea06Key::new(0x2477)),
        }
    }
}

enum Key {
    Legacy(legacy::Stream),
    Current(Ea06Key),
}

impl Key {
    fn decode(&mut self, byte: u8) -> u8 {
        match self {
            Self::Legacy(key) => key.decode(byte),
            Self::Current(key) => key.decode(byte),
        }
    }
}

struct Ea06Key {
    words: [u32; 17],
    at: usize,
}

impl Ea06Key {
    fn new(mut seed: u32) -> Self {
        let words = std::array::from_fn(|_| {
            seed = 1u32.wrapping_sub(seed.wrapping_mul(0x53a9b4fb));
            seed
        });
        let mut key = Self { words, at: 0 };
        for _ in 0..9 {
            key.step();
        }
        key
    }

    fn step(&mut self) -> u32 {
        let a = self.at;
        let b = (a + 10) % self.words.len();
        let value = self.words[a]
            .rotate_left(9)
            .wrapping_add(self.words[b].rotate_left(13));
        self.words[a] = value;
        self.at = if a == 0 { 16 } else { a - 1 };
        value
    }

    fn decode(&mut self, byte: u8) -> u8 {
        self.step();
        byte ^ (self.step() >> 24) as u8
    }
}

fn field(input: &mut &[u8], mask: u32) -> Option<usize> {
    Some((u32::from_le_bytes(input.split_off(..4)?.try_into().ok()?) ^ mask) as usize)
}

struct Record {
    tokenized: bool,
    packed: bool,
    size: usize,
}

impl Record {
    fn parse(input: &mut &[u8], format: Format) -> Option<Self> {
        let (width, tag_mask, path_mask, size_mask) = match format {
            Format::Ea05 { .. } => (1, 0x29bc, 0x29ac, 0x45aa),
            Format::Ea06 => (2, 0xadbc, 0xf820, 0x87bc),
        };
        let units = field(input, tag_mask)?;
        let tag = input.split_off(..units.checked_mul(width)?)?;
        let token_tag = b">>>AUTOIT SCRIPT<<<";
        let tokenized = matches!(format, Format::Ea06) && units == token_tag.len() && {
            let mut key = Ea06Key::new(0xb33f + units as u32);
            tag.iter()
                .copied()
                .map(|b| key.decode(b))
                .eq(token_tag.iter().flat_map(|&c| [c, 0]))
        };
        let path = field(input, path_mask)?;
        input.split_off(..path.checked_mul(width)?)?;
        let packed = input.split_off_first()? != &0;
        let size = field(input, size_mask)?;
        // The extraction length comes from the compressed stream, or the stored byte count.
        input.split_off(..8)?;
        Some(Self {
            tokenized,
            packed,
            size,
        })
    }
}

enum Data<'a> {
    Stored(&'a [u8], Key),
    Packed(packed::Decoder<'a>),
}

struct Reader<'a, 's> {
    data: Data<'a>,
    sink: &'s mut dyn ChildSink,
}

impl Read for Reader<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.sink.check()?;
        let n = out.len().min(8192);
        let out = &mut out[..n];
        match &mut self.data {
            Data::Packed(packed) => packed.read(out, self.sink),
            Data::Stored(data, key) => {
                let n = data.len().min(out.len());
                let chunk = data.split_off(..n).expect("bounded stored read");
                for (dst, &byte) in out.iter_mut().zip(chunk) {
                    *dst = key.decode(byte);
                }
                Ok(n)
            }
        }
    }
}

fn copy_resource(input: &mut dyn Read, output: &mut dyn Write) -> io::Result<u64> {
    let mut chunk = [0; 8192];
    let mut size = 0;
    loop {
        // Scan checks can report Interrupted. Propagate it to the caller.
        let count = input.read(&mut chunk)?;
        if count == 0 {
            return Ok(size);
        }
        output.write_all(&chunk[..count])?;
        size += count as u64;
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some((version, payload)) = bytes.get(MAGIC.len()..).and_then(|tail| tail.split_first())
    else {
        return Ok(Handling::Incomplete);
    };
    let Some((salt, mut rest)) = payload.split_at_checked(16) else {
        // The legacy archive can still match as a whole after a short salt read.
        return Ok(if *version == b'5' {
            Handling::Complete
        } else {
            Handling::Incomplete
        });
    };
    let format = match version {
        b'5' => Format::Ea05 {
            data_seed: 0x22af + salt.iter().map(|&b| u32::from(b)).sum::<u32>(),
        },
        b'6' => Format::Ea06,
        _ => return Ok(Handling::Incomplete),
    };
    loop {
        sink.check()?;
        if sink.child_limit() == Some(Limit::MaxFiles) {
            sink.record_file_limit();
            return Ok(Handling::Complete);
        }
        let Some(after_marker) = rest.strip_prefix(format.marker()) else {
            return Ok(Handling::Complete);
        };
        rest = after_marker;
        let Some(record) = Record::parse(&mut rest, format) else {
            if matches!(format, Format::Ea05 { .. }) {
                // A short legacy header still allows matching the owning file.
                return Ok(Handling::Complete);
            }
            return Ok(Handling::Incomplete);
        };
        let Some(bytes) = rest
            .split_off(..16)
            .and_then(|_| rest.split_off(..record.size))
        else {
            if matches!(format, Format::Ea05 { .. }) {
                // Legacy admission checks the stored length before reading the timestamps and payload.
                sink.skip_declared_size(record.size as u64);
                return Ok(Handling::Complete);
            }
            return Ok(Handling::Incomplete);
        };
        if bytes.is_empty() || sink.skip_declared_size(bytes.len() as u64) {
            continue;
        }
        let mut key = format.key();
        let data = if record.packed {
            let Some((head, data)) = bytes.split_at_checked(8) else {
                return Ok(Handling::Incomplete);
            };
            let mut header = [0; 8];
            for (b, &cipher) in header.iter_mut().zip(head) {
                *b = key.decode(cipher);
            }
            if header[..4] != [b'E', b'A', b'0', *version] {
                return Ok(Handling::Incomplete);
            }
            let size = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
            if sink.skip_declared_size(size as u64) {
                continue;
            }
            Data::Packed(packed::Decoder::new(
                data,
                key,
                size,
                matches!(format, Format::Ea06),
            ))
        } else {
            Data::Stored(bytes, key)
        };
        let mut out = Snapshot::new(sink.temporary_directory());
        let mut discard = io::sink();
        let writer: &mut dyn Write = if sink.child_limit() == Some(Limit::MaxRecursion) {
            &mut discard
        } else {
            &mut out
        };
        let limit = sink.remaining();
        let mut input = Reader { data, sink };
        let size = if record.tokenized {
            let mut buffered = BufReader::new(&mut input);
            let Some(size) = script::render(&mut buffered, writer, limit)? else {
                return Ok(Handling::Incomplete);
            };
            copy_resource(&mut buffered, &mut io::sink())?;
            size
        } else {
            copy_resource(&mut input, writer)?
        };
        if matches!(input.data, Data::Packed(ref d) if !d.complete()) {
            return Ok(Handling::Incomplete);
        }
        drop(input);
        // Legacy recursion limits are deferred. The owning file can still match.
        if matches!(format, Format::Ea05 { .. }) && !sink.can_enter_child() {
            return Ok(Handling::Complete);
        }
        if sink.autoit_child_stop(size) || sink.visit_snapshot(out, None, None)? {
            return Ok(Handling::Stopped);
        }
    }
}
