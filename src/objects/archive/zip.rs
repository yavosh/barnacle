use super::{ChildSink, Handling, decoded};
use crate::objects::Snapshot;
use deflate64::InflaterManaged;
use flate2::read::DeflateDecoder;
use std::io::{self, Cursor, Read, Write};

const LOCAL: &[u8; 4] = b"PK\x03\x04";
const CENTRAL: &[u8; 4] = b"PK\x01\x02";
const END: &[u8; 4] = b"PK\x05\x06";

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(data[at..at + 2].try_into().unwrap())
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

struct Entry<'a> {
    method: u16,
    flags: u16,
    name: &'a [u8],
    compressed: &'a [u8],
    expanded_len: u32,
    consumed: usize,
}

impl<'a> Entry<'a> {
    fn parse(bytes: &'a [u8], sizes: (u32, u32)) -> Option<Self> {
        let (head, rest) = bytes.split_at_checked(30)?;
        if &head[..4] != LOCAL {
            return None;
        }
        let flags = u16_at(head, 6);
        let (compressed_len, expanded_len) = if flags & 8 != 0 {
            sizes
        } else {
            (u32_at(head, 18), u32_at(head, 22))
        };
        if compressed_len == u32::MAX || expanded_len == u32::MAX {
            return None;
        }
        let (name, rest) = rest.split_at_checked(usize::from(u16_at(head, 26)))?;
        let data = rest.get(usize::from(u16_at(head, 28))..)?;
        let (compressed, rest) = data.split_at_checked(compressed_len as usize)?;
        let rest = if flags & 8 != 0 {
            let descriptor = rest.strip_prefix(b"PK\x07\x08").unwrap_or(rest);
            descriptor.get(12..)?
        } else {
            rest
        };
        Some(Self {
            method: u16_at(head, 8),
            flags,
            // The reference supplies the last filename component to its child scanner.
            name: name.rsplit(|&b| b == b'/' || b == b'\\').next()?,
            compressed,
            expanded_len,
            consumed: bytes.len() - rest.len(),
        })
    }

    fn visit(&self, sink: &mut dyn ChildSink) -> io::Result<Handling> {
        if self.flags & 0x2000 != 0 {
            return Ok(Handling::Incomplete);
        }
        // The active local matcher has no password database or encrypted-archive alert.
        // Stock counts an encrypted directory entry but opens no child for it.
        if self.flags & 1 != 0 || self.compressed.is_empty() {
            return Ok(Handling::Complete);
        }
        let max_file_size = sink.max_file_size();
        match self.method {
            0 if self.compressed.len() >= self.expanded_len as usize => {
                // Stored bytes already reside in the immutable archive. The reference
                // clips this span at MaxFileSize before checking the scan budget.
                let len = (self.compressed.len() as u64).min(max_file_size);
                if len <= 5 || (sink.child_limit().is_some() && sink.recorded_limit().is_some()) {
                    return Ok(Handling::Complete);
                }
                let bytes = &self.compressed[..len as usize];
                Ok(
                    if sink.skip_declared_size(len) || sink.child_bytes(bytes, Some(self.name))? {
                        Handling::Stopped
                    } else {
                        Handling::Complete
                    },
                )
            }
            8 => self.scan(
                ZipOutput::new(DeflateDecoder::new(self.compressed), max_file_size),
                sink,
            ),
            9 => self.deflate64(sink),
            12 => self.scan(
                ZipOutput::new(bzip2::read::BzDecoder::new(self.compressed), max_file_size),
                sink,
            ),
            _ => Ok(Handling::Incomplete),
        }
    }

    fn deflate64(&self, sink: &mut dyn ChildSink) -> io::Result<Handling> {
        let denied = sink.child_limit();
        if denied.is_some() && sink.recorded_limit().is_some() {
            return Ok(Handling::Complete);
        }
        let file_limit = sink.max_file_size();
        let mut count_before_spilling = sink.remaining() < file_limit;
        loop {
            let mut child = denied
                .is_none()
                .then(|| Snapshot::new(sink.temporary_directory()));
            let mut size = 0u64;
            {
                let mut decoder = Box::new(InflaterManaged::new());
                let mut input = self.compressed;
                let mut block = [0; 8192];
                loop {
                    let Some(used) = deflate64_block(&mut decoder, &mut input, &mut block, sink)?
                    else {
                        return Ok(Handling::Incomplete);
                    };
                    let next = size + used as u64;
                    if used == 0 || next > file_limit {
                        break;
                    }
                    size = next;
                    if size > 5 && sink.skip_declared_size(size) {
                        return Ok(Handling::Stopped);
                    }
                    if denied.is_some() && !count_before_spilling && size > 5 {
                        sink.can_enter_child();
                        return Ok(Handling::Complete);
                    }
                    let end = used < block.len() || decoder.finished();
                    if count_before_spilling && size > Snapshot::MEMORY_LIMIT as u64 && !end {
                        child = None;
                    }
                    if let Some(child) = &mut child {
                        child.write_all(&block[..used])?;
                    }
                    if end {
                        break;
                    }
                }
            }
            // Stock skips outputs of at most five bytes before entering the child scanner.
            if size <= 5 || !sink.can_enter_child() {
                return Ok(Handling::Complete);
            }
            if let Some(child) = child {
                return Ok(if sink.visit_snapshot(child, None, Some(self.name))? {
                    Handling::Stopped
                } else {
                    Handling::Complete
                });
            }
            // An eligible member exceeded the in-memory spool while the scan budget
            // could still bind. The measured prefix now fits, so retain it on replay.
            count_before_spilling = false;
        }
    }

    fn scan(&self, reader: impl Read, sink: &mut dyn ChildSink) -> io::Result<Handling> {
        let remaining = sink.remaining();
        // When a child cannot enter, check its actual expanded size before recording
        // count or recursion. Stock ignores outputs of at most five bytes.
        let denied = sink.child_limit().is_some();
        if denied && sink.recorded_limit().is_some() {
            return Ok(Handling::Complete);
        }
        if denied || remaining < 5 {
            let probe = if remaining < sink.max_file_size() {
                remaining.saturating_add(1).max(6)
            } else {
                6
            };
            let mut stream = reader.take(probe);
            let mut block = [0; 8192];
            while stream.limit() > 0 {
                sink.check()?;
                match stream.read(&mut block) {
                    Ok(0) => break,
                    Ok(_) => (),
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Ok(Handling::Incomplete),
                }
            }
            let size = probe - stream.limit();
            if size > 5 {
                if sink.skip_declared_size(size) {
                    return Ok(Handling::Stopped);
                }
                sink.can_enter_child();
            }
            return Ok(Handling::Complete);
        }
        let probe = remaining.saturating_add(1);

        let mut stream = reader.take(probe);
        let result = decoded(&mut stream, Some(self.name), false, sink)?;
        // Stock leaves the ZIP member loop when its child scanner exceeds MaxScanSize.
        if probe - stream.limit() > remaining {
            Ok(Handling::Stopped)
        } else {
            Ok(result)
        }
    }
}

// Return a full 8 KiB block, a final short block, or None for invalid data.
fn deflate64_block(
    decoder: &mut InflaterManaged,
    input: &mut &[u8],
    block: &mut [u8; 8192],
    sink: &mut dyn ChildSink,
) -> io::Result<Option<usize>> {
    let mut used = 0;
    while used < block.len() {
        sink.check()?;
        let part = &input[..input.len().min(block.len())];
        let step = decoder.inflate(part, &mut block[used..]);
        if step.data_error {
            return Ok(None);
        }
        *input = &input[step.bytes_consumed..];
        used += step.bytes_written;
        if decoder.finished() {
            break;
        }
        if step.bytes_consumed == 0 && step.bytes_written == 0 {
            // Stock scans the bytes produced before a short final input.
            return Ok(input.is_empty().then_some(used));
        }
    }
    Ok(Some(used))
}

// The reference writes compressed members in 8192-byte batches. When the final
// batch exceeds MaxFileSize, it retains only the preceding complete batches.
struct ZipOutput<R> {
    reader: R,
    full: u64,
    tail_limit: usize,
    tail: Cursor<Vec<u8>>,
}

impl<R: Read> ZipOutput<R> {
    fn new(reader: R, limit: u64) -> Self {
        Self {
            reader,
            full: limit - limit % 8192,
            tail_limit: (limit % 8192) as usize,
            tail: Cursor::default(),
        }
    }
}

impl<R: Read> Read for ZipOutput<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.full > 0 {
            let len = self.full.min(out.len() as u64) as usize;
            let n = self.reader.read(&mut out[..len])?;
            self.full -= n as u64;
            return Ok(n);
        }
        if self.tail_limit > 0 {
            let n = self.tail_limit;
            self.tail_limit = 0;
            (&mut self.reader)
                .take(n as u64 + 1)
                .read_to_end(self.tail.get_mut())?;
            if self.tail.get_ref().len() > n {
                self.tail.get_mut().clear();
            }
        }
        self.tail.read(out)
    }
}

// Scan backward without allocating a list of possible end records. A long trailer
// must still give the caller opportunities to check its time and connection limits.
pub(in crate::objects) fn directory(
    bytes: &[u8],
    sink: &mut dyn ChildSink,
) -> io::Result<Option<(usize, usize)>> {
    Ok(locate(bytes, sink)?.map(|dir| (dir.offset, dir.count)))
}

struct Directory {
    offset: usize,
    count: usize,
    zip64_end: Option<usize>,
}

// Small ZIP64 archives can carry a conventional directory with a 76-byte trailer.
// The classic counts and size can use sentinels. The directory offset must be usable.
fn zip64_directory(bytes: &[u8], end: usize, offset: usize) -> Option<Directory> {
    let start = end.checked_sub(76)?;
    let tail = &bytes[start..end];
    let wide = |i| u64::from_le_bytes(tail[i..i + 8].try_into().unwrap());
    let count = u16::try_from(wide(32)).ok()?;
    let counts_agree = |i| {
        let classic = u16_at(bytes, end + i);
        classic == count || classic == u16::MAX
    };
    let classic_size = u32_at(bytes, end + 12);
    (tail.starts_with(b"PK\x06\x06")
        && wide(4) == 44
        && tail[16..24] == [0; 8]
        && wide(24) == u64::from(count)
        && (classic_size == u32::MAX || wide(40) == u64::from(classic_size))
        && wide(48) == offset as u64
        && wide(40) == start.checked_sub(offset)? as u64
        && &tail[56..60] == b"PK\x06\x07"
        && u32_at(tail, 60) == 0
        && wide(64) == start as u64
        && u32_at(tail, 72) == 1
        && bytes[end + 4..end + 8] == [0; 4]
        && counts_agree(8)
        && counts_agree(10))
    .then_some(Directory {
        offset,
        count: usize::from(count),
        zip64_end: Some(start),
    })
}

fn locate(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Option<Directory>> {
    if bytes.len() < 22 {
        return Ok(None);
    }
    let mut limit = bytes.len() - 21;
    while limit != 0 {
        sink.check()?;
        let begin = limit.saturating_sub(8192);
        for at in (begin..limit).rev() {
            if &bytes[at..at + 4] == END {
                let record = &bytes[at..at + 22];
                let offset = u32_at(record, 16) as usize;
                if offset != 0 && bytes.get(offset..).is_some_and(|b| b.starts_with(CENTRAL)) {
                    let classic = Directory {
                        offset,
                        count: usize::from(u16_at(record, 10)),
                        zip64_end: None,
                    };
                    return Ok(Some(zip64_directory(bytes, at, offset).unwrap_or(classic)));
                }
            }
        }
        limit = begin;
    }
    Ok(None)
}

pub(in crate::objects) fn single(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if bytes.len() < 30 || u16_at(bytes, 6) & 8 != 0 {
        // The embedded reader has no central directory for data-descriptor sizes.
        return Ok(Handling::Complete);
    }
    match Entry::parse(bytes, (0, 0)) {
        Some(member) => member.visit(sink),
        None => Ok(Handling::Incomplete),
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if let Some(Directory {
        offset: directory_offset,
        count,
        zip64_end,
    }) = locate(bytes, sink)?
    {
        let mut directory = &bytes[directory_offset..];
        // A classic directory contains at most 65535 records. Store only offsets
        // and sizes so each filename and member body still borrows the source object.
        let mut records = Vec::new();
        let max_files = sink.max_files();
        let mut visited = 0;
        while visited < count && (max_files == 0 || records.len() < max_files) {
            visited += 1;
            sink.check()?;
            let Some((head, rest)) = directory.split_at_checked(46) else {
                return Ok(Handling::Incomplete);
            };
            if &head[..4] != CENTRAL || u16_at(head, 34) != 0 {
                return Ok(Handling::Incomplete);
            }
            let fields: usize = [28, 30, 32]
                .into_iter()
                .map(|at| usize::from(u16_at(head, at)))
                .sum();
            let Some(next) = rest.get(fields..) else {
                return Ok(Handling::Incomplete);
            };
            directory = next;
            let offset = u32_at(head, 42);
            let sizes = (u32_at(head, 20), u32_at(head, 24));
            if zip64_end.is_some() || (max_files != 0 && count >= max_files) {
                // Empty compressed spans and ZIP64 sentinels consume no directory slot.
                if zip64_end.is_some() && offset == u32::MAX {
                    continue;
                }
                if let Some(local) = bytes
                    .get(offset as usize..directory_offset)
                    .and_then(|b| b.get(..30))
                    && local.starts_with(LOCAL)
                {
                    let compressed = if u16_at(local, 6) & 8 == 0 {
                        u32_at(local, 18)
                    } else {
                        sizes.0
                    };
                    if compressed == 0 || (zip64_end.is_some() && compressed == u32::MAX) {
                        continue;
                    }
                }
            }
            records.push((offset, sizes));
        }
        // Stock records the directory cap before trying the collected members.
        if max_files != 0 && records.len() == max_files {
            sink.record_file_limit();
        }
        if visited == count
            && !directory.starts_with(END)
            && zip64_end != Some(bytes.len() - directory.len())
        {
            return Ok(Handling::Incomplete);
        }
        records.sort_unstable();
        records.dedup();
        let mut last_end = 0;
        for (offset, sizes) in records {
            sink.check()?;
            let offset = offset as usize;
            let Some(data) = bytes.get(offset..directory_offset) else {
                return Ok(Handling::Incomplete);
            };
            let Some(entry) = Entry::parse(data, sizes) else {
                return Ok(Handling::Incomplete);
            };
            if offset < last_end {
                return Ok(Handling::Incomplete);
            }
            last_end = offset + entry.consumed;
            match entry.visit(sink)? {
                Handling::Complete => {}
                Handling::Stopped => break,
                other => return Ok(other),
            }
        }
    }
    // In 1.4.3 the local-header retry requires a previously extracted directory entry.
    // An archive missing its entire directory therefore produces no child.
    Ok(Handling::Complete)
}
