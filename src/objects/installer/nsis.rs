use super::{ChildSink, Copied, Handling, NSIS_MAGIC, Snapshot, copy, le32};
use crate::objects::archive::workspace;
use flate2::bufread::DeflateDecoder;
use lzma_rust2::LzmaReader;
use std::io::{self, BufReader, Cursor, Read, Write};

#[derive(Clone, Copy)]
enum Codec {
    Bzip,
    Lzma,
    Deflate,
}

fn method(bytes: &[u8]) -> Codec {
    if bytes.first() == Some(&0x31) {
        Codec::Bzip
    } else if le32(bytes).is_some_and(|magic| magic & 0x7fff_ffff == 0x5d) {
        Codec::Lzma
    } else {
        Codec::Deflate
    }
}

fn blocks(mut bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Option<Codec>> {
    let mut counts = [0usize; 3];
    while bytes.len() > 4 {
        sink.check()?;
        let word = le32(bytes).expect("checked record header");
        let size = (word & 0x7fff_ffff) as usize;
        let Some((data, rest)) = bytes[4..].split_at_checked(size) else {
            return Ok(None);
        };
        if word >> 31 != 0 {
            counts[method(data) as usize] += 1;
        }
        bytes = rest;
    }
    Ok([Codec::Deflate, Codec::Lzma, Codec::Bzip]
        .into_iter()
        .max_by_key(|&c| counts[c as usize]))
}

struct Decoder<'a> {
    reader: Stream<'a>,
    _workspace: Option<workspace::Lease>,
}

enum Stream<'a> {
    Deflate(BufReader<DeflateDecoder<&'a [u8]>>),
    Lzma(Box<LzmaReader<&'a [u8]>>),
    Buffered {
        data: Cursor<Vec<u8>>,
        truncated: bool,
    },
}

impl Read for Decoder<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match &mut self.reader {
            Stream::Deflate(r) => r.read(output),
            Stream::Lzma(r) => r.read(output),
            Stream::Buffered { data, .. } => data.read(output),
        }
    }
}

impl<'a> Decoder<'a> {
    fn new(codec: Codec, bytes: &'a [u8], sink: &mut dyn ChildSink) -> io::Result<Option<Self>> {
        let (reader, lease) = match codec {
            Codec::Deflate => (
                Stream::Deflate(BufReader::with_capacity(32768, DeflateDecoder::new(bytes))),
                None,
            ),
            Codec::Lzma => {
                let Some((props, data)) = bytes.split_at_checked(5) else {
                    return Ok(None);
                };
                let dict = le32(&props[1..]).expect("five LZMA property bytes");
                let Ok(kib) = lzma_rust2::lzma_get_memory_usage_by_props(dict, props[0]) else {
                    return Ok(None);
                };
                if kib > 1024 * 1024 {
                    return Ok(None);
                }
                let lease = workspace::acquire(u64::from(kib) * 1024, || sink.check())?;
                let Ok(reader) = LzmaReader::new_with_props(data, u64::MAX, props[0], dict, None)
                else {
                    return Ok(None);
                };
                (Stream::Lzma(Box::new(reader)), Some(lease))
            }
            Codec::Bzip => {
                // This codec has a capped output API but cannot yield within
                // a call. Bound both input work and resident output.
                const INPUT: usize = 256 * 1024;
                const OUTPUT: usize = 4 * 1024 * 1024;
                if bytes.len() > INPUT {
                    return Ok(None);
                }
                let lease = workspace::acquire(16 << 20, || sink.check())?;
                let result = ::nsis::decompress::bzip2::decompress_bzip2(
                    bytes,
                    ::nsis::decompress::DecodeLimit::Truncate(OUTPUT),
                );
                sink.check()?;
                let Ok(decoded) = result else {
                    return Ok(None);
                };
                (
                    Stream::Buffered {
                        data: Cursor::new(decoded.data),
                        truncated: decoded.truncated,
                    },
                    Some(lease),
                )
            }
        };
        Ok(Some(Self {
            reader,
            _workspace: lease,
        }))
    }

    fn can_start_frame(&self) -> bool {
        match &self.reader {
            // The stock reader checks the remaining compressed input before
            // starting another solid file, including the archive CRC.
            Stream::Deflate(r) => r.get_ref().get_ref().len() > 4,
            // The LZMA reader buffers compressed bytes internally. Its
            // underlying slice can be empty before all frames are decoded.
            Stream::Lzma(_) => true,
            Stream::Buffered { data, .. } => data.position() < data.get_ref().len() as u64,
        }
    }

    fn truncated(&self) -> bool {
        matches!(
            self.reader,
            Stream::Buffered {
                truncated: true,
                ..
            }
        )
    }
}

fn visit(data: &[u8], first: bool, sink: &mut dyn ChildSink) -> io::Result<bool> {
    if first {
        sink.match_generic_view(data)
    } else {
        sink.child_bytes(data, None)
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if bytes.get(4..20) != Some(NSIS_MAGIC) {
        return Ok(Handling::Unrecognized);
    }
    let Some(total) = bytes.get(24..).and_then(le32) else {
        return Ok(Handling::Incomplete);
    };
    let Some(data) = bytes.get(28..total as usize) else {
        return Ok(Handling::Incomplete);
    };
    if let Some(codec) = blocks(data, sink)? {
        nonsolid(data, codec, sink)
    } else {
        solid(data, method(data), sink)
    }
}

fn nonsolid(mut bytes: &[u8], codec: Codec, sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let mut header = true;
    while bytes.len() > 4 {
        sink.check()?;
        let first = std::mem::replace(&mut header, false);
        let word = le32(bytes).expect("checked record length");
        let size = word & 0x7fff_ffff;
        let Some((data, next)) = bytes[4..].split_at_checked(size as usize) else {
            return Ok(Handling::Incomplete);
        };
        bytes = next;
        if size == 0 || sink.skip_declared_size(size.into()) {
            continue;
        }
        let hit = if word >> 31 == 0 {
            visit(data, first, sink)?
        } else {
            let Some(mut decoder) = Decoder::new(codec, data, sink)? else {
                return Ok(Handling::Incomplete);
            };
            if decoder.truncated() {
                return Ok(Handling::Incomplete);
            }
            let mut snapshot = Snapshot::new(sink.temporary_directory());
            let limit = sink.remaining();
            let result = copy(&mut decoder, &mut snapshot, limit, sink)?;
            drop(decoder);
            match result {
                Copied::Complete(_) => snapshot.with_bytes(|data| visit(data, first, sink))?,
                Copied::Limit => {
                    sink.skip_declared_size(limit.saturating_add(1));
                    false
                }
                Copied::Invalid => return Ok(Handling::Incomplete),
            }
        };
        if hit {
            return Ok(Handling::Stopped);
        }
    }
    Ok(Handling::Complete)
}

enum End {
    Finished,
    Next,
    Limit(u32),
    Invalid,
}

fn solid(bytes: &[u8], codec: Codec, sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let mut start = 0;
    loop {
        let Some(mut decoder) = Decoder::new(codec, bytes, sink)? else {
            return Ok(Handling::Incomplete);
        };
        let mut spool = Snapshot::new(sink.temporary_directory());
        let mut ordinal = 0;
        let mut saved = 0;
        let mut used = 0u64;
        let limit = sink.remaining();
        let end = loop {
            sink.check()?;
            if !decoder.can_start_frame() {
                break if decoder.truncated() {
                    End::Invalid
                } else {
                    End::Finished
                };
            }
            let mut prefix = [0; 4];
            match decoder.read(&mut prefix[..1]) {
                Ok(0) => break End::Finished,
                Err(_) => break End::Invalid,
                Ok(_) => (),
            }
            if decoder.read_exact(&mut prefix[1..]).is_err() {
                break End::Invalid;
            }
            let length = u32::from_le_bytes(prefix);
            let size = u64::from(length);
            if ordinal >= start {
                if size > limit {
                    break End::Limit(length);
                }
                if saved != 0 && used + 4 + size > 32 << 20 {
                    break End::Next;
                }
                spool.write_all(&prefix)?;
            }
            let mut discarded = io::sink();
            let output: &mut dyn Write = if ordinal < start {
                &mut discarded
            } else {
                &mut spool
            };
            match copy(&mut (&mut decoder).take(size), output, size, sink)? {
                Copied::Complete(n) if n == size => (),
                _ => break End::Invalid,
            }
            if ordinal >= start {
                saved += 1;
                used += 4 + size;
            }
            ordinal += 1;
        };
        drop(decoder);
        let seen = spool.with_bytes(|mut records| {
            for i in start..start + saved {
                let size = le32(records).expect("staged prefix") as usize;
                let (data, next) = records[4..].split_at(size);
                records = next;
                if sink.skip_declared_size(size as u64) {
                    return Ok(Some(Handling::Complete));
                }
                if size != 0 && visit(data, i == 0, sink)? {
                    return Ok(Some(Handling::Stopped));
                }
            }
            Ok(None)
        })?;
        if let Some(result) = seen {
            return Ok(result);
        }
        match end {
            End::Finished => return Ok(Handling::Complete),
            End::Invalid => return Ok(Handling::Incomplete),
            End::Limit(size) => {
                sink.skip_declared_size(size.into());
                return Ok(Handling::Complete);
            }
            End::Next => start += saved,
        }
    }
}
