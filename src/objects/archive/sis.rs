use super::{ChildSink, Handling, decoded};
use flate2::read::ZlibDecoder;
use std::io::{self, Read};

fn word(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}

fn short(bytes: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()))
}

struct Inflate<'a> {
    data: io::Take<ZlibDecoder<&'a [u8]>>,
}

impl Read for Inflate<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.data.limit() == 0 && !out.is_empty() {
            if self.data.get_mut().read(&mut [0])? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SIS expanded size exceeds the declared buffer",
                ));
            }
            return Ok(0);
        }
        self.data.read(out)
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    const HEADER: usize = 84;
    if bytes.len() < HEADER || word(bytes, 8) != 0x10000419 {
        return Ok(Handling::Incomplete);
    }
    let languages = short(bytes, 18);
    let compressed = short(bytes, 36) & 8 == 0;
    let table = word(bytes, 52);
    if !(1..100).contains(&languages)
        || table < HEADER
        || bytes
            .get(word(bytes, 48)..)
            .and_then(|b| b.get(..languages * 2))
            .is_none()
    {
        return Ok(Handling::Incomplete);
    }
    let Some(mut records) = bytes.get(table..) else {
        return Ok(Handling::Incomplete);
    };
    let mut result = Handling::Complete;
    for _ in 0..short(bytes, 20) {
        sink.check()?;
        let Some(kind) = records.split_off(..4) else {
            return Ok(Handling::Incomplete);
        };
        let skip = match word(kind, 0) {
            0 => {
                let Some(file) = records.split_off(..24 + languages * 12) else {
                    return Ok(Handling::Incomplete);
                };
                let name = bytes
                    .get(word(file, 12)..)
                    .and_then(|s| s.get(..word(file, 8).min(400)))
                    .map(|s| {
                        s.iter()
                            .step_by(2)
                            .copied()
                            .take_while(|&b| b != 0)
                            .collect::<Vec<_>>()
                    });
                if word(file, 0) != 4 {
                    for i in 0..languages {
                        sink.check()?;
                        let packed = word(file, 24 + i * 4);
                        let offset = word(file, 24 + (languages + i) * 4);
                        let size = word(file, 24 + (2 * languages + i) * 4);
                        if packed == 0 || offset < HEADER || sink.skip_declared_size(packed as u64)
                        {
                            continue;
                        }
                        let Some(data) = bytes.get(offset..).and_then(|b| b.get(..packed)) else {
                            result = Handling::Incomplete;
                            continue;
                        };
                        let scanned = if compressed {
                            let triple = u64::from((packed as u32).wrapping_mul(3));
                            let capacity =
                                if size as u64 <= triple && !sink.skip_declared_size(triple) {
                                    triple
                                } else if !sink.skip_declared_size(size as u64) {
                                    size as u64
                                } else {
                                    continue;
                                };
                            decoded(
                                Inflate {
                                    data: ZlibDecoder::new(data).take(capacity),
                                },
                                name.as_deref(),
                                false,
                                sink,
                            )?
                        } else {
                            decoded(data, name.as_deref(), false, sink)?
                        };
                        if scanned == Handling::Stopped {
                            return Ok(scanned);
                        }
                        if scanned == Handling::Incomplete {
                            result = scanned;
                        }
                    }
                }
                8
            }
            // The pinned parser skips this many bytes for a language-file record.
            1 => languages,
            kind @ 2..=4 => {
                let Some(len) = records.split_off(..4) else {
                    return Ok(Handling::Incomplete);
                };
                let mut n = word(len, 0);
                if kind == 2 {
                    let Some(size) = n.checked_mul(languages * 8) else {
                        return Ok(Handling::Incomplete);
                    };
                    n = size;
                }
                n
            }
            5 | 6 => 0,
            _ => return Ok(Handling::Incomplete),
        };
        if records.split_off(..skip).is_none() {
            return Ok(Handling::Incomplete);
        }
    }
    Ok(result)
}
