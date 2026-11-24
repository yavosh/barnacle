//! Passive pictures in BIFF8 drawing groups and inline OfficeArt file BLIP store entries.
mod report;
use super::{ChildSink, Handling, Input};
use crate::objects::Snapshot;
use std::io::{self, Read, Seek, SeekFrom, Write};

const GROUP: u16 = 0x00eb;
const CONTINUE: u16 = 0x003c;
const MAX_RECORD: usize = 8228;
const REPORT_HEADER: &[u8] = b"-- BIFF content extracted and disassembled from CL_TYPE_MSXL .xls file because a XLM macro was found in the document\n";

// Stock matches its report before flushing the final 4096-byte stdio block. Bound the
// length of its ordinary record lines to establish when only its preamble is visible.
fn report_line_bound(opcode: u16) -> Option<usize> {
    Some(match opcode {
        0x0018 | 0x0207 => return None, // Name and String have variable listings.
        0x0000 | 0x0031 => 24,          // Padding and FONT have no label in the reference listing.
        0x000a => 32,                   // EOF
        0x00e0 => 35,                   // XF
        0x0809 | 0x0022 | 0x00a1 | 0x00fc | 0x0293 => 40,
        0x0042 | 0x003d | 0x008d | 0x0200 | 0x005d | 0x001d => 48,
        0x00eb => 63,  // MSODRAWINGGROUP
        0x0085 => 110, // BOUNDSHEET appends its sheet kind and visibility.
        _ => 74, // The longest static opcode description uses 59 bytes, plus 15 bytes of formatting.
    })
}

fn formula_bound(data: &[u8]) -> Option<usize> {
    let count = u16::from_le_bytes(data.get(20..22)?.try_into().ok()?) as usize;
    let mut tokens = data.get(22..)?;
    if tokens.len() != count {
        return None;
    }
    // Fixed record/coordinate text, the final token boundary, and the terminating newline.
    let mut bound = 96;
    while let Some(&code) = tokens.first() {
        // Each bound includes the token label and all printed operands. The scanner only
        // describes these BIFF tokens. Their formulas and functions are never evaluated.
        let (width, printed) = match code {
            0x03..=0x16 => (1, 16), // arithmetic, comparisons, and range operators
            0x1c | 0x1d => (2, 24), // error or Boolean
            0x1e => (3, 16),        // unsigned 16-bit integer
            0x1f => (9, 336), // a finite double has at most 309 digits before the decimal point
            0x01 | 0x24 | 0x44 | 0x64 => (5, 40), // cell references
            0x25 | 0x45 | 0x65 => (9, 64), // cell ranges
            0x21 | 0x41 | 0x61 => (3, 64), // fixed-arity function
            0x22 | 0x42 | 0x62 if *tokens.get(3)? < 0x80 => (4, 80), // worksheet function
            0x19 if *tokens.get(1)? == 0x10 => (4, 24), // optimized SUM
            _ => return None,
        };
        tokens = tokens.get(width..)?;
        bound += printed;
    }
    Some(bound)
}

pub(super) fn scan(mut input: Input<'_>, sink: &mut dyn ChildSink) -> io::Result<Option<Handling>> {
    let mut group = sink
        .child_limit()
        .is_none()
        .then(|| Snapshot::new(sink.temporary_directory()));
    let mut previous_group = false;
    let mut after_eof = false;
    let report_can_fit = REPORT_HEADER.len() as u64 <= sink.remaining();
    let mut report_bound = 0u64;
    let mut large_report = false;
    let mut group_len = 0u64;
    let mut remaining = input.len();
    let mut buf = [0; MAX_RECORD];
    while remaining >= 4 {
        sink.check()?;
        let mut header = [0; 4];
        input.read_exact(&mut header)?;
        let opcode = u16::from_le_bytes([header[0], header[1]]);
        let size = u16::from_le_bytes([header[2], header[3]]) as usize;
        if size > MAX_RECORD || size as u64 > remaining - 4 {
            if after_eof && trailing_blips(&mut input, header, remaining, sink)? {
                return Ok(Some(Handling::Complete));
            }
            return Ok(Some(Handling::Incomplete));
        }
        after_eof = opcode == 0x000a && size == 0;
        if report_can_fit {
            let line = if opcode == 0x0006 {
                input.read_exact(&mut buf[..size])?;
                formula_bound(&buf[..size])
            } else {
                report_line_bound(opcode)
            };
            let bound = match line {
                Some(bound) => bound,
                // Bound variable report text when only its admission can affect the verdict.
                // A formula token can print a decimal double. Its 22-byte header is fixed.
                None => {
                    large_report = true;
                    if opcode == 0x0006 {
                        128 + 1024 * size.saturating_sub(22)
                    } else {
                        128 + size * 4
                    }
                }
            };
            report_bound = report_bound.saturating_add(bound as u64);
            if group.is_some() && report_bound >= 4096 {
                large_report = true;
            }
        }
        if opcode != CONTINUE {
            previous_group = opcode == GROUP;
        }
        if previous_group && let Some(group) = &mut group {
            group_len += size as u64;
            if group_len >= 1 << 30 {
                return Ok(Some(Handling::Incomplete));
            }
            input.read_exact(&mut buf[..size])?;
            group.write_all(&buf[..size])?;
        } else if !report_can_fit || opcode != 0x0006 {
            input.seek(SeekFrom::Current(size as i64))?;
        }
        remaining -= size as u64 + 4;
    }
    let Some(group) = group else {
        let preamble = REPORT_HEADER.len() as u64;
        if sink.skip_declared_size(preamble) {
            return Ok(Some(Handling::Complete));
        }
        let maximum = preamble.saturating_add(report_bound / 4096 * 4096);
        if maximum > sink.remaining() {
            return report::scan(&mut input, sink, false).map(Some);
        }
        sink.can_enter_child();
        return Ok(Some(Handling::Complete));
    };
    if large_report {
        let maximum = (REPORT_HEADER.len() as u64).saturating_add(report_bound / 4096 * 4096);
        let retain = maximum <= sink.remaining();
        let result = report::scan(&mut input, sink, retain)?;
        if result != Handling::Complete {
            return Ok(Some(result));
        }
    } else if !sink.skip_declared_size(REPORT_HEADER.len() as u64)
        && sink.match_generic_view(REPORT_HEADER)?
    {
        return Ok(Some(Handling::Stopped));
    }
    if group_len == 0 {
        return Ok(None);
    }
    group.with_bytes(|data| pictures(data, sink))
}

// A bare OfficeArt delay stream after BIFF EOF makes stock abandon this pass before
// publishing the report or pictures. Verify every record without copying its payload.
fn trailing_blips(
    input: &mut Input<'_>,
    mut header: [u8; 4],
    mut remaining: u64,
    sink: &mut dyn ChildSink,
) -> io::Result<bool> {
    while remaining >= 8 {
        sink.check()?;
        let flags = u16::from_le_bytes([header[0], header[1]]);
        let kind = u16::from_le_bytes([header[2], header[3]]);
        let Some(prefix) = image_prefix(flags & 15, flags >> 4, kind) else {
            return Ok(false);
        };
        let mut len = [0; 4];
        input.read_exact(&mut len)?;
        let len = u64::from(u32::from_le_bytes(len));
        if len < prefix as u64 || len > remaining - 8 {
            return Ok(false);
        }
        remaining -= 8 + len;
        if remaining < 8 {
            return Ok(remaining == 0);
        }
        input.seek(SeekFrom::Current(len as i64))?;
        input.read_exact(&mut header)?;
    }
    Ok(false)
}

struct Record<'a> {
    version: u16,
    instance: u16,
    kind: u16,
    body: &'a [u8],
    len: usize,
}

fn record_header(data: &[u8]) -> Option<Record<'_>> {
    let (head, tail) = data.split_at_checked(8)?;
    let flags = u16::from_le_bytes([head[0], head[1]]);
    let len = u32::from_le_bytes(head[4..8].try_into().ok()?) as usize;
    let body = &tail[..len.min(tail.len())];
    Some(Record {
        version: flags & 15,
        instance: flags >> 4,
        kind: u16::from_le_bytes([head[2], head[3]]),
        body,
        len,
    })
}

fn record<'a>(data: &mut &'a [u8]) -> Option<Record<'a>> {
    let record = record_header(data)?;
    *data = data.get(8..)?.get(record.len..)?;
    Some(record)
}

fn pictures(mut data: &[u8], sink: &mut dyn ChildSink) -> io::Result<Option<Handling>> {
    let Some(group) = record(&mut data) else {
        return Ok(Some(Handling::Incomplete));
    };
    if group.kind != 0xf000 || group.version != 15 || group.instance != 0 || !data.is_empty() {
        return Ok(Some(Handling::Incomplete));
    }
    let mut children = group.body;
    while !children.is_empty() {
        sink.check()?;
        let Some(container) = record(&mut children) else {
            return Ok(Some(Handling::Incomplete));
        };
        if container.kind != 0xf001 {
            continue;
        }
        if container.version != 15 {
            return Ok(Some(Handling::Incomplete));
        }
        let mut files = container.body;
        let mut scanned = false;
        while !files.is_empty() {
            sink.check()?;
            let block = files;
            let Some(entry) = record(&mut files) else {
                return Ok(Some(Handling::Incomplete));
            };
            let image = match entry.kind {
                0xf007 => match stored_picture(entry, files) {
                    Some(Picture::Data(image)) => Some(image),
                    Some(Picture::Skip) => continue,
                    Some(Picture::End) => {
                        // A short image header ends this store. A store that
                        // emitted no image also ends the workbook traversal.
                        if !scanned {
                            return Ok(Some(Handling::Complete));
                        }
                        break;
                    }
                    None => None,
                },
                // For a bare BLIP stock bounds its image by the entire remaining store.
                _ => image(entry, &block[8..]),
            };
            let Some(image) = image else {
                return Ok(Some(Handling::Incomplete));
            };
            if sink.skip_declared_size(image.len() as u64) {
                return Ok(Some(Handling::Complete));
            }
            scanned = true;
            if sink.child_bytes(image, None)? {
                return Ok(Some(Handling::Stopped));
            }
        }
    }
    Ok(None)
}

enum Picture<'a> {
    Data(&'a [u8]),
    Skip,
    End,
}

fn stored_picture<'a>(entry: Record<'a>, following: &'a [u8]) -> Option<Picture<'a>> {
    if entry.version != 2 {
        return None;
    }
    let header = entry.body.get(..36)?;
    let size = u32::from_le_bytes(header[20..24].try_into().ok()?) as usize;
    let name_len = usize::from(header[33]);
    let mut data = entry.body.get(36 + name_len..)?;
    if data.is_empty() {
        // Stock reads a candidate header after the FBSE name in the same store.
        // The declared size bounds this lookahead; foDelay selects no external stream.
        let visible = &following[..size.min(following.len())];
        let Some(blip) = record_header(visible) else {
            return Some(Picture::End);
        };
        if blip.kind == 0xf007 && blip.version == 2 {
            return Some(Picture::Skip);
        }
        let prefix = image_prefix(blip.version, blip.instance, blip.kind)?;
        if visible.len() - 8 < prefix {
            return Some(Picture::Skip);
        }
        return image(blip, &visible[8..]).map(Picture::Data);
    }
    if data.len() != size {
        return None;
    }
    let blip = record(&mut data)?;
    if !data.is_empty() {
        return None;
    }
    let storage = blip.body;
    image(blip, storage).map(Picture::Data)
}

fn image_prefix(version: u16, instance: u16, kind: u16) -> Option<usize> {
    if version != 0 {
        return None;
    }
    // After the identifiers, stock skips a 34-byte metafile header or one bitmap tag.
    let (first, header) = match (kind, instance) {
        (0xf01a, _) => (0x3d4, 34),                     // EMF
        (0xf01b, _) => (0x216, 34),                     // WMF
        (0xf01c, _) => (0x542, 34),                     // PICT
        (0xf01d | 0xf02a, 0x46a | 0x46b) => (0x46a, 1), // JPEG
        (0xf01d | 0xf02a, 0x6e2 | 0x6e3) => (0x6e2, 1), // CMYK JPEG
        (0xf01e, _) => (0x6e0, 1),                      // PNG
        (0xf01f, _) => (0x7a8, 1),                      // DIB
        (0xf029, _) => (0x6e4, 1),                      // TIFF
        _ => return None,
    };
    let identifiers = match instance.checked_sub(first)? {
        0 => 16,
        1 => 32,
        _ => return None,
    };
    Some(identifiers + header)
}

fn image<'a>(record: Record<'a>, storage: &'a [u8]) -> Option<&'a [u8]> {
    let bytes = storage.get(image_prefix(record.version, record.instance, record.kind)?..)?;
    Some(&bytes[..record.len.min(bytes.len())])
}
