//! Extract archive members in the pinned scanner's order. Member names are metadata only.
use super::{ChildSink, Handling};
use bzip2::read::BzDecoder;
use flate2::read::MultiGzDecoder;
use lzma_rust2::XzReader;
use std::io::{self, Read};

mod alz;
mod arj;
mod binhex;
mod cabinet;
mod chm;
mod cpio;
mod egg;
mod lha;
mod sevenzip;
mod sis;
mod szdd;
pub(super) mod workspace;
mod xar;
mod zip;
pub(super) use zip::directory as zip_directory;
pub(super) use zip::single as zip_single;

pub(super) fn file_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"xar!") {
        return Some("CL_TYPE_XAR");
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK00PK\x03\x04") {
        return Some("CL_TYPE_ZIP");
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Some("CL_TYPE_GZ");
    }
    if bytes.starts_with(b"BZh") {
        return Some("CL_TYPE_BZ");
    }
    if bytes.starts_with(b"\xfd7zXZ\0") {
        return Some("CL_TYPE_XZ");
    }
    if bytes.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Some("CL_TYPE_7Z");
    }
    if bytes.starts_with(b"MSCF\0\0\0\0") {
        return Some("CL_TYPE_MSCAB");
    }
    if bytes.starts_with(b"ITSF") {
        return Some("CL_TYPE_MSCHM");
    }
    if bytes.starts_with(b"ALZ\x01") {
        return Some("CL_TYPE_ALZ");
    }
    if bytes.starts_with(b"EGGA") {
        return Some("CL_TYPE_EGG");
    }
    if bytes.starts_with(&[0x60, 0xea]) {
        return Some("CL_TYPE_ARJ");
    }
    if bytes.starts_with(b"Rar!") {
        return Some("CL_TYPE_RAR");
    }
    if bytes.starts_with(b"(This file must be converted with BinHex 4.0)") {
        return Some("CL_TYPE_BINHEX");
    }
    if lha::recognized(bytes) {
        return Some("CL_TYPE_LHA_LZH");
    }
    if bytes
        .get(8..bytes.len().min(24))
        .is_some_and(|v| v.windows(4).any(|w| w == [0x19, 4, 0, 0x10]))
    {
        return Some("CL_TYPE_SIS");
    }
    if bytes.starts_with(b"SZDD") {
        return Some("CL_TYPE_MSSZDD");
    }
    if bytes.get(257..262) == Some(b"ustar") {
        return Some("CL_TYPE_POSIX_TAR");
    }
    match bytes {
        [b'0', b'7', b'0', b'7', b'0', b'1', ..] => Some("CL_TYPE_CPIO_NEWC"),
        [b'0', b'7', b'0', b'7', b'0', b'2', ..] => Some("CL_TYPE_CPIO_CRC"),
        [b'0', b'7', b'0', b'7', b'0', b'7', ..] => Some("CL_TYPE_CPIO_ODC"),
        [0x71, 0xc7, ..] | [0xc7, 0x71, ..] => Some("CL_TYPE_CPIO_OLD"),
        _ if bytes.get(..512).is_some_and(|h| tar_checksum(h, false))
            && !super::text::plain(bytes) =>
        {
            Some("CL_TYPE_OLD_TAR")
        }
        _ => None,
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    match file_type(bytes) {
        Some("CL_TYPE_XAR") => xar::extract(bytes, sink),
        Some("CL_TYPE_ZIP") => zip::extract(bytes, sink),
        Some("CL_TYPE_7Z") => sevenzip::extract(bytes, sink),
        Some("CL_TYPE_MSCAB") => cabinet::extract(bytes, sink),
        Some("CL_TYPE_MSCHM") => chm::extract(bytes, sink),
        Some("CL_TYPE_ALZ") => alz::extract(bytes, sink),
        Some("CL_TYPE_EGG") => egg::extract(bytes, sink),
        Some("CL_TYPE_ARJ") => arj::extract(bytes, sink),
        // The Debian 1.4.3 reference has no optional UnRAR module.
        Some("CL_TYPE_RAR") => Ok(Handling::Complete),
        Some("CL_TYPE_BINHEX") => binhex::extract(bytes, sink),
        Some("CL_TYPE_LHA_LZH") => lha::extract(bytes, sink),
        Some("CL_TYPE_SIS") => sis::extract(bytes, sink),
        Some("CL_TYPE_MSSZDD") => szdd::extract(bytes, sink),
        // Stock concatenates all gzip members into a single child.
        Some("CL_TYPE_GZ") => decoded(MultiGzDecoder::new(bytes), None, true, sink),
        Some("CL_TYPE_BZ") => decoded(BzDecoder::new(bytes), None, false, sink),
        Some("CL_TYPE_XZ") => xz(bytes, sink),
        Some("CL_TYPE_POSIX_TAR" | "CL_TYPE_OLD_TAR") => tar(bytes, sink),
        Some(_) => cpio::extract(bytes, sink),
        None => Ok(Handling::Unrecognized),
    }
}

fn xz(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    const STOCK_LIMIT_KIB: u32 = 1024 * 1024;
    let history = workspace::history(sink.remaining()).saturating_add(2 << 20);
    // The reader checks every block's model before allocation. Try a quarter
    // of the shared budget first, so ordinary dictionaries can run together.
    let mut limit_kib = (workspace::BUDGET / 4 / 1024) as u32;
    loop {
        let (snapshot, decoder_failed) = {
            let estimate = history.min(u64::from(limit_kib) * 1024);
            let _lease = workspace::acquire(estimate, || sink.check())?;
            let mut decoder = Decoded {
                reader: XzReader::new_mem_limit(bytes, true, limit_kib),
                failed: false,
                allow_partial: false,
            };
            (sink.read_child(&mut decoder), decoder.failed)
        };
        match snapshot {
            // A concatenated stream may increase its dictionary. Drop the
            // earlier pass before acquiring a larger reservation and replay.
            Err(e)
                if decoder_failed
                    && e.kind() == io::ErrorKind::OutOfMemory
                    && limit_kib < STOCK_LIMIT_KIB =>
            {
                limit_kib = STOCK_LIMIT_KIB;
            }
            Err(_) if decoder_failed => return Ok(Handling::Incomplete),
            Err(e) => return Err(e),
            Ok(snapshot) => {
                if let Some(data) = snapshot
                    && sink.visit_snapshot(data, None, None)?
                {
                    return Ok(Handling::Stopped);
                }
                return Ok(Handling::Complete);
            }
        }
    }
}

// Stock scans the bytes the decompressor produced before a malformed trailer.
// Keep that prefix available and remember the decoding error after the child returns.
struct Decoded<R> {
    reader: R,
    failed: bool,
    allow_partial: bool,
}

impl<R: Read> Read for Decoded<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.failed {
            return Ok(0);
        }
        match self.reader.read(out) {
            Err(error) if error.kind() != io::ErrorKind::Interrupted => {
                // All decoder input comes from an immutable byte slice.
                self.failed = true;
                if self.allow_partial {
                    Ok(0)
                } else {
                    Err(error)
                }
            }
            result => result,
        }
    }
}

fn decoded(
    reader: impl Read,
    name: Option<&[u8]>,
    allow_partial: bool,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    // Drop an owned decompressor and its dictionary before entering a nested archive.
    let (snapshot, failed) = {
        let mut data = Decoded {
            reader,
            failed: false,
            allow_partial,
        };
        (sink.read_child(&mut data), data.failed)
    };
    let snapshot = match snapshot {
        Err(_) if failed && !allow_partial => return Ok(Handling::Incomplete),
        result => result?,
    };
    if let Some(snapshot) = snapshot
        && sink.visit_snapshot(snapshot, None, name)?
    {
        return Ok(Handling::Stopped);
    }
    Ok(if failed {
        Handling::Incomplete
    } else {
        Handling::Complete
    })
}

fn digits(field: &[u8], radix: u32) -> Option<usize> {
    let text = std::str::from_utf8(field).ok()?.trim_matches([' ', '\0']);
    usize::from_str_radix(text, radix).ok()
}

fn tar_checksum(header: &[u8], allow_signed: bool) -> bool {
    let mut field = header[148..156]
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .peekable();
    let mut recorded = 0;
    while let Some(digit @ b'0'..=b'7') = field.next_if(|b| matches!(b, b'0'..=b'7')) {
        recorded = recorded * 8 + i32::from(digit - b'0');
    }
    if field
        .next()
        .is_some_and(|b| b != 0 && !b.is_ascii_whitespace())
    {
        return false;
    }
    let content = header[..148].iter().chain(&header[156..]);
    let spaces = 8 * i32::from(b' ');
    let sum = content.clone().fold(spaces, |sum, &b| sum + i32::from(b));
    recorded == sum
        || allow_signed && recorded == content.fold(spaces, |sum, &b| sum + i32::from(b as i8))
}

fn tar(mut bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let posix = bytes.get(257..262) == Some(b"ustar");
    while !bytes.is_empty() {
        sink.check()?;
        let Some((header, rest)) = bytes.split_at_checked(512) else {
            return Ok(Handling::Incomplete);
        };
        if header[0] == 0 {
            return Ok(Handling::Complete);
        }
        if !tar_checksum(header, true) || posix && &header[257..262] != b"ustar" {
            return Ok(Handling::Incomplete);
        }
        let Some(size) = digits(&header[124..136], 8) else {
            return Ok(Handling::Incomplete);
        };
        let available = size.min(rest.len());
        match header[156] {
            0 | b'0' | b'7' | b'M' if available != 0 => {
                let name = header[..100].split(|&b| b == 0).next();
                if sink.child_bytes(&rest[..available], name)? {
                    return Ok(Handling::Stopped);
                }
            }
            0
            | b'0'
            | b'7'
            | b'M'
            | b'1'..=b'6'
            | b'V'
            | b'K'
            | b'L'
            | b'N'
            | b'A'
            | b'E'
            | b'I'
            | b'g'
            | b'x'
            | b'X' => {}
            _ => return Ok(Handling::Incomplete),
        }
        let Some(consumed) = size.checked_next_multiple_of(512) else {
            return Ok(Handling::Incomplete);
        };
        let Some(next) = rest.get(consumed..) else {
            return Ok(Handling::Incomplete);
        };
        bytes = next;
    }
    Ok(Handling::Complete)
}
