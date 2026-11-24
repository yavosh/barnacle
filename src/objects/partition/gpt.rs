use super::{ChildSink, Handling, extent, scan_extent};
use std::io;

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
struct Table<'a> {
    entries: &'a [[u8; 128]],
    sum: u32,
    first: u64,
    last: u64,
}

fn table<'a>(
    bytes: &'a [u8],
    sector: usize,
    index: usize,
    sink: &mut dyn ChildSink,
) -> io::Result<Option<Table<'a>>> {
    let Some(h) = bytes.get(index * sector..).and_then(|b| b.get(..92)) else {
        return Ok(None);
    };
    let end = (bytes.len() / sector - 1) as u64;
    let first = u64le(h, 40);
    let last = u64le(h, 48);
    if !h.starts_with(b"EFI PART")
        || u32le(h, 12) != 92
        || u32le(h, 20) != 0
        || u32le(h, 84) != 128
        || first < 2
        || last >= end
        || first > last
    {
        return Ok(None);
    }
    let current = u64le(h, 24);
    let alternate = u64le(h, 32);
    if !((current == 1 && alternate == end) || (current == end && alternate == 1)) {
        return Ok(None);
    }
    let mut crc = flate2::Crc::new();
    crc.update(&h[..16]);
    crc.update(&[0; 4]);
    crc.update(&h[20..]);
    if crc.sum() != u32le(h, 16) {
        return Ok(None);
    }
    let lba = u64le(h, 72);
    let len = u64::from(u32le(h, 80)) * 128;
    let Some(after) = lba.checked_add(len / (sector as u64)) else {
        return Ok(None);
    };
    if lba < 2 || after > end || (lba <= last && (lba >= first || after > first)) {
        return Ok(None);
    }
    let Some(offset) = usize::try_from(lba)
        .ok()
        .and_then(|n| n.checked_mul(sector))
    else {
        return Ok(None);
    };
    let Some(array) = bytes
        .get(offset..)
        .and_then(|tail| tail.get(..usize::try_from(len).ok()?))
    else {
        return Ok(None);
    };
    let mut crc = flate2::Crc::new();
    for chunk in array.chunks(64 * 1024) {
        sink.check()?;
        crc.update(chunk);
    }
    if crc.sum() != u32le(h, 88) {
        return Ok(None);
    }
    Ok(Some(Table {
        entries: array.as_chunks::<128>().0,
        sum: crc.sum(),
        first,
        last,
    }))
}
impl Table<'_> {
    fn scan(
        &self,
        bytes: &[u8],
        sector: usize,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Option<Handling>> {
        for entry in self.entries.iter().take(sink.max_partitions()) {
            sink.check()?;
            let start = u64le(entry, 32);
            let end = u64le(entry, 40);
            if start < self.first || end > self.last || start > end {
                continue;
            }
            if let Some(data) = extent(bytes, sector, start, end - start + 1) {
                let mut name = [0; 36];
                for (out, pair) in name.iter_mut().zip(entry[56..].as_chunks::<2>().0) {
                    // The reference narrows a UTF-16 unit to one byte for the layer name.
                    *out = pair[0].wrapping_add(pair[1] << 4);
                }
                let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
                if let Some(status) = scan_extent(data, Some(name), sink)? {
                    return Ok(Some(status));
                }
            }
        }
        Ok(None)
    }
}
pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(sector) = [512, 1024, 2048, 4096]
        .into_iter()
        .find(|&n| bytes.get(n..n + 8) == Some(b"EFI PART"))
    else {
        return Ok(Handling::Complete);
    };
    if !bytes.len().is_multiple_of(sector) {
        return Ok(Handling::Complete);
    }
    let primary = table(bytes, sector, 1, sink)?;
    let secondary = table(bytes, sector, bytes.len() / sector - 1, sink)?;
    if let Some(p) = &primary
        && let Some(status) = p.scan(bytes, sector, sink)?
    {
        return Ok(status);
    }
    if let Some(s) = secondary
        && primary.as_ref().is_none_or(|p| p.sum != s.sum)
        && let Some(status) = s.scan(bytes, sector, sink)?
    {
        return Ok(status);
    }
    Ok(Handling::Complete)
}
