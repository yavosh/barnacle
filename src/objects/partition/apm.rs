use super::{ChildSink, Handling, SECTOR, extent, scan_extent};
use std::io;

fn u32be(entry: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(entry[at..at + 4].try_into().unwrap())
}
fn cstr(bytes: &[u8]) -> &[u8] {
    bytes.split(|&b| b == 0).next().unwrap_or_default()
}
fn is_map(kind: &[u8]) -> bool {
    matches!(
        kind,
        b"Apple_Partition_Map" | b"Apple_partition_map" | b"Apple_patition_map"
    )
}
fn entry(bytes: &[u8], sector: usize, index: usize) -> Option<&[u8]> {
    bytes.get(index.checked_mul(sector)?..)?.get(..80)
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if bytes.len() < 8 || !bytes.starts_with(b"ER") {
        return Ok(Handling::Complete);
    }
    let described = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if described == 0 || described.checked_mul(u32be(bytes, 4) as usize) != Some(bytes.len()) {
        return Ok(Handling::Complete);
    }
    let legacy = described == 2048 && bytes.get(512..514) == Some(b"PM");
    let sector = if legacy { SECTOR } else { described };
    let Some(map) = entry(bytes, sector, 1) else {
        return Ok(Handling::Complete);
    };
    if !map.starts_with(b"PM") || !is_map(cstr(&map[48..80])) {
        return Ok(Handling::Complete);
    }
    let count = (u32be(map, 4) as usize).min(sink.max_partitions());
    for index in 2..=count {
        sink.check()?;
        let Some(p) = entry(bytes, sector, index) else {
            break;
        };
        let kind = cstr(&p[48..80]);
        let start = u64::from(u32be(p, 8));
        if start == 0 || is_map(kind) {
            continue;
        }
        let driver = matches!(
            kind,
            b"Apple_Driver"
                | b"Apple_Driver43"
                | b"Apple_Driver43_CD"
                | b"Apple_Driver_ATA"
                | b"Apple_Driver_ATAPI"
                | b"Apple_Patches"
        );
        let blocks = u64::from(u32be(p, 12))
            * if legacy && index % 4 == 0 && driver {
                4
            } else {
                1
            };
        if let Some(bytes) = extent(bytes, sector, start, blocks)
            && let Some(status) = scan_extent(bytes, Some(cstr(&p[16..48])), sink)?
        {
            return Ok(status);
        }
    }
    Ok(Handling::Complete)
}
