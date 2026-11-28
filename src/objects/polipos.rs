//! Read-only Polipos heuristic for the pinned PE32 scanner.
use super::ChildSink;
use crate::body::PeMetadata;
use std::{collections::HashSet, io};

const CHARACTERISTICS: u32 = 0xe0000060;
const MAX_SOURCE: usize = 1024 * 1024 * 1024;
const MAX_TARGETS: usize = 1280;
const CHECK_INTERVAL: usize = 16 * 1024;

pub(super) fn matches(bytes: &[u8], header: &[u8], sink: &mut dyn ChildSink) -> io::Result<bool> {
    // The caller has already validated the PE32 header, ScanPE, HeuristicAlerts and the DLL flag.
    let count = u16::from_le_bytes([header[6], header[7]]) as usize;
    let optional = &header[24..];
    if count < 3
        || bytes.len() - header.len() > 0x800
        || header[4..6] != 0x14cu16.to_le_bytes()
        || !matches!(u16::from_le_bytes([optional[68], optional[69]]), 2 | 3)
        || u32::from_le_bytes(optional[72..76].try_into().unwrap()) < 0x80000
    {
        return Ok(false);
    }
    let table = usize::from(u16::from_le_bytes([header[20], header[21]]));
    let (headers, _) = optional[table..table + count * 40].as_chunks::<40>();
    let mut candidate = false;
    for group in headers[1..].chunks(1024) {
        sink.check()?;
        if group
            .iter()
            .any(|h| h[36..40] == CHARACTERISTICS.to_le_bytes())
        {
            candidate = true;
            break;
        }
    }
    if !candidate {
        return Ok(false);
    }
    let Some(pe) = PeMetadata::with_retained_sections(bytes, 12) else {
        return Ok(false);
    };
    if pe.section_count() < 3 {
        return Ok(false);
    }
    let Some([rva, _, raw, size, ..]) = pe.section(0) else {
        return Ok(false);
    };
    let Some([_, _, target, extent, ..]) = (1..usize::from(pe.section_count()))
        .filter_map(|i| pe.section(i))
        .rfind(|&[_, virtual_size, _, size, flags, ..]| {
            size != 0 && (40001..70000).contains(&virtual_size) && flags == CHARACTERISTICS
        })
    else {
        return Ok(false);
    };
    let size = size as usize;
    if !(6..=MAX_SOURCE).contains(&size) {
        return Ok(false);
    }
    let source = &bytes[raw as usize..][..size];
    let mut targets = HashSet::new();
    // The pinned loop excludes the final five-byte position.
    for (chunk, data) in source[..size - 5].chunks(CHECK_INTERVAL).enumerate() {
        sink.check()?;
        for location in memchr::memchr2_iter(0xe8, 0xe9, data) {
            let offset = chunk * CHECK_INTERVAL + location;
            let displacement =
                u32::from_le_bytes(source[offset + 1..offset + 5].try_into().unwrap());
            let address = rva
                .wrapping_add(offset as u32 + 5)
                .wrapping_add(displacement);
            let Some(at) = pe.raw_offset(address) else {
                continue;
            };
            let Some(relative) = at.checked_sub(target) else {
                continue;
            };
            if extent.saturating_sub(relative) < 9 || !targets.insert(at) {
                continue;
            }
            let sample = &bytes[at as usize..][..9];
            if sample.starts_with(&[0x55, 0x8b, 0xec, 0x60])
                || (sample.starts_with(&[0x55, 0x8b, 0xec, 0x83, 0xec]) && sample[6] == 0x60)
                || (sample.starts_with(&[0x55, 0x8b, 0xec, 0x81, 0xec]) && sample[7..] == [0, 0])
            {
                return Ok(true);
            }
            if targets.len() == MAX_TARGETS {
                return Ok(false);
            }
        }
    }
    Ok(false)
}
