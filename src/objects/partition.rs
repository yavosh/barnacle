//! Partition tables direct scans to borrowed sectors of the current disk image.
mod apm;
mod gpt;
mod mbr;

use super::{ChildSink, Handling};
use std::io;

const SECTOR: usize = 512;

fn extent(bytes: &[u8], sector: usize, start: u64, count: u64) -> Option<&[u8]> {
    let offset = usize::try_from(start).ok()?.checked_mul(sector)?;
    let length = usize::try_from(count).ok()?.checked_mul(sector)?;
    bytes.get(offset..offset.checked_add(length)?)
}

fn scan_extent(
    bytes: &[u8],
    name: Option<&[u8]>,
    sink: &mut dyn ChildSink,
) -> io::Result<Option<Handling>> {
    if sink.skip_declared_size(bytes.len() as u64) {
        return Ok(Some(Handling::Complete));
    }
    Ok(sink
        .partition_bytes(bytes, name)?
        .then_some(Handling::Stopped))
}

pub(super) fn initial(bytes: &[u8]) -> Option<&'static str> {
    if bytes.get(512..520) == Some(b"EFI PART") {
        Some("CL_TYPE_GPT")
    } else if bytes.starts_with(b"ER") && bytes.get(512..516) == Some(b"PM\0\0") {
        Some("CL_TYPE_APM")
    } else {
        None
    }
}

pub(super) fn from_mbr(bytes: &[u8]) -> Option<&'static str> {
    if bytes.get(510..512) != Some(&[0x55, 0xaa])
        || !bytes.len().is_multiple_of(SECTOR)
        || bytes.len() < 2 * SECTOR
    {
        return None;
    }
    if matches!(bytes[450], 0xed | 0xee) {
        return Some("CL_TYPE_GPT");
    }
    mbr::valid(bytes).then_some("CL_TYPE_MBR")
}

pub(super) fn extract(kind: &str, bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    match kind {
        "CL_TYPE_MBR" => mbr::extract(bytes, sink),
        "CL_TYPE_GPT" => gpt::extract(bytes, sink),
        "CL_TYPE_APM" => apm::extract(bytes, sink),
        _ => Ok(Handling::Incomplete),
    }
}
