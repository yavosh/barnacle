//! Universal Mach-O files use an ordered table of offsets to independent object files.
use super::{ChildSink, Handling};
use std::io;

pub(super) fn recognized(bytes: &[u8]) -> bool {
    matches!(bytes, [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0..=31, ..])
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(&count) = bytes.get(7) else {
        return Ok(Handling::Complete);
    };
    for index in 0..usize::from(count) {
        sink.check()?;
        let start = 8 + index * 20;
        let Some(record) = bytes.get(start..start + 20) else {
            break;
        };
        let offset = u32::from_be_bytes(record[8..12].try_into().unwrap()) as usize;
        let size = u32::from_be_bytes(record[12..16].try_into().unwrap()) as usize;
        if offset < start + 20 {
            break;
        }
        let Some(tail) = bytes.get(offset..) else {
            continue;
        };
        // The mapped slice ends at EOF when its length is zero or extends beyond the image.
        let slice = if size == 0 {
            tail
        } else {
            &tail[..size.min(tail.len())]
        };
        if slice.len() <= 5 {
            continue;
        }
        if sink.skip_declared_size(slice.len() as u64) {
            break;
        }
        if sink.child_bytes(slice, None)? {
            return Ok(Handling::Stopped);
        }
    }
    Ok(Handling::Complete)
}
