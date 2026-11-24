//! Read installer resources from an immutable carrier. Names are metadata.
use super::{ChildSink, Handling, Snapshot};
use std::io::{self, Read, Write};

mod nsis;
mod shield;
pub(super) use shield::legacy;

pub(super) const NSIS_MAGIC: &[u8] = b"\xef\xbe\xad\xdeNullsoftInst";
pub(super) const ISHIELD_MAGIC: &[u8] = b"InstallShield\0";

pub(super) fn is_ishield(bytes: &[u8]) -> bool {
    bytes.starts_with(ISHIELD_MAGIC)
        && bytes.get(306..314) == Some(&[6, 0, 0, 0, 0, 0, 0, 0])
        && bytes.get(322..327) == Some(&[0, 0, 0, 0, 1])
}

pub(super) fn extract(kind: &str, bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    match kind {
        "CL_TYPE_NULSFT" => nsis::extract(bytes, sink),
        "CL_TYPE_ISHIELD_MSI" => shield::extract(bytes, sink),
        _ => Ok(Handling::Unrecognized),
    }
}

fn le32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

enum Copied {
    Complete(u64),
    Limit,
    Invalid,
}

// Keep decoder errors distinct from a deadline or scratch I/O error.
fn copy(
    input: &mut dyn Read,
    output: &mut dyn Write,
    limit: u64,
    sink: &mut dyn ChildSink,
) -> io::Result<Copied> {
    let mut buf = [0; 8192];
    let mut copied = 0u64;
    loop {
        sink.check()?;
        let max = (limit - copied).saturating_add(1).min(buf.len() as u64) as usize;
        let size = match input.read(&mut buf[..max]) {
            Ok(0) => return Ok(Copied::Complete(copied)),
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Ok(Copied::Invalid),
        };
        copied += size as u64;
        if copied > limit {
            return Ok(Copied::Limit);
        }
        output.write_all(&buf[..size])?;
    }
}
