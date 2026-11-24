//! OneNote desktop attachment records, as described in MS-ONESTORE 2.6.13.
mod package;
mod properties;
mod wire;

use super::{ChildSink, Handling};
use aho_corasick::AhoCorasick;
use std::{io, sync::LazyLock};

const SECTION: &[u8; 16] = b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3";
const PACKAGE: &[u8; 16] = b"\x2f\xe9\x8d\x63\xd4\xa6\xc1\x4b\x9a\x36\xb3\xfc\x25\x11\xa5\xb7";
const FILE_DATA: &[u8; 16] = b"\xe7\x16\xe3\xbd\x65\x26\x11\x45\xa4\xc4\x8d\x4d\x0b\x7a\x9e\xac";
static RECORD: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new([FILE_DATA]).expect("file data GUID"));

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(SECTION)
}

pub(super) fn extract(mut rest: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if rest.get(48..64) == Some(PACKAGE)
        && rest.get(16..32) == rest.get(32..48)
        && rest.get(64..68) == Some(&[0; 4])
    {
        return package::extract(rest, sink);
    }
    while rest.len() >= FILE_DATA.len() {
        sink.check()?;
        let window = rest.len().min(65536);
        let Some(found) = RECORD.find(&rest[..window]) else {
            rest = &rest[window - (FILE_DATA.len() - 1)..];
            continue;
        };
        let record = &rest[found.start()..];
        let Some(header) = record.get(..36) else {
            break;
        };
        // The pinned desktop reader uses the low 32 bits of cbLength.
        let length =
            u32::from_le_bytes(header[16..20].try_into().expect("file data length")) as usize;
        let Some((child, next)) = record[36..].split_at_checked(length) else {
            break;
        };
        if sink.child_bytes(child, None)? {
            return Ok(Handling::Stopped);
        }
        rest = next;
    }
    Ok(Handling::Complete)
}
