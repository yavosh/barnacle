//! HWP5 stores named streams in a compound file. Selected streams use raw DEFLATE.
use super::{ChildSink, Document, Handling, Input, Inventory, named, normalized_name};
use std::io::{self, Read};

pub(super) fn header(
    doc: &mut Document,
    directory: &Inventory,
    sink: &mut dyn ChildSink,
) -> io::Result<Option<u32>> {
    for entry in directory
        .streams
        .iter()
        .filter(|e| named(e, &["fileheader"]))
    {
        sink.check()?;
        let mut source = Input::open(doc, directory, entry)?;
        let mut header = [0; 40];
        let n = source.len().min(header.len() as u64) as usize;
        source.read_exact(&mut header[..n])?;
        if header.starts_with(b"HWP Document File") {
            return Ok(Some(u32::from_le_bytes(header[36..40].try_into().unwrap())));
        }
    }
    Ok(None)
}
fn compressed_kind(name: &str) -> bool {
    [
        "bin",
        "section",
        "docinfo",
        "viewtext",
        "jscriptversion",
        "defaultjscript",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}
pub(super) fn scan(
    doc: &mut Document,
    directory: &Inventory,
    flags: u32,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let protected = flags & (0x2 | 0x4 | 0x10 | 0x100 | 0x400) != 0;
    for (preceding, entry) in directory.streams.iter().enumerate() {
        sink.check()?;
        if sink.ole_directory_limit(entry.depth, preceding) {
            break;
        }
        let Some(name) = normalized_name(&entry.name) else {
            return Ok(Handling::Incomplete);
        };
        let mut source = Input::open(doc, directory, entry)?;
        let stop = if flags & 1 != 0 && flags & 2 == 0 && compressed_kind(&name) {
            super::super::xml::scan_deflated(&mut source, sink)?
        } else {
            sink.child(&mut source, None, Some(name.as_bytes()))?
        };
        if stop {
            return Ok(Handling::Stopped);
        }
    }
    Ok(if protected {
        Handling::Incomplete
    } else {
        Handling::Complete
    })
}
