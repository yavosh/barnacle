//! Identify Office ZIP containers before scanning their members.
use super::{ChildSink, archive};
use std::io;

const HWP_CONTENT: &[u8] = b"Contents/content.hpf";

fn office_directory_type(name: &[u8]) -> Option<&'static str> {
    for (prefix, kind) in [
        (b"word/".as_slice(), "CL_TYPE_OOXML_WORD"),
        (b"xl/", "CL_TYPE_OOXML_XL"),
        (b"ppt/", "CL_TYPE_OOXML_PPT"),
    ] {
        if name.starts_with(prefix) {
            return Some(kind);
        }
    }
    None
}

fn package_part(name: &[u8]) -> bool {
    [
        b"[Content_Types].xml".as_slice(),
        b"[ContentTypes].xml",
        b"docProps/",
        b"customXml/",
        b"_.rels/.rels",
        b"mimetype",
        b"Contents",
        b"version.xml",
        b"settings.xml",
        b"Preview/PrvText.txt",
        b"META-INF/container.xml",
        b"BinData",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

pub(super) fn classify(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<&'static str> {
    const ZIP: &str = "CL_TYPE_ZIP";
    if bytes.len() <= 70 {
        return Ok(ZIP);
    }
    // The reference examines three readable local headers. A package hint
    // allows a subsequent lookup in the central directory, in directory order.
    let mut hint = false;
    let mut readable = 0;
    let mut start = 0;
    let mut end = bytes.len().min(1024);
    for _ in 0..32 {
        let window = &bytes[start..end];
        if let Some(at) = window.windows(4).position(|b| b == b"PK\x03\x04")
            && let Some(name) = window.get(at + 30..).filter(|name| name.len() > 22)
        {
            // The local check compares prefixes in the header window.
            if name.starts_with(HWP_CONTENT) {
                return Ok("CL_TYPE_OOXML_HWP");
            }
            if let Some(kind) = office_directory_type(name) {
                return Ok(kind);
            }
            hint |= package_part(name);
            readable += 1;
            if readable == 3 {
                break;
            }
            start += at + 30;
        } else {
            if bytes.len() - end <= 30 {
                break;
            }
            start = end.saturating_sub(53);
            end = (start + 1028).min(bytes.len());
        }
    }
    if !hint || readable < 3 {
        return Ok(ZIP);
    }
    let Some((offset, count)) = archive::zip_directory(bytes, sink)? else {
        return Ok(ZIP);
    };
    let mut rest = &bytes[offset..];
    for _ in 0..count {
        sink.check()?;
        let Some((header, fields)) = rest.split_at_checked(46) else {
            break;
        };
        if !header.starts_with(b"PK\x01\x02") {
            break;
        }
        let length = |at| usize::from(u16::from_le_bytes([header[at], header[at + 1]]));
        let Some(name) = fields.get(..length(28)) else {
            break;
        };
        // The central lookup compares the complete HWP package filename.
        if name
            .strip_prefix(HWP_CONTENT)
            .is_some_and(|suffix| matches!(suffix.first(), None | Some(0)))
        {
            return Ok("CL_TYPE_OOXML_HWP");
        }
        if let Some(kind) = office_directory_type(name) {
            return Ok(kind);
        }
        let Some(next) = fields.get(length(28) + length(30) + length(32)..) else {
            break;
        };
        rest = next;
    }
    Ok(ZIP)
}
