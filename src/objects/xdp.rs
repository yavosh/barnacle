//! Visit PDF documents attached to an XML Data Package.
use super::{ChildSink, Handling, text};
use quick_xml::{Reader, events::Event};
use std::io::{self, Read};

pub(super) const MAGIC: &[u8] = b"<xdp:xdp";

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(1024)]
        .windows(MAGIC.len())
        .any(|w| w == MAGIC)
}

pub(super) fn can_retype(name: &str) -> bool {
    name.starts_with("CL_TYPE_TEXT_") || name == "CL_TYPE_BINARY_DATA"
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let mut reader = Reader::from_reader(bytes);
    // Borrow element names from the input so large names do not duplicate the input.
    reader.config_mut().check_end_names = false;
    reader.config_mut().allow_unmatched_ends = true;
    let mut elements = Vec::<&[u8]>::new();
    let mut chunk = None;
    loop {
        sink.check()?;
        let at = reader.buffer_position() as usize;
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                if elements.len() == 256 || chunk.is_some() {
                    return Ok(Handling::Incomplete);
                }
                elements.push(&bytes[at + 1..at + 1 + e.name().as_ref().len()]);
                if e.local_name().as_ref() == "chunk" {
                    chunk = Some(reader.buffer_position() as usize);
                }
            }
            Ok(Event::End(e)) => {
                if elements.pop() != Some(e.name().as_ref().as_bytes()) {
                    return Ok(Handling::Incomplete);
                }
                if let Some(start) = chunk.take() {
                    let data = &bytes[start..at];
                    if !text::valid_base64(data, sink)? {
                        return Ok(Handling::Incomplete);
                    }
                    let mut decoded = text::base64_reader(data);
                    // Stock searches the first 1,028 positions for a PDF header.
                    let mut prefix = Vec::with_capacity(1033);
                    decoded.by_ref().take(1033).read_to_end(&mut prefix)?;
                    if !prefix
                        .windows(6)
                        .any(|w| w[..5].eq_ignore_ascii_case(b"%PDF-"))
                    {
                        return Ok(Handling::Complete);
                    }
                    if sink.child(&mut prefix.as_slice().chain(decoded), None, None)? {
                        return Ok(Handling::Stopped);
                    }
                }
            }
            Ok(Event::Text(_)) => {}
            Ok(Event::Eof) if elements.is_empty() => return Ok(Handling::Complete),
            Ok(Event::Eof | Event::DocType(_)) | Err(_) => return Ok(Handling::Incomplete),
            Ok(_) if chunk.is_some() => return Ok(Handling::Incomplete),
            Ok(_) => {}
        }
    }
}
