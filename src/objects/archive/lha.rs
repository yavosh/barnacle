use super::{ChildSink, Handling, decoded};
use delharc::LhaDecodeReader;
use std::io::{self, Cursor};

pub(super) fn recognized(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(2..7),
        Some([b'-', b'l', b'h', b'0'..=b'7' | b'd' | b'x', b'-'])
            | Some(b"-lzs-" | b"-lz4-" | b"-lz5-" | b"-pm0-")
    )
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Ok(mut archive) = LhaDecodeReader::new(Cursor::new(bytes)) else {
        return Ok(Handling::Incomplete);
    };
    let mut result = Handling::Complete;
    loop {
        sink.check()?;
        let header = archive.header();
        if !header.is_directory()
            && header.original_size > 0
            && !sink.skip_declared_size(header.original_size)
        {
            if archive.is_decoder_supported() {
                let path = header.parse_pathname();
                let name = path.to_string_lossy();
                match decoded(&mut archive, Some(name.as_bytes()), false, sink)? {
                    Handling::Stopped => return Ok(Handling::Stopped),
                    Handling::Incomplete => result = Handling::Incomplete,
                    _ => {}
                }
                // Stock scans decoded members even when their stored CRC does not match.
            } else {
                result = Handling::Incomplete;
            }
        }
        match archive.seek_next_file() {
            Ok(true) => {}
            Ok(false) => return Ok(result),
            Err(_) => return Ok(Handling::Incomplete),
        }
    }
}
