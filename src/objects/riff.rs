//! Bounded animated-cursor header inspection; no cursor payload decoding.
use std::io;

pub(super) fn irregular_header(
    bytes: &[u8],
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<bool> {
    let big = match bytes.get(..4) {
        Some(b"RIFF") => false,
        Some(b"RIFX") => true,
        _ => return Ok(false),
    };
    if bytes.get(8..12) != Some(b"ACON") {
        return Ok(false);
    }
    let mut offset = 12usize;
    let mut groups = 0;
    let mut chunks = 0usize;
    loop {
        if chunks.is_multiple_of(256) {
            check()?;
        }
        chunks += 1;
        let Some(header) = bytes.get(offset..).and_then(|rest| rest.get(..8)) else {
            return Ok(false);
        };
        let word = header[4..8].try_into().unwrap();
        let size = if big {
            u32::from_be_bytes(word)
        } else {
            u32::from_le_bytes(word)
        };
        match &header[..4] {
            b"anih" if size != 36 => return Ok(true),
            b"RIFF" | b"RIFX" => return Ok(false),
            b"LIST" | b"PROP" | b"FORM" | b"CAT " => {
                // Stock descends into groups without using their declared extent.
                // Its 1,000-level limit counts the following child as another level.
                groups += 1;
                if groups >= 1000 || bytes.len() - offset < 12 {
                    return Ok(false);
                }
                offset += 12;
            }
            _ => {
                groups = 0;
                let Some(next) = offset
                    .checked_add(8)
                    .and_then(|v| v.checked_add(size as usize))
                    .and_then(|v| v.checked_add((size & 1) as usize))
                else {
                    return Ok(false);
                };
                if next > bytes.len() {
                    return Ok(false);
                }
                offset = next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(chunks: &[u8]) -> Vec<u8> {
        let mut bytes = b"RIFF".to_vec();
        bytes.extend((4 + chunks.len() as u32).to_le_bytes());
        bytes.extend(b"ACON");
        bytes.extend(chunks);
        bytes
    }

    #[test]
    fn groups_padding_and_stopping() {
        let short = b"anih\0\0\0\0";
        for group in [b"LIST", b"PROP", b"FORM", b"CAT "] {
            let chunks = [group.as_slice(), b"\x0c\0\0\0fram", short].concat();
            assert!(irregular_header(&root(&chunks), || Ok(())).unwrap());
        }
        let chunks = [b"note\x01\0\0\0x\0".as_slice(), short].concat();
        assert!(irregular_header(&root(&chunks), || Ok(())).unwrap());
        for stop in [b"RIFF\0\0\0\0", b"RIFX\0\0\0\0"] {
            assert!(
                !irregular_header(&root(&[stop.as_slice(), short].concat()), || Ok(())).unwrap()
            );
        }
        for end in 0..8 {
            assert!(!irregular_header(&root(&short[..end]), || Ok(())).unwrap());
        }
        assert!(!irregular_header(b"RIFF\x04\0\0\0WAVE", || Ok(())).unwrap());
    }

    #[test]
    fn bounded_groups_and_cancellation() {
        for (depth, expected) in [(999, true), (1000, false)] {
            let mut chunks = b"LIST\x04\0\0\0fram".repeat(depth);
            chunks.extend(b"anih\0\0\0\0");
            assert_eq!(
                irregular_header(&root(&chunks), || Ok(())).unwrap(),
                expected
            );
        }
        let bytes = root(&b"note\0\0\0\0".repeat(300));
        let mut checks = 0;
        let error = irregular_header(&bytes, || {
            checks += 1;
            if checks == 2 {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }
}
