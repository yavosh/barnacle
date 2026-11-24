//! Named references accepted by the pinned scanner. The table contains public
//! character names and Unicode values from HTML 4 and WHATWG named references.
//! The seven older numeric assignments and the accepted names were measured
//! using complete normalized markup from the reference daemon.
//! See THIRD-PARTY-NOTICES.md for the source digest, derivation and data licenses.
use super::{Url, View};
use std::io;

fn named(name: &[u8]) -> Option<u16> {
    let mut key = [b' '; 8];
    key.get_mut(..name.len())?.copy_from_slice(name);
    let (rows, _) = include_bytes!("entities.txt").as_chunks::<14>();
    let i = rows.binary_search_by(|row| row[..8].cmp(&key)).ok()?;
    u16::from_str_radix(std::str::from_utf8(&rows[i][9..13]).ok()?, 16).ok()
}

#[derive(Clone, Copy)]
pub(super) enum Reference<'a> {
    Literal(&'a [u8]),
    Named(u16),
    Number(u32, bool),
}

pub(super) fn parse(bytes: &[u8]) -> Option<(Reference<'_>, usize)> {
    let tail = &bytes[1..];
    if let Some(digits) = tail.strip_prefix(b"#") {
        let (digits, base) = match digits.first() {
            Some(b'x' | b'X') => (&digits[1..], 16),
            _ => (digits, 10),
        };
        let mut value = 0u32;
        let mut used = bytes.len() - digits.len();
        for &b in digits {
            let Some(digit) = char::from(b).to_digit(base) else {
                break;
            };
            if used > 1024 {
                return None;
            }
            value = value.checked_mul(base)?.checked_add(digit)?;
            used += 1;
        }
        let terminated = bytes.get(used) == Some(&b';');
        return Some((
            Reference::Number(value, terminated),
            used + usize::from(terminated),
        ));
    }
    let n = tail
        .iter()
        .take(1024)
        .take_while(|&&b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
        .count();
    let terminated = tail.get(n) == Some(&b';');
    let used = 1 + n + usize::from(terminated);
    let reference = if terminated && let Some(value) = named(&tail[..n]) {
        Reference::Named(value)
    } else {
        Reference::Literal(&bytes[..used])
    };
    Some((reference, used))
}

impl Reference<'_> {
    pub(super) fn write(self, full: &mut View, mut url: Option<&mut Url>) -> io::Result<()> {
        let code = match self {
            Self::Literal(bytes) => {
                let mut lower = [0; 64];
                for chunk in bytes.chunks(lower.len()) {
                    let dest = &mut lower[..chunk.len()];
                    dest.copy_from_slice(chunk);
                    dest.make_ascii_lowercase();
                    full.write(dest)?;
                    if let Some(url) = url.as_mut() {
                        url.push(dest);
                    }
                }
                return Ok(());
            }
            Self::Number(code, false) => return full.write(&[code as u8]),
            Self::Number(code, true) => {
                if let Some(url) = url.take() {
                    url.push(&[code as u8]);
                }
                if code != 0 && code as u16 == 0 {
                    return Ok(());
                }
                code as u16
            }
            Self::Named(code) => code,
        };
        let mut spelling = *b"&#x0000;";
        let bytes = if code < 255 {
            spelling[0] = (code as u8).to_ascii_lowercase();
            &spelling[..1]
        } else {
            for (i, ch) in spelling[3..7].iter_mut().enumerate() {
                *ch = b"0123456789abcdef"[usize::from(code >> (12 - i * 4) & 15)];
            }
            &spelling[..]
        };
        full.write(bytes)?;
        if let Some(url) = url {
            url.push(bytes);
        }
        Ok(())
    }
}
