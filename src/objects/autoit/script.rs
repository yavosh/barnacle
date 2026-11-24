//! Stock's searchable source view preserves token separators and line endings.
use std::io::{self, BufWriter, Read, Write};

const OPERATORS: [&[u8]; 25] = [
    b",", b"=", b">", b"<", b"<>", b">=", b"<=", b"(", b")", b"+", b"-", b"/", b"*", b"&", b"[",
    b"]", b"==", b"^", b"+=", b"-=", b"/=", b"*=", b"&=", b"?", b":",
];

struct Source<'a> {
    out: BufWriter<&'a mut dyn Write>,
    size: u64,
    limit: u64,
}
impl Source<'_> {
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.size += bytes.len() as u64;
        if self.size <= self.limit {
            self.out.write_all(bytes)?;
        }
        Ok(())
    }
}

fn fill(input: &mut dyn Read, mut out: &mut [u8]) -> io::Result<bool> {
    while !out.is_empty() {
        let n = input.read(out)?;
        if n == 0 {
            return Ok(false);
        }
        out = &mut out[n..];
    }
    Ok(true)
}

fn word<const N: usize>(input: &mut dyn Read) -> io::Result<Option<[u8; N]>> {
    let mut word = [0; N];
    Ok(fill(input, &mut word)?.then_some(word))
}

// Clamd uses six significant digits for a floating literal.
fn decimal(value: f64) -> Option<String> {
    if !value.is_finite() {
        return None;
    }
    let scientific = format!("{value:.5e}");
    let (mantissa, exponent) = scientific.split_once('e')?;
    let exponent: i32 = exponent.parse().ok()?;
    let trim = |s: &str| s.trim_end_matches('0').trim_end_matches('.').to_owned();
    if !(-4..6).contains(&exponent) {
        return Some(format!("{}e{exponent:+03}", trim(mantissa)));
    }
    let digits = (5 - exponent) as usize;
    let number = format!("{value:.digits$}");
    Some(if digits == 0 { number } else { trim(&number) })
}

fn string(input: &mut dyn Read, source: &mut Source<'_>, n: usize) -> io::Result<bool> {
    let key = (n as u16).to_le_bytes();
    let Some(mut left) = n.checked_mul(2) else {
        return Ok(false);
    };
    // Stock samples the high bytes of up to ten UTF-16 units. Narrow strings
    // contribute their low bytes. For wide strings it retains n original bytes.
    let mut bytes = [0; 4096];
    let mut first = true;
    let mut narrow = false;
    let mut kept = 0;
    while left > 0 {
        let count = left.min(bytes.len());
        let chunk = &mut bytes[..count];
        if !fill(input, chunk)? {
            return Ok(false);
        }
        if first {
            first = false;
            let probe = &chunk.as_chunks::<2>().0[..n.min(10)];
            narrow = probe.iter().filter(|u| u[1] == key[1]).count() * 2 >= probe.len();
        }
        let len = if narrow {
            for i in 0..count / 2 {
                chunk[i] = chunk[i * 2] ^ key[0];
            }
            count / 2
        } else {
            let len = count.min(n - kept);
            for (i, b) in chunk[..len].iter_mut().enumerate() {
                *b ^= key[i % 2];
            }
            len
        };
        source.append(&chunk[..len])?;
        left -= count;
        kept += len;
    }
    Ok(true)
}

pub(super) fn render(
    input: &mut dyn Read,
    out: &mut dyn Write,
    limit: u64,
) -> io::Result<Option<u64>> {
    let Some(count) = word(input)? else {
        return Ok(None);
    };
    let mut lines = u32::from_le_bytes(count);
    let mut source = Source {
        out: BufWriter::new(out),
        size: 0,
        limit,
    };
    while lines > 0 {
        let Some([op]) = word(input)? else {
            return Ok(None);
        };
        match op {
            0x05 | 0x10 | 0x20 => {
                let number = match op {
                    0x05 => word(input)?.map(|n| format!("0x{:08x}", u32::from_le_bytes(n))),
                    0x10 => word(input)?.map(|n| format!("0x{:016x}", u64::from_le_bytes(n))),
                    _ => word(input)?.and_then(|n| decimal(f64::from_le_bytes(n))),
                };
                let Some(number) = number else {
                    return Ok(None);
                };
                source.append(number.as_bytes())?;
                source.append(b" ")?;
            }
            0x30..=0x37 => {
                let Some(len) = word(input)? else {
                    return Ok(None);
                };
                let (prefix, suffix): (&[u8], &[u8]) = match op {
                    0x32 => (b"@", b" "),
                    0x33 => (b"$", b" "),
                    0x34 => (b"", b""),
                    0x35 => (b".", b" "),
                    0x36 => (b"\"", b"\" "),
                    _ => (b"", b" "),
                };
                source.append(prefix)?;
                if !string(input, &mut source, u32::from_le_bytes(len) as usize)? {
                    return Ok(None);
                }
                source.append(suffix)?;
            }
            0x40..=0x58 => {
                source.append(OPERATORS[usize::from(op - 0x40)])?;
                source.append(b" ")?;
            }
            0x7f => {
                source.append(b"\n")?;
                lines -= 1;
            }
            _ => return Ok(None),
        }
    }
    source.out.flush()?;
    Ok(Some(source.size))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovered_multilingual_source() -> io::Result<()> {
        let mut tokens = 4u32.to_le_bytes().to_vec();
        for (op, text) in [
            (0x33, "Receipt"),
            (0x36, "café € 你好 笑 \"x\" 🧾"),
            (0x36, "中文文档"),
            (0x34, "total"),
        ] {
            let units: Vec<_> = text.encode_utf16().collect();
            tokens.push(op);
            tokens.extend((units.len() as u32).to_le_bytes());
            for unit in &units {
                tokens.extend((unit ^ units.len() as u16).to_le_bytes());
            }
            tokens.push(0x7f);
        }
        let expected =
            b"$Receipt \n\"caf\xe9 \xac `\x7d \x11 \"x\" >\xfe\" \n\"\x2d\x4e\x87\x65\" \ntotal\n";
        let mut out = Vec::new();
        let size =
            render(&mut tokens.as_slice(), &mut out, u64::MAX)?.expect("ordinary text tokens");
        assert_eq!(size, expected.len() as u64);
        assert_eq!(out, expected);
        Ok(())
    }
}
