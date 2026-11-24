use flate2::{Compression, Crc, write::DeflateEncoder};
use std::io::{self, Write};

/// A classic ZIP with one compression method and optional streaming data descriptors.
pub fn zip(
    entries: &[(&str, &[u8])],
    deflate: bool,
    descriptor: bool,
    reverse_directory: bool,
) -> io::Result<Vec<u8>> {
    zip_with_method(
        entries,
        if deflate { 8 } else { 0 },
        descriptor,
        reverse_directory,
    )
}

pub fn zip_with_method(
    entries: &[(&str, &[u8])],
    method: u16,
    descriptor: bool,
    reverse_directory: bool,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut records = Vec::new();
    for &(name, bytes) in entries {
        let compressed = match method {
            0 => bytes.to_vec(),
            8 | 9 => {
                // Uncompressed DEFLATE blocks also represent valid Deflate64 data.
                let level = if method == 9 {
                    Compression::none()
                } else {
                    Compression::default()
                };
                let mut encoder = DeflateEncoder::new(Vec::new(), level);
                encoder.write_all(bytes)?;
                encoder.finish()?
            }
            12 => {
                let mut encoder =
                    bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
                encoder.write_all(bytes)?;
                encoder.finish()?
            }
            _ => unreachable!(),
        };
        let mut crc = Crc::new();
        crc.update(bytes);
        let sizes = [crc.sum(), compressed.len() as u32, bytes.len() as u32];
        let flags: u16 = if descriptor { 8 } else { 0 };
        let offset = out.len() as u32;
        let mut local = vec![0; 30];
        local[..4].copy_from_slice(b"PK\x03\x04");
        local[4..6].copy_from_slice(&20u16.to_le_bytes());
        local[6..8].copy_from_slice(&flags.to_le_bytes());
        local[8..10].copy_from_slice(&method.to_le_bytes());
        local[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
        let mut central = vec![0; 46];
        central[..4].copy_from_slice(b"PK\x01\x02");
        central[4..6].copy_from_slice(&20u16.to_le_bytes());
        central[6..16].copy_from_slice(&local[4..14]);
        central[28..30].copy_from_slice(&local[26..28]);
        central[42..46].copy_from_slice(&offset.to_le_bytes());
        for (index, field) in sizes.iter().enumerate() {
            let at = 14 + index * 4;
            central[at + 2..at + 6].copy_from_slice(&field.to_le_bytes());
            if !descriptor {
                local[at..at + 4].copy_from_slice(&field.to_le_bytes());
            }
        }
        out.extend(local);
        out.extend(name.bytes());
        out.extend(compressed);
        if descriptor {
            out.extend(b"PK\x07\x08");
            for field in sizes {
                out.extend(field.to_le_bytes());
            }
        }
        central.extend(name.bytes());
        records.push(central);
    }
    if reverse_directory {
        records.reverse();
    }
    let offset = out.len() as u32;
    for record in records {
        out.extend(record);
    }
    let size = out.len() as u32 - offset;
    let count = entries.len() as u16;
    out.extend(b"PK\x05\x06\0\0\0\0");
    out.extend(count.to_le_bytes());
    out.extend(count.to_le_bytes());
    out.extend(size.to_le_bytes());
    out.extend(offset.to_le_bytes());
    out.extend([0; 2]);
    Ok(out)
}
