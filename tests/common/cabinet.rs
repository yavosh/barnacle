use flate2::{Compress, Compression, FlushCompress};
use std::io;

pub fn lzx_block(data: &[u8]) -> Vec<u8> {
    // LZX packs bits most-significant first in little-endian 16-bit words.
    // An uncompressed block follows the disabled E8 transform.
    let header = ((3 << 24) | data.len() as u32) << 4;
    let mut bytes = Vec::new();
    bytes.extend(((header >> 16) as u16).to_le_bytes());
    bytes.extend((header as u16).to_le_bytes());
    for _ in 0..3 {
        bytes.extend(1u32.to_le_bytes());
    }
    bytes.extend(data);
    if !data.len().is_multiple_of(2) {
        bytes.push(0);
    }
    bytes
}

/// Two files in one folder. MSZIP's second block references the first dictionary.
pub fn cabinet(first: &[u8], second: &[u8], method: u16) -> io::Result<Vec<u8>> {
    let mut records = Vec::new();
    for (name, offset, data) in [("first", 0, first), ("second", first.len(), second)] {
        records.extend((data.len() as u32).to_le_bytes());
        records.extend((offset as u32).to_le_bytes());
        records.extend([0; 8]);
        records.extend(name.bytes());
        records.push(0);
    }
    let folder = [first, second].concat();
    let parts = folder.chunks(32768);
    let mut blocks = Vec::new();
    for (i, data) in parts.clone().enumerate() {
        let encoded = match method {
            0 => data.to_vec(),
            1 => {
                let mut stream = Compress::new(Compression::best(), false);
                if i != 0 {
                    stream
                        .set_dictionary(&folder[(i - 1) * 32768..i * 32768])
                        .map_err(io::Error::other)?;
                }
                let mut bytes = Vec::with_capacity(data.len() * 2 + 100);
                bytes.extend(b"CK");
                stream
                    .compress_vec(data, &mut bytes, FlushCompress::Finish)
                    .map_err(io::Error::other)?;
                bytes
            }
            3 => lzx_block(data),
            _ => unreachable!(),
        };
        blocks.extend([0; 4]); // Optional block checksum.
        blocks.extend((encoded.len() as u16).to_le_bytes());
        blocks.extend((data.len() as u16).to_le_bytes());
        blocks.extend(encoded);
    }
    let files = 36 + 8;
    let data_at = files + records.len();
    let mut header = vec![0; files];
    header[..4].copy_from_slice(b"MSCF");
    header[8..12].copy_from_slice(&((data_at + blocks.len()) as u32).to_le_bytes());
    header[16..20].copy_from_slice(&(files as u32).to_le_bytes());
    header[24..26].copy_from_slice(&[3, 1]);
    header[26..28].copy_from_slice(&1u16.to_le_bytes());
    header[28..30].copy_from_slice(&2u16.to_le_bytes());
    header[36..40].copy_from_slice(&(data_at as u32).to_le_bytes());
    header[40..42].copy_from_slice(&(parts.len() as u16).to_le_bytes());
    let algorithm = if method == 3 { 3 | (15 << 8) } else { method };
    header[42..44].copy_from_slice(&algorithm.to_le_bytes());
    header.extend(records);
    header.extend(blocks);
    Ok(header)
}
