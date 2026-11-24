use flate2::{Compression, write::ZlibEncoder};
use std::io::{self, Write};

fn uids(values: [u32; 3]) -> Vec<u8> {
    let mut out: Vec<u8> = values.into_iter().flat_map(u32::to_le_bytes).collect();
    for start in [0, 1] {
        let mut crc = 0u16;
        for &b in out[start..12].iter().step_by(2) {
            crc ^= u16::from(b) << 8;
            for _ in 0..8 {
                crc = (crc << 1) ^ if crc & 0x8000 != 0 { 0x1021 } else { 0 };
            }
        }
        out.extend(crc.to_le_bytes());
    }
    out
}

pub fn package(variants: &[&[u8]], compressed: bool) -> io::Result<Vec<u8>> {
    let mut out = uids([0x10000001, 0x10003a12, 0x10000419]);
    out.resize(84, 0);
    out[18..20].copy_from_slice(&(variants.len() as u16).to_le_bytes());
    out[20..22].copy_from_slice(&1u16.to_le_bytes());
    out[32..36].copy_from_slice(&400u32.to_le_bytes());
    out[36..38].copy_from_slice(&(if compressed { 1u16 } else { 9 }).to_le_bytes());
    out[48..52].copy_from_slice(&84u32.to_le_bytes());
    for i in 0..variants.len() {
        out.extend(((i + 1) as u16).to_le_bytes());
    }
    let record = out.len();
    out[52..56].copy_from_slice(&(record as u32).to_le_bytes());
    out.resize(record + 28 + 12 * variants.len() + 8, 0);
    let name = out.len();
    for c in "notes".encode_utf16() {
        out.extend(c.to_le_bytes());
    }
    out[record + 12..record + 16].copy_from_slice(&10u32.to_le_bytes());
    out[record + 16..record + 20].copy_from_slice(&(name as u32).to_le_bytes());
    for (i, data) in variants.iter().enumerate() {
        let packed = if compressed {
            let mut compressor = ZlibEncoder::new(Vec::new(), Compression::default());
            compressor.write_all(data)?;
            compressor.finish()?
        } else {
            data.to_vec()
        };
        for (j, val) in [packed.len(), out.len(), data.len()]
            .into_iter()
            .enumerate()
        {
            let at = record + 28 + 4 * (i + j * variants.len());
            out[at..at + 4].copy_from_slice(&(val as u32).to_le_bytes());
        }
        out.extend(packed);
    }
    Ok(out)
}

pub fn v9(data: &[u8]) -> Vec<u8> {
    fn field(kind: u32, value: &[u8]) -> Vec<u8> {
        let mut out = kind.to_le_bytes().to_vec();
        out.extend((value.len() as u32).to_le_bytes());
        out.extend(value);
        out.resize(out.len().next_multiple_of(4), 0);
        out
    }
    fn array(kind: u32, value: &[u8]) -> Vec<u8> {
        let mut body = kind.to_le_bytes().to_vec();
        body.extend(&field(kind, value)[4..]);
        field(2, &body)
    }
    let mut uncompressed = vec![0; 4];
    uncompressed.extend((data.len() as u64).to_le_bytes());
    uncompressed.extend(data);
    let file = array(32, &field(3, &uncompressed));
    let files = field(30, &array(31, &file));
    let mut contents = field(3, &[0; 12]);
    contents.extend(files);
    let mut out = uids([0x10201a7a, 0, 0x10000001]);
    out.extend(field(12, &contents));
    out
}
