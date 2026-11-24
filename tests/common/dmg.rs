//! Construct small, independent UDIF images from ordinary partition bytes.
use flate2::{Compression, write::ZlibEncoder};
use std::io::{self, Write};

pub const RAW: u32 = 1;
pub const ADC: u32 = 0x80000004;
pub const ZLIB: u32 = 0x80000005;
pub const BZIP: u32 = 0x80000006;
#[path = "base64.rs"]
mod base64;
use base64::encode;
#[derive(Clone, Copy)]
pub struct Stripe {
    pub kind: u32,
    pub sector: u64,
    pub count: u64,
    pub offset: u64,
    pub len: u64,
}
pub fn mish(stripes: &[Stripe]) -> Vec<u8> {
    let mut out = vec![0; 204];
    out[..4].copy_from_slice(b"mish");
    out[4..8].copy_from_slice(&1u32.to_be_bytes());
    let sectors = stripes.iter().map(|s| s.count).sum::<u64>();
    out[16..24].copy_from_slice(&sectors.to_be_bytes());
    out[200..204].copy_from_slice(&(stripes.len() as u32).to_be_bytes());
    for s in stripes {
        out.extend(s.kind.to_be_bytes());
        out.extend([0; 4]);
        for n in [s.sector, s.count, s.offset, s.len] {
            out.extend(n.to_be_bytes());
        }
    }
    out
}
pub fn catalog(maps: &[Vec<u8>], id: &str) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<plist version=\"1.0\"><dict><key>name</key><string>{id}</string><key>resource-fork</key><dict><key>blkx</key><array>"
    );
    for (i, m) in maps.iter().enumerate() {
        xml.push_str(&format!("<dict><key>Name</key><string>Partition {i}</string><key>Data</key><data>{}</data></dict>",encode(m)));
    }
    xml.push_str("</array></dict></dict></plist>\n");
    xml
}
pub fn dmg(fork: &[u8], xml: &str) -> Vec<u8> {
    let mut out = fork.to_vec();
    out.extend(xml.as_bytes());
    let mut trailer = [0; 512];
    trailer[..4].copy_from_slice(b"koly");
    trailer[4..8].copy_from_slice(&4u32.to_be_bytes());
    trailer[8..12].copy_from_slice(&512u32.to_be_bytes());
    trailer[32..40].copy_from_slice(&(fork.len() as u64).to_be_bytes());
    trailer[216..224].copy_from_slice(&(fork.len() as u64).to_be_bytes());
    trailer[224..232].copy_from_slice(&(xml.len() as u64).to_be_bytes());
    out.extend(trailer);
    out
}
pub fn compressed(kind: u32, data: &[u8]) -> io::Result<Vec<u8>> {
    match kind {
        ZLIB => {
            let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
            z.write_all(data)?;
            z.finish()
        }
        BZIP => {
            let mut z = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            z.write_all(data)?;
            z.finish()
        }
        ADC => {
            let mut encoded = Vec::new();
            for run in data.chunks(128) {
                encoded.push(0x80 + (run.len() - 1) as u8);
                encoded.extend(run);
            }
            Ok(encoded)
        }
        _ => Ok(data.to_vec()),
    }
}
pub fn single(kind: u32, data: &[u8], id: &str) -> io::Result<(Vec<u8>, String)> {
    let bytes = compressed(kind, data)?;
    let xml = catalog(
        &[mish(&[Stripe {
            kind,
            sector: 0,
            count: data.len().div_ceil(512) as u64,
            offset: 0,
            len: bytes.len() as u64,
        }])],
        id,
    );
    Ok((dmg(&bytes, &xml), xml))
}
