pub const S: usize = 512;
pub const FIRST: &[u8] = b"First harmless partition note";
pub const SECOND: &[u8] = b"Second harmless partition note";
pub fn note(text: &[u8], len: usize) -> Vec<u8> {
    let mut bytes = vec![b' '; len];
    bytes[..text.len()].copy_from_slice(text);
    bytes
}
fn put(bytes: &mut [u8], at: usize, data: &[u8]) {
    bytes[at..at + data.len()].copy_from_slice(data);
}
fn entries(bytes: &mut [u8], at: usize, parts: &[(u8, u32, u32)]) {
    put(bytes, at + 510, &[0x55, 0xaa]);
    for (i, &(kind, first, size)) in parts.iter().enumerate() {
        let p = at + 446 + 16 * i;
        bytes[p + 4] = kind;
        put(bytes, p + 8, &first.to_le_bytes());
        put(bytes, p + 12, &size.to_le_bytes());
    }
}
pub fn mbr(parts: &[(u8, u32, u32)]) -> Vec<u8> {
    let mut bytes = vec![0; S * 16];
    entries(&mut bytes, 0, parts);
    put(&mut bytes, S * 8, &note(FIRST, S));
    put(&mut bytes, S * 4, &note(SECOND, S));
    bytes
}
pub fn extended() -> Vec<u8> {
    let mut bytes = mbr(&[(5, 2, 12)]);
    entries(&mut bytes, S * 2, &[(0x83, 6, 1), (5, 1, 10)]);
    entries(&mut bytes, S * 3, &[(0x83, 1, 1)]);
    bytes
}
fn crc(bytes: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(bytes);
    crc.sum()
}
pub fn gpt(s: usize, primary: &[(usize, &str)], backup: &[(usize, &str)]) -> Vec<u8> {
    let mut b = vec![0; s * 32];
    entries(&mut b, 0, &[(0xee, 1, 31)]);
    for (hdr, table, other, parts) in [(1usize, 2usize, 31usize, primary), (31, 30, 1, backup)] {
        for (i, &(lba, name)) in parts.iter().enumerate() {
            if lba == 0 {
                continue;
            }
            let p = table * s + i * 128;
            b[p] = 1;
            b[p + 16] = 1;
            for f in [32, 40] {
                put(&mut b, p + f, &(lba as u64).to_le_bytes());
            }
            for (j, c) in name.encode_utf16().enumerate() {
                put(&mut b, p + 56 + j * 2, &c.to_le_bytes());
            }
        }
        let sum = crc(&b[table * s..table * s + 512]);
        let h = &mut b[hdr * s..hdr * s + 92];
        put(h, 0, b"EFI PART");
        put(h, 8, &65536u32.to_le_bytes());
        put(h, 12, &92u32.to_le_bytes());
        for (at, n) in [(24, hdr), (32, other), (40, 3), (48, 29), (72, table)] {
            put(h, at, &(n as u64).to_le_bytes());
        }
        h[56] = 1;
        put(h, 80, &4u32.to_le_bytes());
        put(h, 84, &128u32.to_le_bytes());
        put(h, 88, &sum.to_le_bytes());
        put(h, 16, &crc(h).to_le_bytes());
    }
    put(&mut b, s * 8, &note(FIRST, s));
    put(&mut b, s * 4, &note(SECOND, s));
    b
}
pub fn apm() -> Vec<u8> {
    let mut b = vec![0; 16 * S];
    put(&mut b, 0, b"ER");
    put(&mut b, 2, &512u16.to_be_bytes());
    put(&mut b, 4, &16u32.to_be_bytes());
    for (i, (first, len, name, kind)) in [
        (1u32, 3u32, "map", "Apple_partition_map"),
        (8, 1, "First", "Apple_UNIX_SVR2"),
        (4, 1, "Second", "Apple_UNIX_SVR2"),
    ]
    .iter()
    .enumerate()
    {
        let p = (i + 1) * S;
        put(&mut b, p, b"PM");
        put(&mut b, p + 4, &3u32.to_be_bytes());
        put(&mut b, p + 8, &first.to_be_bytes());
        put(&mut b, p + 12, &len.to_be_bytes());
        put(&mut b, p + 16, name.as_bytes());
        put(&mut b, p + 48, kind.as_bytes());
    }
    put(&mut b, S * 8, &note(FIRST, S));
    put(&mut b, S * 4, &note(SECOND, S));
    b
}

pub fn native_apm_2048() -> Vec<u8> {
    let base = apm();
    let mut image = vec![0; 16 * 2048];
    for (i, sector) in base.as_chunks::<S>().0.iter().enumerate() {
        put(&mut image, i * 2048, sector);
    }
    put(&mut image, 2, &2048u16.to_be_bytes());
    put(&mut image, 8 * 2048, &note(FIRST, 2048));
    image
}
