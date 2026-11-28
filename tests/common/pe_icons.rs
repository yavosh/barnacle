//! Passive PE resources containing ordinary 32×32 document and diamond drawings.
use super::pe;

// ClamAV 1.4.3 metrics for these two drawings.
pub const DOCUMENT: &str = "204da000044d0017400000e15c030215c150215c030aea0302ea1502ea030ac20000c8000ec9001767020167160160020f3e050b3e130b3f07173400311c";
pub const DIAMOND: &str = "20b7a0c05b7a140cb7a050d8660000866001787216009b0c059b140c9b050d970000970017971600470110461612460603000c0a000000000c120e342164";

#[derive(Clone, Copy)]
pub enum Drawing {
    Document,
    Diamond,
    ExtendedHeader,
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn bitmap(drawing: Drawing) -> Vec<u8> {
    const SIDE: usize = 32;
    // A DIB icon stores bottom-up BGRA pixels and a zero transparency mask.
    let mut dib = vec![0; 40 + SIDE * SIDE * 4 + SIDE * 4];
    put32(&mut dib, 0, 40);
    put32(&mut dib, 4, SIDE as u32);
    put32(&mut dib, 8, (SIDE * 2) as u32);
    put16(&mut dib, 12, 1);
    put16(&mut dib, 14, 32);
    put32(&mut dib, 20, (SIDE * SIDE * 4) as u32);
    for y in 0..SIDE {
        for x in 0..SIDE {
            let bgr = match drawing {
                Drawing::Document if !(3..29).contains(&x) || !(2..30).contains(&y) => {
                    [59, 108, 160]
                }
                Drawing::Document if y % 7 == 0 && (5..27).contains(&x) => [78, 54, 23],
                Drawing::Document => [237, 247, 251],
                Drawing::Diamond if x.abs_diff(16) + y.abs_diff(16) < 16 => [155, 55, 11],
                Drawing::Diamond => [47, 151, 49],
                Drawing::ExtendedHeader => [237, 247, 251],
            };
            let at = 40 + 4 * ((SIDE - y - 1) * SIDE + x);
            dib[at..at + 3].copy_from_slice(&bgr);
            dib[at + 3] = 255;
        }
    }
    if matches!(drawing, Drawing::ExtendedHeader) {
        // A BITMAPV4HEADER includes color masks and color-space information.
        dib.splice(40..40, [0; 68]);
        put32(&mut dib, 0, 108);
        put32(&mut dib, 56, 0x7352_4742);
    }
    dib
}

fn directory(resources: &mut Vec<u8>, entries: usize) -> usize {
    let offset = resources.len();
    resources.resize(offset + 16 + entries * 8, 0);
    put16(resources, offset + 14, entries as u16);
    offset
}

pub fn image(drawings: &[Drawing], grouped: bool) -> Vec<u8> {
    let icons: Vec<_> = drawings.iter().copied().map(bitmap).collect();
    let mut group = vec![0; 6 + icons.len() * 14];
    put16(&mut group, 2, 1);
    put16(&mut group, 4, icons.len() as u16);
    for (index, dib) in icons.iter().enumerate() {
        let at = 6 + 14 * index;
        group[at..at + 2].copy_from_slice(&[32, 32]);
        put16(&mut group, at + 4, 1);
        put16(&mut group, at + 6, 32);
        put32(&mut group, at + 8, dib.len() as u32);
        put16(&mut group, at + 12, index as u16 + 1);
    }

    let mut types = vec![(3, icons)]; // RT_ICON
    if grouped {
        types.push((14, vec![group])); // RT_GROUP_ICON
    }
    let mut resources = Vec::new();
    directory(&mut resources, types.len());
    for (type_index, (kind, leaves)) in types.into_iter().enumerate() {
        let type_entry = 16 + 8 * type_index;
        let ids = directory(&mut resources, leaves.len());
        put32(&mut resources, type_entry, kind);
        put32(&mut resources, type_entry + 4, 0x8000_0000 | ids as u32);
        for (index, data) in leaves.into_iter().enumerate() {
            let id_entry = ids + 16 + 8 * index;
            let lang = directory(&mut resources, 1);
            put32(&mut resources, id_entry, index as u32 + 1);
            put32(&mut resources, id_entry + 4, 0x8000_0000 | lang as u32);
            let entry = resources.len();
            resources.resize(entry + 16, 0);
            put32(&mut resources, lang + 16, 0x409);
            put32(&mut resources, lang + 20, entry as u32);
            put32(&mut resources, entry, 4096 + entry as u32 + 16);
            put32(&mut resources, entry + 4, data.len() as u32);
            resources.extend(data);
            resources.resize(resources.len().next_multiple_of(4), 0);
        }
    }

    let mut image = pe::benign_pe();
    let extent = resources.len();
    let raw_size = extent.next_multiple_of(512);
    image.truncate(512);
    image.extend(resources);
    image.resize(512 + raw_size, 0);
    // Replace the fixture's single data section with a mapped resource section.
    image[376..384].copy_from_slice(b".rsrc\0\0\0");
    put32(&mut image, 384, extent as u32);
    put32(&mut image, 392, raw_size as u32);
    put32(
        &mut image,
        208,
        (4096 + extent).next_multiple_of(4096) as u32,
    );
    put32(&mut image, 264, 4096);
    put32(&mut image, 268, extent as u32);
    image
}
