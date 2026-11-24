use std::io;

fn pack_bits(words: impl IntoIterator<Item = (u16, u8)>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut bits = 0;
    for (word, width) in words {
        for bit in (0..width).rev() {
            if bits == 0 {
                out.push(0);
            }
            *out.last_mut().unwrap() |= ((word >> bit) as u8 & 1) << (7 - bits);
            bits = (bits + 1) % 8;
        }
    }
    out
}

pub fn huffman_literals(data: &[u8], position_bits: u8) -> Vec<u8> {
    // Each block contains one command and a single-symbol literal tree.
    pack_bits(data.iter().flat_map(|&b| {
        [
            (1, 16),
            (0, 10),
            (0, 9),
            (u16::from(b), 9),
            (0, 2 * position_bits),
        ]
    }))
}

pub fn arj(method: u8, entries: &[&[u8]]) -> Vec<u8> {
    fn header(out: &mut Vec<u8>, head: &[u8]) {
        out.extend([0x60, 0xea]);
        out.extend((head.len() as u16).to_le_bytes());
        out.extend(head);
        let mut crc = flate2::Crc::new();
        crc.update(head);
        out.extend(crc.sum().to_le_bytes());
        out.extend([0, 0]);
    }
    let mut out = Vec::new();
    let mut main = vec![0; 30];
    main[..7].copy_from_slice(&[30, 11, 1, 0, 0, 0, 2]);
    main.extend(b"notes.arj\0\0");
    header(&mut out, &main);
    for &data in entries {
        let packed = match method {
            0 => data.to_vec(),
            1..=3 => huffman_literals(data, 5),
            _ => pack_bits(data.iter().map(|&b| (u16::from(b), 9))),
        };
        let mut file = vec![0; 30];
        file[..6].copy_from_slice(&[30, 11, 1, 0, 0, method]);
        file[12..16].copy_from_slice(&(packed.len() as u32).to_le_bytes());
        file[16..20].copy_from_slice(&(data.len() as u32).to_le_bytes());
        let mut crc = flate2::Crc::new();
        crc.update(data);
        file[20..24].copy_from_slice(&crc.sum().to_le_bytes());
        file.extend(b"notes\0\0");
        header(&mut out, &file);
        out.extend(packed);
    }
    out.extend([0x60, 0xea, 0, 0]);
    out
}

pub fn sevenzip(solid: bool, entries: &[(&str, &[u8])]) -> io::Result<Vec<u8>> {
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter, SourceReader};
    let mut writer = ArchiveWriter::new(io::Cursor::new(Vec::new())).map_err(io::Error::other)?;
    if solid {
        writer
            .push_archive_entries(
                entries
                    .iter()
                    .map(|(name, _)| ArchiveEntry::new_file(name))
                    .collect(),
                entries
                    .iter()
                    .map(|(_, data)| SourceReader::new(*data))
                    .collect(),
            )
            .map_err(io::Error::other)?;
    } else {
        for &(name, data) in entries {
            writer
                .push_archive_entry(ArchiveEntry::new_file(name), Some(data))
                .map_err(io::Error::other)?;
        }
    }
    Ok(writer.finish()?.into_inner())
}
