fn integer(out: &mut Vec<u8>, mut n: usize) {
    let mut buf = [0; 10];
    let mut pos = buf.len() - 1;
    buf[pos] = (n & 127) as u8;
    while n > 127 {
        n >>= 7;
        pos -= 1;
        buf[pos] = (n as u8 & 127) | 128;
    }
    out.extend(&buf[pos..]);
}

fn entry(out: &mut Vec<u8>, name: &str, section: u8, start: usize, len: usize) {
    integer(out, name.len());
    out.extend(name.bytes());
    out.push(section);
    integer(out, start);
    integer(out, len);
}

pub fn chm(first: &[u8], second: &[u8], compress: bool) -> Vec<u8> {
    const PAGE: usize = 4096;
    const FRAME: usize = 32768;
    let mut entries = Vec::new();
    let mut content = Vec::new();
    let count: u16 = if compress {
        let start = FRAME - 7;
        let mut data = vec![0; 2 * FRAME];
        data[start..start + first.len()].copy_from_slice(first);
        data[..second.len()].copy_from_slice(second);
        entry(&mut entries, "/first", 1, start, first.len());
        entry(&mut entries, "/second", 1, 0, second.len());
        let frame = super::cabinet::lzx_block(&data[..FRAME]);
        let boundary = frame.len();
        content.extend(frame);
        content.extend(super::cabinet::lzx_block(&data[FRAME..]));
        let len = content.len();
        entry(
            &mut entries,
            "::DataSpace/Storage/MSCompressed/Content",
            0,
            0,
            len,
        );
        let mut control = 6u32.to_le_bytes().to_vec();
        control.extend(b"LZXC");
        for n in [2u32, 1, 2, 1, 0] {
            control.extend(n.to_le_bytes());
        }
        entry(
            &mut entries,
            "::DataSpace/Storage/MSCompressed/ControlData",
            0,
            len,
            control.len(),
        );
        content.extend(control);
        let mut table = Vec::new();
        for n in [2u32, 2, 8, 40] {
            table.extend(n.to_le_bytes());
        }
        for n in [data.len(), len, FRAME, 0, boundary] {
            table.extend((n as u64).to_le_bytes());
        }
        entry(
            &mut entries,
            "::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable",
            0,
            content.len(),
            table.len(),
        );
        content.extend(table);
        5
    } else {
        entry(&mut entries, "/first", 0, 0, first.len());
        entry(&mut entries, "/second", 0, first.len(), second.len());
        content.extend(first);
        content.extend(second);
        2
    };
    let directory = 96 + 24;
    let page = directory + 84;
    let payload = page + PAGE;
    let mut file = vec![0u8; payload];
    file[..4].copy_from_slice(b"ITSF");
    file[4..8].copy_from_slice(&3u32.to_le_bytes());
    file[8..12].copy_from_slice(&96u32.to_le_bytes());
    for (off, first) in [(24, 16), (40, 17)] {
        file[off..off + 16].copy_from_slice(&[
            first, 253, 1, 124, 170, 123, 208, 17, 158, 12, 0, 160, 201, 34, 230, 236,
        ]);
    }
    for (off, val) in [
        (56, 96),
        (64, 24),
        (72, directory),
        (80, 84 + PAGE),
        (88, payload),
        (104, payload + content.len()),
    ] {
        file[off..off + 8].copy_from_slice(&(val as u64).to_le_bytes());
    }
    file[directory..directory + 4].copy_from_slice(b"ITSP");
    for (off, val) in [
        (4, 1),
        (8, 84),
        (16, PAGE as u32),
        (20, 2),
        (24, 1),
        (28, u32::MAX),
        (44, 1),
    ] {
        file[directory + off..directory + off + 4].copy_from_slice(&val.to_le_bytes());
    }
    file[page..page + 4].copy_from_slice(b"PMGL");
    file[page + 4..page + 8].copy_from_slice(&((PAGE - 20 - entries.len()) as u32).to_le_bytes());
    file[page + 12..page + 20].fill(255);
    file[page + 20..page + 20 + entries.len()].copy_from_slice(&entries);
    file[payload - 2..payload].copy_from_slice(&count.to_le_bytes());
    file.extend(content);
    file
}
