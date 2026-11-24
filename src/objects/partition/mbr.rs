use super::{ChildSink, Handling, SECTOR, extent, scan_extent};
use std::{collections::HashSet, io};

#[derive(Clone, Copy)]
struct Entry {
    active: u8,
    kind: u8,
    start: u64,
    length: u64,
}
fn entries(sector: &[u8]) -> Option<[Entry; 4]> {
    let record = sector.get(..SECTOR)?;
    if record[510..512] != [0x55, 0xaa] {
        return None;
    }
    let raw: &[[u8; 16]; 4] = record[446..510].as_chunks::<16>().0.try_into().ok()?;
    Some(raw.map(|e| Entry {
        active: e[0],
        kind: e[4],
        start: u32::from_le_bytes(e[8..12].try_into().unwrap()).into(),
        length: u32::from_le_bytes(e[12..16].try_into().unwrap()).into(),
    }))
}
pub(super) fn valid(bytes: &[u8]) -> bool {
    entries(bytes).is_some_and(|table| {
        table.iter().all(|e| {
            matches!(e.active, 0 | 128) && extent(bytes, SECTOR, e.start, e.length).is_some()
        })
    })
}
fn logical(
    area: &[u8],
    seen: &mut usize,
    sink: &mut dyn ChildSink,
) -> io::Result<Option<Handling>> {
    let mut next = 0;
    let mut visited = HashSet::new();
    loop {
        sink.check()?;
        if !visited.insert(next) {
            return Ok(Some(Handling::Incomplete));
        }
        let Some(table) = extent(area, SECTOR, next, 1).and_then(entries) else {
            return Ok(Some(Handling::Complete));
        };
        if table[..2].iter().any(|e| !matches!(e.active, 0 | 128)) {
            return Ok(Some(Handling::Complete));
        }
        *seen += 1;
        let mut link = None;
        for e in &table[..2] {
            match e.kind {
                0 => {}
                5 => {
                    if link.replace(e.start).is_some() {
                        return Ok(Some(Handling::Complete));
                    }
                }
                _ => {
                    let base = link.unwrap_or(next);
                    let Some(part) = extent(area, SECTOR, base + e.start, e.length) else {
                        return Ok(Some(Handling::Complete));
                    };
                    if let Some(status) = scan_extent(part, None, sink)? {
                        return Ok(Some(status));
                    }
                }
            }
        }
        if table[2..].iter().any(|e| e.kind != 0) {
            return Ok(Some(Handling::Complete));
        }
        next = link.unwrap_or(0);
        if next == 0 || *seen >= sink.max_partitions() {
            return Ok(None);
        }
    }
}
pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(table) = entries(bytes) else {
        return Ok(Handling::Complete);
    };
    if sink.skip_declared_size(SECTOR as u64) {
        return Ok(Handling::Complete);
    }
    if sink.child_bytes(&bytes[..SECTOR], None)? {
        return Ok(Handling::Stopped);
    }
    let mut seen = 0;
    for e in table {
        if seen >= sink.max_partitions() {
            break;
        }
        let Some(part) = extent(bytes, SECTOR, e.start, e.length) else {
            return Ok(Handling::Complete);
        };
        let result = if e.kind == 5 {
            logical(part, &mut seen, sink)?
        } else {
            seen += 1;
            if e.kind == 0 || part.is_empty() {
                None
            } else {
                scan_extent(part, None, sink)?
            }
        };
        if let Some(status) = result {
            return Ok(status);
        }
    }
    Ok(Handling::Complete)
}
