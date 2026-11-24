//! Read only the properties used to follow page and attachment links.
use super::{package::Data, wire::*};
use std::io;

#[derive(Default)]
pub(super) struct Properties<'a> {
    pub(super) elements: Vec<Id>,
    pub(super) contents: Vec<Id>,
    pub(super) pages: Vec<Cell>,
    pub(super) filename: &'a [u8],
    pub(super) container: Option<Id>,
}

fn ids<'a>(body: &mut &'a [u8]) -> io::Result<(u32, &'a [u8])> {
    let header = word(body)?;
    let n = (header & 0xffffff) as usize;
    if n > 32768 {
        return Err(invalid());
    }
    Ok((header, take(body, n.checked_mul(4).ok_or_else(invalid)?)?))
}

#[derive(Default)]
struct Positions {
    object: usize,
    space: usize,
}

impl<'a> Properties<'a> {
    pub(super) fn parse(data: Data<'a>, space: Id, kind: u32, work: &mut Work) -> io::Result<Self> {
        let mut body = data.body;
        let (header, object_ids) = ids(&mut body)?;
        let mut space_ids = &[][..];
        if header & (1 << 31) == 0 {
            let (h, v) = ids(&mut body)?;
            space_ids = v;
            if h & (1 << 30) != 0 {
                ids(&mut body)?;
            }
        }
        let mut object_refs = data.objects;
        let mut objects = Vec::new();
        while !object_refs.is_empty() {
            work.step()?;
            objects.push(id(&mut object_refs)?);
        }
        let mut cells = data.cells;
        let mut spaces = Vec::new();
        while !cells.is_empty() {
            work.step()?;
            let entry = cell(&mut cells)?;
            if entry.1 != space {
                spaces.push(entry);
            }
        }
        if object_ids.len() / 4 < objects.len() || space_ids.len() / 4 != spaces.len() {
            return Err(invalid());
        }
        let mut result = Properties::default();
        // The reference parser requires these fields before it yields a section.
        // Checking just the attachment pointers could visit a graph it rejected.
        let required: &[u32] = match kind {
            0 => &[0x1c001d94, 0x1c001d95, 0x14001d93],
            0x60007 => &[0x1c001c30, 0x18001c65],
            0x60008 => &[0x1c001c30],
            0x20031 => &[0x14001d82, 0x1400348b],
            0x20030 => &[0x1c001c30, 0x1c001cf3, 0x18001c65],
            0x6000c => &[0x14001d7a, 0x0c001c03, 0x1c001c12],
            0x6000d => &[0x14001d09, 0x14001d7a, 0x0c001c03, 0x20001d78, 0x20001d79],
            0x60035 => &[0x14001d7a, 0x20001d9b, 0x1c001d9c],
            _ => &[],
        };
        let mut missing = (1u32 << required.len()) - 1;
        let mut positions = Positions::default();
        let mut selected = 0u8;
        set(
            &mut body,
            0,
            &mut positions,
            work,
            &mut |key, slot, count, value| {
                let bit = match key {
                    0x24001c20 => 1,
                    0x24001c1f => 2,
                    0x2c001d63 => 4,
                    0x20001d9b => 8,
                    0x1c001d9c => 16,
                    _ => 0,
                };
                if selected & bit != 0 {
                    return Err(invalid());
                }
                selected |= bit;
                if let Some(i) = required.iter().position(|&field| field == key) {
                    missing &= !(1 << i);
                }
                if matches!(key, 0x1c001d94 | 0x1c001d95 | 0x1c001c30) && value.len() < 16 {
                    return Err(invalid());
                }
                match key {
                    0x24001c20 => result.elements = references(object_ids, &objects, slot, count)?,
                    0x24001c1f => result.contents = references(object_ids, &objects, slot, count)?,
                    0x2c001d63 => result.pages = references(space_ids, &spaces, slot, count)?,
                    0x20001d9b => {
                        result.container =
                            references(object_ids, &objects, slot, 1)?.first().copied()
                    }
                    0x1c001d9c => result.filename = value,
                    _ => {}
                }
                Ok(())
            },
        )?;
        if missing != 0 {
            return Err(invalid());
        }
        Ok(result)
    }
}

// The object and cell mapping tables pair compact IDs with full IDs in stream order.
// A repeated compact ID is resolved by its position inside the requested property.
fn references<T: Copy>(ids: &[u8], values: &[T], start: usize, count: usize) -> io::Result<Vec<T>> {
    let end = start.checked_add(count).ok_or_else(invalid)?;
    let keys = ids.as_chunks::<4>().0;
    let slice = keys.get(start..end).ok_or_else(invalid)?;
    if start == 0 && count <= values.len() {
        return Ok(values[..count].to_vec());
    }
    let mut unique = std::collections::HashMap::new();
    for (key, value) in keys.iter().zip(values) {
        unique
            .entry(key)
            .and_modify(|entry| *entry = None)
            .or_insert(Some(*value));
    }
    let mut out = Vec::new();
    for (i, key) in slice.iter().enumerate() {
        if let Some(value) = values.get(i).filter(|_| keys.get(i) == Some(key)) {
            out.push(*value);
        } else if let Some(Some(value)) = unique.get(key) {
            out.push(*value);
        }
    }
    Ok(out)
}

fn set<'a>(
    input: &mut &'a [u8],
    depth: u8,
    pos: &mut Positions,
    work: &mut Work,
    property: &mut impl FnMut(u32, usize, usize, &'a [u8]) -> io::Result<()>,
) -> io::Result<()> {
    if depth > 16 {
        return Err(invalid());
    }
    let n = u16::from_le_bytes(take(input, 2)?.try_into().expect("two bytes")) as usize;
    let keys = take(input, n * 4)?;
    for key in keys.as_chunks::<4>().0 {
        work.step()?;
        let key = u32::from_le_bytes(*key) & 0x7fffffff;
        let mut count = 0;
        let mut start = 0;
        let mut value = &[][..];
        match key >> 26 {
            1 | 2 => {}
            t @ 3..=6 => {
                take(input, 1 << (t - 3))?;
            }
            7 => {
                let n = word(input)? as usize;
                value = take(input, n)?;
            }
            t @ 8..=13 => {
                count = if t & 1 == 1 { word(input)? as usize } else { 1 };
                match t {
                    8 | 9 => {
                        start = pos.object;
                        pos.object = pos.object.checked_add(count).ok_or_else(invalid)?;
                    }
                    10 | 11 => {
                        start = pos.space;
                        pos.space = pos.space.checked_add(count).ok_or_else(invalid)?;
                    }
                    _ => {}
                }
            }
            16 => {
                let count = word(input)?;
                word(input)?;
                for _ in 0..count {
                    work.step()?;
                    set(input, depth + 1, pos, work, property)?;
                }
            }
            17 => {
                let mut nested = Positions::default();
                set(input, depth + 1, &mut nested, work, property)?;
            }
            _ => return Err(invalid()),
        }
        if depth == 0 {
            property(key, start, count, value)?;
        }
    }
    Ok(())
}
