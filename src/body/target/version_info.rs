//! Resolve ClamAV VI offsets to UTF-16 key starts in a PE version resource.
use super::executable::Section;
use std::io;

pub(super) fn word(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_le_bytes(*bytes.get(at..)?.first_chunk()?) as usize)
}

pub(super) fn dword(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(*bytes.get(at..)?.first_chunk()?) as usize)
}

fn aligned(n: usize) -> usize {
    (n + 3) & !3
}

pub(super) struct Map<'a> {
    section_headers: &'a [[u8; 40]],
    sections: &'a [Section],
    alignment: usize,
    headers_end: usize,
}

impl Map<'_> {
    pub(super) fn offset(&self, rva: usize) -> Option<usize> {
        if rva < self.headers_end {
            return Some(rva);
        }
        self.section_headers
            .iter()
            .zip(self.sections)
            .rev()
            .find_map(|(header, section)| {
                let address = dword(header, 12)?;
                let base = address - address.checked_rem(self.alignment).unwrap_or(0);
                let within = rva.checked_sub(base)?;
                (within < section.size).then(|| section.raw + within)
            })
    }
}

pub(super) fn directory<'a>(
    bytes: &'a [u8],
    sections: &'a [Section],
) -> Option<(Map<'a>, &'a [u8])> {
    let header = bytes.get(dword(bytes, 60)?..)?;
    let (opt, table) = header.get(24..)?.split_at_checked(word(header, 20)?)?;
    let dirs = match word(opt, 0)? {
        0x10b => 96,
        0x20b => 112,
        _ => return None,
    };
    if dword(opt, dirs - 4)? < 3 {
        return None;
    }
    let rva = dword(opt, dirs + 16)?;
    let length = dword(opt, dirs + 20)?;
    if rva == 0 || length == 0 {
        return None;
    }
    let align = dword(opt, 32)?;
    let size = dword(opt, 60)?;
    let headers_end = if align == 0 {
        size
    } else {
        size.div_ceil(align).checked_mul(align)?
    };
    let map = Map {
        section_headers: table
            .get(..sections.len().checked_mul(40)?)?
            .as_chunks::<40>()
            .0,
        sections,
        alignment: align,
        headers_end,
    };
    let tail = bytes.get(map.offset(rva)?..)?;
    Some((map, tail.get(..length.min(tail.len()))?))
}

pub(super) fn entries(tree: &[u8], at: usize) -> Option<&[[u8; 8]]> {
    let directory = tree.get(at..)?;
    let count = word(directory, 12)? + word(directory, 14)?;
    Some(directory.get(16..)?.get(..count * 8)?.as_chunks::<8>().0)
}

const BRANCH: usize = 1 << 31;

pub(super) fn child_directory<'a>(tree: &'a [u8], entry: &[u8; 8]) -> Option<&'a [[u8; 8]]> {
    let offset = dword(entry, 4)?;
    (offset & BRANCH != 0).then(|| entries(tree, offset ^ BRANCH))?
}

// All version blocks start with three WORDs. Names and string values use
// UTF-16LE. Container lengths exclude padding before their next sibling.
fn named(bytes: &[u8], name: &[u8]) -> Option<usize> {
    let end = 6 + (name.len() + 1) * 2;
    let units = bytes.get(6..end)?.as_chunks::<2>().0;
    name.iter()
        .copied()
        .chain([0])
        .zip(units)
        .all(|(ch, pair)| *pair == [ch, 0])
        .then_some(aligned(end))
}

struct Children<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for Children<'a> {
    type Item = (usize, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let start = self.pos;
        let len = word(self.bytes, start)?;
        if len < 6 {
            return None;
        }
        let block = self.bytes.get(start..)?.get(..len)?;
        self.pos += aligned(len);
        Some((start, block))
    }
}

fn strings(version: &[u8], base: usize, output: &mut Vec<usize>) {
    let Some(len) = word(version, 0) else {
        return;
    };
    let Some(root) = version.get(..len) else {
        return;
    };
    let Some(value) = named(root, b"VS_VERSION_INFO") else {
        return;
    };
    if word(root, 2) != Some(52) || dword(root, value) != Some(0xfeef04bd) {
        return;
    }
    for (si, info) in (Children {
        bytes: root,
        pos: value + 52,
    }) {
        let Some(start) = named(info, b"StringFileInfo") else {
            continue;
        };
        for (ti, table) in (Children {
            bytes: info,
            pos: start,
        }) {
            // StringTable starts with an eight-character language/codepage key.
            let Some(name) = table.get(6..24) else {
                continue;
            };
            if name[16..] != [0, 0]
                || !name[..16]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .all(|pair| pair[0].is_ascii_hexdigit() && pair[1] == 0)
            {
                continue;
            }
            for (i, string) in (Children {
                bytes: table,
                pos: 24,
            }) {
                // Stock admits a String when its aligned length fits in its table.
                if i + aligned(string.len()) <= table.len() && string.len() >= 8 {
                    output.push(base + si + ti + i + 6);
                }
            }
        }
    }
}

pub(super) fn keys(
    bytes: &[u8],
    sections: &[Section],
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<Vec<usize>> {
    let mut keys = Vec::new();
    let Some((map, tree)) = directory(bytes, sections) else {
        return Ok(keys);
    };
    let mut leaves = 0;
    let mut visited = 0;
    // Each physical directory entry is eight bytes. Allow repeated visits to
    // shared directory data while bounding work on overlapping directory trees.
    let mut step = |force| -> io::Result<()> {
        visited += 1;
        if force || visited % 256 == 0 {
            check()?;
            if visited > bytes.len() / 4 + 256 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "overlapping PE version resource directories exceed traversal budget",
                ));
            }
        }
        Ok(())
    };
    'root: for ty in entries(tree, 0).unwrap_or_default() {
        step(false)?;
        if dword(ty, 0) != Some(16) {
            continue;
        }
        for name in child_directory(tree, ty).unwrap_or_default() {
            step(false)?;
            for lang in child_directory(tree, name).unwrap_or_default() {
                step(false)?;
                let entry = dword(lang, 4).unwrap();
                if entry & BRANCH != 0 {
                    continue;
                }
                // The pinned engine collects at most 16 version data entries.
                if leaves == 16 {
                    break 'root;
                }
                leaves += 1;
                step(true)?;
                let Some(data) = tree.get(entry..).and_then(|s| s.get(..16)) else {
                    continue;
                };
                let Some(raw) = map.offset(dword(data, 0).unwrap()) else {
                    continue;
                };
                let Some(version) = bytes.get(raw..).and_then(|s| s.get(..dword(data, 4)?)) else {
                    continue;
                };
                strings(version, raw, &mut keys);
            }
        }
    }
    keys.sort_unstable();
    keys.dedup();
    Ok(keys)
}
