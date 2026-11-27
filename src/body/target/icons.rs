//! Read grouped PE icon resources. Group entries name numeric RT_ICON resources.
//! Each resource can contain several localized DIBs.
mod metric;
pub(crate) use metric::IconMetric;

use super::executable::Section;
use super::version_info::{Map, child_directory, directory, dword, entries, word};
use std::{
    collections::{HashMap, HashSet},
    io,
};

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn data<'a>(
    map: &Map<'_>,
    tree: &[u8],
    entry: &[u8; 8],
    bytes: &'a [u8],
) -> Option<(usize, &'a [u8])> {
    let leaf = tree.get(dword(entry, 4)?..)?.get(..16)?;
    let start = map.offset(dword(leaf, 0)?)?;
    Some((start, bytes.get(start..)?.get(..dword(leaf, 4)?)?))
}

#[derive(Debug, Default)]
pub(crate) struct IconSamples {
    pub(crate) values: Vec<IconMetric>,
    pub(crate) unsupported: Option<String>,
}

pub(super) fn metrics(
    bytes: &[u8],
    sections: &[Section],
    max_icons: usize,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<IconSamples> {
    let mut samples = IconSamples::default();
    match read_metrics(bytes, sections, max_icons, check, &mut samples.values) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {
            samples.unsupported = Some(error.to_string());
        }
        Err(error) => return Err(error),
    }
    Ok(samples)
}

fn read_metrics(
    bytes: &[u8],
    sections: &[Section],
    max_icons: usize,
    check: &mut impl FnMut() -> io::Result<()>,
    result: &mut Vec<IconMetric>,
) -> io::Result<()> {
    let Some((map, tree)) = directory(bytes, sections) else {
        return Ok(());
    };
    let types =
        entries(tree, 0).ok_or_else(|| unsupported("incomplete PE resource type directory"))?;
    let mut groups = None;
    let mut icons = None;
    let mut visits = 0usize;
    let mut step = |immediate| -> io::Result<()> {
        visits += 1;
        if immediate || visits.is_multiple_of(256) {
            check()?;
            if visits > bytes.len() / 4 + 256 {
                return Err(unsupported(
                    "overlapping PE icon resources exceed traversal budget",
                ));
            }
        }
        Ok(())
    };
    for ty in types {
        step(false)?;
        match dword(ty, 0) {
            Some(3) => icons = Some(ty),
            Some(14) => groups = Some(ty),
            _ => (),
        }
    }
    let (Some(groups), Some(icons)) = (groups, icons) else {
        return Ok(());
    };
    let children = |entry: &[u8; 8]| {
        child_directory(tree, entry)
            .ok_or_else(|| unsupported("incomplete PE icon resource directory"))
    };
    let Some(first) = children(groups)?.first() else {
        return Ok(());
    };
    // Numeric resource identifiers are 16 bits. Building this map once avoids
    // rescanning the entire name directory for each group entry.
    let mut lookup = HashMap::new();
    for name in children(icons)? {
        step(false)?;
        if let Some(id) = dword(name, 0).and_then(|id| u16::try_from(id).ok()) {
            lookup.entry(id).or_insert(name);
        }
    }
    let mut remaining = max_icons.max(1);
    let mut seen_ids = HashSet::new();
    let mut seen_images = HashSet::new();
    for lang in children(first)? {
        step(false)?;
        let (_, group) =
            data(&map, tree, lang, bytes).ok_or_else(|| unsupported("incomplete PE icon group"))?;
        if word(group, 0) != Some(0) || word(group, 2) != Some(1) {
            return Err(unsupported("unknown PE icon group header"));
        }
        let count = word(group, 4).ok_or_else(|| unsupported("incomplete PE icon group"))?;
        let group_entries = group
            .get(6..)
            .and_then(|s| s.get(..count * 14))
            .ok_or_else(|| unsupported("incomplete PE icon group entries"))?;
        for item in group_entries.as_chunks::<14>().0 {
            step(false)?;
            let id = u16::from_le_bytes([item[12], item[13]]);
            remaining -= 1;
            if seen_ids.insert(id)
                && let Some(name) = lookup.get(&id)
            {
                for lang in children(name)? {
                    step(false)?;
                    let (start, dib) = data(&map, tree, lang, bytes)
                        .ok_or_else(|| unsupported("incomplete PE icon resource"))?;
                    if dib.starts_with(b"\x89PNG\r\n\x1a\n")
                        || !seen_images.insert((start, dib.len()))
                    {
                        continue;
                    }
                    // MaxIconsPE counts group references, not localized bitmaps.
                    // Bound per-object storage even with very large locale catalogs.
                    if seen_images.len() > 4096 {
                        return Err(unsupported("PE icon locale catalog exceeds metric budget"));
                    }
                    if dword(dib, 0) != Some(40) || dword(dib, 16) != Some(0) {
                        return Err(unsupported("unverified PE icon DIB header or compression"));
                    }
                    step(true)?;
                    let metric = IconMetric::from_dib(dib)
                        .ok_or_else(|| unsupported("unverified PE icon raster layout"))?;
                    result.push(metric);
                }
            }
            if remaining == 0 {
                return Ok(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
