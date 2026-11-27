//! All PE fixtures contain one read-only data section and no entry point.
#[path = "../../../../tests/common/pe.rs"]
mod pe;
use super::super::ObjectContext;
use super::IconMetric;
use std::io;

fn put16(data: &mut [u8], pos: usize, value: u16) {
    data[pos..pos + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(data: &mut [u8], pos: usize, value: usize) {
    data[pos..pos + 4].copy_from_slice(&(value as u32).to_le_bytes());
}
fn square(gray: u8) -> Vec<u8> {
    let mut dib = vec![0; 40 + 32 * 32 * 4 + 32 * 4];
    put32(&mut dib, 0, 40);
    put32(&mut dib, 4, 32);
    put32(&mut dib, 8, 64);
    put16(&mut dib, 12, 1);
    put16(&mut dib, 14, 32);
    for pixel in dib[40..40 + 32 * 32 * 4].as_chunks_mut::<4>().0 {
        *pixel = [gray, gray, gray, 255];
    }
    dib
}
fn group(ids: &[u16], len: usize) -> Vec<u8> {
    let mut bytes = vec![0; 6 + 14 * ids.len()];
    put16(&mut bytes, 2, 1);
    put16(&mut bytes, 4, ids.len() as u16);
    for (record, &id) in bytes[6..].as_chunks_mut::<14>().0.iter_mut().zip(ids) {
        record[..2].copy_from_slice(&[32, 32]);
        put16(record, 4, 1);
        put16(record, 6, 32);
        put32(record, 8, len);
        put16(record, 12, id);
    }
    bytes
}
type Names = Vec<(u16, Vec<(u16, Vec<u8>)>)>;

fn directory(tree: &mut Vec<u8>, ids: impl ExactSizeIterator<Item = u16>) -> usize {
    let start = tree.len();
    tree.resize(start + 16 + 8 * ids.len(), 0);
    put16(tree, start + 14, ids.len() as u16);
    for (i, id) in ids.enumerate() {
        put32(tree, start + 16 + i * 8, id as usize);
    }
    start
}

fn image(icons: Names, groups: Names) -> Vec<u8> {
    let mut res = Vec::new();
    let mut payloads = Vec::new();
    let types = directory(&mut res, [3, 14].into_iter());
    for (i, names) in [icons, groups].into_iter().enumerate() {
        let root = directory(&mut res, names.iter().map(|(id, _)| *id));
        put32(&mut res, types + 20 + 8 * i, (1 << 31) | root);
        for (j, (_, languages)) in names.into_iter().enumerate() {
            let lang = directory(&mut res, languages.iter().map(|(id, _)| *id));
            put32(&mut res, root + 20 + 8 * j, (1 << 31) | lang);
            for (k, (_, payload)) in languages.into_iter().enumerate() {
                let entry = res.len();
                res.resize(entry + 16, 0);
                put32(&mut res, lang + 20 + 8 * k, entry);
                payloads.push((entry, payload));
            }
        }
    }
    for (entry, payload) in payloads {
        res.resize(res.len().next_multiple_of(4), 0);
        let rva = 4096 + res.len();
        put32(&mut res, entry, rva);
        put32(&mut res, entry + 4, payload.len());
        res.extend(payload);
    }
    let mut image = pe::benign_pe();
    let size = res.len();
    let raw = size.next_multiple_of(512);
    image.resize(512 + raw, 0);
    image[512..512 + size].copy_from_slice(&res);
    put32(&mut image, 384, size);
    put32(&mut image, 392, raw);
    put32(&mut image, 208, (4096 + size).next_multiple_of(4096));
    put32(&mut image, 264, 4096);
    put32(&mut image, 268, size);
    image
}

#[test]
fn locales_share_an_entry_slot_and_only_first_group_name_is_used() {
    let a = square(100);
    let b = square(180);
    let c = square(220);
    let size = a.len();
    let expected = [&a, &b, &c].map(|dib| IconMetric::from_dib(dib).unwrap());
    let icons = vec![(1, vec![(1033, a), (1036, b)]), (2, vec![(1033, c)])];
    let g1 = group(&[1, 1], size);
    let g2 = group(&[2], size);
    let bytes = image(
        icons.clone(),
        vec![(1, vec![(1033, g1.clone()), (1036, g2.clone())])],
    );
    let ctx = ObjectContext::raw(&bytes);
    for limit in [0, 1, 2] {
        assert_eq!(
            ctx.icon_metrics(&bytes, limit, &mut || Ok(()))
                .unwrap()
                .values,
            expected[..2]
        );
    }
    assert_eq!(
        ctx.icon_metrics(&bytes, 3, &mut || Ok(())).unwrap().values,
        expected
    );
    let bytes = image(icons, vec![(1, vec![(1033, g1)]), (2, vec![(1033, g2)])]);
    assert_eq!(
        ObjectContext::raw(&bytes)
            .icon_metrics(&bytes, 100, &mut || Ok(()))
            .unwrap()
            .values,
        expected[..2]
    );
}
#[test]
fn missing_reference_takes_a_slot_and_deadlines_propagate() {
    let dib = square(100);
    let size = dib.len();
    let bytes = image(
        vec![(2, vec![(1033, dib)])],
        vec![(1, vec![(1033, group(&[77, 2], size))])],
    );
    let ctx = ObjectContext::raw(&bytes);
    assert!(
        ctx.icon_metrics(&bytes, 1, &mut || Ok(()))
            .unwrap()
            .values
            .is_empty()
    );
    assert_eq!(
        ctx.icon_metrics(&bytes, 2, &mut || Ok(()))
            .unwrap()
            .values
            .len(),
        1
    );
    let error = ctx
        .icon_metrics(&bytes, 2, &mut || Err(io::ErrorKind::TimedOut.into()))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}
