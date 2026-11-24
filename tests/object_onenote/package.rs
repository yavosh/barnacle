//! Small MS-ONESTORE package with two attached documents on one page.
const GUID: [u8; 16] = *b"Barnacle section";

fn number(v: usize) -> Vec<u8> {
    let v = v as u64;
    for width in 1..=7 {
        if v < (1u64 << (7 * width)) {
            let code = (v << width) | (1 << (width - 1));
            return code.to_le_bytes()[..width].to_vec();
        }
    }
    [vec![128], v.to_le_bytes().to_vec()].concat()
}
fn extended(guid: [u8; 16], n: u8) -> Vec<u8> {
    let mut r = vec![128];
    r.extend(u32::from(n).to_le_bytes());
    r.extend(guid);
    r
}
fn id(n: u8) -> Vec<u8> {
    if n == 0 { vec![0] } else { extended(GUID, n) }
}
fn seq(values: &[u8]) -> Vec<u8> {
    values.iter().flat_map(|n| id(*n)).collect()
}

fn node(kind: u16, value: Vec<u8>, children: Option<Vec<u8>>) -> Vec<u8> {
    let flags = if children.is_some() { 4 } else { 0 };
    let mut bytes = if kind < 64 && value.len() < 128 {
        ((value.len() as u16) << 9 | kind << 3 | flags)
            .to_le_bytes()
            .to_vec()
    } else {
        ((value.len().min(0x7fff) as u32) << 17 | u32::from(kind) << 3 | u32::from(flags) | 2)
            .to_le_bytes()
            .to_vec()
    };
    if value.len() >= 0x7fff {
        bytes.extend(number(value.len()));
    }
    bytes.extend(value);
    if let Some(children) = children {
        bytes.extend(children);
        // These generated compounds use the shortest end record for their type.
        if kind < 64 {
            bytes.push((kind as u8) << 2 | 1);
        } else {
            bytes.extend((kind << 2 | 3).to_le_bytes());
        }
    }
    bytes
}
fn element(key: u8, kind: u8, children: Vec<u8>) -> Vec<u8> {
    let mut header = id(key);
    header.push(0);
    header.extend(number(kind as usize));
    node(1, header, Some(children))
}
fn stream(kind: u16, data: Vec<u8>) -> Vec<u8> {
    node(kind, data, None)
}
fn binary(bytes: &[u8]) -> Vec<u8> {
    let mut r = number(bytes.len());
    r.extend(bytes);
    r
}
fn counted(bytes: &[u8]) -> Vec<u8> {
    let mut r = (bytes.len() as u32).to_le_bytes().to_vec();
    r.extend(bytes);
    r
}
fn utf16(name: &str) -> Vec<u8> {
    counted(
        &name
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    )
}
fn u32v(n: u32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}
type Fields = Vec<(u32, Vec<u8>)>;

#[derive(Default)]
struct Group {
    declarations: Vec<u8>,
    rows: Vec<u8>,
}

impl Group {
    fn object(&mut self, key: u8, kind: u32, refs: &[u8], pages: &[u8], fields: Fields) {
        self.row(key, 4, &[], &[], &u32v(kind));
        let mut body = u32v(refs.len() as u32 | if pages.is_empty() { 1 << 31 } else { 0 });
        for i in 0..refs.len() {
            body.extend(u32v(100 + i as u32));
        }
        if !pages.is_empty() {
            body.extend(u32v(pages.len() as u32));
            for i in 0..pages.len() {
                body.extend(u32v(200 + i as u32));
            }
        }
        body.extend((fields.len() as u16).to_le_bytes());
        for (id, _) in &fields {
            body.extend(id.to_le_bytes());
        }
        for (_, v) in fields {
            body.extend(v);
        }
        self.row(key, 1, refs, pages, &body);
    }
    fn row(&mut self, key: u8, partition: u8, refs: &[u8], pages: &[u8], body: &[u8]) {
        let mut decl = id(key);
        for n in [partition as usize, body.len(), refs.len(), pages.len()] {
            decl.extend(number(n));
        }
        self.declarations.extend(stream(0x18, decl));
        let mut data = number(refs.len());
        data.extend(seq(refs));
        data.extend(number(pages.len()));
        for &p in pages {
            data.extend(seq(&[0, p]));
        }
        data.extend(binary(body));
        self.rows.extend(stream(0x16, data));
    }
    fn file_data(&mut self, key: u8, blob: u8) {
        let mut decl = seq(&[key, blob]);
        for n in [2, 0, 0] {
            decl.extend(number(n));
        }
        self.declarations.extend(stream(5, decl));
        let mut data = number(0);
        data.extend(number(0));
        data.extend(id(blob));
        self.rows.extend(stream(0x1c, data));
    }
    fn finish(self, key: u8) -> Vec<u8> {
        element(
            key,
            5,
            [
                node(0x1d, vec![], Some(self.declarations)),
                node(0x1e, vec![], Some(self.rows)),
            ]
            .concat(),
        )
    }
}

pub(super) fn section(reverse: bool, first: &[u8], second: &[u8]) -> Vec<u8> {
    let role = *b"\xf8\x17\x37\x4a\x14\x1c\xe7\x49\x95\x26\x81\xd9\x42\xde\x17\x41";
    let header_root = *b"\x9c\x31\x5a\x1a\x6b\xc2\xaa\x41\xb9\xc5\x9b\xd8\xc4\x4e\x07\xd4";
    let data_root = *b"\xb9\xfa\xde\x84\xa3\xaa\x0d\x4a\xa3\xa8\x52\x0c\x77\xac\x70\x73";
    let schema = *b"\xb4\x7c\x93\x1f\x6f\xb2\x5f\x44\xb9\xf8\x17\xe2\x01\x60\xe4\x61";
    let mut mappings = stream(0x11, [id(2), vec![0]].concat());
    let mut manifest = stream(0xc, schema.to_vec());
    for (r, n, space) in [(header_root, 1, 10), (data_root, 2, 20)] {
        manifest.extend(stream(7, [extended(r, n), seq(&[0, space])].concat()));
    }
    let mut elements = element(2, 2, manifest);
    for (space, content, meta) in [(10, 50, 0), (20, 51, 52), (30, 54, 55)] {
        mappings.extend(stream(0xe, [seq(&[0, space, space + 1]), vec![0]].concat()));
        mappings.extend(stream(
            0xd,
            [seq(&[space + 2, space + 3]), vec![0]].concat(),
        ));
        elements.extend(element(space + 1, 3, stream(0x0b, id(space + 2))));
        let mut revision = stream(0x1a, seq(&[space + 2, 0]));
        revision.extend(stream(0x0a, [extended(role, 1), id(content)].concat()));
        if meta != 0 {
            revision.extend(stream(0x0a, [extended(role, 2), id(meta)].concat()));
        }
        revision.extend(stream(0x19, id(space + 4)));
        elements.extend(element(space + 3, 4, revision));
    }
    elements.extend(element(1, 1, mappings));
    let guid = || counted(&GUID);
    let archived_time = || 132000000000000000u64.to_le_bytes().to_vec();
    let mut header = Group::default();
    header.object(
        50,
        0,
        &[],
        &[],
        vec![
            (0x1c001d94, guid()),
            (0x1c001d95, guid()),
            (0x14001d93, u32v(0)),
        ],
    );
    elements.extend(header.finish(14));
    let mut section = Group::default();
    section.object(
        51,
        0x60007,
        &[53],
        &[],
        vec![
            (0x1c001c30, guid()),
            (0x18001c65, archived_time()),
            (0x24001c20, u32v(1)),
        ],
    );
    section.object(
        52,
        0x20031,
        &[],
        &[],
        vec![(0x14001d82, u32v(1)), (0x1400348b, u32v(1))],
    );
    section.object(
        53,
        0x60008,
        &[],
        &[30],
        vec![(0x1c001c30, guid()), (0x2c001d63, u32v(1))],
    );
    elements.extend(section.finish(24));
    let mut page = Group::default();
    page.object(54, 0x60037, &[56], &[], vec![(0x24001c1f, u32v(1))]);
    page.object(
        55,
        0x20030,
        &[],
        &[],
        vec![
            (0x1c001c30, guid()),
            (0x1c001cf3, utf16("Page")),
            (0x18001c65, archived_time()),
        ],
    );
    page.object(56, 0x6000b, &[57], &[], vec![(0x24001c20, u32v(1))]);
    page.object(
        57,
        0x6000c,
        &[58],
        &[],
        vec![
            (0x14001d7a, u32v(1)),
            (0xc001c03, vec![1]),
            (0x1c001c12, counted(&[0; 4])),
            (0x24001c20, u32v(1)),
        ],
    );
    let order = if reverse {
        [60, 59, 63, 63]
    } else {
        [59, 60, 63, 63]
    };
    page.object(
        58,
        0x6000d,
        &order,
        &[],
        vec![
            (0x14001d09, u32v(1)),
            (0x14001d7a, u32v(1)),
            (0xc001c03, vec![1]),
            (0x24001c1f, u32v(2)),
            (0x20001d78, vec![]),
            (0x20001d79, vec![]),
        ],
    );
    for (file, container, name, blob) in [(59, 61, "first.txt", 40), (60, 62, "second.txt", 41)] {
        page.object(
            file,
            0x60035,
            &[container],
            &[],
            vec![
                (0x14001d7a, u32v(1)),
                (0x20001d9b, vec![]),
                (0x1c001d9c, utf16(name)),
            ],
        );
        page.object(container, 0x80036, &[], &[], vec![]);
        page.file_data(container, blob);
    }
    page.object(63, 0x120001, &[], &[], vec![(0x1c001d75, utf16("Author"))]);
    elements.extend(page.finish(34));
    for (blob, data) in [(40, first), (41, second)] {
        elements.extend(element(blob, 10, stream(2, binary(data))));
    }
    let mut doc = super::SECTION.to_vec();
    doc.extend(GUID);
    doc.extend(GUID);
    doc.extend(*b"\x2f\xe9\x8d\x63\xd4\xa6\xc1\x4b\x9a\x36\xb3\xfc\x25\x11\xa5\xb7");
    doc.extend(u32v(0));
    doc.extend(node(
        0x7a,
        [id(1), schema.to_vec()].concat(),
        Some(node(0x15, vec![0], Some(elements))),
    ));
    doc
}
