//! A borrowed index for MS-ONESTORE package files. Object payloads stay in the source map.
use super::{ChildSink, Handling, properties::Properties, wire::*};
use std::{
    collections::{HashMap, HashSet},
    io,
};

const DATA_ROOT: [u8; 16] = *b"\xb9\xfa\xde\x84\xa3\xaa\x0d\x4a\xa3\xa8\x52\x0c\x77\xac\x70\x73";
const CONTENT_ROOT: [u8; 16] = *b"\xf8\x17\x37\x4a\x14\x1c\xe7\x49\x95\x26\x81\xd9\x42\xde\x17\x41";
const HEADER_ROOT: [u8; 16] = *b"\x9c\x31\x5a\x1a\x6b\xc2\xaa\x41\xb9\xc5\x9b\xd8\xc4\x4e\x07\xd4";
const SECTION_SCHEMA: [u8; 16] =
    *b"\xb4\x7c\x93\x1f\x6f\xb2\x5f\x44\xb9\xf8\x17\xe2\x01\x60\xe4\x61";
const MAX_ENTRIES: usize = 32768;

fn limit(n: usize) -> io::Result<()> {
    if n > MAX_ENTRIES {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn only<'a>(mut bytes: &'a [u8], kind: u16, work: &mut Work) -> io::Result<Node<'a>> {
    let node = next(&mut bytes, work)?;
    if node.kind != kind || !bytes.is_empty() {
        return Err(invalid());
    }
    Ok(node)
}

#[derive(Default)]
struct Store<'a> {
    elements: HashMap<Id, Node<'a>>,
    cells: HashMap<Cell, Id>,
    revisions: HashMap<Id, Id>,
    root: Option<Cell>,
    header: Option<Cell>,
}

impl<'a> Store<'a> {
    fn index(bytes: &'a [u8], work: &mut Work) -> io::Result<Self> {
        let package = next(&mut bytes.get(68..).ok_or_else(invalid)?, work)?;
        if package.kind != 0x7a {
            return Err(invalid());
        }
        let mut top = package.value;
        let index_id = id(&mut top)?;
        let mut elements = only(package.children, 0x15, work)?.children;
        let mut store = Self::default();
        while !elements.is_empty() {
            let element = next(&mut elements, work)?;
            if element.kind != 1 {
                return Err(invalid());
            }
            let mut head = element.value;
            let key = id(&mut head)?;
            if take(&mut head, 1)?[0] != 0 {
                take(&mut head, 24)?;
            }
            match compact(&mut head)? {
                1 if key == index_id => store.index_mappings(element.children, work)?,
                2 => {
                    let mut roots = element.children;
                    let schema = next(&mut roots, work)?;
                    if schema.kind != 0x0c || schema.value != SECTION_SCHEMA {
                        return Err(invalid());
                    }
                    while !roots.is_empty() {
                        let node = next(&mut roots, work)?;
                        if node.kind == 7 {
                            let mut body = node.value;
                            let role = id(&mut body)?;
                            if role.guid == HEADER_ROOT
                                && role.number == 1
                                && store.header.replace(cell(&mut body)?).is_some()
                            {
                                return Err(invalid());
                            }
                            if role.guid == DATA_ROOT
                                && role.number == 2
                                && store.root.replace(cell(&mut body)?).is_some()
                            {
                                return Err(invalid());
                            }
                        }
                    }
                }
                3 | 4 | 5 | 10 => {
                    limit(store.elements.len() + 1)?;
                    if store.elements.insert(key, element).is_some() {
                        return Err(invalid());
                    }
                }
                _ => {}
            }
        }
        Ok(store)
    }

    fn index_mappings(&mut self, mut bytes: &[u8], work: &mut Work) -> io::Result<()> {
        while !bytes.is_empty() {
            let node = next(&mut bytes, work)?;
            let mut v = node.value;
            limit(self.cells.len() + self.revisions.len() + 1)?;
            match node.kind {
                0xe => {
                    let cell = cell(&mut v)?;
                    self.cells.insert(cell, id(&mut v)?);
                }
                0xd => {
                    let revision = id(&mut v)?;
                    self.revisions.insert(revision, id(&mut v)?);
                }
                0x11 => {}
                _ => return Err(invalid()),
            }
        }
        Ok(())
    }

    fn space(&self, key: Cell, work: &mut Work) -> io::Result<Space<'a>> {
        let manifest = self
            .elements
            .get(self.cells.get(&key).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        let mut c = only(manifest.children, 0x0b, work)?.value;
        let mut revision = id(&mut c)?;
        let mut seen = HashSet::new();
        let mut space = Space {
            key,
            root: None,
            metadata: None,
            first_object: None,
            objects: HashMap::new(),
        };
        while revision != Id::default() {
            if seen.len() >= 512 || !seen.insert(revision) {
                return Err(invalid());
            }
            let node = self
                .elements
                .get(self.revisions.get(&revision).ok_or_else(invalid)?)
                .ok_or_else(invalid)?;
            let mut list = node.children;
            let record = next(&mut list, work)?;
            if record.kind != 0x1a {
                return Err(invalid());
            }
            let mut v = record.value;
            id(&mut v)?;
            revision = id(&mut v)?;
            while !list.is_empty() {
                let item = next(&mut list, work)?;
                let mut v = item.value;
                match item.kind {
                    0x0a => {
                        let role = id(&mut v)?;
                        if role.guid == CONTENT_ROOT {
                            match role.number {
                                1 => space.root = Some(id(&mut v)?),
                                2 => space.metadata = Some(id(&mut v)?),
                                _ => {}
                            }
                        }
                    }
                    0x19 => {
                        let group = self.elements.get(&id(&mut v)?).ok_or_else(invalid)?;
                        space.load_group(group.children, work)?;
                    }
                    _ => return Err(invalid()),
                }
            }
        }
        Ok(space)
    }

    fn blob(&self, key: Id, work: &mut Work) -> io::Result<&'a [u8]> {
        let e = self.elements.get(&key).ok_or_else(invalid)?;
        let mut v = only(e.children, 2, work)?.value;
        let count = compact(&mut v)?;
        take(&mut v, count)
    }
}

#[derive(Clone, Copy, Default)]
pub(super) struct Data<'a> {
    pub(super) objects: &'a [u8],
    pub(super) cells: &'a [u8],
    pub(super) body: &'a [u8],
}

#[derive(Default)]
struct Object<'a> {
    kind: u32,
    data: Data<'a>,
    blob: Option<Id>,
}

struct Space<'a> {
    key: Cell,
    root: Option<Id>,
    metadata: Option<Id>,
    first_object: Option<Id>,
    objects: HashMap<Id, Object<'a>>,
}

fn array<'a>(data: &mut &'a [u8], pairs: bool, work: &mut Work) -> io::Result<&'a [u8]> {
    let n = compact(data)?;
    limit(n)?;
    let start = *data;
    for _ in 0..n {
        work.step()?;
        id(data)?;
        if pairs {
            id(data)?;
        }
    }
    Ok(&start[..start.len() - data.len()])
}

impl<'a> Space<'a> {
    fn load_group(&mut self, mut bytes: &'a [u8], work: &mut Work) -> io::Result<()> {
        let declarations = next(&mut bytes, work)?;
        if declarations.kind != 0x1d {
            return Err(invalid());
        }
        let mut entries = next(&mut bytes, work)?;
        if entries.kind == 0x79 {
            entries = next(&mut bytes, work)?;
        }
        if entries.kind != 0x1e || !bytes.is_empty() {
            return Err(invalid());
        }
        let mut d = declarations.children;
        let mut v = entries.children;
        let mut group = HashMap::<Id, Object>::new();
        while !d.is_empty() {
            let decl = next(&mut d, work)?;
            let mut h = decl.value;
            let object = id(&mut h)?;
            if decl.kind == 5 {
                id(&mut h)?;
            } else if decl.kind != 0x18 {
                return Err(invalid());
            }
            let part = compact(&mut h)?;
            if part == 1 {
                self.first_object.get_or_insert(object);
            }
            let data = next(&mut v, work)?;
            if self.objects.contains_key(&object) {
                continue;
            }
            limit(group.len() + self.objects.len() + 1)?;
            let target = group.entry(object).or_default();
            let mut payload = data.value;
            let objects = array(&mut payload, false, work)?;
            let cells = array(&mut payload, true, work)?;
            match (part, data.kind) {
                (2, 0x1c) => target.blob = Some(id(&mut payload)?),
                (1 | 4, 0x16) => {
                    let n = compact(&mut payload)?;
                    let mut body = take(&mut payload, n)?;
                    if part == 4 {
                        target.kind = word(&mut body)?;
                    } else {
                        target.data = Data {
                            objects,
                            cells,
                            body,
                        };
                    }
                }
                _ => {}
            }
        }
        if !v.is_empty() {
            return Err(invalid());
        }
        self.objects.extend(group);
        Ok(())
    }

    fn get(&self, k: Id) -> io::Result<&Object<'a>> {
        self.objects.get(&k).ok_or_else(invalid)
    }
    fn props(&self, k: Id, kind: u32, work: &mut Work) -> io::Result<Properties<'a>> {
        let obj = self.get(k)?;
        if obj.kind != kind {
            return Err(invalid());
        }
        Properties::parse(obj.data, self.key.1, kind, work)
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let mut work = Work::new(sink);
    let attachments = match files(bytes, &mut work) {
        Ok(list) => list,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return Ok(Handling::Incomplete),
        Err(e) => return Err(e),
    };
    for (data, name) in attachments.into_iter().rev() {
        let units = name
            .as_chunks::<2>()
            .0
            .iter()
            .map(|v| u16::from_le_bytes(*v))
            .take_while(|&c| c != 0);
        let Ok(decoded) = char::decode_utf16(units).collect::<Result<String, _>>() else {
            return Ok(Handling::Incomplete);
        };
        let name = (!decoded.is_empty()).then_some(decoded.as_bytes());
        if work.sink.child_bytes(data, name)? {
            return Ok(Handling::Stopped);
        }
    }
    Ok(Handling::Complete)
}

fn files<'a>(bytes: &'a [u8], work: &mut Work) -> io::Result<Vec<(&'a [u8], &'a [u8])>> {
    let store = Store::index(bytes, work)?;
    {
        let header = store.space(store.header.ok_or_else(invalid)?, work)?;
        let data = header.get(header.first_object.ok_or_else(invalid)?)?.data;
        Properties::parse(data, header.key.1, 0, work)?;
    }
    let section = store.space(store.root.ok_or_else(invalid)?, work)?;
    section.props(section.metadata.ok_or_else(invalid)?, 0x20031, work)?;
    let root = section.props(section.root.ok_or_else(invalid)?, 0x60007, work)?;
    let mut files = Vec::new();
    for &series in &root.elements {
        for key in section.props(series, 0x60008, work)?.pages {
            let page = store.space(key, work)?;
            page.props(page.metadata.ok_or_else(invalid)?, 0x20030, work)?;
            let manifest = page.props(page.root.ok_or_else(invalid)?, 0x60037, work)?;
            let page_id = *manifest.contents.first().ok_or_else(invalid)?;
            for outline in page.props(page_id, 0x6000b, work)?.elements {
                if page.get(outline)?.kind != 0x6000c {
                    continue;
                }
                for entry in page.props(outline, 0x6000c, work)?.elements {
                    if page.get(entry)?.kind != 0x6000d {
                        continue;
                    }
                    for file in page.props(entry, 0x6000d, work)?.contents {
                        if page.get(file)?.kind != 0x60035 {
                            continue;
                        }
                        let data = page.props(file, 0x60035, work)?;
                        let container = page.get(data.container.ok_or_else(invalid)?)?;
                        if data.filename.len() > 8192
                            || !data.filename.len().is_multiple_of(2)
                            || container.kind != 0x80036
                            || files.len() >= 4096
                        {
                            return Err(invalid());
                        }
                        files.push((
                            store.blob(container.blob.ok_or_else(invalid)?, work)?,
                            data.filename,
                        ));
                    }
                }
            }
        }
    }
    Ok(files)
}
