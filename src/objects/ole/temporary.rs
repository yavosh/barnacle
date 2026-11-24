//! Match the directory order of the Office-specific extractor on the configured scratch filesystem.
use super::directory::{Inventory, Member};
use super::{
    ChildSink, Document, Handling, native, native_payload, normalized_name, raw, temp_name,
};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

struct Layout {
    files: HashMap<String, usize>,
    native: HashMap<usize, Vec<usize>>,
    presentations: HashMap<usize, usize>,
    workbooks: HashMap<usize, usize>,
    folders: HashMap<String, usize>,
}

impl Layout {
    fn create(
        root: &Path,
        directory: &Inventory,
        pictures: bool,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Option<Self>> {
        let mut layout = Self {
            files: HashMap::new(),
            native: HashMap::new(),
            presentations: HashMap::new(),
            workbooks: HashMap::new(),
            folders: HashMap::new(),
        };
        let mut counts = HashMap::new();
        // The names and insertion order affect readdir. File contents stay in the source CFB.
        for &member in &directory.members {
            sink.check()?;
            match member {
                Member::Folder(id) => {
                    let path = directory.temporary_path(id);
                    fs::create_dir(root.join(&path))?;
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .expect("numeric storage name");
                    layout.folders.insert(name.to_owned(), id);
                }
                Member::File(id) => {
                    let entry = &directory.streams[id];
                    let Some(normalized) = normalized_name(&entry.name) else {
                        return Ok(None);
                    };
                    let count = counts.entry(normalized.clone()).or_insert(0);
                    *count += 1;
                    let name = temp_name(&normalized, *count);
                    fs::File::create_new(
                        root.join(directory.temporary_path(entry.parent))
                            .join(&name),
                    )?;
                    layout.files.insert(name, id);
                    if entry.name.eq_ignore_ascii_case("powerpoint document") {
                        layout.presentations.insert(entry.parent, id);
                    }
                    if pictures && entry.name.eq_ignore_ascii_case("workbook") {
                        layout.workbooks.insert(entry.parent, id);
                    }
                    if native(&entry.name) {
                        layout.native.entry(entry.parent).or_default().push(id);
                    }
                }
            }
        }
        Ok(Some(layout))
    }

    fn raw_walk(
        &self,
        path: &Path,
        doc: &mut Document,
        directory: &Inventory,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Option<Handling>> {
        for file in fs::read_dir(path)? {
            sink.check()?;
            let file = file?;
            if file.file_type()?.is_dir() {
                if let Some(result) = self.raw_walk(&file.path(), doc, directory, sink)? {
                    return Ok(Some(result));
                }
            } else if let Some((name, &id)) = file
                .file_name()
                .to_str()
                .and_then(|n| self.files.get_key_value(n))
            {
                let stream = &directory.streams[id];
                if let Some(result) = raw(doc, directory, stream, Some(name.as_bytes()), sink)? {
                    return Ok(Some(result));
                }
            }
        }
        Ok(None)
    }

    fn visit(
        &self,
        path: &Path,
        folder: usize,
        doc: &mut Document,
        directory: &Inventory,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Option<Handling>> {
        // The caller already compared root Package attachments before checking for Office-specific stages.
        if folder != 0
            && let Some(files) = self.native.get(&folder)
        {
            for &id in files.iter().rev() {
                if native_payload(doc, directory, &directory.streams[id], sink)? {
                    return Ok(Some(Handling::Stopped));
                }
            }
        }
        if let Some(&id) = self.presentations.get(&folder)
            && let Some(result) =
                super::powerpoint::scan(doc, directory, &directory.streams[id], sink)?
        {
            return Ok(Some(result));
        }
        if let Some(&id) = self.workbooks.get(&folder)
            && let Some(result) = workbook(doc, directory, id, sink)?
        {
            return Ok(Some(result));
        }
        if let Some(result) = self.raw_walk(path, doc, directory, sink)? {
            return Ok(Some(result));
        }
        for entry in fs::read_dir(path)? {
            sink.check()?;
            let file = entry?;
            if file.file_type()?.is_dir()
                && let Some(&id) = file.file_name().to_str().and_then(|n| self.folders.get(n))
                && let Some(result) = self.visit(&file.path(), id, doc, directory, sink)?
            {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }
}

pub(super) fn scan(
    doc: &mut Document,
    directory: &Inventory,
    pictures: bool,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let scratch = tempfile::tempdir_in(sink.temporary_directory())?;
    let Some(layout) = Layout::create(scratch.path(), directory, pictures, sink)? else {
        return Ok(Handling::Incomplete);
    };
    Ok(layout
        .visit(scratch.path(), 0, doc, directory, sink)?
        .unwrap_or(Handling::Complete))
}

fn workbook(
    doc: &mut Document,
    directory: &Inventory,
    id: usize,
    sink: &mut dyn ChildSink,
) -> io::Result<Option<Handling>> {
    super::drawing::scan(
        super::Input::open(doc, directory, &directory.streams[id])?,
        sink,
    )
}

impl Layout {
    fn workbook_children(
        &self,
        path: &Path,
        doc: &mut Document,
        directory: &Inventory,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Option<Handling>> {
        for entry in fs::read_dir(path)? {
            sink.check()?;
            let file = entry?;
            if !file.file_type()?.is_dir() {
                continue;
            }
            let name = file.file_name();
            let Some(folder) = name.to_str().and_then(|n| self.folders.get(n)) else {
                continue;
            };
            if let Some(&id) = self.workbooks.get(folder)
                && let Some(result) = workbook(doc, directory, id, sink)?
            {
                return Ok(Some(result));
            }
            if let Some(result) = self.workbook_children(&file.path(), doc, directory, sink)? {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }
}

pub(super) fn workbooks(
    doc: &mut Document,
    directory: &Inventory,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    // Either Book or Workbook can enable the pass. Only streams named Workbook are opened.
    let books = directory
        .streams
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.name.eq_ignore_ascii_case("workbook"));
    if let Some((id, _)) = books.clone().find(|(_, entry)| entry.depth == 1)
        && let Some(result) = workbook(doc, directory, id, sink)?
    {
        return Ok(result);
    }
    let mut nested = books.filter(|(_, entry)| entry.depth > 1);
    let Some((first, _)) = nested.next() else {
        return Ok(Handling::Complete);
    };
    if nested.next().is_none() {
        return Ok(workbook(doc, directory, first, sink)?.unwrap_or(Handling::Complete));
    }
    let scratch = tempfile::tempdir_in(sink.temporary_directory())?;
    let Some(layout) = Layout::create(scratch.path(), directory, true, sink)? else {
        return Ok(Handling::Incomplete);
    };
    Ok(layout
        .workbook_children(scratch.path(), doc, directory, sink)?
        .unwrap_or(Handling::Complete))
}
