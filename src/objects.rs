//! Object traversal for one scan against one immutable database generation.
use crate::body::{ObjectContext, Target};
use std::io::{self, Read, Write};
use std::path::Path;

mod archive;
mod autoit;
mod classify;
mod dmg;
mod embedded;
mod hfs;
mod hwp3;
mod installer;
mod iso;
mod macho;
mod office;
mod ole;
mod onenote;
mod partition;
mod pdf;
mod rtf;
mod swf;
mod text;
mod udf;
mod upx;
mod xdp;
mod xml;

/// A handler can recognize a format without proving that it visited every object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Handling {
    Unrecognized,
    Complete,
    Incomplete,
    Stopped,
}

trait ChildSink {
    /// Visit one child synchronously. A true return stops traversal in this handler.
    fn child(
        &mut self,
        data: &mut dyn Read,
        target: Option<Target>,
        name: Option<&[u8]>,
    ) -> io::Result<bool> {
        match self.read_child(data)? {
            Some(snapshot) => self.visit_snapshot(snapshot, target, name),
            None => Ok(false),
        }
    }
    fn mailbox_letters(&mut self, letters: &mut text::SavedLetters) -> io::Result<Handling>;
    fn read_child(&mut self, data: &mut dyn Read) -> io::Result<Option<Snapshot>>;
    fn visit_snapshot(
        &mut self,
        snapshot: Snapshot,
        target: Option<Target>,
        name: Option<&[u8]>,
    ) -> io::Result<bool>;
    fn child_bytes(&mut self, bytes: &[u8], name: Option<&[u8]>) -> io::Result<bool>;
    fn utf16_html(&mut self, bytes: &[u8]) -> io::Result<Handling>;
    fn embedded_archive(&mut self, kind: &'static str, bytes: &[u8]) -> io::Result<Handling>;
    fn embedded_xdp(&mut self, bytes: &[u8]) -> io::Result<Handling>;
    fn cooked_iso(
        &mut self,
        bytes: &[u8],
        layout: iso::Layout,
        primary: bool,
    ) -> io::Result<Handling>;
    fn match_generic_view(&mut self, bytes: &[u8]) -> io::Result<bool>;
    fn partition(&mut self, snapshot: Snapshot) -> io::Result<bool> {
        snapshot.with_bytes(|bytes| self.partition_bytes(bytes, None))
    }
    fn partition_bytes(&mut self, bytes: &[u8], name: Option<&[u8]>) -> io::Result<bool>;
    fn script_view(&mut self, source: &[u8]) -> io::Result<bool>;

    fn check(&mut self) -> io::Result<()>;
    fn at_root(&self) -> bool;
    fn child_limit(&self) -> Option<Limit>;
    fn can_enter_child(&mut self) -> bool;
    fn autoit_child_stop(&mut self, size: u64) -> bool;
    fn remaining(&self) -> u64;
    fn max_file_size(&self) -> u64;
    fn max_files(&self) -> usize;
    fn record_file_limit(&mut self);
    fn recorded_limit(&self) -> Option<Limit>;
    fn max_partitions(&self) -> usize;
    fn ole_directory_limit(&mut self, depth: usize, preceding_streams: usize) -> bool;
    fn size_limit(&self, size: u64) -> Option<Limit>;
    fn skip_declared_size(&mut self, size: u64) -> bool;
    fn text_limits(&self) -> (u64, u64, u64);
    fn temporary_directory(&self) -> &Path;
}

#[derive(Clone, Debug)]
pub struct Options {
    pub max_file_size: u64,
    pub max_scan_size: u64,
    pub max_files: usize,
    pub max_partitions: usize,
    pub max_recursion: usize,
    pub max_rec_hwp3: usize,
    pub alert_exceeds_max: bool,
    pub scan_archive: bool,
    pub scan_pe: bool,
    pub max_embedded_pe: u64,
    pub scan_elf: bool,
    pub scan_pdf: bool,
    pub scan_ole2: bool,
    pub scan_hwp3: bool,
    pub scan_xml_docs: bool,
    pub scan_swf: bool,
    pub scan_onenote: bool,
    pub scan_image: bool,
    pub alert_broken_media: bool,
    pub scan_html: bool,
    pub scan_mail: bool,
    pub max_html_normalize: u64,
    pub max_html_no_tags: u64,
    pub max_script_normalize: u64,
    pub scan_normalized_script: bool,
    pub map_normalized_script: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_file_size: 100 << 20,
            max_scan_size: 400 << 20,
            max_files: 10_000,
            max_partitions: 50,
            max_recursion: 17,
            max_rec_hwp3: 16,
            alert_exceeds_max: false,
            scan_archive: true,
            scan_pe: true,
            max_embedded_pe: 40 << 20,
            scan_elf: true,
            scan_pdf: true,
            scan_ole2: true,
            scan_hwp3: true,
            scan_xml_docs: true,
            scan_swf: true,
            scan_onenote: true,
            scan_image: true,
            alert_broken_media: false,
            scan_html: true,
            scan_mail: true,
            max_html_normalize: 40 << 20,
            max_html_no_tags: 8 << 20,
            max_script_normalize: 20 << 20,
            scan_normalized_script: true,
            map_normalized_script: false,
        }
    }
}

pub struct Layer {
    pub file_type: &'static str,
    pub target: Target,
    pub name: Option<Box<[u8]>>,
    pub size: usize,
}

pub struct Object<'a> {
    pub bytes: &'a [u8],
    pub context: &'a ObjectContext,
    pub parents: &'a [Layer],
    pub layer: &'a Layer,
    pub normalized: bool,
    pub body_only: bool,
    pub handled_format: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Verdict {
    Found(String),
    Miss,
    Incomplete,
    /// The pinned engine omits this entire top-level object.
    Skipped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Limit {
    MaxFileSize,
    MaxScanSize,
    MaxFiles,
    MaxRecursion,
    MaxScanTime,
}

impl Limit {
    pub fn signature(self) -> String {
        format!("Heuristics.Limits.Exceeded.{self:?}")
    }
}

fn unlimited_if_zero(n: u64) -> u64 {
    if n == 0 { u64::MAX } else { n }
}

/// Keep small objects in memory and back larger snapshots with private files.
pub struct Snapshot(tempfile::SpooledTempFile);

// A decoded stream can outlive the callback that first inspects it. The owned
// variants have no writers. Borrowed bytes keep their source lifetime.
enum ObjectBytes<'a> {
    Borrowed(&'a [u8]),
    Memory(Vec<u8>),
    Mapped(memmap2::Mmap),
}

impl AsRef<[u8]> for ObjectBytes<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Memory(bytes) => bytes,
            Self::Mapped(bytes) => bytes,
        }
    }
}

impl Write for Snapshot {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl std::io::Seek for Snapshot {
    fn seek(&mut self, pos: std::io::SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

impl Snapshot {
    const MEMORY_LIMIT: usize = 64 * 1024;

    pub fn new(directory: &Path) -> Self {
        Self::with_memory(Self::MEMORY_LIMIT, directory)
    }

    fn with_memory(memory: usize, directory: &Path) -> Self {
        Self(tempfile::spooled_tempfile_in(memory, directory))
    }

    fn read_bounded(
        input: &mut dyn Read,
        directory: &Path,
        limit: u64,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<Self>> {
        let mut spool = Self::new(directory);
        let mut input = input.take(limit.saturating_add(1));
        let mut size = 0u64;
        let mut buf = [0u8; 8192];
        loop {
            check()?;
            let n = match input.read(&mut buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if n == 0 {
                return Ok(Some(spool));
            }
            size += n as u64;
            if size > limit {
                return Ok(None);
            }
            spool.write_all(&buf[..n])?;
        }
    }
    fn into_bytes(self) -> io::Result<ObjectBytes<'static>> {
        match self.0.into_inner() {
            tempfile::SpooledData::InMemory(data) => Ok(ObjectBytes::Memory(data.into_inner())),
            tempfile::SpooledData::OnDisk(file) => {
                // SAFETY: the spool owns this unlinked file and has finished writing.
                // The read-only mapping keeps the contents alive after the handle closes.
                let bytes = unsafe { memmap2::Mmap::map(&file)? };
                Ok(ObjectBytes::Mapped(bytes))
            }
        }
    }

    pub fn with_bytes<T>(self, visit: impl FnOnce(&[u8]) -> io::Result<T>) -> io::Result<T> {
        visit(self.into_bytes()?.as_ref())
    }
}

type Matcher<'a> =
    dyn FnMut(Object<'_>, &mut dyn FnMut() -> io::Result<()>) -> io::Result<Verdict> + 'a;

struct Traversal<'a> {
    options: &'a Options,
    temporary_directory: &'a Path,
    parents: Vec<Layer>,
    normalized_depth: usize,
    bytes_scanned: u64,
    files_scanned: usize,
    stopped: Option<Verdict>,
    first_limit: Option<Limit>,
    matcher: &'a mut Matcher<'a>,
    check: &'a mut dyn FnMut() -> io::Result<()>,
}

#[derive(Clone, Copy, PartialEq)]
enum InputKind {
    File,
    MailboxLetter,
    Normalized(Target),
    Partition,
}

pub fn scan(
    bytes: &[u8],
    options: &Options,
    temporary_directory: &Path,
    mut matcher: impl FnMut(Object<'_>, &mut dyn FnMut() -> io::Result<()>) -> io::Result<Verdict>,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<Verdict> {
    let mut walk = Traversal {
        options,
        temporary_directory,
        parents: Vec::new(),
        normalized_depth: 0,
        bytes_scanned: 0,
        files_scanned: 0,
        stopped: None,
        first_limit: None,
        matcher: &mut matcher,
        check: &mut check,
    };
    walk.visit(bytes, InputKind::File, None)?;
    Ok(walk.stopped.unwrap_or_else(|| match walk.first_limit {
        Some(limit) if options.alert_exceeds_max => Verdict::Found(limit.signature()),
        _ => Verdict::Miss,
    }))
}

impl Traversal<'_> {
    fn recursion_limit(&self) -> usize {
        match self.options.max_recursion {
            0 => 17,
            value => value,
        }
    }

    fn visit(&mut self, bytes: &[u8], kind: InputKind, name: Option<&[u8]>) -> io::Result<()> {
        self.check()?;
        if bytes.len() <= 5 {
            return Ok(());
        }
        if self.options.max_files != 0 && self.files_scanned >= self.options.max_files {
            self.first_limit.get_or_insert(Limit::MaxFiles);
            return Ok(());
        }
        if self.skip_declared_size(bytes.len() as u64) {
            return Ok(());
        }
        self.files_scanned += 1;
        self.bytes_scanned += bytes.len() as u64;
        if kind == InputKind::File && classify::ignored(bytes) {
            if self.parents.is_empty() {
                self.stopped = Some(Verdict::Skipped);
            }
            return Ok(());
        }
        let file_type = classify::FileType::classify(bytes, kind, self)?;
        if kind == InputKind::MailboxLetter {
            // Directory order is uncertain. Combining hits is valid only for text
            // leaves with the byte and file costs measured by the mailbox parser.
            if !matches!(file_type.parser, classify::Parser::Text)
                || self.options.scan_archive && partition::from_mbr(bytes).is_some()
                || embedded::possible_text_map(bytes, self)?
            {
                self.stopped = Some(Verdict::Incomplete);
                return Ok(());
            }
            if classify::ignored(bytes) {
                return Ok(());
            }
        }
        self.parents.push(Layer {
            target: file_type.context.target(),
            file_type: file_type.name,
            size: bytes.len(),
            name: name.map(Into::into),
        });
        let handling = file_type.parser.before_raw(bytes, self.options, self)?;
        if handling == Handling::Incomplete {
            self.stopped = Some(Verdict::Incomplete);
        }
        if self.stopped.is_none()
            && (!matches!(file_type.parser, classify::Parser::Html { .. })
                || !self.options.scan_html)
        {
            let (layer, parents) = self.parents.split_last().expect("current layer");
            let object = Object {
                bytes,
                context: &file_type.context,
                layer,
                parents,
                normalized: matches!(kind, InputKind::Normalized(_)),
                body_only: false,
                handled_format: handling == Handling::Complete,
            };
            let verdict = (self.matcher)(object, self.check)?;
            if verdict != Verdict::Miss {
                self.stopped = Some(verdict);
            }
        }
        if self.stopped.is_none() {
            let recognize = kind == InputKind::File
                && (self.options.scan_archive
                    || self.options.scan_pe && embedded::pe_carrier(file_type.name)
                    || self.options.scan_pdf && xdp::can_retype(file_type.name))
                && (!matches!(file_type.parser, classify::Parser::Html { .. })
                    || !self.options.scan_html);
            if self.after_raw(bytes, &file_type, recognize)? == Handling::Incomplete {
                self.stopped = Some(Verdict::Incomplete);
            }
        }
        self.parents.pop();
        Ok(())
    }

    fn after_raw(
        &mut self,
        bytes: &[u8],
        file_type: &classify::FileType,
        recognize: bool,
    ) -> io::Result<Handling> {
        if recognize && embedded::enabled(file_type.name) {
            let mut count = 0;
            let mut start = 0;
            let mut disks = if self.options.scan_archive {
                [
                    file_type.parser.disk_descriptor(),
                    if matches!(
                        file_type.parser,
                        classify::Parser::PartitionMap("CL_TYPE_APM")
                    ) {
                        None
                    } else {
                        partition::from_mbr(bytes)
                            .map(|name| (510, classify::Disk::PartitionMap(name)))
                    },
                    dmg::recognized(bytes).then(|| (bytes.len() - 512, classify::Disk::Dmg)),
                ]
            } else {
                [None; 3]
            };
            disks.sort_by_key(|disk| disk.map_or(usize::MAX, |(offset, _)| offset));
            for (offset, disk) in disks.into_iter().flatten() {
                let before = embedded::extract(
                    bytes,
                    file_type.name,
                    start..offset,
                    &mut count,
                    self.options,
                    self,
                )?;
                if matches!(before, Handling::Incomplete | Handling::Stopped)
                    || self.stopped.is_some()
                {
                    return Ok(before);
                }
                self.parents.last_mut().expect("current image").file_type = disk.name();
                let result = disk.extract(bytes, self)?;
                if result == Handling::Incomplete || self.stopped.is_some() {
                    return Ok(result);
                }
                start = offset;
            }
            let result = embedded::extract(
                bytes,
                file_type.name,
                start..bytes.len(),
                &mut count,
                self.options,
                self,
            )?;
            if result == Handling::Incomplete || self.stopped.is_some() {
                return Ok(result);
            }
        }
        file_type.parser.after_raw(bytes, self.options, self)
    }
}

impl ChildSink for Traversal<'_> {
    fn at_root(&self) -> bool {
        self.parents.len() == 1
    }

    fn can_enter_child(&mut self) -> bool {
        if let Some(reason) = self.child_limit() {
            self.first_limit.get_or_insert(reason);
            return false;
        }
        true
    }
    fn autoit_child_stop(&mut self, size: u64) -> bool {
        let Some(limit) = self.size_limit(size).or_else(|| self.child_limit()) else {
            return false;
        };
        let limit = self.first_limit.get_or_insert(limit);
        self.stopped = Some(if self.options.alert_exceeds_max {
            Verdict::Found(limit.signature())
        } else {
            // The pinned daemon reports a finding without a signature name here.
            Verdict::Incomplete
        });
        true
    }

    fn child_limit(&self) -> Option<Limit> {
        if self.options.max_files != 0 && self.files_scanned >= self.options.max_files {
            Some(Limit::MaxFiles)
        } else if self.parents.len() + self.normalized_depth >= self.recursion_limit() {
            Some(Limit::MaxRecursion)
        } else {
            None
        }
    }

    fn match_generic_view(&mut self, bytes: &[u8]) -> io::Result<bool> {
        if !self.can_enter_child() || self.skip_declared_size(bytes.len() as u64) {
            return Ok(false);
        }
        self.check()?;
        let context = ObjectContext::typed(Target::Generic, bytes);
        let layer = Layer {
            file_type: "CL_TYPE_ANY",
            target: Target::Generic,
            name: None,
            size: bytes.len(),
        };
        let object = Object {
            bytes,
            context: &context,
            parents: &self.parents,
            layer: &layer,
            normalized: false,
            body_only: false,
            handled_format: true,
        };
        let verdict = (self.matcher)(object, self.check)?;
        if verdict != Verdict::Miss {
            self.stopped = Some(verdict);
        }
        Ok(self.stopped.is_some())
    }

    fn embedded_xdp(&mut self, bytes: &[u8]) -> io::Result<Handling> {
        let layer = self.parents.last_mut().expect("XDP has an owning object");
        if !xdp::can_retype(layer.file_type) {
            return Ok(Handling::Unrecognized);
        }
        layer.file_type = "CL_TYPE_XDP";
        xdp::extract(bytes, self)
    }

    fn cooked_iso(
        &mut self,
        bytes: &[u8],
        layout: iso::Layout,
        primary: bool,
    ) -> io::Result<Handling> {
        let layer = self.parents.last_mut().expect("ISO has an owning disk");
        // The separately scheduled descriptor already visited a plain or raw image.
        if primary && layer.file_type == "CL_TYPE_ISO9660" {
            return Ok(Handling::Unrecognized);
        }
        layer.file_type = "CL_TYPE_ISO9660";
        iso::extract(bytes, layout, self)
    }

    fn partition_bytes(&mut self, bytes: &[u8], name: Option<&[u8]>) -> io::Result<bool> {
        if self.skip_declared_size(bytes.len() as u64) || !self.can_enter_child() {
            return Ok(false);
        }
        self.visit(bytes, InputKind::Partition, name)?;
        Ok(self.stopped.is_some())
    }

    fn max_partitions(&self) -> usize {
        self.options.max_partitions
    }

    fn embedded_archive(&mut self, kind: &'static str, bytes: &[u8]) -> io::Result<Handling> {
        if self.skip_declared_size(bytes.len() as u64) || !self.can_enter_child() {
            return Ok(Handling::Complete);
        }
        // A suffix is another map of the same input. Stock checks its size
        // and pushes its type, then charges only the newly extracted children.
        self.parents.push(Layer {
            file_type: kind,
            target: if kind == "CL_TYPE_MSEXE" {
                Target::Pe
            } else {
                Target::Generic
            },
            name: None,
            size: bytes.len(),
        });
        let result = embedded::contents(bytes, kind, self);
        self.parents.pop();
        result
    }

    fn mailbox_letters(&mut self, letters: &mut text::SavedLetters) -> io::Result<Handling> {
        // For ordinary text, each admitted letter costs one map and its exact decoded size.
        // A separately mapped script checks one more file slot and at most its input size.
        let mapped = self.options.scan_html
            && self.options.scan_normalized_script
            && self.options.map_normalized_script
            && letters.largest_script != 0;
        let bytes = letters.total + if mapped { letters.largest_script } else { 0 };
        let slots = letters.count + usize::from(mapped);
        let scan_remaining =
            unlimited_if_zero(self.options.max_scan_size).saturating_sub(self.bytes_scanned);
        if bytes > scan_remaining
            || letters.largest > self.max_file_size()
            || self.options.max_files != 0
                && self.options.max_files.saturating_sub(self.files_scanned) < slots
        {
            return Ok(Handling::Incomplete);
        }
        let mut winner = None;
        for _ in 0..letters.count {
            let Some(body) = letters.read(self)? else {
                return Ok(Handling::Incomplete);
            };
            self.visit(body.as_ref(), InputKind::MailboxLetter, None)?;
            let verdict = self.stopped.take().unwrap_or(Verdict::Miss);
            match verdict {
                Verdict::Miss => (),
                Verdict::Found(name) if winner.as_ref().is_none_or(|other| other == &name) => {
                    winner = Some(name)
                }
                _ => return Ok(Handling::Incomplete),
            }
        }
        Ok(if let Some(name) = winner {
            self.stopped = Some(Verdict::Found(name));
            Handling::Stopped
        } else {
            Handling::Complete
        })
    }

    fn read_child(&mut self, data: &mut dyn Read) -> io::Result<Option<Snapshot>> {
        if !self.can_enter_child() {
            return Ok(None);
        }
        let limit = self.remaining();
        let snapshot =
            Snapshot::read_bounded(data, self.temporary_directory, limit, &mut *self.check)?;
        if snapshot.is_none() {
            self.skip_declared_size(limit.saturating_add(1));
        }
        Ok(snapshot)
    }

    fn visit_snapshot(
        &mut self,
        snapshot: Snapshot,
        target: Option<Target>,
        name: Option<&[u8]>,
    ) -> io::Result<bool> {
        let kind = target.map_or(InputKind::File, InputKind::Normalized);
        snapshot.with_bytes(|bytes| self.visit(bytes, kind, name))?;
        Ok(self.stopped.is_some())
    }

    fn utf16_html(&mut self, bytes: &[u8]) -> io::Result<Handling> {
        if self.skip_declared_size((bytes.len() / 2) as u64) || !self.can_enter_child() {
            return Ok(Handling::Complete);
        }
        // Stock counts this buffer for recursion but hides normalized parents from signatures.
        self.normalized_depth += 1;
        let result = text::unicode_html(bytes, true, self);
        self.normalized_depth -= 1;
        result
    }

    fn child_bytes(&mut self, bytes: &[u8], name: Option<&[u8]>) -> io::Result<bool> {
        if !self.can_enter_child() {
            return Ok(false);
        }
        self.check()?;
        let limit = self.remaining();
        if bytes.len() as u64 > limit {
            self.skip_declared_size(limit.saturating_add(1));
            return Ok(false);
        }
        self.visit(bytes, InputKind::File, name)?;
        Ok(self.stopped.is_some())
    }

    fn script_view(&mut self, source: &[u8]) -> io::Result<bool> {
        let mapped = self.options.map_normalized_script;
        if mapped {
            // Normalization can only contract the input. Stock checks the resulting
            // size before count and recursion, without charging a second file.
            if source.len() as u64 > self.remaining() {
                let size = text::NormalizedText::new(source).size(self.check)?;
                if self.skip_declared_size(size) {
                    return Ok(false);
                }
            }
            if !self.can_enter_child() {
                return Ok(false);
            }
        }
        let view =
            text::NormalizedText::new(source).into_bytes(self.temporary_directory, self.check)?;
        let bytes = view.as_ref();
        let (owner, parents) = self
            .parents
            .split_last()
            .expect("view has an owning object");
        let context = ObjectContext::typed(Target::Ascii, bytes);
        let layer = Layer {
            target: Target::Ascii,
            file_type: "CL_TYPE_TEXT_ASCII",
            size: bytes.len(),
            name: owner.name.clone(),
        };
        let object = Object {
            bytes,
            context: &context,
            layer: &layer,
            parents: if mapped { &self.parents } else { parents },
            normalized: true,
            body_only: !mapped,
            handled_format: true,
        };
        let verdict = (self.matcher)(object, self.check)?;
        if verdict != Verdict::Miss {
            self.stopped = Some(verdict);
        }
        Ok(self.stopped.is_some())
    }

    fn check(&mut self) -> io::Result<()> {
        (self.check)()
    }

    fn remaining(&self) -> u64 {
        unlimited_if_zero(self.options.max_file_size)
            .min(unlimited_if_zero(self.options.max_scan_size).saturating_sub(self.bytes_scanned))
    }

    fn max_file_size(&self) -> u64 {
        unlimited_if_zero(self.options.max_file_size)
    }
    fn max_files(&self) -> usize {
        self.options.max_files
    }

    fn recorded_limit(&self) -> Option<Limit> {
        self.first_limit
    }

    fn record_file_limit(&mut self) {
        self.first_limit.get_or_insert(Limit::MaxFiles);
    }

    fn ole_directory_limit(&mut self, depth: usize, preceding_streams: usize) -> bool {
        let limit = if depth > self.recursion_limit() {
            Limit::MaxRecursion
        } else if self.options.max_files != 0
            && self.files_scanned.saturating_add(preceding_streams) > self.options.max_files
        {
            Limit::MaxFiles
        } else {
            return false;
        };
        self.first_limit.get_or_insert(limit);
        true
    }
    fn size_limit(&self, size: u64) -> Option<Limit> {
        if size > unlimited_if_zero(self.options.max_scan_size).saturating_sub(self.bytes_scanned) {
            Some(Limit::MaxScanSize)
        } else if size > self.max_file_size() {
            Some(Limit::MaxFileSize)
        } else {
            None
        }
    }
    fn skip_declared_size(&mut self, size: u64) -> bool {
        if let Some(reason) = self.size_limit(size) {
            self.first_limit.get_or_insert(reason);
            return true;
        }
        false
    }

    fn text_limits(&self) -> (u64, u64, u64) {
        (
            self.options.max_html_normalize,
            self.options.max_html_no_tags,
            self.options.max_script_normalize,
        )
    }
    fn temporary_directory(&self) -> &Path {
        self.temporary_directory
    }
}
