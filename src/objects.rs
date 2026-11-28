//! Object traversal for one scan against one immutable database generation.
use crate::body::{HandlerType, LogicalObject, ObjectContext, Target};
use crate::bytecode::{PdfHookContext, PdfHookResult, Program};
use md5::{Digest, Md5};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PdfHookControl {
    Continue,
    Break,
    Found,
}

/// Scan-time settings for the generation's PDF bytecode programs.
#[derive(Clone, Copy)]
pub struct PdfHooks<'a> {
    pub programs: &'a [Program],
    pub debug: bool,
    pub timeout: Duration,
}

/// Scan-time settings for conditioned PE hooks in database order.
#[derive(Clone, Copy)]
pub struct PeHooks<'a> {
    pub programs: &'a [(u32, Program)],
    pub debug: bool,
    pub timeout: Duration,
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
    fn normalized_file(&mut self, data: &mut dyn Read) -> io::Result<bool>;
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
    fn pdf_hooks_enabled(&self) -> bool;
    fn run_pdf_hooks(
        &mut self,
        input: &[u8],
        context: PdfHookContext<'_>,
    ) -> io::Result<PdfHookControl>;
    fn run_pe_all_hooks(&mut self, bytes: &[u8]) -> io::Result<Handling>;

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
    fn check_partition_intersections(&self) -> bool;
    fn report_heuristic(&mut self, name: &str) -> bool;
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
    pub alert_partition_intersection: bool,
    pub alert_encrypted_doc: bool,
    pub heuristic_alerts: bool,
    pub heuristic_scan_precedence: bool,
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
            alert_partition_intersection: false,
            alert_encrypted_doc: false,
            heuristic_alerts: true,
            heuristic_scan_precedence: false,
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
    /// Stock hides this layer when matching container types.
    pub normalized: bool,
    pub file_type: &'static str,
    pub target: Target,
    pub name: Option<Box<[u8]>>,
    pub size: usize,
}

impl Layer {
    // Remove the current logical object, including any normalized copies of it.
    fn logical_parents(stack: &[Layer]) -> &[Layer] {
        let current = stack
            .iter()
            .rposition(|layer| !layer.normalized)
            .unwrap_or(0);
        &stack[..current]
    }
}

pub struct Object<'a> {
    pub bytes: &'a [u8],
    pub context: &'a ObjectContext,
    pub parents: &'a [Layer],
    pub layer: &'a Layer,
    pub normalized: bool,
    pub body_only: bool,
    /// This scan stage supplies the digest used by stock file-type rules.
    pub logical_rescan: bool,
    pub logical: LogicalObject<'a>,
    pub handled_format: bool,
    /// Matching PE prefilters belong to this map until its PE hook runs.
    pub pe_hook_hits: Option<&'a mut Vec<u32>>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Verdict {
    Found(String),
    /// Run logical file-type rules before reporting the next ordinary finding.
    Handlers {
        rules: Vec<(Result<Option<String>, String>, HandlerType)>,
        finding: Result<Option<String>, String>,
    },
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
    deferred_heuristic: Option<Verdict>,
    last_handler_hash: [u8; 16],
    pdf_hooks: Option<PdfHooks<'a>>,
    pe_hooks: Option<PeHooks<'a>>,
    pe_hook_hits: Vec<u32>,
    matcher: &'a mut Matcher<'a>,
    check: &'a mut dyn FnMut() -> io::Result<()>,
}

#[derive(Clone, Copy, PartialEq)]
enum InputKind {
    File,
    MailboxLetter,
    Normalized(Target),
    Partition,
    Handler(HandlerType),
}

pub fn scan(
    bytes: &[u8],
    options: &Options,
    temporary_directory: &Path,
    matcher: impl FnMut(Object<'_>, &mut dyn FnMut() -> io::Result<()>) -> io::Result<Verdict>,
    check: impl FnMut() -> io::Result<()>,
) -> io::Result<Verdict> {
    scan_with_hooks(
        bytes,
        options,
        temporary_directory,
        None,
        None,
        matcher,
        check,
    )
}

/// Scan objects with PDF bytecode hooks.
pub fn scan_with_pdf_hooks(
    bytes: &[u8],
    options: &Options,
    temporary_directory: &Path,
    pdf_hooks: Option<PdfHooks<'_>>,
    matcher: impl FnMut(Object<'_>, &mut dyn FnMut() -> io::Result<()>) -> io::Result<Verdict>,
    check: impl FnMut() -> io::Result<()>,
) -> io::Result<Verdict> {
    scan_with_hooks(
        bytes,
        options,
        temporary_directory,
        pdf_hooks,
        None,
        matcher,
        check,
    )
}

/// Scan objects with the bytecode hooks from the same database generation.
pub fn scan_with_hooks(
    bytes: &[u8],
    options: &Options,
    temporary_directory: &Path,
    pdf_hooks: Option<PdfHooks<'_>>,
    pe_hooks: Option<PeHooks<'_>>,
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
        deferred_heuristic: None,
        last_handler_hash: [0; 16],
        pdf_hooks,
        pe_hooks,
        pe_hook_hits: Vec::new(),
        matcher: &mut matcher,
        check: &mut check,
    };
    walk.visit(bytes, InputKind::File, None, false)?;
    Ok(walk.stopped.unwrap_or_else(|| {
        match (
            walk.deferred_heuristic,
            walk.first_limit.filter(|_| options.alert_exceeds_max),
        ) {
            // Pinned daemons can select either name among distinct deferred alerts.
            (Some(_), Some(_)) => Verdict::Incomplete,
            (Some(alert), None) => alert,
            (None, Some(limit)) => Verdict::Found(limit.signature()),
            (None, None) => Verdict::Miss,
        }
    }))
}

impl Traversal<'_> {
    fn recursion_limit(&self) -> usize {
        match self.options.max_recursion {
            0 => 17,
            value => value,
        }
    }

    fn visit(
        &mut self,
        bytes: &[u8],
        kind: InputKind,
        name: Option<&[u8]>,
        normalized: bool,
    ) -> io::Result<()> {
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
        let parent_hook_hits = std::mem::take(&mut self.pe_hook_hits);
        self.parents.push(Layer {
            normalized,
            target: file_type.context.target(),
            file_type: file_type.name,
            size: bytes.len(),
            name: name.map(Into::into),
        });
        let handling = file_type.parser.before_raw(bytes, self.options, self)?;
        if handling == Handling::Incomplete {
            self.stopped = Some(Verdict::Incomplete);
        }
        let mut recheck_without_digest = false;
        if self.stopped.is_none()
            && (!matches!(file_type.parser, classify::Parser::Html { .. })
                || !self.options.scan_html)
        {
            let normalized = matches!(kind, InputKind::Normalized(_));
            recheck_without_digest = self.match_layer(
                bytes,
                &file_type.context,
                normalized,
                handling == Handling::Complete,
                !normalized,
            )?;
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
            // Stock's final binary pass checks the same map with no reference digest.
            if recheck_without_digest
                && file_type.name == "CL_TYPE_BINARY_DATA"
                && self.stopped.is_none()
            {
                let context = ObjectContext::typed(Target::Other, bytes);
                self.match_layer(bytes, &context, false, true, false)?;
            }
        }
        self.parents.pop();
        self.pe_hook_hits = parent_hook_hits;
        Ok(())
    }

    fn match_layer(
        &mut self,
        bytes: &[u8],
        context: &ObjectContext,
        normalized: bool,
        handled_format: bool,
        logical_rescan: bool,
    ) -> io::Result<bool> {
        let (layer, parents) = self.parents.split_last().expect("current layer");
        let object = Object {
            bytes,
            context,
            layer,
            parents,
            normalized,
            body_only: false,
            logical_rescan,
            logical: LogicalObject {
                parents: Layer::logical_parents(&self.parents),
                recursion_level: parents.len() + self.normalized_depth,
                file_size: bytes.len(),
                unmapped_script: false,
                script_source: None,
            },
            handled_format,
            pe_hook_hits: (self.pe_hooks.is_some() && !normalized && context.is_valid_pe())
                .then_some(&mut self.pe_hook_hits),
        };
        let verdict = (self.matcher)(object, self.check)?;
        self.apply_verdict(bytes, verdict)
    }

    // Return whether a later stage on the same map may need to retry without a digest.
    fn apply_verdict(&mut self, bytes: &[u8], verdict: Verdict) -> io::Result<bool> {
        match verdict {
            Verdict::Handlers { rules, finding } => {
                let unsupported = |message| io::Error::new(io::ErrorKind::Unsupported, message);
                let mut md5 = Md5::new();
                for block in bytes.chunks(64 << 10) {
                    self.check()?;
                    md5.update(block);
                }
                let hash: [u8; 16] = md5.finalize().into();
                for (name, kind) in rules {
                    if self.last_handler_hash == hash {
                        if let Some(name) = name.map_err(unsupported)? {
                            self.stopped = Some(Verdict::Found(name));
                            return Ok(false);
                        }
                        continue;
                    }
                    self.last_handler_hash = hash;
                    let limit = (self.parents.len() + self.normalized_depth
                        >= self.recursion_limit())
                    .then_some(Limit::MaxRecursion)
                    .or_else(|| self.child_limit())
                    .or_else(|| self.size_limit(bytes.len() as u64));
                    if let Some(limit) = limit {
                        self.first_limit.get_or_insert(limit);
                        return Ok(true);
                    }
                    let filename = self.parents.last().and_then(|p| p.name.clone());
                    self.visit(bytes, InputKind::Handler(kind), filename.as_deref(), false)?;
                    if self.stopped.is_some() {
                        return Ok(false);
                    }
                }
                self.stopped = finding.map_err(unsupported)?.map(Verdict::Found);
                return Ok(true);
            }
            Verdict::Miss => (),
            other => self.stopped = Some(other),
        }
        Ok(false)
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

    fn report_hook_detection(&mut self, name: &str) -> bool {
        if name.starts_with("BC.Heuristics") {
            return self.report_heuristic(name);
        }
        self.stopped = Some(Verdict::Found(name.to_owned()));
        true
    }
}

impl ChildSink for Traversal<'_> {
    fn pdf_hooks_enabled(&self) -> bool {
        self.pdf_hooks
            .is_some_and(|hooks| !hooks.programs.is_empty())
    }

    fn run_pdf_hooks(
        &mut self,
        input: &[u8],
        context: PdfHookContext<'_>,
    ) -> io::Result<PdfHookControl> {
        let mut control = PdfHookControl::Continue;
        if let Some(hooks) = self.pdf_hooks {
            for program in hooks.programs {
                match program.run_pdf(
                    input,
                    context,
                    hooks.debug,
                    hooks.timeout,
                    &mut *self.check,
                )? {
                    PdfHookResult::Found(name) if self.report_hook_detection(name) => {
                        return Ok(PdfHookControl::Found);
                    }
                    PdfHookResult::Found(_) | PdfHookResult::Continue => (),
                    PdfHookResult::Break => control = PdfHookControl::Break,
                }
            }
        }
        Ok(control)
    }

    fn run_pe_all_hooks(&mut self, bytes: &[u8]) -> io::Result<Handling> {
        let Some(hooks) = self.pe_hooks.filter(|_| !self.pe_hook_hits.is_empty()) else {
            return Ok(Handling::Unrecognized);
        };
        if !classify::pe32_optional_header(bytes) {
            return Ok(Handling::Unrecognized);
        }
        self.pe_hook_hits.sort_unstable();
        for (id, program) in hooks.programs {
            if self.pe_hook_hits.binary_search(id).is_err() {
                continue;
            }
            if let PdfHookResult::Found(name) =
                program.run_pe_all(bytes, hooks.debug, hooks.timeout, &mut *self.check)?
                && self.report_hook_detection(name)
            {
                return Ok(Handling::Stopped);
            }
        }
        Ok(Handling::Complete)
    }

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
            normalized: false,
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
            logical_rescan: false,
            logical: LogicalObject {
                parents: &self.parents,
                recursion_level: self.parents.len() + self.normalized_depth,
                file_size: bytes.len(),
                unmapped_script: false,
                script_source: None,
            },
            handled_format: true,
            pe_hook_hits: None,
        };
        let verdict = (self.matcher)(object, self.check)?;
        self.apply_verdict(bytes, verdict)?;
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
        self.visit(bytes, InputKind::Partition, name, false)?;
        Ok(self.stopped.is_some())
    }

    fn max_partitions(&self) -> usize {
        self.options.max_partitions
    }

    fn check_partition_intersections(&self) -> bool {
        self.options.alert_partition_intersection
    }

    fn report_heuristic(&mut self, name: &str) -> bool {
        if self.options.heuristic_scan_precedence {
            self.stopped = Some(Verdict::Found(name.to_owned()));
            true
        } else {
            match &self.deferred_heuristic {
                None => self.deferred_heuristic = Some(Verdict::Found(name.to_owned())),
                Some(Verdict::Found(existing)) if existing != name => {
                    self.deferred_heuristic = Some(Verdict::Incomplete)
                }
                _ => (),
            }
            false
        }
    }

    fn embedded_archive(&mut self, kind: &'static str, bytes: &[u8]) -> io::Result<Handling> {
        if self.skip_declared_size(bytes.len() as u64) || !self.can_enter_child() {
            return Ok(Handling::Complete);
        }
        // A suffix is another map of the same input. Stock checks its size
        // and pushes its type, then charges only the newly extracted children.
        self.parents.push(Layer {
            normalized: false,
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
            self.visit(body.as_ref(), InputKind::MailboxLetter, None, false)?;
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
        snapshot.with_bytes(|bytes| self.visit(bytes, kind, name, target.is_some()))?;
        Ok(self.stopped.is_some())
    }

    fn normalized_file(&mut self, data: &mut dyn Read) -> io::Result<bool> {
        if let Some(snapshot) = self.read_child(data)? {
            snapshot.with_bytes(|bytes| self.visit(bytes, InputKind::File, None, true))?;
        }
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
        self.visit(bytes, InputKind::File, name, false)?;
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
            normalized: true,
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
            logical_rescan: false,
            logical: LogicalObject {
                parents: Layer::logical_parents(&self.parents),
                recursion_level: parents.len() + self.normalized_depth + usize::from(mapped),
                file_size: if mapped { bytes.len() } else { owner.size },
                unmapped_script: !mapped,
                script_source: Some(source),
            },
            handled_format: true,
            pe_hook_hits: None,
        };
        let verdict = (self.matcher)(object, self.check)?;
        self.apply_verdict(bytes, verdict)?;
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
