//! Evaluate logical signatures against the evidence from one stock scan object.
use super::byte_compare::ByteCompare;
use super::image_fuzzy;
use super::logic_expression::Expression;
use super::logical_pcre::{PcreLimits, RegexChild};
use super::search::{STOCK_WINDOW, SearchEvent};
use super::{ObjectContext, Offset, Pattern, Rule, SearchIndex, Target, invalid, level};
use crate::IgnoreSet;
use crate::objects::Layer;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::ops::RangeInclusive;
use std::path::Path;

const MAX_LINE: usize = 32768;
const MAX_CHILDREN: usize = 64;

/// File-map and container information used by the pinned logical matcher.
#[derive(Clone, Copy)]
pub struct LogicalObject<'a> {
    /// Ancestors of the owning object, from outermost to innermost.
    pub parents: &'a [Layer],
    /// Physical recursion depth, including normalized layers.
    pub recursion_level: usize,
    /// Active file map length. An unmapped view uses the owning map.
    pub file_size: usize,
    /// An in-memory script view has no generic relative-offset table.
    pub unmapped_script: bool,
    /// A mapped script also evaluates empty counts against its restored source map.
    pub mapped_source_size: Option<usize>,
}

struct Conditions {
    target: Target,
    attributes: Option<Box<ObjectConditions>>,
}

#[derive(Default)]
struct ObjectConditions {
    container: Option<&'static str>,
    intermediates: Box<[&'static str]>,
    size: Option<RangeInclusive<u32>>,
    entry_point: Option<RangeInclusive<u32>>,
    sections: Option<RangeInclusive<u32>>,
}

impl ObjectConditions {
    fn matches(range: &Option<RangeInclusive<u32>>, actual: Option<usize>) -> bool {
        range.as_ref().is_none_or(|range| {
            actual.is_some_and(|n| u32::try_from(n).is_ok_and(|n| range.contains(&n)))
        })
    }

    fn accepts(&self, context: &ObjectContext, object: &LogicalObject<'_>) -> bool {
        let mut ancestors = object
            .parents
            .iter()
            .rev()
            .filter(|p| !p.normalized)
            .map(|p| p.file_type);
        if self
            .container
            .is_some_and(|kind| ancestors.clone().next().unwrap_or("CL_TYPE_ANY") != kind)
            || self.intermediates.len() > object.recursion_level
        {
            return false;
        }
        // Stock counts ANY toward the minimum depth, without consuming a typed ancestor.
        for &kind in self.intermediates.iter().rev() {
            if kind != "CL_TYPE_ANY" && ancestors.next() != Some(kind) {
                return false;
            }
        }
        let (entry, sections) = context
            .executable_metadata()
            .map_or((None, None), |(entry, sections)| {
                (Some(entry), Some(sections))
            });
        Self::matches(&self.size, Some(object.file_size))
            && Self::matches(&self.entry_point, entry)
            && Self::matches(&self.sections, sections)
    }
}

impl Conditions {
    fn accepts(&self, context: &ObjectContext, object: &LogicalObject<'_>) -> bool {
        self.attributes
            .as_ref()
            .is_none_or(|a| a.accepts(context, object))
    }
}

struct LogicalRule {
    name: Box<str>,
    conditions: Conditions,
    expression: usize,
    children: usize,
}

struct ChildBinding {
    owner: u32,
    slot: u8,
}

#[derive(Default)]
struct Builder {
    records: Vec<LogicalRule>,
    children: Vec<Rule>,
    bindings: Vec<ChildBinding>,
    expressions: Vec<Expression>,
    expression_ids: HashMap<usize, HashMap<Box<str>, usize>>,
    zero_matches: Vec<u32>,
    byte_compares: HashMap<Target, Vec<(u32, ByteCompare)>>,
    images: HashMap<u64, Vec<ChildBinding>>,
    regexes: HashMap<u32, Box<[RegexChild]>>,
    zero_triggers: Vec<u32>,
}

/// Logical matcher for extended patterns, byte comparisons, image hashes, and PCRE.
pub struct LogicalIndex {
    records: Vec<LogicalRule>,
    children: Vec<Rule>,
    bindings: Vec<ChildBinding>,
    expressions: Vec<Expression>,
    zero_matches: Vec<u32>,
    byte_compares: HashMap<Target, Vec<(u32, ByteCompare)>>,
    images: HashMap<u64, Vec<ChildBinding>>,
    regexes: HashMap<u32, Box<[RegexChild]>>,
    zero_triggers: Vec<u32>,
    pcre_limits: PcreLimits,
    image_fuzzy_enabled: bool,
    search: SearchIndex,
}

impl LogicalIndex {
    pub fn load_with(
        paths: &[(&Path, bool)],
        flevel: u32,
        ignored: &IgnoreSet,
        mut open: impl FnMut(&Path) -> io::Result<File>,
    ) -> io::Result<Self> {
        let mut builder = Builder::default();
        for &(path, official) in paths {
            let file = open(path)
                .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
            let mut reader = BufReader::new(file);
            let mut line = String::new();
            for number in 1.. {
                line.clear();
                let located = |e: io::Error| {
                    io::Error::new(e.kind(), format!("{}:{number}: {e}", path.display()))
                };
                let n = reader
                    .by_ref()
                    .take((MAX_LINE + 1) as u64)
                    .read_line(&mut line)
                    .map_err(located)?;
                if n == 0 {
                    if number == 1 {
                        return Err(located(invalid("empty logical database")));
                    }
                    break;
                }
                if n > MAX_LINE {
                    return Err(located(invalid(
                        "logical database line exceeds 32768 bytes",
                    )));
                }
                if !line.starts_with('#') {
                    builder
                        .add(
                            line.trim_end_matches(['\r', '\n']),
                            official,
                            flevel,
                            ignored,
                        )
                        .map_err(located)?;
                }
            }
        }
        drop(builder.expression_ids);
        let search = SearchIndex::build(&builder.children)?;
        Ok(Self {
            records: builder.records,
            children: builder.children,
            bindings: builder.bindings,
            expressions: builder.expressions,
            zero_matches: builder.zero_matches,
            byte_compares: builder.byte_compares,
            images: builder.images,
            image_fuzzy_enabled: true,
            regexes: builder.regexes,
            zero_triggers: builder.zero_triggers,
            pcre_limits: PcreLimits::default(),
            search,
        })
    }

    /// Use the daemon's PCRE limits for this generation.
    pub fn with_pcre_limits(mut self, limits: PcreLimits) -> Self {
        self.pcre_limits = limits;
        self
    }

    /// Use the daemon's image fuzzy hash scan policy for this generation.
    pub fn with_image_fuzzy_hash(mut self, enabled: bool) -> Self {
        self.image_fuzzy_enabled = enabled;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn needs_normalized_script(&self) -> bool {
        self.records
            .iter()
            .any(|r| matches!(r.conditions.target, Target::Generic | Target::Ascii))
    }

    pub fn needs_normalized_script_map(&self) -> bool {
        self.children
            .iter()
            .any(|r| r.target == Target::Ascii && r.offset.is_relative())
    }

    /// Return the first eligible logical signature for this object.
    pub fn first_match_checked(
        &self,
        bytes: &[u8],
        context: &ObjectContext,
        object: LogicalObject<'_>,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<&str>> {
        let mut evidence: HashMap<u32, Evidence> = HashMap::new();
        self.search.run_events(
            &self.children,
            bytes,
            context,
            false,
            &mut check,
            &mut |event| {
                let hit = match event {
                    SearchEvent::Match(hit) => hit,
                    SearchEvent::EndWindow {
                        target,
                        bytes,
                        check,
                    } => {
                        if let Some(compares) = self.byte_compares.get(&target) {
                            for (i, (owner, compare)) in compares.iter().enumerate() {
                                if i % 256 == 0 {
                                    check()?;
                                }
                                let Some(e) = evidence.get_mut(owner) else {
                                    continue;
                                };
                                if e.counts
                                    .get(compare.trigger)
                                    .is_some_and(|&count| count != 0)
                                    && compare.matches(bytes, e.last[compare.trigger])
                                {
                                    e.counts[compare.slot] = e.counts[compare.slot].wrapping_add(1);
                                }
                            }
                        }
                        return Ok(());
                    }
                };
                let child = hit.rule_id as usize;
                let binding = &self.bindings[child];
                let record = &self.records[binding.owner as usize];
                if !record.conditions.accepts(context, &object)
                    || object.unmapped_script
                        && record.conditions.target == Target::Generic
                        && self.children[child].offset.is_relative()
                {
                    return Ok(());
                }
                let slot = usize::from(binding.slot);
                let e = evidence.entry(binding.owner).or_insert_with(|| Evidence {
                    counts: vec![0; record.children],
                    last: vec![0; record.children],
                });
                // Stock counts repeated multipart completions at the same first-part
                // position. It suppresses earlier positions for every subsignature.
                let partial = self.children[child].pattern.parts().len() > 1;
                if e.counts[slot] == 0
                    || hit.start > e.last[slot]
                    || partial && hit.start == e.last[slot]
                {
                    e.counts[slot] = e.counts[slot].wrapping_add(1);
                    e.last[slot] = hit.start;
                }
                Ok(())
            },
        )?;
        if self.image_fuzzy_enabled
            && context.target() == Target::Graphics
            && !self.images.is_empty()
            && let Some(hash) = image_fuzzy::hash(bytes, &mut check)?
            && let Some(bindings) = self.images.get(&hash)
        {
            for (i, binding) in bindings.iter().enumerate() {
                if i % 256 == 0 {
                    check()?;
                }
                let record = &self.records[binding.owner as usize];
                if context.accepts(record.conditions.target)
                    && record.conditions.accepts(context, &object)
                {
                    let entry = evidence.entry(binding.owner).or_insert_with(|| Evidence {
                        counts: vec![0; record.children],
                        last: vec![0; record.children],
                    });
                    entry.counts[usize::from(binding.slot)] = 1;
                }
            }
        }
        self.scan_regexes(bytes, context, &object, &mut evidence, &mut check)?;
        let first = self.evaluate(context, &object, &evidence, &mut check)?;
        if first.is_none()
            && let Some(size) = object.mapped_source_size
        {
            // cli_scanscript restores the source map after scanning the mapped view,
            // then checks the caller's initially empty logical counters.
            let restored = LogicalObject {
                file_size: size,
                recursion_level: object.recursion_level.saturating_sub(1),
                ..object
            };
            return self.evaluate(context, &restored, &HashMap::new(), &mut check);
        }
        Ok(first)
    }

    fn scan_regexes(
        &self,
        bytes: &[u8],
        context: &ObjectContext,
        object: &LogicalObject<'_>,
        evidence: &mut HashMap<u32, Evidence>,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let limits = self.pcre_limits;
        if self.regexes.is_empty()
            || limits.max_file_size != 0 && bytes.len() as u64 > limits.max_file_size
        {
            return Ok(());
        }
        let mut scratch = None;
        let mut scan = |id: u32, counts: &mut [u32]| -> io::Result<()> {
            let Some(children) = self.regexes.get(&id) else {
                return Ok(());
            };
            let conditions = &self.records[id as usize].conditions;
            if context.accepts(conditions.target) && conditions.accepts(context, object) {
                for child in children {
                    check()?;
                    if child.trigger.matches(counts) {
                        counts[child.slot] =
                            child.count(bytes, context, limits, &mut scratch, check)?;
                    }
                }
            }
            Ok(())
        };
        for (&id, e) in evidence.iter_mut() {
            scan(id, &mut e.counts)?;
        }
        for &id in &self.zero_triggers {
            if let std::collections::hash_map::Entry::Vacant(entry) = evidence.entry(id) {
                let mut zero = [0; MAX_CHILDREN];
                let counts = &mut zero[..self.records[id as usize].children];
                scan(id, counts)?;
                if counts.iter().any(|&n| n != 0) {
                    entry.insert(Evidence {
                        counts: counts.to_vec(),
                        last: Vec::new(),
                    });
                }
            }
        }
        Ok(())
    }

    fn evaluate(
        &self,
        context: &ObjectContext,
        object: &LogicalObject<'_>,
        evidence: &HashMap<u32, Evidence>,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<&str>> {
        // Each target's logical table is evaluated in load order after scanning.
        // The specific target precedes generic. Only touched records and those
        // known to pass with all-zero counts can win.
        let mut winner = None;
        let candidates = evidence.iter().map(|(&id, e)| (id, Some(e))).chain(
            self.zero_matches
                .iter()
                .filter(|id| !evidence.contains_key(id))
                .map(|&id| (id, None)),
        );
        for (n, (id, e)) in candidates.enumerate() {
            if n % 256 == 0 {
                check()?;
            }
            let rule = &self.records[id as usize];
            let key = (rule.conditions.target == Target::Generic, id);
            if winner.is_some_and(|earlier| earlier <= key)
                || !context.accepts(rule.conditions.target)
                || !rule.conditions.accepts(context, object)
            {
                continue;
            }
            if e.is_none_or(|e| self.expressions[rule.expression].matches(&e.counts)) {
                winner = Some(key);
            }
        }
        Ok(winner.map(|(_, id)| self.records[id as usize].name.as_ref()))
    }
}

struct Evidence {
    counts: Vec<u32>,
    last: Vec<usize>,
}

impl Builder {
    fn add(
        &mut self,
        line: &str,
        official: bool,
        flevel: u32,
        ignored: &IgnoreSet,
    ) -> io::Result<()> {
        let mut fields = line.splitn(4, ';');
        let name = fields.next().unwrap_or_default();
        let title = fields
            .next()
            .ok_or_else(|| invalid("missing target description"))?;
        let logic = fields
            .next()
            .ok_or_else(|| invalid("missing logical expression"))?;
        let text = fields
            .next()
            .ok_or_else(|| invalid("missing logical subsignatures"))?;
        if ignored.matches(name, line) {
            return Ok(());
        }
        // The stock LDB tokenizer permits semicolons between the two PCRE slashes.
        // Preserve the true arity when diagnosing an unsupported child or filtering Engine.
        let mut in_regex = false;
        let mut previous = ';';
        let fields = text.split(move |ch| {
            if ch == '/' && previous != '\\' {
                in_regex = !in_regex;
            }
            previous = ch;
            ch == ';' && !in_regex
        });
        let children = fields.clone().count();
        if children > MAX_CHILDREN {
            return Err(invalid("logical signature exceeds 64 subsignatures"));
        }
        let ids = self.expression_ids.entry(children).or_default();
        let expression = if let Some(&id) = ids.get(logic) {
            id
        } else {
            let id = self.expressions.len();
            self.expressions.push(Expression::parse(logic, children)?);
            ids.insert(logic.into(), id);
            id
        };
        let Some(conditions) = parse_title(title, flevel)? else {
            return Ok(());
        };
        let source_name = name.split_once(" (Clam)").map_or(name, |(name, _)| name);
        if source_name.is_empty() || source_name.chars().any(char::is_control) {
            return Err(invalid(
                "empty or control-containing logical signature name",
            ));
        }
        let name = if official {
            source_name.into()
        } else {
            format!("{source_name}.UNOFFICIAL").into_boxed_str()
        };
        let id = u32::try_from(self.records.len())
            .map_err(|_| invalid("too many logical signatures"))?;
        let mut regexes = Vec::new();
        for (i, field) in fields.enumerate() {
            let located = |e: io::Error| io::Error::new(e.kind(), format!("subsignature {i}: {e}"));
            if field.contains('/') {
                regexes.push(RegexChild::parse(field, conditions.target, i).map_err(located)?);
                continue;
            }
            if field.starts_with("fuzzy_img#") {
                let hash = image_fuzzy::parse(field).map_err(located)?;
                self.images.entry(hash).or_default().push(ChildBinding {
                    owner: id,
                    slot: i as u8,
                });
                continue;
            }
            if field.contains('#') && field.starts_with(|c: char| c.is_ascii_digit()) {
                let compare = ByteCompare::parse(field, i).map_err(located)?;
                self.byte_compares
                    .entry(conditions.target)
                    .or_default()
                    .push((id, compare));
                continue;
            }
            let variants = parse_child(field, conditions.target).map_err(located)?;
            for rule in variants.into_iter().flatten() {
                if self.children.len() >= u32::MAX as usize {
                    return Err(invalid("too many logical subsignatures"));
                }
                self.children.push(rule);
                self.bindings.push(ChildBinding {
                    owner: id,
                    slot: i as u8,
                });
            }
        }
        let zero = &[0; MAX_CHILDREN][..children];
        if !regexes.is_empty() {
            if regexes.iter().any(|child| child.trigger.matches(zero)) {
                self.zero_triggers.push(id);
            }
            self.regexes.insert(id, regexes.into_boxed_slice());
        }
        if self.expressions[expression].matches(zero) {
            self.zero_matches.push(id);
        }
        self.records.push(LogicalRule {
            name,
            conditions,
            expression,
            children,
        });
        Ok(())
    }
}

fn range(text: &str) -> io::Result<RangeInclusive<u32>> {
    let (min, max) = text
        .split_once('-')
        .ok_or_else(|| invalid("expected a minimum-maximum range"))?;
    Ok(level(min)?..=level(max)?)
}

fn parse_title(title: &str, flevel: u32) -> io::Result<Option<Conditions>> {
    let mut engine = None;
    let mut target = None;
    let mut file = ObjectConditions::default();
    let mut container = None;
    let mut intermediates = None;
    for (i, field) in title.split(',').enumerate() {
        let (key, value) = field
            .split_once(':')
            .ok_or_else(|| invalid("malformed logical target description"))?;
        match key {
            "Engine" if i == 0 => engine = Some(range(value)?),
            "Engine" => return Err(invalid("Engine must be the first logical target field")),
            "Target" => {
                level(value).map_err(|_| invalid("invalid logical Target number"))?;
                target = Some(value);
            }
            "FileSize" => file.size = Some(range(value)?),
            "EntryPoint" => file.entry_point = Some(range(value)?),
            "NumberOfSections" => file.sections = Some(range(value)?),
            "Container" => container = Some(value),
            "Intermediates" => intermediates = Some(value),
            _ if engine.as_ref().is_some_and(|r| !r.contains(&flevel)) => return Ok(None),
            _ => return Err(invalid(format!("unsupported logical target field {key}"))),
        }
    }
    let executable = file.entry_point.is_some() || file.sections.is_some();
    let constrained =
        file.size.is_some() || executable || container.is_some() || intermediates.is_some();
    if constrained && engine.as_ref().is_none_or(|r| *r.start() < 51) {
        return Err(invalid(
            "logical target attributes require an Engine minimum of at least 51",
        ));
    }
    if engine.as_ref().is_some_and(|r| !r.contains(&flevel)) {
        return Ok(None);
    }
    let target = target.ok_or_else(|| invalid("missing logical signature Target"))?;
    let target = Target::parse(target)?;
    if executable && !target.executable() {
        return Err(invalid(
            "EntryPoint and NumberOfSections require an executable Target",
        ));
    }
    let file_type = |value: &str, field: &str| {
        CONTAINERS
            .iter()
            .copied()
            .find(|&kind| kind == value)
            .ok_or_else(|| invalid(format!("unsupported {field} type {value}")))
    };
    file.container = container
        .map(|value| file_type(value, "Container"))
        .transpose()?;
    if let Some(value) = intermediates {
        // The pinned parser reads at most 16 tokens from an Intermediates field.
        file.intermediates = value
            .split('>')
            .take(16)
            .map(|kind| file_type(kind, "Intermediates"))
            .collect::<io::Result<_>>()?;
    }
    Ok(Some(Conditions {
        target,
        attributes: constrained.then(|| Box::new(file)),
    }))
}

#[derive(Default)]
struct Modifiers {
    ascii: bool,
    wide: bool,
    nocase: bool,
    fullword: bool,
}

impl Modifiers {
    fn parse(text: &str) -> io::Result<Self> {
        let mut flags = Self::default();
        for flag in text.bytes() {
            match flag {
                b'a' => flags.ascii = true,
                b'w' => flags.wide = true,
                b'i' => flags.nocase = true,
                b'f' => flags.fullword = true,
                _ => return Err(invalid("unsupported subsignature modifier")),
            }
        }
        Ok(flags)
    }
}

fn parse_child(field: &str, target: Target) -> io::Result<[Option<Rule>; 2]> {
    if field.starts_with('$') {
        return Err(invalid("unsupported macro subsignature"));
    }
    if field.contains('#') {
        return Err(invalid("unsupported fuzzy hash subsignature"));
    }
    let (field, modifiers) = match field.split_once("::") {
        // Stock uses the unmodified pattern when a second modifier delimiter is present.
        Some((field, flags)) if flags.contains("::") => (field, Modifiers::default()),
        Some((field, flags)) => {
            if field.contains("!(") {
                return Err(invalid("modifiers on negated alternatives are unsupported"));
            }
            (field, Modifiers::parse(flags)?)
        }
        None => (field, Modifiers::default()),
    };
    let (position, body) = field.split_once(':').unwrap_or(("*", field));
    let offset = Offset::parse(position, target)?;
    let mut variants = [None, None];
    for (i, wide) in [false, true].into_iter().enumerate() {
        if (wide && !modifiers.wide) || (!wide && modifiers.wide && !modifiers.ascii) {
            continue;
        }
        let pattern = Pattern::compile_modified(body, wide, modifiers.nocase, modifiers.fullword)?;
        if pattern
            .parts()
            .iter()
            .any(|part| part.max_span() >= STOCK_WINDOW)
        {
            return Err(invalid("subsignature exceeds the reference scan window"));
        }
        // Stock compiles ordinary logical subsignatures in its AC root, including literals.
        variants[i] = Some(Rule {
            name: "".into(),
            target,
            offset,
            pattern,
            bm_prefix: None,
        });
    }
    Ok(variants)
}

// Names accepted by cli_ftcode in the pinned engine.
const CONTAINERS: &[&str] = &[
    "CL_TYPE_TEXT_ASCII",
    "CL_TYPE_TEXT_UTF8",
    "CL_TYPE_TEXT_UTF16LE",
    "CL_TYPE_TEXT_UTF16BE",
    "CL_TYPE_BINARY_DATA",
    "CL_TYPE_IGNORED",
    "CL_TYPE_ANY",
    "CL_TYPE_MSEXE",
    "CL_TYPE_ELF",
    "CL_TYPE_MACHO",
    "CL_TYPE_MACHO_UNIBIN",
    "CL_TYPE_POSIX_TAR",
    "CL_TYPE_OLD_TAR",
    "CL_TYPE_CPIO_OLD",
    "CL_TYPE_CPIO_ODC",
    "CL_TYPE_CPIO_NEWC",
    "CL_TYPE_CPIO_CRC",
    "CL_TYPE_GZ",
    "CL_TYPE_ZIP",
    "CL_TYPE_BZ",
    "CL_TYPE_RAR",
    "CL_TYPE_ARJ",
    "CL_TYPE_MSSZDD",
    "CL_TYPE_MSOLE2",
    "CL_TYPE_MSCAB",
    "CL_TYPE_MSCHM",
    "CL_TYPE_SIS",
    "CL_TYPE_SCRENC",
    "CL_TYPE_GRAPHICS",
    "CL_TYPE_GIF",
    "CL_TYPE_PNG",
    "CL_TYPE_JPEG",
    "CL_TYPE_TIFF",
    "CL_TYPE_RIFF",
    "CL_TYPE_BINHEX",
    "CL_TYPE_TNEF",
    "CL_TYPE_CRYPTFF",
    "CL_TYPE_PDF",
    "CL_TYPE_UUENCODED",
    "CL_TYPE_HTML_UTF16",
    "CL_TYPE_SCRIPT",
    "CL_TYPE_RTF",
    "CL_TYPE_HTML",
    "CL_TYPE_MAIL",
    "CL_TYPE_SFX",
    "CL_TYPE_ZIPSFX",
    "CL_TYPE_RARSFX",
    "CL_TYPE_CABSFX",
    "CL_TYPE_ARJSFX",
    "CL_TYPE_NULSFT",
    "CL_TYPE_AUTOIT",
    "CL_TYPE_ISHIELD_MSI",
    "CL_TYPE_7Z",
    "CL_TYPE_7ZSFX",
    "CL_TYPE_SWF",
    "CL_TYPE_ISO9660",
    "CL_TYPE_JAVA",
    "CL_TYPE_DMG",
    "CL_TYPE_MBR",
    "CL_TYPE_GPT",
    "CL_TYPE_APM",
    "CL_TYPE_XAR",
    "CL_TYPE_PART_ANY",
    "CL_TYPE_PART_HFSPLUS",
    "CL_TYPE_XZ",
    "CL_TYPE_OOXML_WORD",
    "CL_TYPE_OOXML_PPT",
    "CL_TYPE_OOXML_XL",
    "CL_TYPE_INTERNAL",
    "CL_TYPE_XDP",
    "CL_TYPE_XML_WORD",
    "CL_TYPE_XML_XL",
    "CL_TYPE_HWP3",
    "CL_TYPE_XML_HWP",
    "CL_TYPE_HWPOLE2",
    "CL_TYPE_OOXML_HWP",
    "CL_TYPE_PS",
    "CL_TYPE_MHTML",
    "CL_TYPE_LNK",
    "CL_TYPE_EGG",
    "CL_TYPE_EGGSFX",
    "CL_TYPE_UDF",
    "CL_TYPE_ALZ",
    "CL_TYPE_ONENOTE",
    "CL_TYPE_PYTHON_COMPILED",
    "CL_TYPE_LHA_LZH",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn load(text: &str) -> io::Result<LogicalIndex> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sample.ldb");
        std::fs::write(&path, text)?;
        LogicalIndex::load_with(&[(&path, true)], 213, &IgnoreSet::default(), |p| {
            File::open(p)
        })
    }

    #[test]
    fn counts_and_target_precedence_are_local_to_each_object() -> io::Result<()> {
        let index = load(concat!(
            "Generic;Target:0;0;68656164\n",
            "Missing;Target:7;0=0;7461696c\n",
            "Multiple;Target:7;0=2;68656164*7461696c\n",
            "Other;Target:7;0;7461696c\n",
        ))?;
        for (bytes, target, expected) in [
            (b"head tail tail".as_slice(), Target::Ascii, "Multiple"),
            (b"other text".as_slice(), Target::Ascii, "Missing"),
            (b"head tail".as_slice(), Target::Ascii, "Other"),
            (b"head".as_slice(), Target::Pdf, "Generic"),
        ] {
            assert_eq!(
                index.first_match_checked(
                    bytes,
                    &ObjectContext::typed(target, bytes),
                    LogicalObject {
                        parents: &[],
                        recursion_level: 0,
                        file_size: bytes.len(),
                        unmapped_script: false,
                        mapped_source_size: None,
                    },
                    || Ok(())
                )?,
                Some(expected)
            );
        }
        Ok(())
    }

    #[test]
    fn top_level_container_and_file_map_size() -> io::Result<()> {
        let index = load(concat!(
            "Top;Engine:51-255,Target:7,Container:CL_TYPE_ANY,FileSize:20-21;0;6d61726b\n",
            "Member;Engine:51-255,Target:7,Container:CL_TYPE_ZIP;0;6d61726b\n",
        ))?;
        let bytes = b"mark";
        let context = ObjectContext::typed(Target::Ascii, bytes);
        for (parent, size, expected) in [
            (None, 20, Some("Top")),
            (None, 21, Some("Top")),
            (None, 19, None),
            (Some("CL_TYPE_ZIP"), 20, Some("Member")),
            (Some("CL_TYPE_GZ"), 20, None),
        ] {
            let layers = parent.map(|file_type| Layer {
                file_type,
                target: Target::Generic,
                size,
                name: None,
                normalized: false,
            });
            assert_eq!(
                index.first_match_checked(
                    bytes,
                    &context,
                    LogicalObject {
                        parents: layers.as_slice(),
                        recursion_level: layers.as_slice().len(),
                        file_size: size,
                        unmapped_script: false,
                        mapped_source_size: None,
                    },
                    || Ok(())
                )?,
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_or_unsupported_active_rules_have_located_errors() -> io::Result<()> {
        let skipped = "Future;Engine:214-255,Target:0;0;0/read/i\n";
        assert!(load(skipped)?.is_empty());
        for (rule, reason) in [
            ("Current;Target:0;1;6d61726b;0/read/j", "PCRE option"),
            (
                "Current;Target:0;0&1;6d61726b;0/r(ead;file/i",
                "PCRE2 compile error",
            ),
            (
                "Current;Engine:51-255,Target:0,HandlerType:CL_TYPE_MAIL;0;6d61726b",
                "HandlerType",
            ),
            (
                "Current;Target:0;0;616263!(64|65)666768::a",
                "negated alternatives",
            ),
            ("Current;Engine:81-255,Target:0;0;6d61726b::x", "modifier"),
            ("Current;Target:0,FileSize:4-4;0;6d61726b", "Engine minimum"),
            (
                "Current;Engine:51-255,Target:0,EntryPoint:0-0;0;6d61726b",
                "executable Target",
            ),
            (
                "Current;Engine:50-255,Target:1,NumberOfSections:1-1;0;6d61726b",
                "Engine minimum",
            ),
        ] {
            let error = load(&format!("{skipped}{rule}\n"))
                .err()
                .expect("unsupported active rule");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("sample.ldb:2:"));
            assert!(error.to_string().contains(reason), "{error}");
        }
        Ok(())
    }
}
