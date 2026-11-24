//! Body-signature evidence on one immutable object. A miss leaves its scan incomplete.
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use crate::IgnoreSet;
use pattern::Pattern;
use search::SearchIndex;

mod pattern;
mod search;
mod target;
pub use target::{ObjectContext, Offset, Target};

const FILEBUFF: usize = 8192;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Counts refer to records. One active record may use several features.
#[derive(Default, Debug)]
pub struct BodyInventory {
    pub path: PathBuf,
    pub records: usize,
    pub active: usize,
    pub skipped_flevel: usize,
    pub skipped_ignored: usize,
    pub targets: BTreeMap<u8, usize>,
    pub offsets: BTreeMap<&'static str, usize>,
    pub features: BTreeMap<&'static str, usize>,
}

struct Rule {
    name: Box<str>,
    target: Target,
    offset: Offset,
    pattern: Pattern,
    bm_prefix: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyMatch {
    pub rule_id: u32,
    /// Byte offset relative to this object, excluding bracket flanks.
    pub start: usize,
    /// Exclusive byte offset.
    pub end: usize,
}

pub struct BodyIndex {
    pub inventory: Vec<BodyInventory>,
    rules: Vec<Rule>,
    search: SearchIndex,
}

impl BodyIndex {
    /// Compile .ndb sources in stock load order. The boolean identifies official signatures.
    pub fn load_sources(
        paths: &[(&Path, bool)],
        flevel: u32,
        ignored: &IgnoreSet,
    ) -> io::Result<Self> {
        Self::load_with(paths, flevel, ignored, |path| File::open(path))
    }

    /// Open one database at a time. Callers can unlink private snapshots after opening them.
    pub fn load_with(
        paths: &[(&Path, bool)],
        flevel: u32,
        ignored: &IgnoreSet,
        mut open: impl FnMut(&Path) -> io::Result<File>,
    ) -> io::Result<Self> {
        let mut rules = Vec::new();
        let mut inventory = Vec::with_capacity(paths.len());
        // Stock balances its static matcher prefixes separately for generic and PE roots.
        let mut occupied = [HashSet::new(), HashSet::new()];
        for &(path, official) in paths {
            let mut stats = BodyInventory {
                path: path.to_owned(),
                ..Default::default()
            };
            let file = open(path)
                .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
            let mut input = BufReader::new(file);
            let mut line = String::new();
            let mut number = 0;
            loop {
                number += 1;
                line.clear();
                let located = |e: io::Error| {
                    io::Error::new(e.kind(), format!("{}:{number}: {e}", path.display()))
                };
                let n = input
                    .by_ref()
                    .take(FILEBUFF as u64)
                    .read_line(&mut line)
                    .map_err(located)?;
                if n == 0 {
                    break;
                }
                if n == FILEBUFF {
                    return Err(located(invalid("body database line exceeds 8191 bytes")));
                }
                let line = line.trim_end_matches(['\r', '\n']);
                if line.starts_with('#') {
                    continue;
                }
                let rule = parse_record(line, official, flevel, ignored, &mut stats, &mut occupied)
                    .map_err(located)?;
                if let Some(rule) = rule {
                    u32::try_from(rules.len())
                        .map_err(|_| located(invalid("too many body rules")))?;
                    rules.push(rule);
                }
            }
            if number == 1 {
                return Err(invalid(format!("{}: empty body database", path.display())));
            }
            inventory.push(stats);
        }
        drop(occupied);
        let search = SearchIndex::build(&rules)?;
        Ok(Self {
            rules,
            search,
            inventory,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// A normalized text view can match generic and ASCII body rules.
    pub fn needs_normalized_script(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| matches!(rule.target, Target::Generic | Target::Ascii))
    }

    /// The pinned script scanner maps its normalized output when target 7 needs relative offsets.
    pub fn needs_normalized_script_map(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.target == Target::Ascii && rule.offset.is_relative())
    }
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
    pub fn name(&self, id: u32) -> &str {
        &self.rules[id as usize].name
    }

    /// Emit each rule occurrence using the pinned matcher's offsets. Counts can be
    /// accumulated by rule ID without allocating one result per match.
    pub fn scan(
        &self,
        input: &[u8],
        context: &ObjectContext,
        mut emit: impl FnMut(BodyMatch),
    ) -> io::Result<()> {
        self.search
            .run(&self.rules, input, context, false, || Ok(()), &mut emit)?;
        Ok(())
    }

    pub fn first_match(&self, input: &[u8], context: &ObjectContext) -> io::Result<Option<&str>> {
        self.first_match_checked(input, context, || Ok(()))
    }

    /// Check resource limits and cancellation while processing large objects.
    pub fn first_match_checked(
        &self,
        input: &[u8],
        context: &ObjectContext,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<&str>> {
        let hit = self
            .search
            .run(&self.rules, input, context, true, check, &mut |_| {})?;
        Ok(hit.map(|hit| self.name(hit.rule_id)))
    }
}

fn level(value: &str) -> io::Result<u32> {
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("invalid functionality level"));
    }
    value
        .parse()
        .map_err(|_| invalid("invalid functionality level"))
}

fn parse_record(
    line: &str,
    official: bool,
    flevel: u32,
    ignored: &IgnoreSet,
    stats: &mut BodyInventory,
    occupied: &mut [HashSet<u16>; 2],
) -> io::Result<Option<Rule>> {
    let mut fields = line.split(':');
    let name = fields.next().unwrap_or_default();
    let target = fields
        .next()
        .ok_or_else(|| invalid("missing body target"))?;
    let offset_text = fields
        .next()
        .ok_or_else(|| invalid("missing body offset"))?;
    let text = fields
        .next()
        .ok_or_else(|| invalid("missing body pattern"))?;
    let min = fields.next();
    let max = fields.next();
    if fields.next().is_some() {
        return Err(invalid("extra body database fields"));
    }
    stats.records += 1;
    if ignored.matches(name, line) {
        stats.skipped_ignored += 1;
        return Ok(None);
    }
    if min.map(level).transpose()?.is_some_and(|v| v > flevel)
        || max.map(level).transpose()?.is_some_and(|v| v < flevel)
    {
        stats.skipped_flevel += 1;
        return Ok(None);
    }
    let target = Target::parse(if target == "*" { "0" } else { target })?;
    let offset = Offset::parse(offset_text, target)?;
    let pattern = Pattern::compile(text)?;
    if pattern
        .parts()
        .iter()
        .any(|part| part.max_span() >= search::STOCK_WINDOW)
    {
        return Err(invalid("body pattern part exceeds the reference window"));
    }
    let source_name = name.split_once(" (Clam)").map_or(name, |(name, _)| name);
    if source_name.is_empty() || source_name.chars().any(char::is_control) {
        return Err(invalid("empty or control-containing body signature name"));
    }
    let name = if official {
        source_name.into()
    } else {
        format!("{source_name}.UNOFFICIAL").into_boxed_str()
    };

    let static_matcher = target == Target::Generic
        || (target == Target::Pe && offset_text != "*" && !offset_text.contains(','));
    let bm_prefix = if static_matcher && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let bytes = pattern.parts()[0]
            .literal()
            .ok_or_else(|| invalid("invalid literal pattern"))?;
        if bytes.len() < 3 {
            return Err(invalid("static body patterns need at least three bytes"));
        }
        let hashes = &mut occupied[target.id() as usize];
        let hash = |w: &[u8]| 211 * u16::from(w[0]) + 37 * u16::from(w[1]) + u16::from(w[2]);
        let shift = bytes
            .windows(3)
            .position(|w| !hashes.contains(&hash(w)))
            .unwrap_or(0);
        hashes.insert(hash(&bytes[shift..]));
        Some(shift as u16)
    } else {
        None
    };

    stats.active += 1;
    *stats.targets.entry(target.id()).or_default() += 1;
    let (base, shift) = offset_text
        .split_once(',')
        .map_or((offset_text, false), |(a, _)| (a, true));
    let form = if base == "*" {
        "any"
    } else if base.starts_with("EOF") {
        "EOF"
    } else if base.starts_with("EP+") {
        "EP+"
    } else if base.starts_with("EP-") {
        "EP-"
    } else if base.starts_with("SE") {
        "section extent"
    } else if base.starts_with("SL") {
        "last section"
    } else if base.starts_with('S') {
        "section"
    } else {
        "absolute"
    };
    *stats.offsets.entry(form).or_default() += 1;
    if shift {
        *stats.features.entry("floating offset").or_default() += 1;
    }
    if bm_prefix.is_some() || text.bytes().all(|b| b.is_ascii_hexdigit()) {
        *stats.features.entry("literal").or_default() += 1;
    }
    for (symbol, label) in [
        ("?", "byte/nibble mask"),
        ("*", "unbounded gap"),
        ("{", "brace gap"),
        ("[", "bracket range"),
        ("|", "alternatives"),
        ("!(", "negation"),
        ("(B)", "word boundary"),
        ("(L)", "line boundary"),
        ("(W)", "word character class"),
    ] {
        if text.contains(symbol) {
            *stats.features.entry(label).or_default() += 1;
        }
    }
    Ok(Some(Rule {
        name,
        target,
        offset,
        pattern,
        bm_prefix,
    }))
}
