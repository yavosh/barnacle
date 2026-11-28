//! Compile a ClamAV hex body into literal-anchored parts.
//! Bracket ranges check surrounding bytes. Brace ranges and stars join parts.
use std::collections::HashSet;
use std::hash::Hash;
use std::io;
use std::ops::RangeInclusive;

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[derive(Clone, Copy, Debug, Default)]
struct Gap {
    min: u32,
    // The pinned multipart matcher uses zero for an unrestricted upper bound.
    max: u32,
}

fn number(text: &str) -> io::Result<u32> {
    if text.is_empty() || !text.bytes().all(|c| c.is_ascii_digit()) {
        return Err(invalid("expected a decimal wildcard distance"));
    }
    text.parse()
        .map_err(|_| invalid("wildcard distance overflow"))
}

fn distance(text: &str) -> io::Result<Gap> {
    if let Some((min, max)) = text.split_once('-') {
        if min.is_empty() && max.is_empty() {
            return Err(invalid("missing wildcard distances"));
        }
        let min = if min.is_empty() { 0 } else { number(min)? };
        let max = if max.is_empty() { 0 } else { number(max)? };
        if max != 0 && max < min {
            return Err(invalid("reversed wildcard distances"));
        }
        Ok(Gap { min, max })
    } else {
        let n = number(text)?;
        Ok(Gap { min: n, max: n })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Byte {
    value: u8,
    mask: u8,
}

impl Byte {
    fn parse(pair: &[u8]) -> io::Result<Self> {
        if pair.len() != 2 {
            return Err(invalid("byte pattern needs two nibbles"));
        }
        let nibble = |c| match c {
            b'?' => Ok((0, 0)),
            b'0'..=b'9' => Ok((c - b'0', 15)),
            b'a'..=b'f' => Ok((c - b'a' + 10, 15)),
            b'A'..=b'F' => Ok((c - b'A' + 10, 15)),
            _ => Err(invalid("invalid hexadecimal nibble")),
        };
        let (a, am) = nibble(pair[0])?;
        let (b, bm) = nibble(pair[1])?;
        Ok(Self {
            value: a << 4 | b,
            mask: am << 4 | bm,
        })
    }

    fn fold(mut self, nocase: bool) -> Self {
        if nocase && self.mask == u8::MAX {
            self.value.make_ascii_lowercase();
        }
        self
    }

    fn matches(self, actual: u8, nocase: bool) -> bool {
        if nocase && self.mask == u8::MAX {
            self.value.eq_ignore_ascii_case(&actual)
        } else {
            actual & self.mask == self.value
        }
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
enum Atom {
    Literal(Box<[u8]>),
    Byte(Byte),
    Skip(usize),
    Choice {
        options: Box<[Box<[Byte]>]>,
        negative: bool,
    },
}

impl Atom {
    fn max_len(&self) -> usize {
        match self {
            Self::Literal(s) => s.len(),
            Self::Byte(_) => 1,
            Self::Skip(n) => *n,
            Self::Choice { options, .. } => options.iter().map(|s| s.len()).max().unwrap_or(0),
        }
    }

    // Input coordinates mark gaps between bytes, allowing identical forward and backward checks.
    fn step(
        &self,
        data: &[u8],
        pos: usize,
        reverse: bool,
        nocase: bool,
        mut success: impl FnMut(usize),
    ) {
        let span = |n| {
            if reverse {
                let start = pos.checked_sub(n)?;
                Some((data.get(start..pos)?, start))
            } else {
                let end = pos.checked_add(n)?;
                Some((data.get(pos..end)?, end))
            }
        };
        match self {
            Self::Literal(bytes) => {
                if let Some((s, next)) = span(bytes.len())
                    && literal_matches(s, bytes, nocase)
                {
                    success(next);
                }
            }
            Self::Byte(byte) => {
                if let Some((s, next)) = span(1)
                    && byte.matches(s[0], nocase)
                {
                    success(next);
                }
            }
            Self::Skip(n) => {
                if let Some((_, next)) = span(*n) {
                    success(next);
                }
            }
            Self::Choice { options, negative } => {
                for option in options {
                    // Stock's backward verifier skips zero-length arms.
                    if reverse && option.is_empty() {
                        continue;
                    }
                    if let Some((s, next)) = span(option.len())
                        && option
                            .iter()
                            .zip(s)
                            .all(|(b, &actual)| b.matches(actual, nocase))
                    {
                        if *negative {
                            return;
                        }
                        success(next);
                    }
                }
                if *negative && let Some((_, next)) = span(options[0].len()) {
                    success(next);
                }
            }
        }
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
struct Flank {
    byte: Byte,
    min: usize,
    max: usize,
}

impl Flank {
    fn parse(byte: &str, range: &str, nocase: bool) -> io::Result<Self> {
        let (min, max) = range.split_once('-').unwrap_or((range, range));
        let (min, max) = (number(min)? as usize, number(max)? as usize);
        if min > max || max > 32 {
            return Err(invalid("bracket distances must be ordered and at most 32"));
        }
        Ok(Self {
            byte: Byte::parse(byte.as_bytes())?.fold(nocase),
            min,
            max,
        })
    }

    fn matches(&self, input: &[u8], pos: usize, left: bool, nocase: bool) -> bool {
        // A full wildcard in the flank occupies the reference engine's "ignore" slot.
        if self.byte.mask == 0 {
            return true;
        }
        (self.min..=self.max).any(|gap| {
            let at = if left {
                pos.checked_sub(gap + 1)
            } else {
                pos.checked_add(gap)
            };
            at.and_then(|i| input.get(i))
                .is_some_and(|&b| self.byte.matches(b, nocase))
        })
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
enum Body {
    Literal {
        bytes: Box<[u8]>,
        anchor: u16,
        flags: Flags,
    },
    Program(Box<Program>),
}

#[derive(Debug, Eq, Hash, PartialEq)]
struct Program {
    flags: Flags,
    atoms: Box<[Atom]>,
    anchor: usize,
    span: usize,
    left: Option<Flank>,
    right: Option<Flank>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum WordWidth {
    Ascii,
    Wide,
}

impl WordWidth {
    fn left(self, input: &[u8], preceding: &[u8], start: usize) -> bool {
        let mut before = input[..start].iter().rev().chain(preceding.iter().rev());
        let high = before.next();
        match self {
            Self::Ascii => high.is_none_or(|byte| !byte.is_ascii_alphanumeric()),
            Self::Wide => match (before.next(), high) {
                (Some(low), Some(high)) => *high != 0 || !low.is_ascii_alphanumeric(),
                _ => true,
            },
        }
    }

    fn right(self, input: &[u8], end: usize) -> bool {
        match (self, &input[end..]) {
            (_, []) => true,
            (Self::Wide, [low, high, ..]) => *high != 0 || !low.is_ascii_alphanumeric(),
            (_, [next, ..]) => !next.is_ascii_alphanumeric(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Flags {
    nocase: bool,
    left_word: Option<WordWidth>,
    right_word: Option<WordWidth>,
}

#[derive(Debug)]
pub(super) struct Part {
    gap: Gap,
    body: Body,
}

#[derive(Debug)]
pub(super) enum Pattern {
    Single(Part),
    Multipart(Box<[Part]>),
}

impl Pattern {
    pub(super) fn compile(text: &str) -> io::Result<Self> {
        Self::compile_modified(text, false, false, false)
    }

    pub(super) fn compile_modified(
        text: &str,
        wide: bool,
        nocase: bool,
        fullword: bool,
    ) -> io::Result<Self> {
        if text.is_empty() || !text.is_ascii() {
            return Err(invalid("expected a nonempty ASCII hex pattern"));
        }
        if (wide || nocase || fullword) && text.contains("!(") {
            return Err(invalid(
                "negated alternatives with modifiers are unsupported",
            ));
        }
        let word = fullword.then_some(if wide {
            WordWidth::Wide
        } else {
            WordWidth::Ascii
        });
        let modified;
        let text = if wide {
            modified = wide_pattern(text)?;
            &modified
        } else if fullword && text.contains('[') {
            modified = text.replace('[', "{").replace(']', "}");
            &modified
        } else {
            text
        };
        // The reference expands leading exact brace counts below 128 into byte wildcards.
        // Once it reaches a multipart range, subsequent braces separate indexed parts.
        let mut parts = Vec::new();
        let mut gap = Gap::default();
        let mut expand = true;
        let mut start = 0;
        let mut i = 0;
        let mut group = false;
        while i < text.len() {
            match text.as_bytes()[i] {
                b'(' if !group => group = true,
                b')' if group => group = false,
                b'(' | b')' => return Err(invalid("unbalanced or nested alternatives")),
                b'{' | b'*' => {
                    let (next, new_gap, split) = if text.as_bytes()[i] == b'*' {
                        (i + 1, Gap::default(), true)
                    } else {
                        let close = text[i + 1..]
                            .find('}')
                            .ok_or_else(|| invalid("unclosed brace wildcard"))?
                            + i
                            + 1;
                        let range = &text[i + 1..close];
                        let g = distance(range)?;
                        let fixed = expand && !range.contains('-') && (1..128).contains(&g.min);
                        if !fixed {
                            expand = false;
                        }
                        (close + 1, g, !fixed)
                    };
                    if split {
                        if group {
                            return Err(invalid("multipart range inside an alternative"));
                        }
                        let flags = Flags {
                            nocase,
                            left_word: if parts.is_empty() { word } else { None },
                            right_word: None,
                        };
                        parts.push(Part::compile(&text[start..i], gap, flags)?);
                        start = next;
                        gap = new_gap;
                    }
                    i = next;
                    continue;
                }
                _ => (),
            }
            i += 1;
        }
        if group {
            return Err(invalid("unclosed alternative"));
        }
        let flags = Flags {
            nocase,
            left_word: if parts.is_empty() { word } else { None },
            right_word: word,
        };
        let last = Part::compile(&text[start..], gap, flags)?;
        if parts.is_empty() {
            return Ok(Self::Single(last));
        }
        parts.push(last);
        if parts.len() > u16::MAX.into() {
            return Err(invalid("too many pattern parts"));
        }
        Ok(Self::Multipart(parts.into_boxed_slice()))
    }

    pub(super) fn parts(&self) -> &[Part] {
        match self {
            Self::Single(part) => std::slice::from_ref(part),
            Self::Multipart(parts) => parts,
        }
    }
}

// Expand byte tokens only. Stock retains brace distances as raw byte counts.
// Widened bracket flanks contain two bytes, so the brackets become ordinary
// gaps and both flanks are included in the reported match coordinates.
fn wide_pattern(mut text: &str) -> io::Result<String> {
    let mut result = String::with_capacity(text.len());
    while let Some(&first) = text.as_bytes().first() {
        match first {
            b'{' | b'[' => {
                let close = if first == b'{' { '}' } else { ']' };
                let (distance, rest) = text[1..]
                    .split_once(close)
                    .ok_or_else(|| invalid("unclosed wide pattern distance"))?;
                result.push('{');
                result.push_str(distance);
                result.push('}');
                text = rest;
            }
            b'*' | b'!' | b'(' | b')' | b'|' => {
                result.push(char::from(first));
                text = &text[1..];
            }
            _ => {
                let pair = text
                    .get(..2)
                    .ok_or_else(|| invalid("truncated wide byte pattern"))?;
                Byte::parse(pair.as_bytes())?;
                result.push_str(pair);
                result.push_str("00");
                text = &text[2..];
            }
        }
    }
    Ok(result)
}

fn literal_matches(actual: &[u8], pattern: &[u8], nocase: bool) -> bool {
    if nocase {
        actual.eq_ignore_ascii_case(pattern)
    } else {
        actual == pattern
    }
}

fn starts_with(input: &[u8], at: usize, pattern: &[u8], nocase: bool) -> bool {
    input
        .get(at..)
        .and_then(|tail| tail.get(..pattern.len()))
        .is_some_and(|s| literal_matches(s, pattern, nocase))
}

// Stock indexes up to three static bytes and prefers a prefix without two leading zeroes.
fn anchor_position(atoms: &[Atom]) -> io::Result<(usize, usize)> {
    if let Some(Atom::Literal(s)) = atoms.first()
        && (s.len() >= 3 || atoms.len() == 1)
        && s.iter().take(3).any(|&b| b != 0)
        && s.len() >= 2
    {
        return Ok((0, 0));
    }
    let mut best = None;
    let mut nonzero = None;
    let mut depth = 0;
    let mut nonzero_depth = 0;
    for (index, atom) in atoms.iter().enumerate() {
        let Atom::Literal(bytes) = atom else {
            continue;
        };
        for (shift, pair) in bytes.windows(2).enumerate() {
            let n = (bytes.len() - shift).min(3);
            if n >= depth {
                depth = n;
                best = Some((index, shift));
                if pair != [0, 0] {
                    if n == 3 {
                        return Ok((index, shift));
                    }
                    if n > nonzero_depth {
                        nonzero = best;
                        nonzero_depth = n;
                    }
                }
            }
        }
    }
    let best = best.ok_or_else(|| invalid("pattern part needs two adjacent literal bytes"))?;
    if let Atom::Literal(s) = &atoms[best.0]
        && s[best.1..].starts_with(&[0, 0])
    {
        Ok(nonzero.unwrap_or(best))
    } else {
        Ok(best)
    }
}

fn parse_atoms(mut text: &str, nocase: bool) -> io::Result<Vec<Atom>> {
    let mut atoms = Vec::new();
    let mut literal = Vec::new();
    while !text.is_empty() {
        let atom = match text.as_bytes()[0] {
            b'{' => {
                let close = text
                    .find('}')
                    .ok_or_else(|| invalid("unclosed exact wildcard"))?;
                let n = number(&text[1..close])? as usize;
                if !(1..128).contains(&n) {
                    return Err(invalid("invalid inline exact wildcard"));
                }
                text = &text[close + 1..];
                Atom::Skip(n)
            }
            b'(' | b'!' => {
                let negative = text.starts_with('!');
                let rest = text
                    .strip_prefix('!')
                    .unwrap_or(text)
                    .strip_prefix('(')
                    .ok_or_else(|| invalid("expected parenthesized alternatives"))?;
                let (options, tail) = rest
                    .split_once(')')
                    .ok_or_else(|| invalid("unclosed alternative"))?;
                text = tail;
                let mut choices: Vec<Box<[Byte]>> = Vec::new();
                for option in options.split('|') {
                    if option.is_empty() {
                        if negative
                            || choices.len() != 1
                            || !options.ends_with('|')
                            || options.matches('|').count() != 1
                        {
                            return Err(invalid("unsupported empty alternative"));
                        }
                        if atoms.is_empty() && literal.is_empty() {
                            return Err(invalid("unsupported leading group with an empty arm"));
                        }
                    }
                    let mut bytes = Vec::new();
                    let mut raw = option;
                    while !raw.is_empty() {
                        if let Some(rest) = raw.strip_prefix('{') {
                            let (count, tail) = rest
                                .split_once('}')
                                .ok_or_else(|| invalid("unclosed alternative wildcard"))?;
                            let n = number(count)? as usize;
                            if !(1..128).contains(&n) {
                                return Err(invalid("invalid alternative wildcard"));
                            }
                            bytes.extend(std::iter::repeat_n(Byte { value: 0, mask: 0 }, n));
                            raw = tail;
                        } else {
                            let pair = raw
                                .get(..2)
                                .ok_or_else(|| invalid("invalid alternative byte"))?;
                            bytes.push(Byte::parse(pair.as_bytes())?.fold(nocase));
                            raw = &raw[2..];
                        }
                    }
                    if negative
                        && (bytes.iter().any(|b| b.mask != 255)
                            || choices.first().is_some_and(|s| s.len() != bytes.len()))
                    {
                        return Err(invalid(
                            "negated alternatives need equal-length literal strings",
                        ));
                    }
                    choices.push(bytes.into_boxed_slice());
                }
                if choices
                    .iter()
                    .all(|s| s.len() == choices[0].len() && s.iter().all(|b| b.mask == 255))
                {
                    choices.sort_unstable();
                }
                Atom::Choice {
                    options: choices.into_boxed_slice(),
                    negative,
                }
            }
            _ => {
                let pair = text
                    .get(..2)
                    .ok_or_else(|| invalid("truncated byte pattern"))?;
                let b = Byte::parse(pair.as_bytes())?.fold(nocase);
                text = &text[2..];
                if b.mask == 255 {
                    literal.push(b.value);
                    continue;
                }
                if b.mask == 0 {
                    Atom::Skip(1)
                } else {
                    Atom::Byte(b)
                }
            }
        };
        if !literal.is_empty() {
            atoms.push(Atom::Literal(
                std::mem::take(&mut literal).into_boxed_slice(),
            ));
        }
        if let Atom::Skip(n) = &atom
            && let Some(Atom::Skip(last)) = atoms.last_mut()
        {
            *last += n;
        } else {
            atoms.push(atom);
        }
    }
    if !literal.is_empty() {
        atoms.push(Atom::Literal(literal.into_boxed_slice()));
    }
    Ok(atoms)
}

impl Part {
    fn compile(mut text: &str, gap: Gap, flags: Flags) -> io::Result<Self> {
        let mut left = None;
        let mut right = None;
        if text.as_bytes().get(2) == Some(&b'[') {
            let (range, rest) = text[3..]
                .split_once(']')
                .ok_or_else(|| invalid("unclosed left bracket"))?;
            left = Some(Flank::parse(&text[..2], range, flags.nocase)?);
            text = rest;
        }
        if let Some((core, rest)) = text.split_once('[') {
            let (range, byte) = rest
                .split_once(']')
                .ok_or_else(|| invalid("unclosed right bracket"))?;
            right = Some(Flank::parse(byte, range, flags.nocase)?);
            text = core;
        }
        let mut atoms = parse_atoms(text, flags.nocase)?;
        let (mut anchor, shift) = anchor_position(&atoms)?;
        let span = atoms.iter().map(Atom::max_len).sum::<usize>();
        if span > u16::MAX.into() {
            return Err(invalid("pattern part exceeds the maximum width"));
        }
        if atoms.len() == 1
            && left.is_none()
            && right.is_none()
            && let Some(Atom::Literal(bytes)) = atoms.pop()
        {
            return Ok(Self {
                gap,
                body: Body::Literal {
                    bytes,
                    anchor: shift as u16,
                    flags,
                },
            });
        }
        if shift != 0
            && let Atom::Literal(bytes) = &atoms[anchor]
        {
            let prefix = Atom::Literal(bytes[..shift].into());
            let tail = Atom::Literal(bytes[shift..].into());
            atoms[anchor] = prefix;
            anchor += 1;
            atoms.insert(anchor, tail);
        }
        let body = Body::Program(Box::new(Program {
            flags,
            atoms: atoms.into_boxed_slice(),
            anchor,
            span,
            left,
            right,
        }));
        Ok(Self { gap, body })
    }

    pub(super) fn nocase(&self) -> bool {
        match &self.body {
            Body::Literal { flags, .. } => flags.nocase,
            Body::Program(p) => p.flags.nocase,
        }
    }

    pub(super) fn literal(&self) -> Option<&[u8]> {
        match &self.body {
            Body::Literal { bytes, .. } => Some(bytes),
            _ => None,
        }
    }

    pub(super) fn shape_key(&self) -> impl Eq + Hash + '_ {
        &self.body
    }

    pub(super) fn anchor(&self) -> &[u8] {
        match &self.body {
            Body::Literal { bytes, anchor, .. } => &bytes[usize::from(*anchor)..],
            Body::Program(p) => match &p.atoms[p.anchor] {
                Atom::Literal(s) => s,
                _ => unreachable!(),
            },
        }
    }

    pub(super) fn stock_anchor_len(&self) -> usize {
        self.anchor().len().min(3)
    }

    pub(super) fn max_span(&self) -> usize {
        match &self.body {
            Body::Literal { bytes, .. } => bytes.len(),
            Body::Program(p) => p.span,
        }
    }

    pub(super) fn hits_for_anchor(
        &self,
        input: &[u8],
        preceding: &[u8],
        anchor_start: usize,
        range: RangeInclusive<usize>,
        mut emit: impl FnMut(usize, usize),
    ) -> io::Result<()> {
        match &self.body {
            Body::Literal {
                bytes,
                anchor,
                flags,
            } => {
                if let Some(start) = anchor_start.checked_sub(usize::from(*anchor))
                    && range.contains(&start)
                    && starts_with(input, start, bytes, flags.nocase)
                    && flags
                        .left_word
                        .is_none_or(|w| w.left(input, preceding, start))
                    && flags
                        .right_word
                        .is_none_or(|w| w.right(input, start + bytes.len()))
                {
                    emit(start, start + bytes.len());
                }
            }
            Body::Program(p) => {
                let anchor = self.anchor();
                if !starts_with(input, anchor_start, anchor, p.flags.nocase) {
                    return Ok(());
                }
                let left = side(
                    input,
                    anchor_start,
                    p.atoms[..p.anchor].iter().rev(),
                    true,
                    p.flags.nocase,
                )
                .select(|s| {
                    range.contains(&s)
                        && p.left
                            .as_ref()
                            .is_none_or(|f| f.matches(input, s, true, p.flags.nocase))
                });
                // Stock commits to a backward alternative before testing its word boundary.
                if let Some(start) = left
                    && p.flags
                        .left_word
                        .is_none_or(|w| w.left(input, preceding, start))
                {
                    let right = side(
                        input,
                        anchor_start + anchor.len(),
                        p.atoms[p.anchor + 1..].iter(),
                        false,
                        p.flags.nocase,
                    )
                    .select(|end| {
                        p.flags.right_word.is_none_or(|w| w.right(input, end))
                            && p.right
                                .as_ref()
                                .is_none_or(|f| f.matches(input, end, false, p.flags.nocase))
                    });
                    if let Some(end) = right {
                        emit(start, end);
                    }
                }
            }
        }
        Ok(())
    }
}

// Keep the ordinary verifier allocation-free. Only variable-width alternatives can
// branch. Coalesce equal cursors after each atom so their suffix is verified once.
#[derive(Default)]
enum Positions {
    #[default]
    Empty,
    One(usize),
    Several {
        values: Vec<usize>,
        seen: HashSet<usize>,
    },
}

impl Positions {
    fn push(&mut self, n: usize) {
        match self {
            Self::Empty => *self = Self::One(n),
            Self::One(old) if *old != n => {
                *self = Self::Several {
                    values: vec![*old, n],
                    seen: HashSet::from([*old, n]),
                }
            }
            Self::One(_) => (),
            Self::Several { values, seen } => {
                if seen.insert(n) {
                    values.push(n);
                }
            }
        }
    }

    fn select(self, condition: impl Fn(usize) -> bool) -> Option<usize> {
        match self {
            Self::Empty => None,
            Self::One(n) => condition(n).then_some(n),
            Self::Several { values, .. } => values.into_iter().find(|&n| condition(n)),
        }
    }
}

fn side<'a>(
    input: &[u8],
    cursor: usize,
    atoms: impl Iterator<Item = &'a Atom>,
    reverse: bool,
    nocase: bool,
) -> Positions {
    let mut active = Positions::One(cursor);
    for atom in atoms {
        let mut next = Positions::Empty;
        match active {
            Positions::Empty => break,
            Positions::One(n) => atom.step(input, n, reverse, nocase, |p| next.push(p)),
            Positions::Several { values, .. } => {
                for n in values {
                    atom.step(input, n, reverse, nocase, |p| next.push(p));
                }
            }
        }
        active = next;
    }
    active
}

// The pinned AC matcher keeps the first partial match plus eight replaceable slots.
// When the second part connects to another first-part match, it brings that match
// into the first slot. Logical subsignatures report its start for each final hit.
#[derive(Default)]
struct History {
    spans: Vec<(usize, usize)>,
    next: usize,
}

impl History {
    fn record(&mut self, span: (usize, usize)) {
        const SLOTS: usize = 9;
        if self.spans.len() < SLOTS {
            self.spans.push(span);
        } else {
            self.spans[self.next] = span;
        }
        self.next += 1;
        if self.next == SLOTS {
            self.next = 1;
        }
    }
}

#[derive(Default)]
pub(super) struct MatchState {
    history: Vec<History>,
}

impl MatchState {
    pub(super) fn advance(
        &mut self,
        pattern: &Pattern,
        part: usize,
        start: usize,
        end: usize,
    ) -> Option<(usize, usize)> {
        let parts = pattern.parts();
        if parts.len() == 1 {
            return Some((start, end));
        }
        if self.history.is_empty() {
            if part != 0 {
                return None;
            }
            self.history.resize_with(parts.len() - 1, History::default);
        }
        if part != 0 {
            let gap = parts[part].gap;
            let previous = &mut self.history[part - 1].spans;
            let selected = previous.iter().position(|&(_, prev_end)| {
                start.checked_sub(prev_end).is_some_and(|d| {
                    d >= gap.min as usize && (gap.max == 0 || d <= gap.max as usize)
                })
            })?;
            if part == 1 {
                previous.swap(0, selected);
            }
        }
        if part == parts.len() - 1 {
            Some((self.history[0].spans[0].0, end))
        } else {
            self.history[part].record((start, end));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part_hits(text: &str, data: &[u8], range: RangeInclusive<usize>) -> Vec<(usize, usize)> {
        let pattern = Pattern::compile(text).unwrap();
        assert_eq!(pattern.parts().len(), 1);
        let part = &pattern.parts()[0];
        let mut hits = Vec::new();
        for pos in 0..data.len() {
            part.hits_for_anchor(data, &[], pos, range.clone(), |a, b| hits.push((a, b)))
                .unwrap();
        }
        hits
    }

    fn modified_hits(
        pattern: &Pattern,
        part: usize,
        data: &[u8],
        preceding: &[u8],
    ) -> Vec<(usize, usize)> {
        let mut hits = Vec::new();
        for pos in 0..data.len() {
            pattern.parts()[part]
                .hits_for_anchor(data, preceding, pos, 0..=data.len(), |start, end| {
                    hits.push((start, end))
                })
                .unwrap();
        }
        hits
    }

    #[test]
    fn nocase_folds_ascii_literals_and_alternatives_but_preserves_masks() {
        let p = Pattern::compile_modified("4142(63|78)44?5", false, true, false).unwrap();
        assert!(p.parts()[0].nocase());
        assert_eq!(p.parts()[0].anchor(), b"ab");
        assert_eq!(modified_hits(&p, 0, b"ABcDe abXDE", &[]), [(0, 5), (6, 11)]);
        let mask = Pattern::compile_modified("41626?64", false, true, false).unwrap();
        assert_eq!(modified_hits(&mask, 0, b"ABcD ABCD", &[]), [(0, 4)]);
        let high = Pattern::compile_modified("c06162", false, true, false).unwrap();
        assert_eq!(modified_hits(&high, 0, b"\xc0AB \xe0ab", &[]), [(0, 3)]);
        assert!(Pattern::compile_modified("6162!(63|78)6465", false, true, false).is_err());
    }

    #[test]
    fn wide_bytes_and_raw_gaps_keep_distinct_widths() {
        for (hex, yes, no) in [
            ("61??63", b"a\0X\0c\0".as_slice(), b"a\0XYc\0".as_slice()),
            ("61{1}63", b"a\0Xc\0", b"a\0X\0c\0"),
            ("61(62|78)63", b"a\0x\0c\0", b"a\0xXc\0"),
            ("61(62{1}|78)63", b"a\0b\0Xc\0", b"a\0b\0X\0c\0"),
            ("61[1]63", b"a\0Xc\0", b"a\0X\0c\0"),
        ] {
            let p = Pattern::compile_modified(hex, true, false, false).unwrap();
            assert_eq!(modified_hits(&p, 0, yes, &[]), [(0, yes.len())], "{hex}");
            assert!(modified_hits(&p, 0, no, &[]).is_empty(), "{hex}");
        }
        let p = Pattern::compile_modified("61{1-2}63", true, false, false).unwrap();
        assert_eq!(p.parts().len(), 2);
        let mut state = MatchState::default();
        assert_eq!(state.advance(&p, 0, 0, 2), None);
        assert_eq!(state.advance(&p, 1, 5, 7), None);
        assert_eq!(state.advance(&p, 1, 4, 6), Some((0, 6)));
    }

    #[test]
    fn fullword_brackets_and_alternatives_use_reference_span() {
        for (hex, data, expected) in [
            ("61[1]626364", b" aXbcd ".as_slice(), Some((1, 6))),
            ("616263(64|6465)", b" abcde ", Some((1, 6))),
            ("(64|6564)616263", b" edabc ", None),
            ("(6564|64)616263", b" edabc ", Some((1, 6))),
        ] {
            let p = Pattern::compile_modified(hex, false, false, true).unwrap();
            assert_eq!(
                modified_hits(&p, 0, data, &[]),
                expected.into_iter().collect::<Vec<_>>(),
                "{hex}"
            );
        }
        for (hex, text, expected) in [
            ("637265646974(20|2078)", "credit x ", Some((0, 16))),
            ("(20|7820)637265646974", "x credit", None),
            ("(7820|20)637265646974", "x credit", Some((0, 16))),
        ] {
            let wide = text
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            let p = Pattern::compile_modified(hex, true, false, true).unwrap();
            assert_eq!(
                modified_hits(&p, 0, &wide, &[]),
                expected.into_iter().collect::<Vec<_>>(),
                "{hex}"
            );
        }
        assert!(Pattern::compile_modified("61[1-2]626364", false, false, true).is_err());
        let p = Pattern::compile_modified("48454144*5441494c", false, false, true).unwrap();
        let data = b"xHEAD  HEAD TAIL .";
        assert_eq!(modified_hits(&p, 0, data, &[]), [(7, 11)]);
        assert_eq!(modified_hits(&p, 1, data, &[]), [(12, 16)]);
    }

    #[test]
    fn word_boundaries_use_preceding_bytes() {
        let ascii = Pattern::compile_modified("6162", false, false, true).unwrap();
        assert_eq!(modified_hits(&ascii, 0, b"ab_", &[]), [(0, 2)]);
        assert!(modified_hits(&ascii, 0, b"ab_", b"xx").is_empty());
        assert_eq!(modified_hits(&ascii, 0, b".ab", b"xx"), [(1, 3)]);
        let wide = Pattern::compile_modified("6162", true, false, true).unwrap();
        assert_eq!(modified_hits(&wide, 0, b"Xa\0b\0", &[]), [(1, 5)]);
        assert_eq!(modified_hits(&wide, 0, b"Xa\0b\0", b"xx"), [(1, 5)]);
        assert_eq!(modified_hits(&wide, 0, b"\0a\0b\0", b"x."), [(1, 5)]);
        assert!(modified_hits(&wide, 0, b"\0a\0b\0", b".x").is_empty());
        assert!(modified_hits(&wide, 0, b".\0a\0b\0Q", b"xx").is_empty());
        assert_eq!(modified_hits(&wide, 0, b".\0a\0b\0Q!", b"xx"), [(2, 6)]);
        assert!(modified_hits(&wide, 0, b"X\0a\0b\0", &[]).is_empty());
    }

    #[test]
    fn bytes_masks_alternatives_and_overlaps() {
        assert_eq!(part_hits("616161", b"aaaa", 0..=4), [(0, 3), (1, 4)]);
        assert_eq!(part_hits("6?6263?4??", b"abcd!abcd!", 1..=9), [(5, 10)]);
        assert_eq!(
            part_hits("6162(6364|6378)65", b"abcdeabcxe", 0..=10),
            [(0, 5), (5, 10)]
        );
        assert_eq!(
            part_hits("6162!(6364|6263)65", b"abcdeabcxe", 0..=10),
            [(5, 10)]
        );
        assert_eq!(
            part_hits("6162(63|6364)65", b"abcdeabce", 0..=9),
            [(0, 5), (5, 9)]
        );
        assert_eq!(
            part_hits("6162(63{1}|7?7?)65", b"abcdeabzze", 0..=10),
            [(0, 5), (5, 10)]
        );
        // Preserve alternative order when different lengths can both finish at this anchor.
        assert_eq!(part_hits("616263(6465|64)", b"abcde", 0..=5), [(0, 5)]);
    }

    #[test]
    fn single_arm_groups_keep_the_stock_anchor_and_width() {
        assert_eq!(part_hits("4142(6364)4546", b"--ABcdEF--", 2..=2), [(2, 8)]);
        assert!(part_hits("4142(6364)4546", b"---ABcdEF--", 2..=2).is_empty());
        assert!(part_hits("4142(6364)4546", b"--ABEF--", 2..=2).is_empty());
        assert!(Pattern::compile("(414263644546)").is_err());
        assert_eq!(
            part_hits("4142!(6364)4546", b"--ABcdEF--ABxyEF--", 0..=18),
            [(10, 16)]
        );
        assert_eq!(part_hits("4142(63?4)4546", b"--ABcTEF--", 0..=10), [(2, 8)]);
        let fullword = Pattern::compile_modified("4142(6364)4546", false, false, true).unwrap();
        assert_eq!(
            modified_hits(&fullword, 0, b"-ABcdEF-ABcdEFx", &[]),
            [(1, 7)]
        );
    }

    #[test]
    fn trailing_empty_arm_depends_on_anchor_direction() {
        let data = b"--ABCDcdEFGH--ABCDEFGH--ABCDxyEFGH--";
        assert_eq!(
            part_hits("41424344(6364|)45464748", data, 0..=data.len()),
            [(2, 12), (14, 22)]
        );
        assert_eq!(
            part_hits("4142(6364|)4546", b"--ABcdEF--ABEF--", 0..=16),
            [(2, 8)]
        );
        let wide = Pattern::compile_modified("4142(6364|)4546", true, false, false).unwrap();
        assert_eq!(modified_hits(&wide, 0, b"A\0B\0E\0F\0", &[]), [(0, 8)]);
        let fullword = Pattern::compile_modified("41424344(6364|)", false, false, true).unwrap();
        assert_eq!(
            modified_hits(&fullword, 0, b" ABCDcd ABCD! ABCDxy ", &[]),
            [(1, 7), (8, 12)]
        );
    }

    #[test]
    fn bracket_flanks_keep_core_coordinates() {
        let pattern = "41[1-2]424344[0-1]45";
        assert_eq!(part_hits(pattern, b"AxBCDE", 2..=2), [(2, 5)]);
        assert_eq!(part_hits(pattern, b"AxxBCDxE", 3..=3), [(3, 6)]);
        assert!(part_hits(pattern, b"AxxxBCDE", 0..=8).is_empty());
        assert!(part_hits(pattern, b"AxBCDx", 0..=6).is_empty());
        assert!(part_hits(pattern, b"AxBCDE", 0..=0).is_empty());
    }

    #[test]
    fn multipart_reports_stock_first_position_for_each_final_hit() {
        let pattern = Pattern::compile("6162{2-5}6364*6566").unwrap();
        let mut state = MatchState::default();
        assert_eq!(state.advance(&pattern, 0, 1, 3), None);
        assert_eq!(state.advance(&pattern, 0, 9, 11), None);
        assert_eq!(state.advance(&pattern, 1, 13, 15), None);
        assert_eq!(state.advance(&pattern, 2, 15, 17), Some((9, 17)));
        assert_eq!(state.advance(&pattern, 2, 20, 22), Some((9, 22)));
    }

    #[test]
    fn multipart_tracks_first_slot_and_eight_recent_ends() {
        let pattern = Pattern::compile("6162{1-1}6364").unwrap();
        let mut state = MatchState::default();
        for start in 0..11 {
            assert_eq!(state.advance(&pattern, 0, start, start + 2), None);
        }
        // The oldest start is retained even after the history wraps.
        assert_eq!(state.advance(&pattern, 1, 3, 5), Some((0, 5)));
        assert_eq!(state.advance(&pattern, 1, 4, 6), None);
        assert_eq!(state.advance(&pattern, 1, 13, 15), Some((10, 15)));
    }

    #[test]
    fn malformed_and_unimplemented_syntax_returns_errors() {
        for text in [
            "a",
            "6162?",
            "6162**6364",
            "6162{4-2}6364",
            "6162{a}6364",
            "6162!",
            "????",
            "61[34]6263",
            "6162[1-2]ff00",
            "6162(63|646)",
            "6162!(63|6465)",
            "6162()",
            "6162(|63)",
            "6162!(63|)",
            "(63|)6162",
            "6162(63||64)",
            "6162(6*|6465)",
            "6162(B)",
            "6162{2",
        ] {
            assert!(Pattern::compile(text).is_err(), "{text}");
        }
    }
}
