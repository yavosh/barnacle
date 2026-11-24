//! Passive local destinations in PDF 1.7, sections 12.3.2 and 12.6.4.2.
use super::{ChildSink, Id, Object, Tokens, number, stream_start};
use std::{collections::HashMap, io};

#[derive(Clone, Copy)]
pub(super) enum Destination {
    Inline,
    Page(Id),
    Indirect(Id),
}

// The grammar uses Option for unrecognized syntax. Keep cancellation and I/O
// errors from the token reader distinct when returning to the scanner.
struct Reader<'a, 's> {
    input: Tokens<'a>,
    budget: super::TokenBudget,
    check: &'s mut dyn FnMut() -> io::Result<()>,
    error: Option<io::Error>,
}

impl<'a> Reader<'a, '_> {
    fn parse<T>(
        body: &'a [u8],
        check: &mut dyn FnMut() -> io::Result<()>,
        parse: impl FnOnce(&mut Reader<'a, '_>) -> T,
    ) -> io::Result<T> {
        let mut reader = Reader {
            input: Tokens { data: body, pos: 0 },
            budget: super::TokenBudget::default(),
            check,
            error: None,
        };
        let result = parse(&mut reader);
        reader.error.map_or(Ok(result), Err)
    }

    fn charge(&mut self, n: usize) -> Option<()> {
        if self.error.is_some() {
            return None;
        }
        self.budget
            .charge(n, self.check)
            .map_err(|e| self.error = Some(e))
            .ok()
    }

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.error.is_some() {
            return None;
        }
        self.input
            .next_with(&mut |n| self.budget.charge(n, self.check))
            .map_err(|e| self.error = Some(e))
            .ok()
            .flatten()
    }

    fn number(&mut self, token: &[u8]) -> Option<usize> {
        if self.error.is_some() {
            return None;
        }
        super::number_with(token, &mut |n| self.budget.charge(n, self.check))
            .map_err(|e| self.error = Some(e))
            .ok()
            .flatten()
    }

    fn integer(&mut self) -> Option<usize> {
        let token = self.next()?;
        self.number(token)
    }

    fn reference(&mut self) -> Option<Id> {
        let at = self.input.pos;
        let id = (|| {
            let id = (self.integer()?, self.integer()?);
            (self.next()? == b"R").then_some(id)
        })();
        if id.is_none() {
            self.input.pos = at;
        }
        id
    }

    // Skip one PDF value. Keep only the nesting depth.
    fn skip_value(&mut self) -> Option<()> {
        let first = self.next()?;
        if self.number(first).is_some() {
            let after = self.input.pos;
            if self.integer().is_some() && self.next()? == b"R" {
                return Some(());
            }
            self.input.pos = after;
        }
        let mut depth = usize::from(matches!(first, b"[" | b"<<"));
        while depth != 0 {
            match self.next()? {
                b"[" | b"<<" => depth += 1,
                b"]" | b">>" => depth -= 1,
                _ => (),
            }
        }
        Some(())
    }
}

fn coordinate(value: &[u8], reader: &mut Reader<'_, '_>) -> Option<bool> {
    let value = value
        .strip_prefix(b"-")
        .or_else(|| value.strip_prefix(b"+"))
        .unwrap_or(value);
    let (mut digits, mut dot) = (false, false);
    for chunk in value.chunks(super::TOKEN_BLOCK) {
        reader.charge(chunk.len())?;
        for &c in chunk {
            if c.is_ascii_digit() {
                digits = true;
            } else if c == b'.' && !dot {
                dot = true;
            } else {
                return Some(false);
            }
        }
    }
    Some(digits)
}

fn array(input: &mut Reader<'_, '_>) -> Option<Id> {
    let id = (input.integer()?, input.integer()?);
    if input.next()? != b"R" {
        return None;
    }
    let kind = input.next()?;
    let count = match kind {
        b"/Fit" | b"/FitB" => 0,
        b"/FitH" | b"/FitBH" | b"/FitV" | b"/FitBV" => 1,
        b"/XYZ" => 3,
        b"/FitR" => 4,
        _ => return None,
    };
    for _ in 0..count {
        let value = input.next()?;
        if !(coordinate(value, input)? || value == b"null" && kind != b"/FitR") {
            return None;
        }
    }
    (input.next()? == b"]").then_some(id)
}

fn goto(input: &mut Reader<'_, '_>) -> Option<()> {
    let (mut subtype, mut dest, mut typed) = (false, false, false);
    loop {
        match input.next()? {
            b"/S" if !subtype && input.next()? == b"/GoTo" => subtype = true,
            b"/Type" if !typed && input.next()? == b"/Action" => typed = true,
            b"/D" if !dest => {
                match input.next()? {
                    b"[" => {
                        array(input)?;
                    }
                    v if v.starts_with(b"/") && v.len() > 1 => {
                        for chunk in v.chunks(super::TOKEN_BLOCK) {
                            input.charge(chunk.len())?;
                            if chunk.contains(&b'#') {
                                return None;
                            }
                        }
                    }
                    v if v.starts_with(b"(") && v.ends_with(b")") => {}
                    _ => return None,
                }
                dest = true;
            }
            b">>" => return (subtype && dest).then_some(()),
            _ => return None,
        }
    }
}

// Only fields in the outer dictionary identify catalogs and pages. Ignore names
// inside strings, arrays and nested dictionaries. Duplicate fields are ambiguous.
#[derive(Default)]
struct Fields {
    kind: Option<usize>,
    opening: Option<usize>,
}

fn fields(input: &mut Reader<'_, '_>, read_opening: bool) -> Option<Fields> {
    if input.next()? != b"<<" {
        return None;
    }
    let mut fields = Fields::default();
    loop {
        let selected = match input.next()? {
            b">>" => return input.next().is_none().then_some(fields),
            b"/Type" => Some(&mut fields.kind),
            b"/OpenAction" if read_opening => Some(&mut fields.opening),
            key if !key.starts_with(b"/") => return None,
            _ => None,
        };
        if let Some(field) = selected
            && field.replace(input.input.pos).is_some()
        {
            return None;
        }
        input.skip_value()?;
    }
}

pub(super) fn catalog(
    body: &[u8],
    check: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<Option<Destination>> {
    Reader::parse(body, check, |input| {
        let pos = fields(input, true)?;
        input.input.pos = pos.kind?;
        if input.next()? != b"/Catalog" {
            return None;
        }
        input.input.pos = pos.opening?;
        if let Some(id) = input.reference() {
            return Some(Destination::Indirect(id));
        }
        match input.next()? {
            b"[" => array(input).map(Destination::Page),
            b"<<" => goto(input).map(|()| Destination::Inline),
            _ => None,
        }
    })
}

#[derive(Default)]
enum Definition<'a> {
    #[default]
    Missing,
    Unique {
        start: usize,
        body: &'a [u8],
        page: bool,
        action: bool,
        selected: bool,
    },
    Ambiguous,
}

pub(super) fn page(body: &[u8], check: &mut dyn FnMut() -> io::Result<()>) -> io::Result<bool> {
    Reader::parse(body, check, |input| {
        fields(input, false).and_then(|f| f.kind).and_then(|p| {
            input.input.pos = p;
            input.next()
        }) == Some(b"/Page")
    })
}

pub(super) fn passive_body(
    body: &[u8],
    check: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<bool> {
    Reader::parse(body, check, |input| {
        let valid = match input.next() {
            Some(b"[") => array(input).is_some(),
            Some(b"<<") => goto(input).is_some(),
            _ => false,
        };
        valid && input.next().is_none()
    })
}

// Only referenced IDs occupy the lookup table. A single pass finds forward and
// backward references, and never interprets a token inside a physical stream.
pub(super) fn resolve<'a>(
    data: &'a [u8],
    objects: &mut Vec<Object<'a>>,
    requests: &[(usize, Destination)],
    sink: &mut dyn ChildSink,
) -> io::Result<bool> {
    let mut definitions = HashMap::new();
    for &(_, request) in requests {
        if let Destination::Page(id) | Destination::Indirect(id) = request {
            definitions.insert(id, Definition::Missing);
        }
    }
    if definitions.is_empty() {
        return Ok(true);
    }
    // The first pass already located every stream payload. Advance over those
    // spans directly so large attachments are read only once.
    let mut streams = objects
        .iter()
        .filter(|o| !o.raw_destination)
        .filter_map(|o| o.encoded.map(|bytes| (o.start, bytes)));
    let mut input = Tokens { data, pos: 0 };
    let mut token_budget = super::TokenBudget::default();
    let mut last = [None, None];
    while let Some(token) = input.next_checked(&mut token_budget, sink)? {
        if token != b"obj" {
            last = [last[1], number(token)];
            continue;
        }
        sink.check()?;
        let start = input.pos;
        let mut stream = false;
        let [Some(id), Some(generation)] = last else {
            return Ok(false);
        };
        let definition = definitions.get_mut(&(id, generation));
        let end = loop {
            match input.next_checked(&mut token_budget, sink)? {
                Some(b"endobj") => break input.pos - 6,
                Some(b"stream") => {
                    stream = true;
                    let Some((owner, bytes)) = streams.next() else {
                        return Ok(false);
                    };
                    let Some(at) = stream_start(&mut input) else {
                        return Ok(false);
                    };
                    if owner != start || data[at..].as_ptr() != bytes.as_ptr() {
                        return Ok(false);
                    }
                    input.pos = at + bytes.len() + b"endstream".len();
                }
                None => return Ok(false),
                _ => {}
            }
        };
        if let Some(definition) = definition {
            *definition = if matches!(definition, Definition::Missing) && !stream {
                let body = &data[start..end];
                Definition::Unique {
                    start,
                    body,
                    page: page(body, &mut || sink.check())?,
                    action: passive_body(body, &mut || sink.check())?,
                    selected: false,
                }
            } else {
                Definition::Ambiguous
            };
        }
        last = [None, None];
    }
    for &(owner, request) in requests {
        let (Destination::Page(id) | Destination::Indirect(id)) = request else {
            continue;
        };
        if let Some(Definition::Unique {
            page,
            action,
            selected,
            ..
        }) = definitions.get_mut(&id)
            && match request {
                Destination::Page(_) => *page,
                _ => *action,
            }
        {
            *selected = true;
        } else {
            objects[owner].unsupported = true;
        }
    }
    for (id, definition) in definitions {
        if let Definition::Unique {
            start,
            body,
            selected: true,
            ..
        } = definition
        {
            objects.push(Object {
                id,
                start,
                raw_destination: true,
                encoded: Some(body),
                ..Object::default()
            });
        }
    }
    objects.sort_unstable_by_key(|obj| (obj.start, obj.raw_destination));
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_inside_dictionary_values() {
        let size = 5 * super::super::TOKEN_BLOCK;
        for (prefix, filler, suffix) in [
            (b"(".as_slice(), b'A', b")".as_slice()),
            (b"<", b'6', b">"),
            (b"/", b'R', b""),
            (b"%", b'T', b"\n(Receipt)"),
            (b"", b' ', b"(Receipt)"),
            (b"[", b' ', b"]"),
        ] {
            let mut value = prefix.to_vec();
            value.resize(size, filler);
            value.extend_from_slice(suffix);
            let body = [
                b"<< /Type /Catalog /Title ".as_slice(),
                &value,
                b" /OpenAction << /S /GoTo /D (Receipt) >> >>",
            ]
            .concat();
            let mut polls = 0;
            let dest = catalog(&body, &mut || {
                polls += 1;
                Ok(())
            })
            .unwrap();
            assert!(matches!(dest, Some(Destination::Inline)));
            assert!(polls >= 5);
            for fail_at in [1, 3] {
                let mut polls = 0;
                let error = catalog(&body, &mut || {
                    polls += 1;
                    if polls == fail_at {
                        Err(io::Error::other("PDF checkpoint"))
                    } else {
                        Ok(())
                    }
                })
                .err()
                .expect("cancellation must reach the caller");
                assert_eq!(error.to_string(), "PDF checkpoint");
                assert_eq!(polls, fail_at);
            }
        }
    }
}
