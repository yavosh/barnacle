//! Metadata attached to one PDF parser invocation, independent of its current input map.
use super::{ChildSink, Handling, Id, MAX_OBJECTS, PdfHookControl, TOKEN_BLOCK, number, white};
use crate::bytecode::{PdfHookContext, PdfHookObject, PdfPhase};
use memchr::memmem;
use std::io;

pub(super) struct Hooks<'a> {
    parent: &'a [u8],
    start: usize,
    objects: Option<Vec<PdfHookObject>>,
    physical_end: usize,
    flags: Option<u32>,
    known_nonzero: bool,
}

impl<'a> Hooks<'a> {
    pub fn new(parent: &'a [u8], start: usize) -> Self {
        let flags = header_flags(parent, start);
        Self {
            parent,
            start,
            objects: Some(Vec::new()),
            physical_end: 0,
            flags,
            known_nonzero: flags.is_some_and(|v| v != 0),
        }
    }

    pub fn run(
        &self,
        phase: PdfPhase,
        input: &[u8],
        sink: &mut dyn ChildSink,
    ) -> io::Result<PdfHookControl> {
        sink.check()?;
        sink.run_pdf_hooks(
            input,
            PdfHookContext {
                phase,
                flags: self.flags,
                objects: self.objects.as_deref(),
                start: self.start,
                size: self.parent.len() - self.start,
            },
        )
    }

    pub fn parent_phase(
        &self,
        phase: PdfPhase,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Option<Handling>> {
        Ok(match self.run(phase, self.parent, sink)? {
            PdfHookControl::Continue => None,
            PdfHookControl::Break => Some(Handling::Complete),
            PdfHookControl::Found => Some(Handling::Stopped),
        })
    }

    pub fn finish(&self, sink: &mut dyn ChildSink) -> io::Result<Option<Handling>> {
        if self.known_nonzero {
            return self.parent_phase(PdfPhase::End, sink);
        }
        Ok(self.flags.is_none().then_some(Handling::Incomplete))
    }

    pub fn obfuscated_name(&mut self) {
        self.known_nonzero = true;
        if let Some(flags) = &mut self.flags {
            *flags |= 1 << 11;
        }
    }

    pub fn unknown_flags(&mut self) {
        self.flags = None;
    }

    pub fn unknown_objects(&mut self) {
        self.objects = None;
    }

    pub fn add_object(&mut self, id: Id, start: usize) {
        if let Some(list) = &mut self.objects {
            if let (Ok(n), Ok(start)) = (u32::try_from(id.0), u32::try_from(start))
                && list.len() < MAX_OBJECTS
            {
                list.push(PdfHookObject {
                    id: (n << 8) | (id.1 as u32 & 255),
                    start,
                });
            } else {
                self.objects = None;
            }
        }
    }

    pub fn physical(
        &mut self,
        id: Id,
        start: usize,
        end: usize,
        sink: &mut dyn ChildSink,
    ) -> io::Result<()> {
        let data = &self.parent[self.start..];
        // Stock scans for raw object and end markers. The tokenizer can skip these
        // inside comments, strings and stream content. Keep only identical boundaries.
        let head = &data[self.physical_end..start - 3];
        let suffix = &head[head.len().saturating_sub(96)..];
        let mut p = suffix.len();
        let field = |pos: &mut usize| {
            let end = *pos;
            while *pos != 0 && white(suffix[*pos - 1]) {
                *pos -= 1;
            }
            let digits_end = *pos;
            while *pos != 0 && suffix[*pos - 1].is_ascii_digit() {
                *pos -= 1;
            }
            (digits_end < end && *pos != digits_end && *pos > 0 && white(suffix[*pos - 1]))
                .then(|| number(&suffix[*pos..digits_end]))
                .flatten()
        };
        let generation = field(&mut p);
        let object = field(&mut p);
        if generation != Some(id.1)
            || object != Some(id.0)
            || contains(head, b"obj", sink)?
            || contains(&data[start..end - 6], b"endobj", sink)?
        {
            self.unknown_objects();
            self.unknown_flags();
        }
        // The tokenizer skips comments. Stock's raw dictionary scan can still
        // recognize names in those bytes, so the exact flags are unknown.
        if self.flags.is_some() && contains(&data[start..end - 6], b"%", sink)? {
            self.unknown_flags();
        }
        self.physical_end = end;
        self.add_object(id, start);
        Ok(())
    }

    pub fn finish_discovery(&mut self, sink: &mut dyn ChildSink) -> io::Result<()> {
        if contains(&self.parent[self.start + self.physical_end..], b"obj", sink)? {
            self.unknown_objects();
            self.unknown_flags();
        }
        Ok(())
    }
}

fn contains(data: &[u8], pattern: &[u8], sink: &mut dyn ChildSink) -> io::Result<bool> {
    let finder = memmem::Finder::new(pattern);
    for start in (0..data.len()).step_by(TOKEN_BLOCK) {
        sink.check()?;
        if finder
            .find(&data[start..data.len().min(start + TOKEN_BLOCK + pattern.len() - 1)])
            .is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn header_flags(parent: &[u8], start: usize) -> Option<u32> {
    let data = &parent[start..];
    let version = data.get(5..8)?;
    let mut flags =
        u32::from(!(version[0] == b'1' && version[1] == b'.' && matches!(version[2], b'1'..=b'9')));
    flags |= u32::from(start != 0) << 1;
    let tail = &parent[parent.len().saturating_sub(2048)..];
    let xref = memmem::rfind(tail, b"%%EOF")
        .filter(|&n| n > 0)
        .and_then(|n| memmem::rfind(&tail[..n], b"startxref"))
        .filter(|&n| n > 0);
    let Some(xref) = xref else {
        return Some(flags | 4);
    };
    if memmem::find(tail, b"/Encrypt").is_some() {
        flags |= 1 << 17;
    }
    let arg = tail[xref + 9..].trim_ascii_start();
    let n = arg.iter().take_while(|b| b.is_ascii_digit()).count();
    if n == 0 {
        return None;
    }
    let offset = number(&arg[..n])?;
    let span = data.get(offset..).unwrap_or_default();
    let span = &span[..span.len().min(4096)];
    let p = span
        .iter()
        .position(|b| !matches!(b, b' ' | b'\r' | b'\n'))
        .unwrap_or(span.len());
    let span = &span[p..];
    if span.len() <= 4
        || (!span.starts_with(b"xref") && memmem::find(&span[..span.len() - 1], b"/XRef").is_none())
    {
        flags |= 4;
    }
    Some(flags)
}

/// These physical object tokens do not set flags during stock name parsing.
/// Other dictionaries can still use the phase, file and object APIs.
pub(super) fn passive_token(token: &[u8]) -> bool {
    if token.starts_with(b"/") && token.len() <= 64 && token.contains(&b'#') {
        return matches!(
            super::escaped_token(token, &mut [0; 63]),
            Some(b"Type" | b"Page")
        );
    }
    matches!(
        token,
        b"<<"
            | b">>"
            | b"["
            | b"]"
            | b"R"
            | b"endobj"
            | b"stream"
            | b"endstream"
            | b"/Type"
            | b"/Catalog"
            | b"/Pages"
            | b"/Page"
            | b"/Kids"
            | b"/Count"
            | b"/Parent"
            | b"/MediaBox"
            | b"/Length"
            | b"/EmbeddedFile"
            | b"/Names"
            | b"/EmbeddedFiles"
    ) || token.len() <= 20
        && token.first().is_some_and(u8::is_ascii_digit)
        && token.iter().all(u8::is_ascii_digit)
}
