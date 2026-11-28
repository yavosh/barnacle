//! Read-only CBC queries against the PDF parser's current phase.
use super::{Cursor, Frame, I32, Slot, Value, Width, unsupported};
use crate::bytecode::{PdfHookContext, PdfPhase};
use std::io;

const COUNT: u64 = 77;
const FLAGS: u64 = 78;
const LOOKUP: u64 = 80;
const SIZE: u64 = 81;
const OFFSET: u64 = 86;
const PHASE: u64 = 87;

pub(super) fn declaration(id: u64) -> Option<(&'static [u8], &'static [u64])> {
    Some(match id {
        COUNT => (b"pdf_get_obj_num\0", &[I32]),
        FLAGS => (b"pdf_get_flags\0", &[I32]),
        LOOKUP => (b"pdf_lookupobj\0", &[I32, I32]),
        SIZE => (b"pdf_getobjsize\0", &[I32, I32]),
        OFFSET => (b"pdf_get_offset\0", &[I32, I32]),
        PHASE => (b"pdf_get_phase\0", &[I32]),
        _ => return None,
    })
}

#[derive(Debug)]
pub(super) enum Query {
    Count,
    Flags,
    Lookup(Value),
    Size(Value),
    Offset(Value),
    Phase,
}

impl Query {
    pub(super) fn decode(
        id: u64,
        count: u64,
        line: &mut Cursor<'_>,
        slots: &[Slot],
    ) -> io::Result<Self> {
        Ok(match (id, count) {
            (COUNT, 0) => Self::Count,
            (FLAGS, 0) => Self::Flags,
            (PHASE, 0) => Self::Phase,
            (LOOKUP, 1) => Self::Lookup(line.scalar(slots, Width::WORD)?),
            (SIZE, 1) => Self::Size(line.scalar(slots, Width::WORD)?),
            (OFFSET, 1) => Self::Offset(line.scalar(slots, Width::WORD)?),
            _ => return Err(unsupported("PDF API argument count")),
        })
    }

    pub(super) fn eval(
        &self,
        frame: &Frame<'_>,
        context: Option<PdfHookContext<'_>>,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<u32> {
        let Some(pdf) = context else {
            return Ok(if matches!(self, Self::Phase | Self::Size(_)) {
                0
            } else {
                u32::MAX
            });
        };
        let objects = || {
            pdf.objects
                .ok_or_else(|| unsupported("PDF object table for this phase"))
        };
        let value = match self {
            Self::Phase => pdf.phase as u32,
            Self::Flags => pdf
                .flags
                .ok_or_else(|| unsupported("PDF flags for this phase"))?,
            Self::Count => objects()?.len() as u32,
            Self::Lookup(id) => {
                let id = id.get(frame) as u32;
                for (i, obj) in objects()?.iter().enumerate() {
                    if i.is_multiple_of(4096) {
                        check()?;
                    }
                    if obj.id == id {
                        return Ok(i as u32);
                    }
                }
                u32::MAX
            }
            Self::Size(_) if pdf.phase == PdfPhase::PostDump => 0,
            Self::Size(index) => {
                let i = index.get(frame) as u32 as usize;
                let objects = objects()?;
                let Some(obj) = objects.get(i) else {
                    return Ok(0);
                };
                // These ABI results are unsigned 32-bit differences, including packed objects.
                if let Some(next) = objects.get(i + 1) {
                    next.start.wrapping_sub(obj.start).wrapping_sub(4)
                } else {
                    (pdf.size as u32).wrapping_sub(obj.start)
                }
            }
            Self::Offset(index) => objects()?
                .get(index.get(frame) as u32 as usize)
                .map_or(u32::MAX, |obj| (pdf.start as u32).wrapping_add(obj.start)),
        };
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::PdfHookObject;

    #[test]
    fn queries_preserve_phase_sentinels_and_require_metadata_on_demand() -> io::Result<()> {
        let objects = [
            PdfHookObject { id: 10, start: 12 },
            PdfHookObject { id: 20, start: 34 },
        ];
        let pdf = PdfHookContext {
            phase: PdfPhase::Parsed,
            flags: Some(42),
            objects: Some(&objects),
            start: 2,
            size: 54,
        };
        let frame = Frame::new(&[]);
        let eval = |query: Query, pdf| query.eval(&frame, pdf, &mut || Ok(()));
        let at = Value::Constant;
        assert_eq!(eval(Query::Lookup(at(20)), Some(pdf))?, 1);
        assert_eq!(eval(Query::Count, Some(pdf))?, 2);
        assert_eq!(eval(Query::Flags, Some(pdf))?, 42);
        assert_eq!(eval(Query::Size(at(0)), Some(pdf))?, 18);
        assert_eq!(eval(Query::Size(at(1)), Some(pdf))?, 20);
        assert_eq!(eval(Query::Size(at(2)), Some(pdf))?, 0);
        assert_eq!(eval(Query::Offset(at(1)), Some(pdf))?, 36);
        assert_eq!(eval(Query::Offset(at(2)), Some(pdf))?, u32::MAX);
        let post = Some(PdfHookContext {
            phase: PdfPhase::PostDump,
            objects: None,
            flags: None,
            ..pdf
        });
        assert_eq!(eval(Query::Size(at(0)), post)?, 0);
        assert_eq!(eval(Query::Phase, post)?, 2);
        assert_eq!(
            eval(Query::Flags, post).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            eval(Query::Count, post).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(eval(Query::Phase, None)?, 0);
        assert_eq!(eval(Query::Count, None)?, u32::MAX);
        Ok(())
    }
}
