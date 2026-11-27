//! PCRE subsignatures evaluated after the indexed patterns for one object.
use super::logic_expression::Expression;
use super::pcre::{Code, MatchError, Session};
use super::{ObjectContext, Offset, Target, invalid};
use pcre2_sys::{
    PCRE2_ANCHORED, PCRE2_CASELESS, PCRE2_DOLLAR_ENDONLY, PCRE2_DOTALL, PCRE2_EXTENDED,
    PCRE2_MULTILINE, PCRE2_UNGREEDY,
};
use std::io;

const HEAP_KIB: u32 = 8 * 1024;

/// PCRE limits for one immutable signature generation.
#[derive(Clone, Copy, Debug)]
pub struct PcreLimits {
    /// Skip PCRE on larger objects. Zero disables this size limit.
    pub max_file_size: u64,
    /// Maximum PCRE match effort per starting position.
    pub match_limit: u32,
    /// Maximum PCRE backtracking depth.
    pub depth_limit: u32,
}

impl Default for PcreLimits {
    fn default() -> Self {
        Self {
            max_file_size: 100 << 20,
            match_limit: 100_000,
            depth_limit: 2_000,
        }
    }
}

pub(super) struct RegexChild {
    pub(super) slot: usize,
    pub(super) trigger: Expression,
    offset: Offset,
    code: Code,
    global: bool,
    encompass: bool,
}

impl RegexChild {
    pub(super) fn parse(field: &str, target: Target, slot: usize) -> io::Result<Self> {
        let (prefix, regex) = field
            .split_once('/')
            .ok_or_else(|| invalid("missing PCRE opening slash"))?;
        let (regex, options) = regex
            .rsplit_once('/')
            .ok_or_else(|| invalid("missing PCRE closing slash"))?;
        if regex.is_empty() {
            return Err(invalid("empty PCRE subsignature"));
        }
        let (position, trigger) = prefix.split_once(':').unwrap_or(("*", prefix));
        let offset = Offset::parse(position, target)?;
        let trigger = Expression::trigger(trigger, slot)?;
        let options = options
            .split_once("::")
            .map_or(options, |(options, _)| options);
        let mut flags = 0;
        let mut global = false;
        let mut rolling = false;
        let mut encompass = false;
        for option in options.bytes() {
            flags |= match option {
                b'A' => PCRE2_ANCHORED,
                b'E' => PCRE2_DOLLAR_ENDONLY,
                b'U' => PCRE2_UNGREEDY,
                b'i' => PCRE2_CASELESS,
                b'm' => PCRE2_MULTILINE,
                b's' => PCRE2_DOTALL,
                b'x' => PCRE2_EXTENDED,
                b'g' => {
                    global = true;
                    0
                }
                b'r' => {
                    rolling = true;
                    0
                }
                b'e' => {
                    encompass = true;
                    0
                }
                _ => return Err(invalid("unsupported PCRE option")),
            };
        }
        if !rolling && !offset.is_any() && !offset.has_shift() {
            flags |= PCRE2_ANCHORED;
        }
        Ok(Self {
            slot,
            trigger,
            offset,
            code: Code::compile(regex.as_bytes(), flags)?,
            global,
            encompass,
        })
    }

    pub(super) fn count(
        &self,
        bytes: &[u8],
        context: &ObjectContext,
        limits: PcreLimits,
        scratch: &mut Option<Session>,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<u32> {
        let Some(range) = context.offset_range(&self.offset, bytes.len()) else {
            return Ok(0);
        };
        let start = *range.start();
        let end = *range.end();
        let subject = if self.encompass && self.offset.has_shift() {
            &bytes[start..end]
        } else {
            &bytes[start..]
        };
        let max_start = if self.offset.has_shift() {
            (end - start).min(subject.len())
        } else {
            subject.len()
        };
        if scratch.is_none() {
            *scratch = Some(Session::new(
                limits.match_limit,
                limits.depth_limit,
                HEAP_KIB,
            )?);
        }
        let scratch = scratch.as_mut().unwrap();
        let mut count = 0u32;
        let mut next = 0;
        while next <= max_start {
            let hit = match scratch.find(&self.code, subject, next, max_start, check) {
                Ok(hit) => hit,
                Err(
                    MatchError::MatchLimit
                    | MatchError::DepthLimit
                    | MatchError::PatternHeapLimit
                    | MatchError::UtfSubject
                    | MatchError::UtfOffset,
                ) => break,
                Err(MatchError::HeapLimit) => {
                    return Err(io::Error::other("PCRE heap limit exceeded"));
                }
                Err(MatchError::Check(error) | MatchError::Engine(error)) => return Err(error),
            };
            let Some((from, to)) = hit else {
                break;
            };
            if from > max_start {
                break;
            }
            count = count.wrapping_add(1);
            if !self.global {
                break;
            }
            // Empty matches consume no bytes. Always advance before checking again.
            next = to;
            if from == to {
                next += 1;
                if self.code.is_utf() {
                    while subject.get(next).is_some_and(|&byte| byte & 0xc0 == 0x80) {
                        next += 1;
                    }
                }
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_empty_matches_advance_by_code_point() -> io::Result<()> {
        let rule = RegexChild::parse("0/(*UTF)(?=.)/g", Target::Generic, 1)?;
        let bytes = "été".as_bytes();
        let context = ObjectContext::raw(bytes);
        let mut polls = 0;
        let found = rule.count(
            bytes,
            &context,
            PcreLimits::default(),
            &mut None,
            &mut || {
                polls += 1;
                if polls > 30 {
                    return Err(io::Error::other("empty regex stopped advancing"));
                }
                Ok(())
            },
        )?;
        assert_eq!(found, 3);
        Ok(())
    }
}
