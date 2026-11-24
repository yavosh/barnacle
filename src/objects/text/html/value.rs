//! Borrow the source blocks used by the reference HTML attribute parser.
use super::{ChildSink, Url, View, entities};
use std::io;

const BLOCK: usize = 8191;

#[derive(Clone, Copy)]
pub(super) struct Blocks<'a> {
    source: &'a [u8],
    keep: usize,
    end: usize,
    trim: bool,
}

impl<'a> Blocks<'a> {
    pub(super) fn new(source: &'a [u8], trim: bool) -> Self {
        Self {
            source,
            keep: 0,
            end: if source.len() <= BLOCK {
                source.len()
            } else {
                0
            },
            trim,
        }
    }

    fn seek(&mut self, pos: usize, sink: &mut dyn ChildSink) -> io::Result<()> {
        let space = |b: u8| matches!(b, b' ' | b'\t'..=b'\r');
        while self.end <= pos && self.end < self.source.len() {
            sink.check()?;
            let start = self.end;
            self.end = (start + BLOCK).min(self.source.len());
            self.keep = start;
            if !self.trim {
                continue;
            }
            let raw = &self.source[start..self.end];
            if raw.contains(&0) {
                // Stock fills a block with nonzero bytes, then rewinds in original offsets.
                let mut count = 0;
                let mut last_space = None;
                self.end = start;
                'fill: for part in self.source[start..].chunks(BLOCK) {
                    sink.check()?;
                    for &b in part {
                        self.end += 1;
                        if b != 0 {
                            if space(b) {
                                last_space = Some(count);
                            }
                            count += 1;
                            if count == BLOCK {
                                break 'fill;
                            }
                        }
                    }
                }
                if self.source.get(self.end).is_some_and(|&b| !space(b))
                    && let Some(i) = last_space.filter(|&i| i > 0)
                {
                    self.end -= count - i - 1;
                }
            } else if self.source.get(self.end).is_some_and(|&b| !space(b))
                && let Some(i) = raw.iter().rposition(|&b| space(b))
                && i > 0
            {
                self.end = start + i + 1;
            }
            for part in self.source[start..self.end].chunks(BLOCK) {
                let skip = part.iter().take_while(|&&b| space(b) || b == 0).count();
                self.keep += skip;
                if skip < part.len() {
                    break;
                }
                sink.check()?;
            }
        }
        Ok(())
    }

    pub(super) fn value(
        &mut self,
        tail: &'a [u8],
        sink: &mut dyn ChildSink,
    ) -> io::Result<Value<'a>> {
        let pos = self.source.len() - tail.len();
        self.seek(pos, sink)?;
        Ok(Value {
            blocks: *self,
            pos,
            end: self.source.len(),
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct Value<'a> {
    pub(super) blocks: Blocks<'a>,
    pos: usize,
    end: usize,
}

impl<'a> Value<'a> {
    fn slice(&mut self, sink: &mut dyn ChildSink) -> io::Result<&'a [u8]> {
        while self.pos < self.end {
            self.blocks.seek(self.pos, sink)?;
            self.pos = self.pos.max(self.blocks.keep).min(self.end);
            let end = self
                .end
                .min(self.blocks.end)
                .min(self.pos.saturating_add(BLOCK));
            if self.pos < end {
                return Ok(&self.blocks.source[self.pos..end]);
            }
        }
        Ok(&[])
    }

    pub(super) fn length(
        mut self,
        delimiter: impl Fn(u8) -> bool,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Option<usize>> {
        let start = self.pos;
        loop {
            let span = self.slice(sink)?;
            if span.is_empty() {
                return Ok(None);
            }
            if let Some(i) = span.iter().position(|&b| delimiter(b)) {
                return Ok(Some(self.pos - start + i));
            }
            self.pos += span.len();
            if span.len() == BLOCK {
                sink.check()?;
            }
        }
    }

    pub(super) fn limit(&mut self, size: usize) {
        self.end = self.pos + size;
    }

    pub(super) fn next(&mut self, sink: &mut dyn ChildSink) -> io::Result<Option<u8>> {
        while self.pos < self.end {
            if (self.pos >= self.blocks.end || self.pos < self.blocks.keep)
                && self.slice(sink)?.is_empty()
            {
                break;
            }
            let b = self.blocks.source[self.pos];
            self.pos += 1;
            if !matches!(b, 0 | b'\r') {
                return Ok(Some(b));
            }
            if self.pos.is_multiple_of(8192) {
                sink.check()?;
            }
        }
        Ok(None)
    }

    pub(super) fn split_data(mut self, sink: &mut dyn ChildSink) -> io::Result<bool> {
        for &expected in b"data:" {
            if self.next(sink)? != Some(expected) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn repeat_byte(&mut self) {
        self.pos -= 1;
    }

    pub(super) fn reference(
        &mut self,
        full: &mut View,
        url: Option<&mut Url>,
        sink: &mut dyn ChildSink,
    ) -> io::Result<bool> {
        self.repeat_byte(); // Include the ampersand just returned by next().
        let span = self.slice(sink)?;
        let Some((reference, used)) = entities::parse(span) else {
            return Ok(false);
        };
        if (span.len() == used && self.pos + used == self.end)
            || span.get(used).is_some_and(|b| !matches!(b, 0 | b'\r'))
            || span[used - 1] == b';'
        {
            reference.write(full, url)?;
            self.pos += used;
            return Ok(true);
        }
        // Cross-block or CR-split references need at most an ampersand, 1,024 token
        // bytes and a terminator. Keep ordinary references borrowed above.
        let mut token = [0; 1026];
        let mut len = 0;
        let mut cursor = *self;
        while len < token.len()
            && let Some(b) = cursor.next(sink)?
        {
            token[len] = b;
            len += 1;
            if len > 1 && !b.is_ascii_alphanumeric() && !b"-_:#".contains(&b) {
                break;
            }
        }
        let Some((reference, used)) = entities::parse(&token[..len]) else {
            return Ok(false);
        };
        reference.write(full, url)?;
        for _ in 0..used {
            self.next(sink)?;
        }
        Ok(true)
    }
}
