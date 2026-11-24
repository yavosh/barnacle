use super::{ChildSink, Key};
use std::io;

struct Bits<'a> {
    bytes: &'a [u8],
    key: Key,
    bits: u32,
    count: usize,
}

impl Bits<'_> {
    fn read(&mut self, n: usize) -> Option<usize> {
        while self.count < n {
            let byte = *self.bytes.split_off_first()?;
            self.bits = (self.bits << 8) | u32::from(self.key.decode(byte));
            self.count += 8;
        }
        self.count -= n;
        Some(((self.bits >> self.count) & ((1 << n) - 1)) as usize)
    }

    fn length(&mut self, remaining: usize, sink: &mut dyn ChildSink) -> io::Result<Option<usize>> {
        let mut n: usize = 3;
        let mut step = 0;
        loop {
            let width = [2, 3, 5, 8][step];
            let Some(add) = self.read(width) else {
                return Ok(None);
            };
            if n > remaining || add > remaining - n {
                return Ok(None);
            }
            n += add;
            if add != (1 << width) - 1 {
                return Ok(Some(n));
            }
            step = (step + 1).min(3);
            if step == 3 && self.bytes.len().is_multiple_of(4096) {
                sink.check()?;
            }
        }
    }
}

pub(super) struct Decoder<'a> {
    bits: Bits<'a>,
    history: Box<[u8]>,
    position: usize,
    written: usize,
    size: usize,
    pending: usize,
    distance: usize,
    failed: bool,
    literal_flag: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(input: &'a [u8], key: Key, size: usize, literal_one: bool) -> Self {
        Self {
            bits: Bits {
                // The packed stream is read in complete 16-bit words.
                bytes: &input[..input.len() & !1],
                key,
                bits: 0,
                count: 0,
            },
            history: vec![0; size.min(32768)].into_boxed_slice(),
            position: 0,
            written: 0,
            size,
            pending: 0,
            distance: 0,
            failed: false,
            literal_flag: usize::from(literal_one),
        }
    }

    pub fn complete(&self) -> bool {
        self.written == self.size
    }

    pub fn read(&mut self, out: &mut [u8], sink: &mut dyn ChildSink) -> io::Result<usize> {
        if self.failed {
            return Ok(0);
        }
        let mut n = 0;
        for dst in out.iter_mut().take(self.size - self.written) {
            let mut literal = None;
            if self.pending == 0 {
                match self.bits.read(1) {
                    Some(flag) if flag == self.literal_flag => {
                        literal = self.bits.read(8).map(|v| v as u8)
                    }
                    Some(_) => {
                        if let Some(distance) = self.bits.read(15)
                            && distance > 0
                            && distance <= self.written
                            && let Some(count) = self.bits.length(self.size - self.written, sink)?
                        {
                            self.distance = distance;
                            self.pending = count;
                        }
                    }
                    _ => (),
                }
            }
            *dst = if let Some(b) = literal {
                b
            } else if self.pending != 0 {
                self.pending -= 1;
                let from = if self.position >= self.distance {
                    self.position - self.distance
                } else {
                    self.history.len() - (self.distance - self.position)
                };
                self.history[from]
            } else {
                self.failed = true;
                break;
            };
            self.history[self.position] = *dst;
            self.position += 1;
            if self.position == self.history.len() {
                self.position = 0;
            }
            self.written += 1;
            n += 1;
        }
        Ok(n)
    }
}
