//! Numeric checks relative to a logical subsignature match.
use super::invalid;
use std::{cmp::Ordering, io};

const HEX_WIDTH: usize = 18;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Notation {
    Binary,
    Decimal,
    Hex,
    Auto,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Endian {
    Big,
    Little,
}

struct Format {
    notation: Option<Notation>,
    endian: Option<Endian>,
    exact: bool,
    width: usize,
}

struct Condition {
    order: Ordering,
    value: i64,
}

pub(super) struct ByteCompare {
    pub(super) slot: usize,
    pub(super) trigger: usize,
    shift: i32,
    format: Format,
    condition: Condition,
    second: Option<Condition>,
}

impl ByteCompare {
    pub(super) fn parse(text: &str, slot: usize) -> io::Result<Self> {
        let (trigger, body) = text
            .split_once('(')
            .ok_or_else(|| invalid("missing byte comparison trigger"))?;
        let trigger = trigger
            .parse()
            .ok()
            .filter(|&id| id < 64)
            .ok_or_else(|| invalid("invalid byte comparison trigger"))?;
        let body = body
            .strip_suffix(')')
            .ok_or_else(|| invalid("unclosed byte comparison"))?;
        let mut fields = body.split('#');
        let [Some(shift), Some(format), Some(conditions), None] =
            [fields.next(), fields.next(), fields.next(), fields.next()]
        else {
            return Err(invalid(
                "expected byte comparison offset, format, and conditions",
            ));
        };
        let shift = if let Some(n) = shift.strip_prefix(">>") {
            integer(n)?.try_into().ok()
        } else if let Some(n) = shift.strip_prefix("<<") {
            integer(n)?.checked_neg().and_then(|n| n.try_into().ok())
        } else if matches!(shift, "" | "0") {
            Some(0)
        } else {
            None
        }
        .ok_or_else(|| invalid("invalid byte comparison offset"))?;
        let format = Format::parse(format)?;
        let mut conditions = conditions.split(',');
        let condition = Condition::parse(conditions.next().unwrap_or_default())?;
        let second = conditions.next().map(Condition::parse).transpose()?;
        if conditions.next().is_some() {
            return Err(invalid("too many byte comparison conditions"));
        }
        Ok(Self {
            slot,
            trigger,
            shift,
            format,
            condition,
            second,
        })
    }

    pub(super) fn matches(&self, bytes: &[u8], trigger_offset: usize) -> bool {
        trigger_offset
            .checked_add_signed(self.shift as isize)
            .filter(|&start| start > 0)
            .and_then(|start| bytes.get(start..))
            .and_then(|rest| rest.get(..self.format.width))
            .and_then(|field| self.format.read(field))
            .is_some_and(|value| {
                self.condition.accepts(value)
                    && self.second.as_ref().is_none_or(|c| c.accepts(value))
            })
    }
}

impl Condition {
    fn parse(text: &str) -> io::Result<Self> {
        let (sign, value) = text
            .split_at_checked(1)
            .ok_or_else(|| invalid("missing byte comparison condition"))?;
        let order = match sign {
            "<" => Ordering::Less,
            ">" => Ordering::Greater,
            "=" => Ordering::Equal,
            _ => return Err(invalid("unsupported byte comparison operator")),
        };
        Ok(Self {
            order,
            value: integer(value)?,
        })
    }

    fn accepts(&self, value: i64) -> bool {
        value.cmp(&self.value) == self.order
    }
}

impl Format {
    fn parse(text: &str) -> io::Result<Self> {
        let n = text
            .find(|ch: char| !ch.is_ascii_alphabetic())
            .ok_or_else(|| invalid("missing byte comparison width"))?;
        let (flags, width) = text.split_at(n);
        let mut notation = None;
        let mut endian = None;
        let mut exact = false;
        for flag in flags.bytes() {
            let next_notation = match flag {
                b'i' => Some(Notation::Binary),
                b'd' => Some(Notation::Decimal),
                b'h' => Some(Notation::Hex),
                b'a' => Some(Notation::Auto),
                b'b' | b'l' => {
                    let next = if flag == b'b' {
                        Endian::Big
                    } else {
                        Endian::Little
                    };
                    if endian.is_some_and(|old| old != next) {
                        return Err(invalid("conflicting byte comparison byte order"));
                    }
                    endian = Some(next);
                    None
                }
                b'e' => {
                    exact = true;
                    None
                }
                _ => return Err(invalid("unknown byte comparison format flag")),
            };
            if let Some(next) = next_notation {
                if notation.is_some_and(|old| old != next) {
                    return Err(invalid("conflicting byte comparison number formats"));
                }
                notation = Some(next);
            }
        }
        if notation == Some(Notation::Decimal) {
            if endian == Some(Endian::Little) {
                return Err(invalid("decimal byte comparisons require big endian"));
            }
            endian = Some(Endian::Big);
        }
        let width = u32::try_from(integer(width)?)
            .ok()
            .filter(|&n| n != 0)
            .ok_or_else(|| invalid("invalid byte comparison width"))? as usize;
        if (notation == Some(Notation::Binary) && !matches!(width, 1 | 2 | 4 | 8))
            || (notation == Some(Notation::Hex) && width > HEX_WIDTH)
        {
            return Err(invalid("unsupported byte comparison width for this format"));
        }
        Ok(Self {
            notation,
            endian,
            exact,
            width,
        })
    }

    fn read(&self, bytes: &[u8]) -> Option<i64> {
        let endian = self.endian?;
        let mut notation = self.notation?;
        if notation == Notation::Binary {
            let mut value = [0; 8];
            return Some(match endian {
                Endian::Big => {
                    value[8 - bytes.len()..].copy_from_slice(bytes);
                    i64::from_be_bytes(value)
                }
                Endian::Little => {
                    value[..bytes.len()].copy_from_slice(bytes);
                    i64::from_le_bytes(value)
                }
            });
        }
        let trimmed = bytes.trim_ascii_start();
        let prefixed = trimmed.len() >= 3 && matches!(trimmed, [b'0', b'x' | b'X', ..]);
        if self.exact && trimmed.len() != bytes.len() {
            return None;
        }
        if notation == Notation::Auto {
            if trimmed.len() < 3 {
                return None;
            }
            notation = if prefixed {
                Notation::Hex
            } else {
                Notation::Decimal
            };
        }
        let number = match (notation, endian) {
            (Notation::Decimal, Endian::Big) => prefix(trimmed.iter().copied(), 10),
            (Notation::Hex, Endian::Big) => prefix(trimmed.iter().copied(), 16),
            (Notation::Hex, Endian::Little) => read_reversed_hex(trimmed, prefixed),
            _ => return None,
        };
        (!number.overflow && (!self.exact || number.used == bytes.len())).then_some(number.value)
    }
}

struct Number {
    value: i64,
    used: usize,
    overflow: bool,
}

fn integer(text: &str) -> io::Result<i64> {
    let text = text.as_bytes().trim_ascii_start();
    let number = prefix(text.iter().copied(), 0);
    if number.used == text.len() && number.used != 0 {
        Ok(number.value)
    } else {
        Err(invalid("expected a byte comparison integer"))
    }
}

fn prefix(mut bytes: impl Iterator<Item = u8> + Clone, mut base: u32) -> Number {
    let sign = bytes.clone().next().filter(|b| matches!(b, b'+' | b'-'));
    let negative = sign == Some(b'-');
    let mut prefix_width = usize::from(sign.is_some());
    if sign.is_some() {
        bytes.next();
    }
    let mut beginning = bytes.clone();
    let first = beginning.next();
    // Stock's subject parser handles a signed hex value without removing 0x.
    // Its rule parser accepts a sign before the radix marker.
    let prefixed = first == Some(b'0')
        && matches!(beginning.next(), Some(b'x' | b'X'))
        && match base {
            0 => beginning.next().is_some_and(|b| b.is_ascii_hexdigit()),
            16 => sign.is_none(),
            _ => false,
        };
    if prefixed {
        bytes.next();
        bytes.next();
        prefix_width += 2;
        base = 16;
    } else if base == 0 {
        base = if first == Some(b'0') { 8 } else { 10 };
    }
    let mut value = 0i64;
    let mut used = 0;
    let mut overflow = false;
    for byte in bytes {
        let Some(digit) = char::from(byte).to_digit(base) else {
            break;
        };
        if !overflow {
            let digit = if negative {
                -i64::from(digit)
            } else {
                i64::from(digit)
            };
            if let Some(next) = value
                .checked_mul(i64::from(base))
                .and_then(|n| n.checked_add(digit))
            {
                value = next;
            } else {
                overflow = true;
                value = if negative { i64::MIN } else { i64::MAX };
            }
        }
        used += 1;
    }
    Number {
        value,
        used: if used == 0 { 0 } else { prefix_width + used },
        overflow,
    }
}

fn read_reversed_hex(bytes: &[u8], prefixed: bool) -> Number {
    if bytes.len() <= 1 {
        return prefix(bytes.iter().copied(), 16);
    }
    let pad = bytes.len() % 2;
    let length = bytes.len() + pad;
    let original_byte = |at: usize| {
        if prefixed && at == 0 {
            b'x'
        } else if prefixed && pad != 0 && at < 3 {
            b'0'
        } else {
            at.checked_sub(pad).map_or(b'0', |i| bytes[i])
        }
    };
    // Invalid pairs erase the bytes processed so far in stock's right-to-left pass.
    let zero_until = (0..length)
        .step_by(2)
        .find(|&at| {
            [original_byte(at), original_byte(at + 1)]
                .iter()
                .any(|b| !b.is_ascii_hexdigit() && !matches!(b, b'x' | b'X'))
        })
        .map_or(0, |at| length - at);
    let reversed = (0..length).map(|i| {
        if i < zero_until {
            b'0'
        } else {
            original_byte(length - 2 - (i & !1) + i % 2)
        }
    });
    prefix(reversed, 16)
}
