//! Numeric input and diagnostic calls used by the CBC interpreter.
use super::{
    Address, BYTE_POINTER, Cursor, Frame, Global, I32, Slot, Value, Width, memory, unsupported,
};
use std::io::{self, Write};

const DEBUG_STRING: u64 = 6;
const DEBUG_UINT: u64 = 7;
const READ_NUMBER: u64 = 23;
const RUNTIME_ERROR: u64 = 42;
const DEBUG_START: u64 = 54;
const DEBUG_BYTES: u64 = 55;
const NUMBER_WINDOW: usize = 16;
const POLL_BYTES: usize = 256 * 1024;

pub(super) fn declaration(id: u64) -> Option<(&'static [u8], &'static [u64])> {
    Some(match id {
        DEBUG_STRING => (b"debug_print_str\0", &[I32, BYTE_POINTER, I32]),
        DEBUG_UINT => (b"debug_print_uint\0", &[I32, I32]),
        READ_NUMBER => (b"read_number\0", &[I32, I32]),
        RUNTIME_ERROR => (b"bytecode_rt_error\0", &[I32, I32]),
        DEBUG_START => (b"debug_print_str_start\0", &[I32, BYTE_POINTER, I32]),
        DEBUG_BYTES => (b"debug_print_str_nonl\0", &[I32, BYTE_POINTER, I32]),
        _ => return None,
    })
}

#[derive(Debug)]
pub(super) enum TextMode {
    Line,
    Start,
    Bytes,
}

#[derive(Debug)]
pub(super) enum Operation {
    Number(Value),
    RuntimeError(Value),
    DebugInt(Value),
    DebugText(Address, Value, TextMode),
}

pub(super) fn decode(
    id: u64,
    count: u64,
    line: &mut Cursor<'_>,
    slots: &[Slot],
    globals: &[Global],
) -> io::Result<Operation> {
    Ok(match (id, count) {
        (READ_NUMBER, 1) => Operation::Number(line.scalar(slots, Width::WORD)?),
        (RUNTIME_ERROR, 1) => Operation::RuntimeError(line.scalar(slots, Width::WORD)?),
        (DEBUG_UINT, 1) => Operation::DebugInt(line.scalar(slots, Width::WORD)?),
        (DEBUG_STRING | DEBUG_START | DEBUG_BYTES, 2) => {
            let source = Address::decode(line, slots, globals, false)?;
            let len = line.scalar(slots, Width::WORD)?;
            let mode = match id {
                DEBUG_STRING => TextMode::Line,
                DEBUG_START => TextMode::Start,
                _ => TextMode::Bytes,
            };
            Operation::DebugText(source, len, mode)
        }
        _ => return Err(unsupported("host call argument count")),
    })
}

impl Operation {
    pub(super) fn eval(
        &self,
        frame: &mut Frame<'_>,
        input: &[u8],
        debug: bool,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<u64>> {
        let result = match self {
            Self::Number(radix) => {
                let radix = radix.get(frame) as u32;
                read_number(input, &mut frame.cursor, radix, check)?
            }
            Self::RuntimeError(location) => {
                let location = location.get(frame) as i32;
                let _ = writeln!(
                    io::stderr().lock(),
                    "barnacle: bytecode runtime error at line {}, col {}",
                    (location >> 8) as u32,
                    location & 255
                );
                0
            }
            Self::DebugInt(value) if debug => {
                let printed = (value.get(frame) as i32).to_string();
                io::stderr()
                    .lock()
                    .write_all(printed.as_bytes())
                    .map_or(u32::MAX, |_| printed.len() as u32)
            }
            Self::DebugInt(_) => 0,
            Self::DebugText(address, len, mode) => {
                let len = len.get(frame) as usize;
                let Some(bytes) = memory::outcome(address.read(frame, len))? else {
                    return Ok(None);
                };
                if len == 0 && !matches!(mode, TextMode::Line) {
                    return Ok(Some(u32::MAX.into()));
                }
                if !debug {
                    return Ok(Some(0));
                }
                let mut output = io::stderr().lock();
                if matches!(mode, TextMode::Bytes) {
                    return Ok(Some(output.write(bytes).unwrap_or(0) as u64));
                }
                let bytes = if matches!(mode, TextMode::Line) {
                    let Some(available) = memory::outcome(address.remaining(frame))? else {
                        return Ok(None);
                    };
                    let end = memchr::memchr(0, available)
                        .ok_or_else(|| unsupported("unterminated diagnostic string"))?;
                    &available[..end]
                } else {
                    &bytes[..memchr::memchr(0, bytes).unwrap_or(bytes.len())]
                };
                let _ = output.write_all(b"barnacle: bytecode debug: ");
                let _ = output.write_all(bytes);
                if matches!(mode, TextMode::Line) {
                    let _ = output.write_all(b"\n");
                }
                0
            }
        };
        Ok(Some(u64::from(result)))
    }
}

fn read_number(
    input: &[u8],
    cursor: &mut usize,
    radix: u32,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<u32> {
    if !matches!(radix, 10 | 16) {
        return Ok(u32::MAX);
    }

    let digit = |byte: u8| char::from(byte).to_digit(radix);
    let mut inspected = 0;
    loop {
        let Some(window) = input[*cursor..].get(..NUMBER_WINDOW) else {
            return Ok(u32::MAX);
        };
        if let Some(offset) = window.iter().position(|&byte| digit(byte).is_some()) {
            let start = *cursor + offset;
            let tail = &input[start..];
            if tail.len() < NUMBER_WINDOW {
                return Ok(u32::MAX);
            }

            let mut consumed = 0;
            if radix == 16 && matches!(tail[..2], [b'0', b'x' | b'X']) && digit(tail[2]).is_some() {
                consumed = 2;
            }
            let mut number = 0u64;
            for (i, &byte) in tail[consumed..].iter().enumerate() {
                let Some(value) = digit(byte) else {
                    break;
                };
                if i != 0 && i % POLL_BYTES == 0 {
                    check()?;
                }
                number = number
                    .saturating_mul(u64::from(radix))
                    .saturating_add(u64::from(value));
                consumed += 1;
            }
            *cursor = start + consumed;
            return Ok(number as u32);
        }
        *cursor += NUMBER_WINDOW;
        inspected += NUMBER_WINDOW;
        if inspected == POLL_BYTES {
            inspected = 0;
            check()?;
        }
    }
}
