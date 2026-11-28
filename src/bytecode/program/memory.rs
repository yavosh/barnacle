//! Checked local storage and file operations for a single CBC invocation.
use super::{Cursor, Global, Type, Value, Width, field, invalid, unsupported, user_type};
use std::{io, ops::Range, sync::Arc};

#[derive(Debug, Clone, Copy)]
pub(super) struct Slot {
    pub(super) ty: u64,
    pub(super) width: Option<Width>,
    start: usize,
    size: usize,
    pub(super) addressable: bool,
}

impl Slot {
    pub(super) fn new(
        ty: u64,
        addressable: bool,
        start: usize,
        types: &[Type],
    ) -> io::Result<Self> {
        let width = Width::new(ty).ok();
        let size = match (width, user_type(types, ty)) {
            (Some(w), _) => w.bytes(),
            (_, Some(Type::Bytes(n))) if addressable => *n,
            (_, _) if pointer_element(types, ty).is_some() && !addressable => 8,
            _ => return Err(unsupported("frame local type or storage")),
        };
        Ok(Self {
            ty,
            width,
            start,
            size,
            addressable,
        })
    }

    pub(super) fn end(&self) -> usize {
        self.start + self.size
    }

    fn object(&self) -> Range<usize> {
        self.start..self.end()
    }
}

fn pointer_element(types: &[Type], ty: u64) -> Option<u64> {
    match ty {
        65..=68 => Some(8 << (ty - 65)),
        _ => match user_type(types, ty)? {
            Type::Pointer(id) => Some(*id),
            _ => None,
        },
    }
}

impl Width {
    fn bytes(self) -> usize {
        self.0.div_ceil(8) as usize
    }
}

fn read_int(bytes: &[u8]) -> u64 {
    match *bytes {
        [a] => u64::from(a),
        [a, b] => u64::from(u16::from_ne_bytes([a, b])),
        [a, b, c, d] => u64::from(u32::from_ne_bytes([a, b, c, d])),
        [a, b, c, d, e, f, g, h] => u64::from_ne_bytes([a, b, c, d, e, f, g, h]),
        _ => unreachable!("validated integer width"),
    }
}

fn write_int(bytes: &mut [u8], n: u64) {
    match bytes.len() {
        1 => bytes[0] = n as u8,
        2 => bytes.copy_from_slice(&(n as u16).to_ne_bytes()),
        4 => bytes.copy_from_slice(&(n as u32).to_ne_bytes()),
        8 => bytes.copy_from_slice(&n.to_ne_bytes()),
        _ => unreachable!("validated integer width"),
    }
}

pub(super) struct Frame<'a> {
    slots: &'a [Slot],
    registers: Option<Vec<u64>>,
    bytes: Vec<u8>,
    pub(super) cursor: usize,
}

impl<'a> Frame<'a> {
    pub(super) fn new(slots: &'a [Slot]) -> Self {
        let addressable = slots.iter().any(|slot| slot.addressable);
        Self {
            slots,
            registers: (!addressable).then(|| vec![0; slots.len()]),
            bytes: if addressable {
                vec![0; slots.last().map_or(0, Slot::end)]
            } else {
                Vec::new()
            },
            cursor: 0,
        }
    }

    // The compiler emits scalar reads and writes only for integer or pointer slots.
    pub(super) fn get(&self, i: usize) -> u64 {
        if let Some(registers) = &self.registers {
            return registers[i];
        }
        let slot = self.slots[i];
        let value = read_int(&self.bytes[slot.object()]);
        if slot.ty == 1 { value & 1 } else { value }
    }

    pub(super) fn set(&mut self, i: usize, value: u64) {
        if let Some(registers) = &mut self.registers {
            // Scalar operations already restrict results to the destination width.
            registers[i] = value;
        } else {
            write_int(&mut self.bytes[self.slots[i].object()], value);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum MemoryFault {
    Null,
    Bounds,
    OverlappingCopy,
}

pub(super) fn outcome<T>(result: Result<T, MemoryFault>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(MemoryFault::Null) => Ok(None),
        Err(MemoryFault::OverlappingCopy) => Err(unsupported("overlapping MEMCPY ranges")),
        Err(MemoryFault::Bounds) => Err(unsupported("memory span outside its modeled object")),
    }
}

#[derive(Debug)]
pub(super) enum Address {
    Object(usize),
    Pointer(usize),
    Constant(Arc<[u8]>, usize),
}

impl Address {
    pub(super) fn decode(
        line: &mut Cursor<'_>,
        slots: &[Slot],
        globals: &[Global],
        writable: bool,
    ) -> io::Result<Self> {
        if matches!(line.first(), Some(b'@'..=b'P')) {
            if writable {
                return Err(unsupported("write to global bytes"));
            }
            let Global::Pointer { base, offset } = line.global(globals)? else {
                return Err(unsupported("non-byte global memory operand"));
            };
            let Some(Global::Bytes(bytes)) = globals.get(*base) else {
                return Err(invalid("invalid CBC byte pointer"));
            };
            return Ok(Self::Constant(Arc::clone(bytes), *offset));
        }
        let i = usize::try_from(field(line.number())?)
            .map_err(|_| invalid("invalid CBC address index"))?;
        let slot = field(slots.get(i))?;
        if slot.addressable {
            Ok(Self::Object(i))
        } else if slot.width.is_none() {
            Ok(Self::Pointer(i))
        } else {
            Err(unsupported("address of a register"))
        }
    }

    fn local_pointer(&self, frame: &Frame<'_>) -> Result<(usize, i32), MemoryFault> {
        match *self {
            Self::Object(i) => Ok((i, 0)),
            Self::Pointer(i) => {
                // A zero high word is null. GEP instructions create the other pointer values.
                let encoded = frame.get(i);
                let object = (encoded >> 32).checked_sub(1).ok_or(MemoryFault::Null)?;
                Ok((object as usize, encoded as i32))
            }
            Self::Constant(_, _) => Err(MemoryFault::Bounds),
        }
    }

    fn range(&self, frame: &Frame<'_>, len: usize) -> Result<Range<usize>, MemoryFault> {
        let (i, off) = self.local_pointer(frame)?;
        let object = frame.slots.get(i).ok_or(MemoryFault::Bounds)?;
        let start = usize::try_from(off).map_err(|_| MemoryFault::Bounds)?;
        let end = start.checked_add(len).ok_or(MemoryFault::Bounds)?;
        if !object.addressable || end > object.size {
            return Err(MemoryFault::Bounds);
        }
        Ok(object.start + start..object.start + end)
    }

    pub(super) fn read<'a>(
        &'a self,
        frame: &'a Frame<'_>,
        len: usize,
    ) -> Result<&'a [u8], MemoryFault> {
        match self {
            Self::Constant(bytes, off) => bytes
                .get(*off..off.checked_add(len).ok_or(MemoryFault::Bounds)?)
                .ok_or(MemoryFault::Bounds),
            _ => Ok(&frame.bytes[self.range(frame, len)?]),
        }
    }
}

#[derive(Debug)]
pub(super) enum MemoryOp {
    Gep(Address, Value, i32),
    Load(Address, Width),
    Store(Address, Value, Width),
    Compare(Address, Address, Value),
    Transfer {
        dest: Address,
        source: Address,
        len: Value,
        overlapping: bool,
    },
    Fill(Address, Value, Value),
    Read(Address, Value),
    Seek(Value, Value),
}

impl MemoryOp {
    pub(super) fn eval(&self, frame: &mut Frame<'_>, input: &[u8]) -> Result<u64, MemoryFault> {
        match self {
            Self::Gep(base, index, stride) => {
                let (object, offset) = base.local_pointer(frame)?;
                let index = index.get(frame) as i32;
                let offset = index
                    .checked_mul(*stride)
                    .and_then(|n| n.checked_add(offset))
                    .ok_or(MemoryFault::Bounds)?;
                Ok(((object as u64 + 1) << 32) | u64::from(offset as u32))
            }
            Self::Load(source, width) => {
                Ok(read_int(source.read(frame, width.bytes())?) & width.mask())
            }
            Self::Store(dest, value, width) => {
                let value = value.get(frame);
                let range = dest.range(frame, width.bytes())?;
                write_int(&mut frame.bytes[range], value);
                Ok(0)
            }
            Self::Compare(left, right, len) => {
                let len = len.get(frame) as usize;
                let a = left.read(frame, len)?;
                let b = right.read(frame, len)?;
                let diff = a
                    .iter()
                    .zip(b)
                    .find(|(a, b)| a != b)
                    .map_or(0, |(&a, &b)| i32::from(a) - i32::from(b));
                Ok(u64::from(diff as u32))
            }
            Self::Transfer {
                dest,
                source,
                len,
                overlapping,
            } => {
                let len = len.get(frame) as usize;
                let dest = dest.range(frame, len)?;
                if let Address::Constant(bytes, off) = source {
                    frame.bytes[dest].copy_from_slice(
                        bytes
                            .get(*off..off.checked_add(len).ok_or(MemoryFault::Bounds)?)
                            .ok_or(MemoryFault::Bounds)?,
                    );
                } else {
                    let source = source.range(frame, len)?;
                    if !overlapping && source.start < dest.end && dest.start < source.end {
                        return Err(MemoryFault::OverlappingCopy);
                    }
                    frame.bytes.copy_within(source, dest.start);
                }
                Ok(0)
            }
            Self::Fill(dest, value, len) => {
                let range = dest.range(frame, len.get(frame) as usize)?;
                let byte = value.get(frame) as u8;
                frame.bytes[range].fill(byte);
                Ok(0)
            }
            Self::Read(dest, len) => {
                let size = len.get(frame) as usize;
                let range = dest.range(frame, size)?;
                let tail = &input[frame.cursor..];
                let n = size.min(tail.len());
                frame.bytes[range.start..range.start + n].copy_from_slice(&tail[..n]);
                frame.cursor += n;
                Ok(n as u64)
            }
            Self::Seek(pos, whence) => {
                let base = match whence.get(frame) {
                    0 => 0,
                    1 => frame.cursor,
                    2 => input.len(),
                    _ => return Ok(u32::MAX.into()),
                };
                let position = base.checked_add_signed(pos.get(frame) as i32 as isize);
                match position.filter(|&n| n <= input.len()) {
                    Some(n) => {
                        frame.cursor = n;
                        Ok(n as u32 as u64)
                    }
                    None => Ok(u32::MAX.into()),
                }
            }
        }
    }
}

pub(super) fn gep(
    line: &mut Cursor<'_>,
    opcode: u64,
    output_type: u64,
    slots: &[Slot],
    types: &[Type],
    globals: &[Global],
) -> io::Result<MemoryOp> {
    let ty = field(line.number())?;
    let element = pointer_element(types, ty).ok_or_else(|| unsupported("GEP base type"))?;
    let base = Address::decode(line, slots, globals, true)?;
    let stride = if opcode == 36 {
        if pointer_element(types, output_type) != Some(8)
            || !matches!(user_type(types, element), Some(Type::Bytes(_)))
        {
            return Err(unsupported("GEPZ element type"));
        }
        if let Address::Object(i) = base
            && slots[i].ty != element
        {
            return Err(invalid("CBC GEPZ base type mismatch"));
        }
        1
    } else {
        if pointer_element(types, output_type) != Some(element)
            || !matches!(base, Address::Pointer(_))
        {
            return Err(unsupported("GEP1 base storage"));
        }
        Width::new(element)?.bytes() as i32
    };
    let index = line.scalar(slots, Width::WORD)?;
    Ok(MemoryOp::Gep(base, index, stride))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_and_seek_share_a_cursor_and_preserve_other_bytes() -> io::Result<()> {
        let slots = [Slot::new(32, true, 0, &[])?, Slot::new(32, false, 4, &[])?];
        let mut frame = Frame::new(&slots);
        frame.set(0, u32::MAX.into());
        frame.set(1, 123);
        let input = b"abc";
        let seek = |pos: i32, whence| {
            MemoryOp::Seek(Value::Constant(pos as u32 as u64), Value::Constant(whence))
        };
        assert_eq!(seek(-2, 2).eval(&mut frame, input), Ok(1));
        assert_eq!(seek(-2, 1).eval(&mut frame, input), Ok(u32::MAX.into()));
        let read = MemoryOp::Read(Address::Object(0), Value::Constant(3));
        assert_eq!(read.eval(&mut frame, input), Ok(2));
        assert_eq!(&frame.bytes[..4], &[b'b', b'c', 255, 255]);
        assert_eq!(
            frame.get(0),
            u64::from(u32::from_ne_bytes([b'b', b'c', 255, 255]))
        );
        assert_eq!(read.eval(&mut frame, input), Ok(0));
        assert_eq!(frame.cursor, 3);
        assert_eq!(frame.get(1), 123);
        Ok(())
    }

    #[test]
    fn moves_only_verified_ranges_and_compares_unsigned_bytes() -> io::Result<()> {
        let types = [Type::Bytes(4)];
        let slots = [
            Slot::new(69, true, 0, &types)?,
            Slot::new(65, false, 4, &types)?,
        ];
        let mut frame = Frame::new(&slots);
        let set = MemoryOp::Fill(
            Address::Object(0),
            Value::Constant(0xff),
            Value::Constant(4),
        );
        assert_eq!(set.eval(&mut frame, &[]), Ok(0));
        let source = Address::Constant(b"abc".as_slice().into(), 0);
        let copy = MemoryOp::Transfer {
            dest: Address::Object(0),
            source,
            len: Value::Constant(3),
            overlapping: false,
        };
        assert_eq!(copy.eval(&mut frame, &[]), Ok(0));
        let gep = MemoryOp::Gep(Address::Object(0), Value::Constant(1), 1);
        let ptr = gep.eval(&mut frame, &[]).unwrap();
        frame.set(1, ptr);
        let transfer = |overlapping| MemoryOp::Transfer {
            dest: Address::Pointer(1),
            source: Address::Object(0),
            len: Value::Constant(2),
            overlapping,
        };
        assert_eq!(
            transfer(false).eval(&mut frame, &[]),
            Err(MemoryFault::OverlappingCopy)
        );
        assert_eq!(transfer(true).eval(&mut frame, &[]), Ok(0));
        assert_eq!(&frame.bytes[..4], &[b'a', b'a', b'b', 255]);
        let compare =
            MemoryOp::Compare(Address::Pointer(1), Address::Object(0), Value::Constant(3));
        assert_eq!(compare.eval(&mut frame, &[]), Ok(1));
        Ok(())
    }

    #[test]
    fn symbolic_pointers_cannot_address_neighboring_locals() -> io::Result<()> {
        let types = [Type::Bytes(4)];
        let slots = [
            Slot::new(69, true, 0, &types)?,
            Slot::new(65, false, 4, &types)?,
        ];
        let mut frame = Frame::new(&slots);
        let load = MemoryOp::Load(Address::Pointer(1), Width(16));
        assert_eq!(load.eval(&mut frame, &[]), Err(MemoryFault::Null));
        let offset = |n| MemoryOp::Gep(Address::Object(0), Value::Constant(n), 1);
        for off in [3, 4, u32::MAX.into()] {
            let ptr = offset(off).eval(&mut frame, &[]).unwrap();
            frame.set(1, ptr);
            assert_eq!(load.eval(&mut frame, &[]), Err(MemoryFault::Bounds));
        }
        let ptr = offset(2).eval(&mut frame, &[]).unwrap();
        frame.set(1, ptr);
        let store = MemoryOp::Store(Address::Pointer(1), Value::Constant(0x1234), Width(16));
        assert_eq!(store.eval(&mut frame, &[]), Ok(0));
        assert_eq!(load.eval(&mut frame, &[]), Ok(0x1234));
        Ok(())
    }
}
