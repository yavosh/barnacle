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
        let (size, alignment) = match (width, user_type(types, ty)) {
            (Some(w), _) => (w.bytes(), w.bytes()),
            (_, Some(Type::Bytes(n))) if addressable => (*n, 1),
            // The pinned interpreter does not compute general structure alignment.
            (_, Some(Type::Struct { .. }))
                if addressable && start == 0 && super::host::disasm_record_type(ty, types) =>
            {
                (64, 1)
            }
            (_, _)
                if ty == super::BYTE_POINTER
                    || pointer_element(types, ty).is_some() && !addressable =>
            {
                (8, 8)
            }
            _ => return Err(unsupported("frame local type or storage")),
        };
        let start = start.next_multiple_of(alignment);
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

    pub(super) fn padded_i32_cell(&self, next: Option<&Slot>) -> bool {
        // Stock aligns the constant table to 8 after its last local.
        let end = next.map_or_else(|| self.end().next_multiple_of(8), |s| s.start);
        self.width == Some(Width::WORD) && self.start.is_multiple_of(8) && end >= self.start + 8
    }

    fn object(&self) -> Range<usize> {
        self.start..self.end()
    }
}

pub(super) fn pointer_element(types: &[Type], ty: u64) -> Option<u64> {
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

struct Storage<'a> {
    base: u32,
    slots: &'a [Slot],
    registers: Option<Vec<u64>>,
    bytes: Vec<u8>,
    // Allocated only for frames containing a partial copy of cli_environment.
    unknown_environment: Option<Box<[bool]>>,
}

impl<'a> Storage<'a> {
    fn new(slots: &'a [Slot], base: u32) -> Self {
        let addressable = slots.iter().any(|slot| slot.addressable);
        Self {
            base,
            slots,
            registers: (!addressable).then(|| vec![0; slots.len()]),
            unknown_environment: None,
            bytes: if addressable {
                vec![0; slots.last().map_or(0, Slot::end)]
            } else {
                Vec::new()
            },
        }
    }

    fn slot(&self, id: u32) -> Option<Slot> {
        self.slots
            .get(id.checked_sub(self.base)? as usize)
            .copied()
            .filter(|s| s.addressable)
    }

    fn mark_known(&mut self, range: Range<usize>) {
        if let Some(mask) = &mut self.unknown_environment {
            mask[range].fill(false);
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

const HEAP_TAG: u32 = 1 << 31;
const MODULE_TAG: u32 = 1 << 30;
// Stock FLEVEL 213 reserves IDs 1..=6 for host globals and ID 7 for module data.
const FIRST_HEAP_ID: u32 = 8;
const HEAP_OBJECT_LIMIT: usize = 4096;

pub(super) fn module_pointer(base: usize, offset: usize) -> io::Result<u64> {
    let index = u32::try_from(base)
        .ok()
        .filter(|&i| i < MODULE_TAG)
        .ok_or_else(|| unsupported("module object identity budget"))?;
    let offset = u32::try_from(offset).map_err(|_| unsupported("module pointer offset"))?;
    Ok((u64::from(MODULE_TAG | index) << 32) | u64::from(offset))
}

struct Allocation {
    bytes: Vec<u8>,
    initialized: Vec<bool>,
}

pub(super) struct Frame<'a> {
    pub(super) module_globals: &'a [Global],
    current: Storage<'a>,
    parents: Vec<Storage<'a>>,
    next_object: u32,
    heap: Vec<Allocation>,
    heap_bytes: usize,
    pub(super) cursor: usize,
}

impl<'a> Frame<'a> {
    pub(super) fn new(slots: &'a [Slot]) -> Self {
        Self {
            module_globals: &[],
            current: Storage::new(slots, 1),
            parents: Vec::new(),
            next_object: 1 + slots.len() as u32,
            heap: Vec::new(),
            heap_bytes: 0,
            cursor: 0,
        }
    }

    pub(super) fn get(&self, i: usize) -> u64 {
        self.current.get(i)
    }
    pub(super) fn set(&mut self, i: usize, n: u64) {
        self.current.set(i, n)
    }

    pub(super) fn enter(&mut self, slots: &'a [Slot], args: &[Value]) -> io::Result<()> {
        let base = self.next_object;
        // Retired objects never reuse their handle during the invocation.
        self.next_object = base
            .checked_add(slots.len() as u32)
            .filter(|&next| next < MODULE_TAG)
            .ok_or_else(|| unsupported("frame object identity budget"))?;
        let mut child = Storage::new(slots, base);
        for (i, arg) in args.iter().enumerate() {
            child.set(i, arg.get(self));
        }
        self.parents
            .push(std::mem::replace(&mut self.current, child));
        Ok(())
    }

    pub(super) fn leave(&mut self) {
        self.current = self.parents.pop().expect("paired direct call frame");
    }

    pub(super) fn allocate(&mut self, size: usize) -> io::Result<u64> {
        if size == 0 {
            return Ok(0);
        }
        let total = self
            .heap_bytes
            .checked_add(size)
            .filter(|&n| n <= super::MAX_MEMBER_BYTES as usize)
            .ok_or_else(|| unsupported("scan heap byte limit"))?;
        if self.heap.len() >= HEAP_OBJECT_LIMIT {
            return Err(unsupported("scan heap allocation count"));
        }
        let id = HEAP_TAG | self.heap.len() as u32;
        self.heap.push(Allocation {
            bytes: vec![0; size],
            initialized: vec![false; size],
        });
        self.heap_bytes = total;
        Ok(u64::from(id) << 32)
    }

    pub(super) fn pointer_integer(&self, slot: usize) -> io::Result<u64> {
        let encoded = self.get(slot);
        if encoded == 0 {
            return Ok(0);
        }
        let id = (encoded >> 32) as u32;
        if id & MODULE_TAG != 0 {
            let (bytes, base) = self
                .module_object(id)
                .map_err(|_| unsupported("unknown module pointer"))?;
            let offset = encoded as u32 as usize;
            if offset > bytes.len() {
                return Err(unsupported(
                    "integer conversion outside a module byte array",
                ));
            }
            // Stock registers all private module data under object ID seven.
            return Ok((7u64 << 32) | (base + offset) as u64);
        }
        if id & HEAP_TAG == 0 {
            return Err(unsupported("integer conversion of a frame address"));
        }
        let allocation = id ^ HEAP_TAG;
        if self.heap.get(allocation as usize).is_none() {
            return Err(unsupported("integer conversion of an unknown heap address"));
        }
        Ok((u64::from(FIRST_HEAP_ID + allocation) << 32) | u64::from(encoded as u32))
    }

    fn stack_object(&self, id: u32) -> Result<(&Storage<'a>, Slot), MemoryFault> {
        std::iter::once(&self.current)
            .chain(self.parents.iter().rev())
            .find_map(|f| f.slot(id).map(|s| (f, s)))
            .ok_or(MemoryFault::Bounds)
    }

    fn module_object(&self, id: u32) -> Result<(&[u8], usize), MemoryFault> {
        match self.module_globals.get((id ^ MODULE_TAG) as usize) {
            Some(Global::Bytes(bytes, base)) => Ok((bytes, *base)),
            _ => Err(MemoryFault::Bounds),
        }
    }

    fn object_len(&self, id: u32) -> Result<usize, MemoryFault> {
        if id & MODULE_TAG != 0 {
            return Ok(self.module_object(id)?.0.len());
        }
        if id & HEAP_TAG != 0 {
            return self
                .heap
                .get((id ^ HEAP_TAG) as usize)
                .map(|h| h.bytes.len())
                .ok_or(MemoryFault::Bounds);
        }
        Ok(self.stack_object(id)?.1.size)
    }

    fn read(&self, id: u32, range: Range<usize>) -> Result<&[u8], MemoryFault> {
        if id & MODULE_TAG != 0 {
            return self
                .module_object(id)?
                .0
                .get(range)
                .ok_or(MemoryFault::Bounds);
        }
        if id & HEAP_TAG != 0 {
            let h = self
                .heap
                .get((id ^ HEAP_TAG) as usize)
                .ok_or(MemoryFault::Bounds)?;
            if !h.initialized[range.clone()].iter().all(|&v| v) {
                return Err(MemoryFault::Uninitialized);
            }
            return Ok(&h.bytes[range]);
        }
        let (storage, slot) = self.stack_object(id)?;
        let range = slot.start + range.start..slot.start + range.end;
        if storage
            .unknown_environment
            .as_ref()
            .is_some_and(|mask| mask[range.clone()].contains(&true))
        {
            return Err(MemoryFault::Environment);
        }
        Ok(&storage.bytes[range])
    }

    fn transfer(
        &mut self,
        src: u32,
        from: Range<usize>,
        dest: u32,
        to: Range<usize>,
    ) -> Result<(), MemoryFault> {
        // Validate all source bytes before modifying the destination.
        self.read(src, from.clone())?;
        if dest & MODULE_TAG != 0 {
            return Err(MemoryFault::Immutable);
        }
        if src == dest && src & HEAP_TAG != 0 {
            let h = &mut self.heap[(src ^ HEAP_TAG) as usize];
            h.bytes.copy_within(from, to.start);
            h.initialized[to].fill(true);
            return Ok(());
        }
        for storage in std::iter::once(&mut self.current).chain(self.parents.iter_mut().rev()) {
            if let (Some(s), Some(d)) = (storage.slot(src), storage.slot(dest)) {
                storage.mark_known(d.start + to.start..d.start + to.end);
                storage
                    .bytes
                    .copy_within(s.start + from.start..s.start + from.end, d.start + to.start);
                return Ok(());
            }
        }
        // Different backing buffers cannot overlap.
        let mut buffer = [0u8; 4096];
        for offset in (0..from.len()).step_by(buffer.len()) {
            let n = buffer.len().min(from.len() - offset);
            let at = from.start + offset;
            buffer[..n].copy_from_slice(self.read(src, at..at + n)?);
            let at = to.start + offset;
            self.writable(dest, at..at + n)?
                .copy_from_slice(&buffer[..n]);
        }
        Ok(())
    }

    fn writable(&mut self, id: u32, range: Range<usize>) -> Result<&mut [u8], MemoryFault> {
        if id & MODULE_TAG != 0 {
            return Err(MemoryFault::Immutable);
        }
        if id & HEAP_TAG != 0 {
            let h = self
                .heap
                .get_mut((id ^ HEAP_TAG) as usize)
                .ok_or(MemoryFault::Bounds)?;
            h.initialized[range.clone()].fill(true);
            return Ok(&mut h.bytes[range]);
        }
        std::iter::once(&mut self.current)
            .chain(self.parents.iter_mut().rev())
            .find_map(|f| {
                let slot = f.slot(id)?;
                let range = slot.start + range.start..slot.start + range.end;
                f.mark_known(range.clone());
                Some(&mut f.bytes[range])
            })
            .ok_or(MemoryFault::Bounds)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum MemoryFault {
    Null,
    Immutable,
    Bounds,
    OverlappingCopy,
    Uninitialized,
    Environment,
    EnvironmentDestination,
}

pub(super) fn outcome<T>(result: Result<T, MemoryFault>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(MemoryFault::Null) => Ok(None),
        Err(MemoryFault::Immutable) => Err(unsupported("write to module byte array")),
        Err(MemoryFault::OverlappingCopy) => Err(unsupported("overlapping MEMCPY ranges")),
        Err(MemoryFault::Uninitialized) => Err(unsupported("read from unwritten heap storage")),
        Err(MemoryFault::Environment) => Err(unsupported("read of an unmodeled environment field")),
        Err(MemoryFault::EnvironmentDestination) => Err(unsupported(
            "environment destination outside a stack aggregate",
        )),
        Err(MemoryFault::Bounds) => Err(unsupported("memory span outside its modeled object")),
    }
}

#[derive(Debug)]
pub(super) enum Address {
    Null,
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
            let Global::Pointer {
                base,
                offset,
                source_at_zero,
            } = line.global(globals)?
            else {
                return Err(unsupported("non-byte global memory operand"));
            };
            if *source_at_zero {
                return Ok(Self::Null);
            }
            let Some(Global::Bytes(bytes, _)) = globals.get(*base) else {
                return Err(invalid("invalid CBC byte pointer"));
            };
            return Ok(Self::Constant(Arc::clone(bytes), *offset));
        }
        let i = usize::try_from(field(line.number())?)
            .map_err(|_| invalid("invalid CBC address index"))?;
        let slot = field(slots.get(i))?;
        if slot.addressable {
            if slot.ty == super::BYTE_POINTER {
                return Err(unsupported("byte access to a pointer cell"));
            }
            Ok(Self::Object(i))
        } else if slot.width.is_none() {
            Ok(Self::Pointer(i))
        } else {
            Err(unsupported("address of a register"))
        }
    }

    fn local_pointer(&self, frame: &Frame<'_>) -> Result<(u32, i32), MemoryFault> {
        match *self {
            Self::Null => Err(MemoryFault::Null),
            Self::Object(i) => Ok((frame.current.base + i as u32, 0)),
            Self::Pointer(i) => {
                let encoded = frame.get(i);
                let id = (encoded >> 32) as u32;
                if id == 0 {
                    return Err(MemoryFault::Null);
                }
                Ok((id, encoded as i32))
            }
            Self::Constant(_, _) => Err(MemoryFault::Bounds),
        }
    }

    fn span(&self, frame: &Frame<'_>, len: usize) -> Result<(u32, Range<usize>), MemoryFault> {
        let (id, off) = self.local_pointer(frame)?;
        let start = usize::try_from(off).map_err(|_| MemoryFault::Bounds)?;
        let end = start.checked_add(len).ok_or(MemoryFault::Bounds)?;
        if end > frame.object_len(id)? {
            return Err(MemoryFault::Bounds);
        }
        Ok((id, start..end))
    }

    /// The host call requires a pointer inside the object, even for empty buffers.
    pub(super) fn check_host_span(&self, frame: &Frame<'_>, len: usize) -> Result<(), MemoryFault> {
        let len = len.max(1);
        match self {
            Self::Constant(bytes, off) => bytes
                .get(*off..)
                .and_then(|bytes| bytes.get(..len))
                .map(|_| ())
                .ok_or(MemoryFault::Bounds),
            _ => self.span(frame, len).map(|_| ()),
        }
    }

    pub(super) fn remaining<'a>(&'a self, frame: &'a Frame<'_>) -> Result<&'a [u8], MemoryFault> {
        match self {
            Self::Constant(bytes, off) => bytes.get(*off..).ok_or(MemoryFault::Bounds),
            _ => {
                let (id, start) = self.span(frame, 0)?;
                if id & MODULE_TAG != 0 {
                    return Ok(&frame.module_object(id)?.0[start.start..]);
                }
                if id & HEAP_TAG != 0 {
                    let heap = &frame.heap[(id ^ HEAP_TAG) as usize];
                    let available = heap.initialized[start.start..]
                        .iter()
                        .take_while(|&&v| v)
                        .count();
                    return Ok(&heap.bytes[start.start..start.start + available]);
                }
                let (storage, slot) = frame.stack_object(id)?;
                let range = slot.start + start.start..slot.end();
                let bytes = &storage.bytes[range.clone()];
                let end = storage
                    .unknown_environment
                    .as_ref()
                    .and_then(|mask| mask[range].iter().position(|&unknown| unknown))
                    .unwrap_or(bytes.len());
                Ok(&bytes[..end])
            }
        }
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
            _ => {
                let (id, range) = self.span(frame, len)?;
                frame.read(id, range)
            }
        }
    }

    pub(super) fn write(&self, frame: &mut Frame<'_>, bytes: &[u8]) -> Result<(), MemoryFault> {
        self.write_at(frame, 0, bytes)
    }

    pub(super) fn mark_environment(
        &self,
        frame: &mut Frame<'_>,
        len: usize,
    ) -> Result<(), MemoryFault> {
        let (id, range) = self.span(frame, len)?;
        for storage in std::iter::once(&mut frame.current).chain(frame.parents.iter_mut().rev()) {
            if let Some(slot) = storage.slot(id) {
                // Scalar locals also have direct register reads which bypass byte access.
                if slot.width.is_some() {
                    break;
                }
                let mask = storage
                    .unknown_environment
                    .get_or_insert_with(|| vec![false; storage.bytes.len()].into_boxed_slice());
                mask[slot.start + range.start..slot.start + range.end].fill(true);
                return Ok(());
            }
        }
        Err(MemoryFault::EnvironmentDestination)
    }

    pub(super) fn write_at(
        &self,
        frame: &mut Frame<'_>,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), MemoryFault> {
        let len = offset.checked_add(bytes.len()).ok_or(MemoryFault::Bounds)?;
        let (id, range) = self.span(frame, len)?;
        frame
            .writable(id, range.start + offset..range.end)?
            .copy_from_slice(bytes);
        Ok(())
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
                if object & MODULE_TAG != 0
                    && (offset < 0 || offset as usize > frame.object_len(object)?)
                {
                    return Err(MemoryFault::Bounds);
                }
                // A negative heap offset changes the stock object ID through a borrow.
                if object & HEAP_TAG != 0 && offset < 0 {
                    return Err(MemoryFault::Bounds);
                }
                Ok((u64::from(object) << 32) | u64::from(offset as u32))
            }
            Self::Load(source, width) => {
                Ok(read_int(source.read(frame, width.bytes())?) & width.mask())
            }
            Self::Store(dest, value, width) => {
                let value = value.get(frame);
                let (id, range) = dest.span(frame, width.bytes())?;
                write_int(frame.writable(id, range)?, value);
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
                let len = len.get(frame) as u32 as usize;
                let (id, to) = dest.span(frame, len)?;
                if let Address::Constant(bytes, off) = source {
                    let data = bytes
                        .get(*off..off.checked_add(len).ok_or(MemoryFault::Bounds)?)
                        .ok_or(MemoryFault::Bounds)?;
                    frame.writable(id, to)?.copy_from_slice(data);
                } else {
                    let (from_id, from) = source.span(frame, len)?;
                    if !overlapping && from_id == id && from.start < to.end && to.start < from.end {
                        return Err(MemoryFault::OverlappingCopy);
                    }
                    frame.transfer(from_id, from, id, to)?;
                }
                Ok(0)
            }
            Self::Fill(dest, value, len) => {
                let (id, range) = dest.span(frame, len.get(frame) as u32 as usize)?;
                let byte = value.get(frame) as u8;
                frame.writable(id, range)?.fill(byte);
                Ok(0)
            }
            Self::Read(dest, len) => {
                let size = len.get(frame) as usize;
                dest.span(frame, size)?;
                let tail = &input[frame.cursor..];
                let n = size.min(tail.len());
                dest.write(frame, &tail[..n])?;
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
    fn pointer_cells_preserve_immutable_array_bounds() -> io::Result<()> {
        let slots = [
            Slot::new(8, false, 0, &[])?,
            Slot::new(65, true, 1, &[])?,
            Slot::new(65, false, 16, &[])?,
        ];
        assert_eq!(slots[1].object(), 8..16);
        // A pointer cell can only be read or written through typed COPY.
        assert!(Address::decode(&mut Cursor(b"aa"), &slots, &[], true).is_err());
        assert!(Address::decode(&mut Cursor(b"aa"), &slots, &[], false).is_err());
        let globals = [
            Global::Bytes(Arc::from(*b"pen"), 32),
            Global::Bytes(Arc::from(*b"pad"), 35),
        ];
        let mut frame = Frame::new(&slots);
        frame.module_globals = &globals;
        frame.set(2, module_pointer(0, 2)?);
        let address = Address::Pointer(2);
        assert_eq!(address.read(&frame, 1), Ok(b"n".as_slice()));
        assert_eq!(address.read(&frame, 2), Err(MemoryFault::Bounds));
        assert_eq!(address.write(&mut frame, b"x"), Err(MemoryFault::Immutable));
        assert_eq!(frame.pointer_integer(2)?, (7 << 32) | 34);
        let past_end = MemoryOp::Gep(address, Value::Constant(2), 1);
        assert_eq!(past_end.eval(&mut frame, &[]), Err(MemoryFault::Bounds));
        Ok(())
    }

    #[test]
    fn environment_bytes_stay_guarded_across_calls_and_transfers() -> io::Result<()> {
        let types = [Type::Bytes(8)];
        let caller = [
            Slot::new(69, true, 0, &types)?,
            Slot::new(65, false, 8, &types)?,
        ];
        let child = [Slot::new(65, false, 0, &[])?];
        let mut frame = Frame::new(&caller);
        let pointer = MemoryOp::Gep(Address::Object(0), Value::Constant(1), 1)
            .eval(&mut frame, &[])
            .unwrap();
        frame.set(1, pointer);
        frame.enter(&child, &[Value::Local(1)])?;
        Address::Pointer(0).mark_environment(&mut frame, 5).unwrap();
        assert_eq!(
            Address::Pointer(0).read(&frame, 1),
            Err(MemoryFault::Environment)
        );
        Address::Pointer(0).write_at(&mut frame, 1, b"A").unwrap();
        frame.leave();
        let id = frame.current.base;
        assert_eq!(Address::Object(0).remaining(&frame), Ok(&[0][..]));
        assert_eq!(frame.read(id, 0..1), Ok(&[0][..]));
        assert_eq!(frame.read(id, 6..8), Ok(&[0; 2][..]));
        assert_eq!(
            frame.transfer(id, 1..2, id, 2..3),
            Err(MemoryFault::Environment)
        );
        assert_eq!(frame.read(id, 2..3), Ok(b"A".as_slice()));
        frame.transfer(id, 2..3, id, 4..5).unwrap();
        assert_eq!(frame.read(id, 4..5), Ok(b"A".as_slice()));
        assert_eq!(frame.read(id, 3..5), Err(MemoryFault::Environment));
        Ok(())
    }

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
        assert_eq!(&frame.current.bytes[..4], &[b'b', b'c', 255, 255]);
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
        assert_eq!(&frame.current.bytes[..4], &[b'a', b'a', b'b', 255]);
        let compare =
            MemoryOp::Compare(Address::Pointer(1), Address::Object(0), Value::Constant(3));
        assert_eq!(compare.eval(&mut frame, &[]), Ok(1));
        Ok(())
    }

    #[test]
    fn pointer_arguments_share_live_storage_and_retired_frames_stay_inaccessible() -> io::Result<()>
    {
        let types = [Type::Bytes(4)];
        let caller = [
            Slot::new(69, true, 0, &types)?,
            Slot::new(65, false, 4, &types)?,
        ];
        let child = [
            Slot::new(65, false, 0, &types)?,
            Slot::new(69, true, 8, &types)?,
        ];
        let mut frame = Frame::new(&caller);
        let addr = MemoryOp::Gep(Address::Object(0), Value::Constant(1), 1)
            .eval(&mut frame, &[])
            .unwrap();
        frame.set(1, addr);
        frame.enter(&child, &[Value::Local(1)])?;
        assert_eq!(
            frame.pointer_integer(0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        Address::Pointer(0).write(&mut frame, b"abc").unwrap();
        let retired = MemoryOp::Gep(Address::Object(1), Value::Constant(0), 1)
            .eval(&mut frame, &[])
            .unwrap();
        frame.leave();
        assert_eq!(Address::Pointer(1).read(&frame, 3), Ok(&b"abc"[..]));
        frame.enter(&child, &[Value::Constant(retired)])?;
        assert_eq!(
            Address::Pointer(0).read(&frame, 1),
            Err(MemoryFault::Bounds)
        );
        Ok(())
    }

    #[test]
    fn allocated_bytes_require_initialization_and_enforce_object_bounds() -> io::Result<()> {
        let slots = [Slot::new(65, false, 0, &[])?, Slot::new(65, false, 8, &[])?];
        let mut frame = Frame::new(&slots);
        assert_eq!(frame.allocate(0)?, 0);
        let ptr = frame.allocate(4)?;
        frame.set(0, ptr);
        let below = MemoryOp::Gep(Address::Pointer(0), Value::Constant(u64::from(u32::MAX)), 1);
        assert_eq!(below.eval(&mut frame, &[]), Err(MemoryFault::Bounds));
        let addr = Address::Pointer(0);
        assert_eq!(addr.read(&frame, 1), Err(MemoryFault::Uninitialized));
        MemoryOp::Read(addr, Value::Constant(4))
            .eval(&mut frame, b"xy")
            .unwrap();
        assert_eq!(Address::Pointer(0).read(&frame, 2), Ok(&b"xy"[..]));
        assert_eq!(Address::Pointer(0).remaining(&frame), Ok(&b"xy"[..]));
        assert_eq!(
            Address::Pointer(0).read(&frame, 3),
            Err(MemoryFault::Uninitialized)
        );
        let out = MemoryOp::Gep(Address::Pointer(0), Value::Constant(3), 1)
            .eval(&mut frame, &[])
            .unwrap();
        frame.set(1, out);
        assert_eq!(
            Address::Pointer(1).write(&mut frame, b"ok"),
            Err(MemoryFault::Bounds)
        );
        frame.enter(&slots, &[Value::Local(0)])?;
        Address::Pointer(0).write(&mut frame, b"abcd").unwrap();
        frame.leave();
        assert_eq!(Address::Pointer(0).read(&frame, 4), Ok(&b"abcd"[..]));
        assert_eq!(
            frame
                .allocate(super::super::MAX_MEMBER_BYTES as usize)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        Ok(())
    }

    #[test]
    fn cross_object_copy_validates_all_input_before_writing() -> io::Result<()> {
        let slots = [Slot::new(65, false, 0, &[])?, Slot::new(65, false, 8, &[])?];
        let mut frame = Frame::new(&slots);
        let len = 8200;
        for i in 0..2 {
            let ptr = frame.allocate(len)?;
            frame.set(i, ptr);
        }
        let fill = |i, value, n| {
            MemoryOp::Fill(
                Address::Pointer(i),
                Value::Constant(value),
                Value::Constant(n),
            )
        };
        fill(0, 1, len as u64 - 1).eval(&mut frame, &[]).unwrap();
        fill(1, 2, len as u64).eval(&mut frame, &[]).unwrap();
        let copy = MemoryOp::Transfer {
            dest: Address::Pointer(1),
            source: Address::Pointer(0),
            len: Value::Constant(len as u64),
            overlapping: false,
        };
        assert_eq!(copy.eval(&mut frame, &[]), Err(MemoryFault::Uninitialized));
        assert!(
            Address::Pointer(1)
                .read(&frame, len)
                .unwrap()
                .iter()
                .all(|&n| n == 2)
        );
        fill(0, 1, len as u64).eval(&mut frame, &[]).unwrap();
        assert_eq!(copy.eval(&mut frame, &[]), Ok(0));
        assert!(
            Address::Pointer(1)
                .read(&frame, len)
                .unwrap()
                .iter()
                .all(|&n| n == 1)
        );
        Ok(())
    }

    #[test]
    fn narrow_length_needs_an_aligned_cell_with_unused_upper_bytes() -> io::Result<()> {
        let word = Slot::new(32, false, 0, &[])?;
        let adjacent = Slot::new(32, false, 4, &[])?;
        let padded = Slot::new(65, false, 4, &[])?;
        assert!(word.padded_i32_cell(Some(&padded)));
        assert!(!word.padded_i32_cell(Some(&adjacent)));
        assert!(!adjacent.padded_i32_cell(None));
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
