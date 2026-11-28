//! A typed scalar interpreter for a single logical bytecode entry point.
use super::{Cursor, MAX_MEMBER_BYTES, invalid};
use std::time::{Duration, Instant};
use std::{io, str, sync::Arc};

mod memory;
use memory::{Address, Frame, MemoryOp, Slot};

const LOGICAL_HOOK: u64 = 256;
const SET_VIRUS_NAME: u64 = 5;
const I32: u64 = 32;
const BYTE_POINTER: u64 = 65;
const FIRST_USER_TYPE: usize = 69;
const CLOCK_INTERVAL: u32 = 5_000;
const FIND_WINDOW: usize = 4096;

#[derive(Debug)]
pub struct Program {
    trigger: Box<str>,
    locals: Vec<Slot>,
    blocks: Vec<Vec<Instruction>>,
    uses_match_offsets: bool,
}

fn field<T>(value: Option<T>) -> io::Result<T> {
    value.ok_or_else(|| invalid("invalid or truncated CBC field"))
}

fn unsupported(feature: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("unsupported CBC {feature}"),
    )
}

impl Program {
    /// Compile one logical entry point, or skip a module outside the format or engine window.
    pub fn compile(contents: &[u8], engine_level: u64) -> io::Result<Option<Self>> {
        if contents.len() as u64 > MAX_MEMBER_BYTES {
            return Err(invalid("CBC exceeds the module size limit"));
        }
        let mut lines = contents
            .split(|&b| b == b'\n')
            .map(|s| s.strip_suffix(b"\r").unwrap_or(s));
        let first = field(lines.next())?;
        let mut h = Cursor(field(first.strip_prefix(b"ClamBC"))?);
        if !matches!(field(h.number())?, 6 | 7) {
            return Ok(None);
        }
        field(h.number())?; // Timestamp.
        field(h.string())?; // Author.
        let exclude = field(h.number())?;
        let hook = field(h.number())?;
        let min = field(h.number())?;
        let max = field(h.number())?;
        if engine_level < min || max != 0 && engine_level > max {
            return Ok(None);
        }
        if hook != LOGICAL_HOOK || exclude != 0 {
            return Err(unsupported("hook or target exclusion"));
        }
        if field(h.number())? != 0 {
            return Err(unsupported("resource requirement"));
        }
        field(h.string())?; // Compiler version.
        let type_count = field(h.number())?;
        if field(h.number())? != 1 {
            return Err(unsupported("entry function count"));
        }
        if field(h.number())? != 0x53e5493e9f3d1c30 || field(h.fixed(2))? != 42 {
            return Err(invalid("invalid CBC header magic"));
        }
        field(h.expect(b':'))?;
        let max_line = str::from_utf8(h.0)
            .ok()
            .and_then(|s| s.parse::<usize>().ok());
        let max_line = field(max_line.filter(|&n| n > 0))?;
        let mut line = || {
            let bytes = field(lines.next())?;
            if bytes.len() > max_line {
                return Err(invalid("CBC line exceeds its declared size"));
            }
            Ok(Cursor(bytes))
        };
        let trigger = str::from_utf8(line()?.0).map_err(|_| invalid("invalid CBC trigger text"))?;
        if trigger.is_empty() || trigger.bytes().any(|b| b.is_ascii_control()) {
            return Err(invalid("invalid CBC logical trigger"));
        }
        let types = types(line()?, type_count)?;
        let apis = api(line()?, &types)?;
        let globals = globals(line()?, &types)?;
        let function = line()?;
        if function.first() == Some(b'D') {
            return Err(unsupported("debug metadata"));
        }
        let (slots, instruction_count, block_count) = entry(function, &types)?;
        let mut blocks = Vec::new();
        let mut remaining = instruction_count;
        let mut data_budget = MAX_MEMBER_BYTES as usize;
        let ctx = Decode {
            types: &types,
            apis: &apis,
            globals: &globals,
            engine_level,
        };
        for index in 0..block_count {
            let mut line = line()?;
            field(line.expect(b'B'))?;
            let mut instructions = Vec::new();
            loop {
                remaining = remaining
                    .checked_sub(1)
                    .ok_or_else(|| invalid("excess CBC instructions"))?;
                if line.first() == Some(b'T') {
                    instructions.push(terminator(&mut line, &slots, block_count)?);
                    break;
                }
                instructions.push(instruction(&mut line, &slots, &ctx, &mut data_budget)?);
            }
            if index + 1 == block_count {
                field(line.expect(b'E'))?;
            }
            if line.first() == Some(b'D') {
                return Err(unsupported("block debug metadata"));
            }
            field(line.end())?;
            blocks.push(instructions);
        }
        if remaining != 0 {
            return Err(invalid("missing CBC instructions"));
        }
        if lines.next().and_then(|s| s.first()) != Some(&b'S') {
            return Err(invalid("missing CBC source boundary"));
        }
        let uses_match_offsets = blocks
            .iter()
            .flatten()
            .any(|op| matches!(op, Instruction::Write(_, Expression::MatchOffset(_))));
        Ok(Some(Self {
            trigger: trigger.into(),
            uses_match_offsets,
            locals: slots,
            blocks,
        }))
    }

    pub fn trigger(&self) -> &str {
        &self.trigger
    }

    pub fn uses_match_offsets(&self) -> bool {
        self.uses_match_offsets
    }

    /// Run on the current scan object. Treat a bytecode-only timeout as a miss.
    pub fn run(
        &self,
        input: &[u8],
        offsets: &[u32; 64],
        counts: &[u32],
        timeout: Duration,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<&str>> {
        let mut locals = Frame::new(&self.locals);
        let mut name = None;
        let mut block = 0;
        let start = Instant::now();
        let mut operations = 0;
        loop {
            for instruction in &self.blocks[block] {
                check()?;
                operations += 1;
                if operations == CLOCK_INTERVAL {
                    operations = 0;
                    if start.elapsed() >= timeout {
                        return Ok(None);
                    }
                }
                match instruction {
                    Instruction::Write(dest, expression) => {
                        let Some(value) = expression.eval(
                            &mut locals,
                            input,
                            offsets,
                            counts,
                            &mut name,
                            &mut check,
                        )?
                        else {
                            return Ok(None);
                        };
                        locals.set(*dest, value);
                    }
                    Instruction::Effect(op) => {
                        if memory::outcome(op.eval(&mut locals, input))?.is_none() {
                            return Ok(None);
                        }
                    }
                    Instruction::Branch(value, yes, no) => {
                        block = if value.get(&locals) & 1 != 0 {
                            *yes
                        } else {
                            *no
                        };
                        break;
                    }
                    Instruction::Jump(target) => {
                        block = *target;
                        break;
                    }
                    Instruction::Return => return Ok(name),
                    Instruction::Abort => return Ok(None),
                }
            }
        }
    }
}

enum Type {
    HostArray,
    Bytes(usize),
    Pointer(u64),
    Function(Vec<u64>),
}

fn user_type(types: &[Type], id: u64) -> Option<&Type> {
    types.get(usize::try_from(id).ok()?.checked_sub(FIRST_USER_TYPE)?)
}

fn types(mut line: Cursor<'_>, total: u64) -> io::Result<Vec<Type>> {
    field(line.expect(b'T'))?;
    if field(line.fixed(2))? != FIRST_USER_TYPE as u64 {
        return Err(unsupported("type table base"));
    }
    // Four built-in pointer types and one reserved slot are included in the declared count.
    let count = field(total.checked_sub(5))?;
    if count > line.0.len() as u64 {
        return Err(invalid("truncated CBC type table"));
    }
    let mut types = Vec::new();
    for _ in 0..count {
        let ty = match field(line.fixed(1))? {
            1 => {
                let args = field(line.number())?;
                if args == 0 || args > line.0.len() as u64 {
                    return Err(unsupported("function prototype"));
                }
                Type::Function(
                    (0..args)
                        .map(|_| field(line.number()))
                        .collect::<io::Result<_>>()?,
                )
            }
            4 => {
                let n = field(line.number())?;
                match (field(line.number())?, n) {
                    (32, 1 | 64) => Type::HostArray,
                    (8, n) if n <= MAX_MEMBER_BYTES => Type::Bytes(n as usize),
                    _ => return Err(unsupported("array type or length")),
                }
            }
            5 => Type::Pointer(field(line.number())?),
            _ => return Err(unsupported("type kind")),
        };
        types.push(ty);
    }
    field(line.end())?;
    for ty in &types {
        if let Type::Pointer(id) = ty
            && !matches!(*id, 8 | 32 | BYTE_POINTER | 67)
            && !matches!(
                user_type(&types, *id),
                Some(Type::Bytes(_) | Type::HostArray)
            )
        {
            return Err(unsupported("pointer type"));
        }
    }
    Ok(types)
}

const READ: u64 = 2;
const SEEK: u64 = 4;
const FILE_FIND: u64 = 16;
const FILE_BYTEAT: u64 = 17;
const FILE_FIND_LIMIT: u64 = 65;
const ENGINE_LEVEL: u64 = 66;

fn api(mut line: Cursor<'_>, types: &[Type]) -> io::Result<Vec<u64>> {
    field(line.expect(b'E'))?;
    let max_id = field(line.number())?;
    let count = field(line.number())?;
    let mut apis = Vec::new();
    for _ in 0..count {
        let id = field(line.number())?;
        let (name, prototype): (&[u8], &[u64]) = match id {
            READ => (b"read\0", &[I32, BYTE_POINTER, I32]),
            SEEK => (b"seek\0", &[I32, I32, I32]),
            FILE_FIND => (b"file_find\0", &[I32, BYTE_POINTER, I32]),
            SET_VIRUS_NAME => (b"setvirusname\0", &[I32, BYTE_POINTER, I32]),
            FILE_BYTEAT => (b"file_byteat\0", &[I32, I32]),
            FILE_FIND_LIMIT => (b"file_find_limit\0", &[I32, BYTE_POINTER, I32, I32]),
            ENGINE_LEVEL => (b"engine_functionality_level\0", &[I32]),
            _ => return Err(unsupported("API declaration")),
        };
        let ty = user_type(types, field(line.number())?);
        if id > max_id
            || apis.contains(&id)
            || !matches!(ty, Some(Type::Function(args)) if args == prototype)
        {
            return Err(invalid("invalid CBC API declaration or prototype"));
        }
        let encoded = field(line.string())?;
        let decoded = encoded
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| ((pair[1] & 15) << 4) | (pair[0] & 15));
        if !decoded.eq(name.iter().copied()) {
            return Err(invalid("unexpected CBC name for API ID"));
        }
        apis.push(id);
    }
    field(line.end())?;
    Ok(apis)
}

enum Global {
    FileSize,
    Scalar,
    MatchOffset(usize),
    MatchCount(usize),
    Zero,
    Bytes(Arc<[u8]>),
    Pointer { base: usize, offset: usize },
}

impl Cursor<'_> {
    fn literal(&mut self) -> io::Result<u64> {
        let prefix = field(self.take(1))?[0];
        if !(b'@'..=b'P').contains(&prefix) {
            return Err(invalid("invalid CBC literal"));
        }
        field(self.fixed(usize::from(prefix - b'@')))
    }

    fn index_literal(&mut self) -> io::Result<usize> {
        usize::try_from(self.literal()?).map_err(|_| invalid("CBC index exceeds addressable data"))
    }

    fn i32_literal(&mut self) -> io::Result<u32> {
        let value = self.literal()?;
        if field(self.fixed(1))? != 4 {
            return Err(unsupported("scalar operand width"));
        }
        u32::try_from(value).map_err(|_| invalid("CBC scalar exceeds i32 storage"))
    }
}

fn globals(mut line: Cursor<'_>, types: &[Type]) -> io::Result<Vec<Global>> {
    field(line.expect(b'G'))?;
    const MATCH_COUNTS: u64 = 0x8000;
    const FILE_SIZE: u64 = 0x8004;
    const MATCH_OFFSETS: u64 = 0x8005;
    let max_host = field(line.number())?;
    if !matches!(max_host, 0 | MATCH_COUNTS | FILE_SIZE | MATCH_OFFSETS) {
        return Err(unsupported("host global"));
    }
    let count = field(line.number())?;
    if count > line.0.len() as u64 {
        return Err(invalid("truncated CBC global table"));
    }
    let mut globals = Vec::new();
    for index in 0..count {
        let id = field(line.number())?;
        let global = match (id, user_type(types, id)) {
            (0, _) if index == 0 && line.literal()? == 0 => Global::Zero,
            (1 | 8 | 16 | 32 | 64, _) => {
                line.literal()?;
                Global::Scalar
            }
            (67, _) | (_, Some(Type::Pointer(32))) => {
                let offset = line.index_literal()?;
                let base = line.literal()?;
                match base {
                    MATCH_COUNTS if max_host >= MATCH_COUNTS && offset % 4 == 0 && offset < 256 => {
                        Global::MatchCount(offset / 4)
                    }
                    FILE_SIZE if offset == 0 && max_host >= FILE_SIZE => Global::FileSize,
                    MATCH_OFFSETS
                        if max_host == MATCH_OFFSETS && offset % 4 == 0 && offset < 256 =>
                    {
                        Global::MatchOffset(offset / 4)
                    }
                    _ => return Err(unsupported("i32 pointer outside supported host globals")),
                }
            }
            (BYTE_POINTER, _) | (_, Some(Type::Pointer(8))) => Global::Pointer {
                offset: line.index_literal()?,
                base: line.index_literal()?,
            },
            (_, Some(Type::Bytes(len))) => {
                if *len > line.0.len() {
                    return Err(invalid("truncated CBC byte array"));
                }
                let mut bytes = Vec::with_capacity(*len);
                for _ in 0..*len {
                    bytes.push(
                        u8::try_from(line.literal()?).map_err(|_| invalid("invalid CBC byte"))?,
                    );
                }
                Global::Bytes(bytes.into())
            }
            _ => return Err(unsupported("global type")),
        };
        field(line.expect(b'`'))?;
        globals.push(global);
    }
    field(line.end())?;
    for global in &globals {
        if let Global::Pointer { base, offset } = global
            && !matches!(globals.get(*base),Some(Global::Bytes(bytes)) if *offset <= bytes.len())
        {
            return Err(invalid("CBC global pointer outside its byte array"));
        }
    }
    Ok(globals)
}

fn entry(mut line: Cursor<'_>, types: &[Type]) -> io::Result<(Vec<Slot>, usize, usize)> {
    field(line.expect(b'A'))?;
    if field(line.fixed(1))? != 0 || field(line.number())? != I32 {
        return Err(unsupported("entry signature"));
    }
    field(line.expect(b'L'))?;
    let count = field(line.number())?;
    if count > u16::MAX.into() || count > line.0.len() as u64 {
        return Err(invalid("invalid CBC local count"));
    }
    let mut slots = Vec::new();
    let mut bytes = 0;
    for _ in 0..count {
        let ty = field(line.number())?;
        let addressable = field(line.fixed(1))? != 0;
        let slot = Slot::new(ty, addressable, bytes, types)?;
        bytes = slot.end();
        if bytes > MAX_MEMBER_BYTES as usize {
            return Err(unsupported("entry frame size"));
        }
        slots.push(slot);
    }
    field(line.expect(b'F'))?;
    let instructions = field(line.number())?;
    let blocks = field(line.number())?;
    if instructions > u16::MAX.into() || blocks == 0 || blocks > instructions {
        return Err(invalid("invalid CBC instruction or block count"));
    }
    field(line.end())?;
    Ok((slots, instructions as usize, blocks as usize))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Width(u32);

impl Width {
    const BOOL: Self = Self(1);
    const WORD: Self = Self(32);

    fn new(id: u64) -> io::Result<Self> {
        match id {
            1 | 8 | 16 | 32 | 64 => Ok(Self(id as u32)),
            _ => Err(unsupported("scalar type")),
        }
    }

    fn mask(self) -> u64 {
        u64::MAX >> (64 - self.0)
    }

    fn signed(self, value: u64) -> i64 {
        let shift = 64 - self.0;
        ((value << shift) as i64) >> shift
    }
}

#[derive(Clone, Copy, Debug)]
enum Value {
    Constant(u64),
    Local(usize),
}

impl Value {
    fn get(self, locals: &Frame<'_>) -> u64 {
        match self {
            Self::Constant(value) => value,
            Self::Local(i) => locals.get(i),
        }
    }
}

impl Cursor<'_> {
    fn local(&mut self, slots: &[Slot]) -> io::Result<(usize, Width)> {
        if matches!(self.first(), Some(b'@'..=b'P')) {
            return Err(unsupported("non-local operand"));
        }
        let i = usize::try_from(field(self.number())?)
            .map_err(|_| invalid("invalid CBC local index"))?;
        let width = field(slots.get(i))?
            .width
            .ok_or_else(|| unsupported("non-integer register"))?;
        Ok((i, width))
    }

    fn scalar(&mut self, slots: &[Slot], width: Width) -> io::Result<Value> {
        if matches!(self.first(), Some(b'@'..=b'P')) {
            let value = self.literal()?;
            if field(self.fixed(1))? != u64::from(width.0.div_ceil(8)) {
                return Err(unsupported("scalar operand width or global operand"));
            }
            Ok(Value::Constant(value & width.mask()))
        } else {
            let (i, ty) = self.local(slots)?;
            if ty != width {
                return Err(invalid("CBC scalar operand type mismatch"));
            }
            Ok(Value::Local(i))
        }
    }

    fn memory_length(&mut self, slots: &[Slot], wide: bool) -> io::Result<Value> {
        if !wide {
            return self.scalar(slots, Width::WORD);
        }
        // Stock reads a whole 64-bit cell for MEMSET and MEMMOVE.
        // The compiler stores each immediate in its own zero-padded cell.
        if matches!(self.first(), Some(b'@'..=b'P')) {
            let v = self.literal()?;
            return match field(self.fixed(1))? {
                4 => Ok(Value::Constant(v & u64::from(u32::MAX))),
                8 => Ok(Value::Constant(v)),
                _ => Err(unsupported("memory length operand width")),
            };
        }
        self.scalar(slots, Width(64))
    }

    fn global<'a>(&mut self, globals: &'a [Global]) -> io::Result<&'a Global> {
        if !matches!(self.first(), Some(b'@'..=b'P')) {
            return Err(unsupported("non-global pointer operand"));
        }
        let id = self.index_literal()?;
        if field(self.fixed(1))? != 0 {
            return Err(unsupported("non-global pointer operand"));
        }
        field(globals.get(id))
    }

    fn const_bytes<'a>(&mut self, globals: &'a [Global]) -> io::Result<(&'a [u8], usize)> {
        let Global::Pointer { base, offset } = self.global(globals)? else {
            return Err(unsupported("host call without an immutable byte pointer"));
        };
        let Some(Global::Bytes(bytes)) = globals.get(*base) else {
            return Err(invalid("invalid CBC byte pointer"));
        };
        let bytes = field(bytes.get(*offset..))?;
        if !matches!(self.first(), Some(b'@'..=b'P')) {
            return Err(unsupported("dynamic host-call buffer length"));
        }
        let len = self.i32_literal()? as usize;
        if len > bytes.len() {
            return Err(invalid("CBC host-call length exceeds its global array"));
        }
        Ok((bytes, len))
    }
}

#[derive(Debug)]
enum Instruction {
    Write(usize, Expression),
    Effect(MemoryOp),
    Branch(Value, usize, usize),
    Jump(usize),
    Return,
    Abort,
}

#[derive(Debug, Clone, Copy)]
enum Binary {
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    URem,
    SRem,
    Shl,
    LShr,
    AShr,
    And,
    Or,
    Xor,
    Eq,
    Ne,
    Ugt,
    Uge,
    Ult,
    Ule,
    Sgt,
    Sge,
    Sle,
    Slt,
}

impl Binary {
    const MATH: [Self; 13] = [
        Self::Add,
        Self::Sub,
        Self::Mul,
        Self::UDiv,
        Self::SDiv,
        Self::URem,
        Self::SRem,
        Self::Shl,
        Self::LShr,
        Self::AShr,
        Self::And,
        Self::Or,
        Self::Xor,
    ];
    const COMPARISON: [Self; 10] = [
        Self::Eq,
        Self::Ne,
        Self::Ugt,
        Self::Uge,
        Self::Ult,
        Self::Ule,
        Self::Sgt,
        Self::Sge,
        Self::Sle,
        Self::Slt,
    ];

    fn eval(self, width: Width, a: u64, b: u64) -> Option<u64> {
        // The interpreter reads i1 arithmetic operands as masked, positive bytes.
        let signed = |n| {
            if width == Width::BOOL {
                n as i64
            } else {
                width.signed(n)
            }
        };
        let value = match self {
            Self::Add => a.wrapping_add(b),
            Self::Sub => a.wrapping_sub(b),
            Self::Mul => a.wrapping_mul(b),
            Self::UDiv => a.checked_div(b)?,
            Self::URem => a.checked_rem(b)?,
            Self::SDiv => signed(a).checked_div(signed(b))? as u64,
            Self::SRem => signed(a).checked_rem(signed(b))? as u64,
            Self::Shl | Self::LShr | Self::AShr if b > u64::from(width.0) => return None,
            Self::Shl | Self::LShr | Self::AShr => {
                // Narrow C operands are promoted to 32 bits before shifting.
                let shift = b as u32 % width.0.max(32);
                match self {
                    Self::Shl => a << shift,
                    Self::LShr => a >> shift,
                    _ => (signed(a) >> shift) as u64,
                }
            }
            Self::And => a & b,
            Self::Or => a | b,
            Self::Xor => a ^ b,
            Self::Eq => u64::from(a == b),
            Self::Ne => u64::from(a != b),
            Self::Ugt => u64::from(a > b),
            Self::Uge => u64::from(a >= b),
            Self::Ult => u64::from(a < b),
            Self::Ule => u64::from(a <= b),
            Self::Sgt => u64::from(signed(a) > signed(b)),
            Self::Sge => u64::from(signed(a) >= signed(b)),
            Self::Sle => u64::from(signed(a) <= signed(b)),
            Self::Slt => u64::from(signed(a) < signed(b)),
        };
        Some(value & width.mask())
    }
}

#[derive(Debug)]
enum Expression {
    Binary(Binary, Width, Value, Value),
    Cast {
        source: usize,
        from: Width,
        to: Width,
        sign_extend: bool,
    },
    Select(Value, Value, Value),
    Copy(Value),
    FileByte(Value),
    Find(Address, Value, Option<Value>),
    Memory(MemoryOp),
    ByteSwap(Value, Width),
    MatchOffset(usize),
    MatchCount(usize),
    FileSize,
    SetName(Box<str>),
}

impl Expression {
    fn eval<'a>(
        &'a self,
        locals: &mut Frame<'_>,
        input: &[u8],
        offsets: &[u32; 64],
        counts: &[u32],
        name: &mut Option<&'a str>,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<u64>> {
        let value = match *self {
            Self::Binary(op, width, a, b) => {
                return Ok(op.eval(width, a.get(locals), b.get(locals)));
            }
            Self::Cast {
                source,
                from,
                to,
                sign_extend,
            } => {
                let v = locals.get(source);
                (if sign_extend {
                    from.signed(v) as u64
                } else {
                    v
                }) & to.mask()
            }
            Self::Select(cond, yes, no) => {
                (if cond.get(locals) & 1 == 1 { yes } else { no }).get(locals)
            }
            Self::Copy(v) => v.get(locals),
            Self::FileByte(v) => input
                .get(v.get(locals) as usize)
                .map_or(u32::MAX as u64, |&b| u64::from(b)),
            Self::FileSize => input.len() as u32 as u64,
            Self::MatchCount(i) => u64::from(counts.get(i).copied().unwrap_or(0)),
            Self::MatchOffset(i) => u64::from(offsets[i]),
            Self::Memory(ref op) => return memory::outcome(op.eval(locals, input)),
            Self::ByteSwap(v, width) => {
                let v = v.get(locals);
                match width.0 {
                    16 => u64::from((v as u16).swap_bytes()),
                    32 => u64::from((v as u32).swap_bytes()),
                    _ => v.swap_bytes(),
                }
            }
            Self::Find(ref source, len, limit) => {
                let size = len.get(locals) as usize;
                let Some(needle) = memory::outcome(source.read(locals, size))? else {
                    return Ok(None);
                };
                let limit = limit.map_or(input.len(), |v| (v.get(locals) as i32).max(0) as usize);
                let length = input.len().min(limit);
                let mut result = u32::MAX;
                if !needle.is_empty() && needle.len() <= 1024 {
                    // Stock file_find_limit searches each 4096-byte read independently.
                    let finder = memchr::memmem::Finder::new(needle);
                    for (i, chunk) in input
                        .get(locals.cursor..length)
                        .unwrap_or_default()
                        .chunks(FIND_WINDOW)
                        .enumerate()
                    {
                        if i != 0 && i % 64 == 0 {
                            check()?;
                        }
                        if let Some(at) = finder.find(chunk) {
                            result = (locals.cursor + i * FIND_WINDOW + at) as u32;
                            break;
                        }
                    }
                }
                u64::from(result)
            }
            Self::SetName(ref s) => {
                *name = Some(s);
                0
            }
        };
        Ok(Some(value))
    }
}

fn terminator(line: &mut Cursor<'_>, slots: &[Slot], blocks: usize) -> io::Result<Instruction> {
    field(line.expect(b'T'))?;
    let target = |line: &mut Cursor<'_>| -> io::Result<usize> {
        let i = field(line.number())?;
        if i == 0 || i >= blocks as u64 {
            return Err(invalid("CBC branch target outside function"));
        }
        Ok(i as usize)
    };
    Ok(match field(line.fixed(2))? {
        17 => Instruction::Branch(
            line.scalar(slots, Width::BOOL)?,
            target(line)?,
            target(line)?,
        ),
        18 => Instruction::Jump(target(line)?),
        19 => {
            if field(line.number())? != I32 {
                return Err(unsupported("entry return type"));
            }
            line.scalar(slots, Width::WORD)?;
            Instruction::Return
        }
        45 => Instruction::Abort,
        _ => return Err(unsupported("entry terminator")),
    })
}

struct Decode<'a> {
    types: &'a [Type],
    apis: &'a [u64],
    globals: &'a [Global],
    engine_level: u64,
}

fn instruction(
    line: &mut Cursor<'_>,
    slots: &[Slot],
    ctx: &Decode<'_>,
    data_budget: &mut usize,
) -> io::Result<Instruction> {
    let ty = field(line.number())?;
    let dest = field(line.number())?;
    let opcode = field(line.fixed(2))?;
    if dest >= slots.len() as u64 && (opcode != 45 || dest != 0) {
        return Err(invalid("CBC instruction destination outside function"));
    }
    if opcode == 45 {
        return Ok(Instruction::Abort);
    }
    let globals = ctx.globals;
    if matches!(opcode, 35 | 36) {
        let dest = dest as usize;
        let slot = field(slots.get(dest))?;
        if slot.ty != ty || slot.addressable || slot.width.is_some() {
            return Err(invalid("CBC GEP destination must be a pointer register"));
        }
        let gep = memory::gep(line, opcode, ty, slots, ctx.types, globals)?;
        return Ok(Instruction::Write(dest, Expression::Memory(gep)));
    }
    if opcode == 38 {
        let width = Width::new(ty)?;
        let value = line.scalar(slots, width)?;
        let ptr = Address::decode(line, slots, globals, true)?;
        if !matches!(ptr, Address::Pointer(_)) {
            return Err(unsupported("STORE destination outside a pointer register"));
        }
        return Ok(Instruction::Effect(MemoryOp::Store(ptr, value, width)));
    }
    if matches!(opcode, 40..=42) {
        if ty != 0 {
            return Err(invalid("CBC memory operation must be void"));
        }
        let dest = Address::decode(line, slots, globals, true)?;
        let op = if opcode == 40 {
            let byte = line.scalar(slots, Width(8))?;
            MemoryOp::Fill(dest, byte, line.memory_length(slots, true)?)
        } else {
            let source = Address::decode(line, slots, globals, false)?;
            MemoryOp::Transfer {
                dest,
                source,
                len: line.memory_length(slots, opcode == 42)?,
                overlapping: opcode == 42,
            }
        };
        return Ok(Instruction::Effect(op));
    }
    if opcode == 34 {
        // COPY writes its second operand. Its instruction header carries no result.
        let source = if matches!(line.first(), Some(b'@'..=b'P')) {
            let value = line.literal()?;
            let storage = field(line.fixed(1))?;
            let (i, width) = line.local(slots)?;
            if storage != u64::from(width.0.div_ceil(8)) {
                return Err(unsupported("COPY constant width or global"));
            }
            (i, Value::Constant(value & width.mask()))
        } else {
            let (src, from) = line.local(slots)?;
            let (i, to) = line.local(slots)?;
            if from != to {
                return Err(invalid("CBC COPY operand types differ"));
            }
            (i, Value::Local(src))
        };
        return Ok(Instruction::Write(source.0, Expression::Copy(source.1)));
    }
    let width = Width::new(ty)?;
    let dest = usize::try_from(dest).map_err(|_| invalid("invalid CBC destination"))?;
    if slots.get(dest).and_then(|s| s.width) != Some(width) {
        return Err(invalid("CBC destination type mismatch"));
    }
    let expr = match opcode {
        1..=13 | 21..=30 => {
            let (op, ty) = if opcode <= 13 {
                (Binary::MATH[opcode as usize - 1], width)
            } else {
                if width != Width::BOOL {
                    return Err(invalid("CBC comparison result must be i1"));
                }
                (
                    Binary::COMPARISON[opcode as usize - 21],
                    Width::new(field(line.number())?)?,
                )
            };
            Expression::Binary(op, ty, line.scalar(slots, ty)?, line.scalar(slots, ty)?)
        }
        14..=16 => {
            let (source, from) = line.local(slots)?;
            if (opcode == 14 && from.0 <= width.0) || (opcode != 14 && from.0 >= width.0) {
                return Err(invalid("invalid CBC integer cast widths"));
            }
            Expression::Cast {
                source,
                from,
                to: width,
                sign_extend: opcode == 15,
            }
        }
        31 => Expression::Select(
            line.scalar(slots, Width::BOOL)?,
            line.scalar(slots, width)?,
            line.scalar(slots, width)?,
        ),
        33 => host_call(line, width, slots, ctx, data_budget)?,
        39 => {
            let mut peek = Cursor(line.0);
            let host = if matches!(line.first(), Some(b'@'..=b'P')) {
                match peek.global(globals)? {
                    Global::MatchCount(i) => Some(Expression::MatchCount(*i)),
                    Global::MatchOffset(i) => Some(Expression::MatchOffset(*i)),
                    Global::FileSize => Some(Expression::FileSize),
                    _ => None,
                }
            } else {
                None
            };
            if let Some(host) = host {
                if width != Width::WORD {
                    return Err(unsupported("host global load width"));
                }
                *line = peek;
                host
            } else {
                Expression::Memory(MemoryOp::Load(
                    Address::decode(line, slots, globals, false)?,
                    width,
                ))
            }
        }
        43 if width == Width::WORD => Expression::Memory(MemoryOp::Compare(
            Address::decode(line, slots, globals, false)?,
            Address::decode(line, slots, globals, false)?,
            line.scalar(slots, Width::WORD)?,
        )),
        44 if width == Width::BOOL => {
            Expression::Copy(Value::Constant(u64::from(cfg!(target_endian = "big"))))
        }
        46..=48 if width.0 == 16 << (opcode - 46) => {
            Expression::ByteSwap(line.scalar(slots, width)?, width)
        }
        _ => return Err(unsupported("instruction opcode")),
    };
    Ok(Instruction::Write(dest, expr))
}

fn host_call(
    line: &mut Cursor<'_>,
    width: Width,
    slots: &[Slot],
    ctx: &Decode<'_>,
    data_budget: &mut usize,
) -> io::Result<Expression> {
    let globals = ctx.globals;
    let count = field(line.fixed(1))?;
    let id = field(line.number())?;
    if width != Width::WORD || !ctx.apis.contains(&id) {
        return Err(unsupported("host call"));
    }
    Ok(match (id, count) {
        (SET_VIRUS_NAME, 2) => {
            let (bytes, _) = line.const_bytes(globals)?;
            // The VM checks the supplied length. The API reads through the first NUL.
            let nul = field(bytes.iter().position(|&b| b == 0))?;
            let name =
                str::from_utf8(&bytes[..nul]).map_err(|_| invalid("invalid CBC detection name"))?;
            if name.is_empty() || name.bytes().any(|b| b.is_ascii_control()) {
                return Err(invalid("empty or control-containing CBC detection name"));
            }
            *data_budget = data_budget
                .checked_sub(name.len())
                .ok_or_else(|| unsupported("constant data budget"))?;
            Expression::SetName(name.into())
        }
        (FILE_BYTEAT, 1) => Expression::FileByte(line.scalar(slots, Width::WORD)?),
        (READ, 2) => Expression::Memory(MemoryOp::Read(
            Address::decode(line, slots, globals, true)?,
            line.scalar(slots, Width::WORD)?,
        )),
        (SEEK, 2) => Expression::Memory(MemoryOp::Seek(
            line.scalar(slots, Width::WORD)?,
            line.scalar(slots, Width::WORD)?,
        )),
        (FILE_FIND, 2) | (FILE_FIND_LIMIT, 3) => {
            let from = Address::decode(line, slots, globals, false)?;
            let len = line.scalar(slots, Width::WORD)?;
            let limit = if id == FILE_FIND_LIMIT {
                Some(line.scalar(slots, Width::WORD)?)
            } else {
                None
            };
            Expression::Find(from, len, limit)
        }
        (ENGINE_LEVEL, 0) => {
            Expression::Copy(Value::Constant(ctx.engine_level & u64::from(u32::MAX)))
        }
        _ => return Err(unsupported("host call argument count")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    fn fixed(value: u64, digits: usize) -> String {
        (0..digits)
            .map(|i| char::from(0x60 | ((value >> (4 * i)) & 0xf) as u8))
            .collect()
    }

    fn number(value: u64, literal: bool) -> String {
        let width = (64 - value.leading_zeros() as usize).div_ceil(4);
        let marker = if literal { b'@' } else { b'`' };
        format!(
            "{}{}",
            char::from(marker + width as u8),
            fixed(value, width)
        )
    }

    fn encoded_string(value: &[u8]) -> String {
        let encoded: String = value.iter().map(|&b| fixed(u64::from(b), 2)).collect();
        format!("|{}{encoded}", number(value.len() as u64, false))
    }

    // Assemble a local record with independent type IDs and a name beginning at a nonzero offset.
    fn sample(calls: bool) -> Vec<String> {
        let n = |v| number(v, false);
        let c = |v| number(v, true);
        let data = b"-Local.Receipt\0";
        let mut head = String::from("ClamBC");
        for part in [
            n(7),
            n(0),
            encoded_string(b"lab\0"),
            n(0),
            n(256),
            n(56),
            n(0),
            n(0),
            encoded_string(b"test\0"),
            n(7),
            n(1),
            n(0x53e5493e9f3d1c30),
            fixed(42, 2),
        ] {
            head += &part;
        }
        head += ":4096";
        let mut types = format!("T{}", fixed(69, 2));
        for value in [
            fixed(1, 1),
            n(3),
            n(32),
            n(65),
            n(32),
            fixed(4, 1),
            n(data.len() as u64),
            n(8),
        ] {
            types += &value;
        }
        let api = format!(
            "E{}{}{}{}{}",
            n(5),
            n(1),
            n(5),
            n(69),
            encoded_string(b"setvirusname\0")
        );
        let mut globals = format!("G{}{}{}{}`{}", n(0), n(3), n(0), c(0), n(70));
        for &byte in data {
            globals += &c(u64::from(byte));
        }
        globals += &format!("`{}{}{}`", n(65), c(1), c(1));
        let mut entry = format!("A{}{}L{}", fixed(0, 1), n(32), n(u64::from(calls)));
        let mut block = String::from("B");
        if calls {
            entry += &format!("{}{}", n(32), fixed(0, 1));
            for v in [
                n(32),
                n(0),
                fixed(33, 2),
                fixed(2, 1),
                n(5),
                c(2),
                fixed(0, 1),
                c(13),
                fixed(4, 1),
            ] {
                block += &v;
            }
        }
        entry += &format!("F{}{}", n(if calls { 2 } else { 1 }), n(1));
        block += &format!("T{}{}{}{}E", fixed(19, 2), n(32), c(9), fixed(4, 1));
        vec![
            head,
            "Local.Trigger;Target:0;0;72656365697074".into(),
            types,
            api,
            globals,
            entry,
            block,
            "S".into(),
        ]
    }

    #[test]
    fn resolves_names_from_compiled_bytes_and_checks_each_instruction() -> io::Result<()> {
        for calls in [true, false] {
            let module = sample(calls).join("\n");
            let program = Program::compile(module.as_bytes(), 213)?.unwrap();
            assert_eq!(program.trigger(), "Local.Trigger;Target:0;0;72656365697074");
            let mut steps = 0;
            assert_eq!(
                program.run(&[], &[0; 64], &[], TEST_TIMEOUT, || {
                    steps += 1;
                    Ok(())
                })?,
                calls.then_some("Local.Receipt")
            );
            assert_eq!(steps, if calls { 2 } else { 1 });
            assert!(
                program
                    .run(&[], &[0; 64], &[], TEST_TIMEOUT, || Err(io::Error::other(
                        "cancelled"
                    )))
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn checks_skip_windows_and_rejects_other_operations() {
        let text = sample(true).join("\n");
        assert!(Program::compile(text.as_bytes(), 55).unwrap().is_none());
        assert!(Program::compile(b"ClamBCai", 213).unwrap().is_none()); // Format 9.
        let mut unsupported = sample(true);
        unsupported[6] = unsupported[6].replacen(&fixed(33, 2), &fixed(32, 2), 1);
        assert_eq!(
            Program::compile(unsupported.join("\n").as_bytes(), 213)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        let mut outside = sample(true);
        outside[6] = outside[6].replace(&number(13, true), &number(15, true));
        assert!(Program::compile(outside.join("\n").as_bytes(), 213).is_err());
        let mut missing = sample(true);
        missing.remove(6);
        assert!(Program::compile(missing.join("\n").as_bytes(), 213).is_err());
    }

    #[test]
    fn executes_a_counted_loop_and_checks_cancellation_on_back_edges() -> io::Result<()> {
        let mut module = sample(true);
        let n = |v| number(v, false);
        let op = |ty, dest, opcode| format!("{}{}{}", n(ty), n(dest), fixed(opcode, 2));
        let byte = |v| number(v, true) + &fixed(1, 1);
        let jump = |block| format!("T{}{}", fixed(18, 2), n(block));
        let branch = |v, yes, no| format!("T{}{}{}{}", fixed(17, 2), n(v), n(yes), n(no));
        let mut entry = format!("A{}{}L{}", fixed(0, 1), n(32), n(3));
        for ty in [32, 8, 1] {
            entry += &(n(ty) + &fixed(0, 1));
        }
        module[5] = entry + "F" + &n(7) + &n(3);
        let hit = module[6].clone();
        module.splice(
            6..7,
            [
                "B".to_string() + &op(0, 0, 34) + &byte(3) + &n(1) + &jump(1),
                "B".to_string()
                    + &op(8, 1, 2)
                    + &n(1)
                    + &byte(1)
                    + &op(1, 2, 21)
                    + &n(8)
                    + &n(1)
                    + &byte(0)
                    + &branch(2, 2, 1),
                hit,
            ],
        );
        let program = Program::compile(module.join("\n").as_bytes(), 213)?.unwrap();
        let mut steps = 0;
        let result = program.run(&[], &[0; 64], &[], TEST_TIMEOUT, || {
            steps += 1;
            Ok(())
        })?;
        assert_eq!(result, Some("Local.Receipt"));
        assert_eq!(steps, 13);
        let mut steps = 0;
        let error = program
            .run(&[], &[0; 64], &[], TEST_TIMEOUT, || {
                steps += 1;
                if steps == 8 {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        for target in [0, 3] {
            let mut bad = module.clone();
            bad[7] = bad[7].replace(&branch(2, 2, 1), &branch(2, target, 1));
            assert!(Program::compile(bad.join("\n").as_bytes(), 213).is_err());
        }
        Ok(())
    }

    #[test]
    fn preserves_signedness_width_and_arithmetic_faults() {
        for bits in [1, 8, 16, 32, 64] {
            let w = Width(bits);
            let max = w.mask();
            assert_eq!(Binary::Add.eval(w, max, 1), Some(0));
            assert_eq!(Binary::Sub.eval(w, 0, 1), Some(max));
            assert_eq!(Binary::Ult.eval(w, max, 0), Some(0));
            assert_eq!(Binary::Slt.eval(w, max, 0), Some(u64::from(bits != 1)));
            assert_eq!(Binary::UDiv.eval(w, 1, 0), None);
        }
        assert_eq!(Binary::SDiv.eval(Width(8), 250, 2), Some(253));
        assert_eq!(Binary::SRem.eval(Width(16), 65531, 2), Some(65535));
        assert_eq!(Binary::AShr.eval(Width(16), 0x8000, 1), Some(0xc000));
        assert_eq!(Binary::Shl.eval(Width(8), 1, 9), None);
        assert_eq!(Binary::SDiv.eval(Width(64), 1 << 63, u64::MAX), None);
    }

    #[test]
    fn decodes_scalar_casts_and_select() -> io::Result<()> {
        let slots = [8, 16, 32, 1, 64]
            .into_iter()
            .enumerate()
            .map(|(i, w)| Slot::new(w, false, i * 8, &[]))
            .collect::<io::Result<Vec<_>>>()?;
        let mut locals = Frame::new(&slots);
        locals.set(0, 0xfb);
        let n = |v| number(v, false);
        let write = |outputs: &mut Frame<'_>, ty, dest, opcode, args: String| -> io::Result<()> {
            let text = n(ty) + &n(dest) + &fixed(opcode, 2) + &args;
            let mut line = Cursor(text.as_bytes());
            let Instruction::Write(i, expr) = instruction(
                &mut line,
                &slots,
                &Decode {
                    types: &[],
                    apis: &[],
                    globals: &[],
                    engine_level: 213,
                },
                &mut 0,
            )?
            else {
                panic!("expected scalar result")
            };
            field(line.end())?;
            let result = expr
                .eval(outputs, &[], &[0; 64], &[], &mut None, &mut || Ok(()))?
                .unwrap();
            outputs.set(i, result);
            Ok(())
        };
        write(&mut locals, 16, 1, 15, n(0))?; // Sign-extend i8 -5.
        write(&mut locals, 32, 2, 16, n(1))?; // Zero-extend i16.
        write(&mut locals, 1, 3, 14, n(2))?; // Truncate to the low bit.
        write(&mut locals, 64, 4, 15, n(3))?;
        let choices = n(3) + &n(2) + &number(7, true) + &fixed(4, 1);
        write(&mut locals, 32, 2, 31, choices.clone())?;
        assert_eq!(
            [0, 1, 2, 3, 4].map(|i| locals.get(i)),
            [0xfb, 0xfffb, 0xfffb, 1, u64::MAX]
        );
        locals.set(3, 0);
        write(&mut locals, 32, 2, 31, choices)?;
        assert_eq!(locals.get(2), 7);
        Ok(())
    }

    #[test]
    fn reads_checked_host_data_with_the_stock_search_window() {
        let offsets = [123; 64];
        let mut input = vec![0xff; 8192];
        input[4095..4097].copy_from_slice(b"ab");
        input[5010..5012].copy_from_slice(b"ab");
        let read = |expr: Expression| {
            expr.eval(
                &mut Frame::new(&[]),
                &input,
                &offsets,
                &[],
                &mut None,
                &mut || Ok(()),
            )
            .unwrap()
        };
        assert_eq!(read(Expression::FileByte(Value::Constant(0))), Some(255));
        assert_eq!(
            read(Expression::FileByte(Value::Constant(8192))),
            Some(u32::MAX.into())
        );
        assert_eq!(read(Expression::MatchOffset(63)), Some(123));
        let find = |limit| {
            read(Expression::Find(
                Address::Constant(b"ab".as_slice().into(), 0),
                Value::Constant(2),
                Some(Value::Constant(limit)),
            ))
        };
        assert_eq!(find(5011), Some(u32::MAX.into()));
        assert_eq!(find(5012), Some(5010));
        assert_eq!(find(u32::MAX.into()), Some(u32::MAX.into()));
    }

    #[test]
    fn polls_cancellation_during_a_single_host_search() {
        let input = vec![b'-'; 65 * FIND_WINDOW];
        let search = Expression::Find(
            Address::Constant(b"ABC".as_slice().into(), 0),
            Value::Constant(3),
            None,
        );
        let error = search
            .eval(
                &mut Frame::new(&[]),
                &input,
                &[0; 64],
                &[],
                &mut None,
                &mut || Err(io::ErrorKind::Interrupted.into()),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    #[ignore = "requires the pinned upstream harmless CBC fixture"]
    fn stock_marker() -> io::Result<()> {
        let path = std::env::var_os("BARNACLE_CBC_FIXTURE").ok_or_else(|| {
            io::Error::other("set BARNACLE_CBC_FIXTURE to the pinned stock fixture")
        })?;
        let data = std::fs::read(path)?;
        let program = Program::compile(&data, 213)?.unwrap();
        assert_eq!(
            program.run(&[], &[0; 64], &[], TEST_TIMEOUT, || Ok(()))?,
            Some("BC.Clamav-Unit-Test-Signature")
        );
        Ok(())
    }
}
