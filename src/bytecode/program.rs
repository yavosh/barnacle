//! A typed CBC interpreter for logical signatures, PDF hooks, and PE hooks.
use super::{Cursor, MAX_MEMBER_BYTES, PdfHookContext, PdfHookResult, invalid};
use std::time::{Duration, Instant};
use std::{io, str, sync::Arc};

mod disasm;
mod host;
mod memory;
mod pdf;
use memory::{Address, Frame, MemoryOp, Slot};

const LOGICAL_HOOK: u64 = 256;
const PE_UNPACKER_HOOK: u64 = 257;
const PDF_HOOK: u64 = 258;
const PE_ALL_HOOK: u64 = 259;
const BREAK_RESULT: u64 = 0xcea5e;
const SET_VIRUS_NAME: u64 = 5;
const EXTRACT_NEW: u64 = 22;
const I32: u64 = 32;
const BYTE_POINTER: u64 = 65;
const FIRST_USER_TYPE: usize = 69;
const CLOCK_INTERVAL: u32 = 5_000;
const FIND_WINDOW: usize = 4096;
const MAX_CALL_DEPTH: usize = 64;

#[derive(Debug)]
pub struct Program {
    hook: u64,
    trigger: Box<str>,
    functions: Vec<Function>,
    module_globals: Box<[Global]>,
    uses_match_offsets: bool,
    pub(crate) match_count_slots: u64,
    pub(crate) writes_output: bool,
}

#[derive(Debug)]
struct Function {
    slots: Vec<Slot>,
    frame_bytes: usize,
    blocks: Vec<Vec<Instruction>>,
}

struct Signature {
    args: Vec<u64>,
    result: Option<Width>,
}

struct Header {
    signature: Signature,
    slots: Vec<Slot>,
    instructions: usize,
    blocks: usize,
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
    /// Compile a supported entry point inside its format and engine window.
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
        if !matches!(
            hook,
            LOGICAL_HOOK | PE_UNPACKER_HOOK | PDF_HOOK | PE_ALL_HOOK
        ) || exclude != 0
        {
            return Err(unsupported("hook or target exclusion"));
        }
        if field(h.number())? != 0 {
            return Err(unsupported("resource requirement"));
        }
        field(h.string())?; // Compiler version.
        let type_count = field(h.number())?;
        let function_count = field(h.number())?;
        if !(1..=u16::MAX.into()).contains(&function_count) {
            return Err(invalid("invalid CBC function count"));
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
            return Err(invalid("invalid CBC trigger text"));
        }
        match (hook, trigger.contains(';')) {
            (PDF_HOOK, true) => return Err(unsupported("conditional PDF hook")),
            (PE_ALL_HOOK, false) => {
                return Err(unsupported("PE_ALL hook without a logical prefilter"));
            }
            _ => {}
        }
        let types = types(line()?, type_count)?;
        let apis = api(line()?, &types, hook)?;
        let globals = globals(line()?, &types, hook)?;
        // Calls name functions by index and may target a later definition.
        let mut signatures = Vec::new();
        let mut bodies = Vec::new();
        let mut total = 0;
        for index in 0..function_count {
            let header = line()?;
            if header.first() == Some(b'D') {
                return Err(unsupported("debug metadata"));
            }
            let header = function_header(header, &types, index == 0)?;
            total += header.instructions;
            if total > u16::MAX as usize {
                return Err(unsupported("module instruction budget"));
            }
            let blocks = (0..header.blocks)
                .map(|_| line())
                .collect::<io::Result<Vec<_>>>()?;
            signatures.push(header.signature);
            bodies.push((header.slots, header.instructions, blocks));
        }
        if lines.next().and_then(|s| s.first()) != Some(&b'S') {
            return Err(invalid("missing CBC source boundary"));
        }
        let ctx = Decode {
            types: &types,
            apis: &apis,
            globals: &globals,
            engine_level,
            signatures: &signatures,
        };
        let mut data_budget = MAX_MEMBER_BYTES as usize;
        let mut functions = Vec::new();
        for ((slots, mut remaining, body), signature) in bodies.into_iter().zip(&signatures) {
            let block_count = body.len();
            let mut blocks = Vec::new();
            for (index, mut line) in body.into_iter().enumerate() {
                field(line.expect(b'B'))?;
                let mut instructions = Vec::new();
                loop {
                    remaining = remaining
                        .checked_sub(1)
                        .ok_or_else(|| invalid("excess CBC instructions"))?;
                    if line.first() == Some(b'T') {
                        instructions.push(terminator(
                            &mut line,
                            &slots,
                            block_count,
                            signature.result,
                        )?);
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
            let frame_bytes = if slots.iter().any(|s| s.addressable) {
                slots.last().map_or(0, Slot::end)
            } else {
                slots.len() * size_of::<u64>()
            };
            functions.push(Function {
                slots,
                frame_bytes,
                blocks,
            });
        }
        let mut uses_match_offsets = false;
        let mut uses_module_pointers = false;
        let mut match_count_slots = 0;
        for instruction in functions.iter().flat_map(|f| f.blocks.iter().flatten()) {
            match instruction {
                Instruction::Write(_, Expression::MatchOffset(_)) => uses_match_offsets = true,
                Instruction::Write(_, Expression::ModulePointer(_)) => uses_module_pointers = true,
                Instruction::Write(_, Expression::MatchCount(i)) => match_count_slots |= 1u64 << i,
                _ => (),
            }
        }
        Ok(Some(Self {
            hook,
            trigger: trigger.into(),
            uses_match_offsets,
            match_count_slots,
            writes_output: apis.contains(&host::WRITE),
            functions,
            module_globals: if uses_module_pointers {
                globals.into()
            } else {
                Box::default()
            },
        }))
    }

    pub fn trigger(&self) -> &str {
        &self.trigger
    }

    pub fn is_pdf_hook(&self) -> bool {
        self.hook == PDF_HOOK
    }

    pub fn is_pe_all_hook(&self) -> bool {
        self.hook == PE_ALL_HOOK
    }

    pub(crate) fn is_pe_unpacker(&self) -> bool {
        self.hook == PE_UNPACKER_HOOK
    }

    pub fn uses_match_offsets(&self) -> bool {
        self.hook == LOGICAL_HOOK && self.uses_match_offsets
    }

    /// Run on the current scan object. Treat a bytecode-only timeout as a miss.
    pub fn run(
        &self,
        input: &[u8],
        offsets: &[u32; 64],
        counts: &[u32],
        debug: bool,
        timeout: Duration,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<&str>> {
        self.run_logical(
            input,
            LogicalInput {
                offsets,
                counts,
                has_entry: None,
                output: None,
            },
            debug,
            timeout,
            check,
        )
    }

    pub(crate) fn run_logical(
        &self,
        input: &[u8],
        logical: LogicalInput<'_>,
        debug: bool,
        timeout: Duration,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<&str>> {
        if self.hook != LOGICAL_HOOK {
            return Err(unsupported("hook outside its scan phase"));
        }
        let scan = Scan {
            input,
            offsets: logical.offsets,
            counts: logical.counts,
            debug,
            output: logical.output,
            extract: None,
            has_entry: logical.has_entry.map_or_else(Default::default, Into::into),
            pdf: None,
            pe: Default::default(),
        };
        Ok(match self.execute(scan, timeout, check)? {
            PdfHookResult::Found(name) => Some(name),
            _ => None,
        })
    }

    /// Run one hook on its phase input. PostDump receives the extracted object's bytes.
    pub fn run_pdf(
        &self,
        input: &[u8],
        context: PdfHookContext<'_>,
        debug: bool,
        timeout: Duration,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<PdfHookResult<'_>> {
        if !self.is_pdf_hook() {
            return Err(unsupported("non-PDF entry in a PDF phase"));
        }
        self.run_hook(input, Some(context), None, debug, timeout, check)
    }

    pub fn run_pe_all(
        &self,
        input: &[u8],
        debug: bool,
        timeout: Duration,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<PdfHookResult<'_>> {
        if !self.is_pe_all_hook() {
            return Err(unsupported("non-PE_ALL entry in a PE phase"));
        }
        self.run_hook(input, None, None, debug, timeout, check)
    }

    pub(crate) fn run_pe_unpacker(
        &self,
        input: &[u8],
        unpacker: UnpackerInput<'_>,
        debug: bool,
        timeout: Duration,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<PdfHookResult<'_>> {
        if !self.is_pe_unpacker() {
            return Err(unsupported("non-unpacker entry in PE unpacker phase"));
        }
        self.run_hook(input, None, Some(unpacker), debug, timeout, check)
    }

    fn run_hook(
        &self,
        input: &[u8],
        pdf: Option<PdfHookContext<'_>>,
        unpacker: Option<UnpackerInput<'_>>,
        debug: bool,
        timeout: Duration,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<PdfHookResult<'_>> {
        // Stock executes the hook in a fresh context after prefilter selection.
        let scan = Scan {
            input,
            counts: &[],
            offsets: &[0; 64],
            debug,
            pdf,
            output: unpacker.as_ref().map(|u| (u.output, u.directory)),
            extract: unpacker.map(|u| u.extract),
            has_entry: Default::default(),
            pe: Default::default(),
        };
        self.execute(scan, timeout, check)
    }

    fn execute(
        &self,
        scan: Scan<'_>,
        timeout: Duration,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<PdfHookResult<'_>> {
        let mut function = &self.functions[0];
        let mut locals = Frame::new(&function.slots);
        locals.module_globals = &self.module_globals;
        let mut next = 0;
        let mut stack = Vec::<Caller<'_>>::new();
        let mut frame_bytes = function.frame_bytes;
        let mut name = None;
        let mut block = 0;
        let start = Instant::now();
        let mut operations = 0;
        loop {
            let first = std::mem::take(&mut next);
            for (index, instruction) in function.blocks[block].iter().enumerate().skip(first) {
                check()?;
                operations += 1;
                if operations == CLOCK_INTERVAL {
                    operations = 0;
                    if start.elapsed() >= timeout {
                        return Ok(PdfHookResult::Continue);
                    }
                }
                match instruction {
                    Instruction::Write(dest, expression) => {
                        let Some(value) =
                            expression.eval(&mut locals, &scan, &mut name, &mut check)?
                        else {
                            return Ok(PdfHookResult::Continue);
                        };
                        locals.set(*dest, value);
                    }
                    Instruction::Effect(op) => {
                        if memory::outcome(op.eval(&mut locals, scan.input))?.is_none() {
                            return Ok(PdfHookResult::Continue);
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
                    Instruction::Call { target, dest, args } => {
                        let callee = &self.functions[*target];
                        if stack.len() + 1 >= MAX_CALL_DEPTH
                            || frame_bytes + callee.frame_bytes > MAX_MEMBER_BYTES as usize
                        {
                            return Err(unsupported("direct call stack limit"));
                        }
                        locals.enter(&callee.slots, args)?;
                        stack.push(Caller {
                            function,
                            block,
                            next: index + 1,
                            dest: *dest,
                        });
                        function = callee;
                        frame_bytes += callee.frame_bytes;
                        block = 0;
                        break;
                    }
                    Instruction::Return(result) => {
                        let Some(caller) = stack.pop() else {
                            return Ok(match name {
                                Some(name) => PdfHookResult::Found(name),
                                None if self.hook != LOGICAL_HOOK
                                    && result.is_some_and(|v| v.get(&locals) == BREAK_RESULT) =>
                                {
                                    PdfHookResult::Break
                                }
                                None => PdfHookResult::Continue,
                            });
                        };
                        let value = result.map(|v| v.get(&locals));
                        locals.leave();
                        if let (Some(dest), Some(value)) = (caller.dest, value) {
                            locals.set(dest, value);
                        }
                        frame_bytes -= function.frame_bytes;
                        function = caller.function;
                        block = caller.block;
                        next = caller.next;
                        break;
                    }
                    Instruction::Abort => return Ok(PdfHookResult::Continue),
                }
            }
        }
    }
}

struct Caller<'a> {
    function: &'a Function,
    block: usize,
    next: usize,
    dest: Option<usize>,
}

pub(crate) struct LogicalInput<'a> {
    pub offsets: &'a [u32; 64],
    pub counts: &'a [u32],
    pub has_entry: Option<bool>,
    pub output: Option<(&'a std::cell::RefCell<super::Output>, &'a std::path::Path)>,
}

pub(crate) struct UnpackerInput<'a> {
    pub output: &'a std::cell::RefCell<super::Output>,
    pub directory: &'a std::path::Path,
    pub extract: &'a dyn Fn() -> io::Result<Option<u32>>,
}

struct Scan<'a> {
    extract: Option<&'a dyn Fn() -> io::Result<Option<u32>>>,
    output: Option<(&'a std::cell::RefCell<super::Output>, &'a std::path::Path)>,
    input: &'a [u8],
    offsets: &'a [u32; 64],
    counts: &'a [u32],
    debug: bool,
    pdf: Option<PdfHookContext<'a>>,
    has_entry: std::cell::OnceCell<bool>,
    pe: std::cell::OnceCell<Option<crate::body::PeMetadata>>,
}

enum Type {
    Array { len: usize, element: u64 },
    Struct { packed: bool, fields: Vec<u64> },
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
            kind @ (2 | 3) => {
                let n = field(line.number())?;
                if n == 0 || n > line.0.len() as u64 {
                    return Err(invalid("invalid CBC structure field count"));
                }
                let fields = (0..n)
                    .map(|_| field(line.number()))
                    .collect::<io::Result<_>>()?;
                Type::Struct {
                    packed: kind == 2,
                    fields,
                }
            }
            4 => {
                let n = field(line.number())?;
                match (field(line.number())?, n) {
                    (8, n) if n <= MAX_MEMBER_BYTES => Type::Bytes(n as usize),
                    (element, n) if n <= MAX_MEMBER_BYTES => Type::Array {
                        len: n as usize,
                        element,
                    },
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
        let valid =
            |id| matches!(id, 1 | 8 | 16 | 32 | 64 | 65..=68) || user_type(&types, id).is_some();
        match ty {
            Type::Struct { fields, .. } if fields.iter().any(|&id| !valid(id)) => {
                return Err(invalid("invalid CBC structure field type"));
            }
            Type::Array { len, element } => {
                if !valid(*element) {
                    return Err(invalid("invalid CBC array element type"));
                }
                if let Ok(width) = Width::new(*element)
                    && len.saturating_mul(width.0.div_ceil(8) as usize) > MAX_MEMBER_BYTES as usize
                {
                    return Err(unsupported("array type size"));
                }
            }
            _ => {}
        }
    }
    for ty in &types {
        if let Type::Pointer(id) = ty
            && !matches!(*id, 1 | 8 | 16 | 32 | 64 | 65..=68)
            && !matches!(
                user_type(&types, *id),
                Some(Type::Bytes(_) | Type::Array { .. } | Type::Struct { .. } | Type::Pointer(_))
            )
        {
            return Err(unsupported("pointer type"));
        }
    }
    Ok(types)
}

const READ: u64 = 2;
const SEEK: u64 = 4;
const MALLOC: u64 = 18;
const MEMSTR: u64 = 51;
const PE_SECTION: u64 = 20;
const FILE_FIND: u64 = 16;
const FILE_BYTEAT: u64 = 17;
const FILE_FIND_LIMIT: u64 = 65;
const ENGINE_LEVEL: u64 = 66;
const DCONF_LEVEL: u64 = 67;
const PINNED_DCONF_LEVEL: u64 = 213;

fn api(mut line: Cursor<'_>, types: &[Type], hook: u64) -> io::Result<Vec<u64>> {
    field(line.expect(b'E'))?;
    let max_id = field(line.number())?;
    let count = field(line.number())?;
    let mut apis = Vec::new();
    for _ in 0..count {
        let id = field(line.number())?;
        if id == host::WRITE && !matches!(hook, LOGICAL_HOOK | PE_UNPACKER_HOOK) {
            return Err(unsupported(
                "write outside a logical program or PE unpacker",
            ));
        }
        if id == host::MATCH_ICON && hook != LOGICAL_HOOK {
            return Err(unsupported("matchicon outside a logical program"));
        }
        if id == EXTRACT_NEW && hook != PE_UNPACKER_HOOK {
            return Err(unsupported("extract_new outside a PE unpacker"));
        }
        let (name, prototype): (&[u8], &[u64]) = match id {
            READ => (b"read\0", &[I32, BYTE_POINTER, I32]),
            EXTRACT_NEW => (b"extract_new\0", &[I32, I32]),
            SEEK => (b"seek\0", &[I32, I32, I32]),
            MALLOC => (b"malloc\0", &[BYTE_POINTER, I32]),
            MEMSTR => (b"memstr\0", &[I32, BYTE_POINTER, I32, BYTE_POINTER, I32]),
            host::DISASM => (b"disasm_x86\0", &[]),
            PE_SECTION => (b"get_pe_section\0", &[]),
            FILE_FIND => (b"file_find\0", &[I32, BYTE_POINTER, I32]),
            SET_VIRUS_NAME => (b"setvirusname\0", &[I32, BYTE_POINTER, I32]),
            FILE_BYTEAT => (b"file_byteat\0", &[I32, I32]),
            FILE_FIND_LIMIT => (b"file_find_limit\0", &[I32, BYTE_POINTER, I32, I32]),
            ENGINE_LEVEL => (b"engine_functionality_level\0", &[I32]),
            DCONF_LEVEL => (b"engine_dconf_level\0", &[I32]),
            _ => host::declaration(id)
                .or_else(|| pdf::declaration(id))
                .ok_or_else(|| unsupported(&format!("API declaration {id}")))?,
        };
        let ty = user_type(types, field(line.number())?);
        if id > max_id
            || apis.contains(&id)
            || !matches!(ty, Some(Type::Function(args)) if match id {
                host::DISASM => host::disasm_prototype(args, types),
                PE_SECTION => host::pe_section_prototype(args, types),
                host::GET_ENVIRONMENT => host::environment_prototype(args, types),
                _ => args == prototype,
            })
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

#[derive(Debug)]
enum Global {
    FileSize,
    PeField(host::PeField),
    Scalar,
    MatchOffset(usize),
    MatchCount(usize),
    Zero,
    Bytes(Arc<[u8]>, usize),
    Pointer {
        base: usize,
        offset: usize,
        source_at_zero: bool,
    },
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

fn globals(mut line: Cursor<'_>, types: &[Type], hook: u64) -> io::Result<Vec<Global>> {
    field(line.expect(b'G'))?;
    const MATCH_COUNTS: u64 = 0x8000;
    const PE_DATA: u64 = 0x8003;
    const FILE_SIZE: u64 = 0x8004;
    const MATCH_OFFSETS: u64 = 0x8005;
    let max_host = field(line.number())?;
    if !matches!(
        max_host,
        0 | MATCH_COUNTS | PE_DATA | FILE_SIZE | MATCH_OFFSETS
    ) {
        return Err(unsupported("host global"));
    }
    let count = field(line.number())?;
    if count > line.0.len() as u64 {
        return Err(invalid("truncated CBC global table"));
    }
    let mut globals = Vec::new();
    let mut blob_end = 0usize;
    let mut bytes_left = MAX_MEMBER_BYTES as usize;
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
                    PE_DATA if max_host >= PE_DATA => Global::PeField(match offset {
                        4 => host::PeField::RawEntry,
                        52 | 280 if matches!(hook, PE_ALL_HOOK | PE_UNPACKER_HOOK) => {
                            host::PeField::EntryRva
                        }
                        60 if matches!(hook, PE_ALL_HOOK | PE_UNPACKER_HOOK) => {
                            host::PeField::BaseOfData
                        }
                        148 | 392 | 520 if matches!(hook, PE_ALL_HOOK | PE_UNPACKER_HOOK) => {
                            host::PeField::ResourceRva
                        }
                        152 | 396 | 524 if matches!(hook, PE_ALL_HOOK | PE_UNPACKER_HOOK) => {
                            host::PeField::ResourceSize
                        }
                        632 if matches!(hook, PE_ALL_HOOK | PE_UNPACKER_HOOK) => {
                            host::PeField::HeaderOffset
                        }
                        _ => {
                            return Err(unsupported(&format!(
                                "i32 PE data field at offset {offset}"
                            )));
                        }
                    }),
                    MATCH_OFFSETS
                        if max_host == MATCH_OFFSETS && offset % 4 == 0 && offset < 256 =>
                    {
                        Global::MatchOffset(offset / 4)
                    }
                    _ => {
                        return Err(unsupported(&format!(
                            "i32 pointer to global {base:#x} at offset {offset}"
                        )));
                    }
                }
            }
            (66, _) | (_, Some(Type::Pointer(16))) => {
                let offset = line.index_literal()?;
                let base = line.literal()?;
                let field = match (base, offset) {
                    (PE_DATA, 8) if max_host >= PE_DATA => host::PeField::SectionCount,
                    (PE_DATA, 32)
                        if max_host >= PE_DATA
                            && matches!(hook, PE_ALL_HOOK | PE_UNPACKER_HOOK) =>
                    {
                        host::PeField::OptionalSize
                    }
                    (PE_DATA, 264)
                        if max_host >= PE_DATA
                            && matches!(hook, PE_ALL_HOOK | PE_UNPACKER_HOOK) =>
                    {
                        host::PeField::OptionalMagic
                    }
                    _ => return Err(unsupported("i16 pointer outside supported host globals")),
                };
                Global::PeField(field)
            }
            (BYTE_POINTER, _) | (_, Some(Type::Pointer(8))) => Global::Pointer {
                offset: line.index_literal()?,
                base: line.index_literal()?,
                source_at_zero: blob_end == 0,
            },
            (_, Some(Type::Bytes(len))) => {
                bytes_left = bytes_left
                    .checked_sub(*len)
                    .ok_or_else(|| unsupported("expanded globals size"))?;
                let bytes = if line.0.starts_with(b"@`") {
                    // A single zero literal initializes the entire object.
                    line.literal()?;
                    vec![0; *len]
                } else {
                    if *len > line.0.len() {
                        return Err(invalid("truncated CBC byte array"));
                    }
                    (0..*len)
                        .map(|_| {
                            u8::try_from(line.literal()?).map_err(|_| invalid("invalid CBC byte"))
                        })
                        .collect::<io::Result<Vec<_>>>()?
                };
                Global::Bytes(bytes.into(), blob_end)
            }
            _ => return Err(unsupported("global type")),
        };
        // Stock lays out scalars and pointers at their natural alignment. Byte arrays align to one.
        let (size, align) = match &global {
            Global::Zero => (0, 1),
            Global::Bytes(bytes, _) => (bytes.len(), 1),
            Global::Scalar => {
                let bytes = id.div_ceil(8) as usize;
                (bytes, bytes)
            }
            _ => (8, 8),
        };
        // Counts and array lengths are bounded by the module byte limit.
        blob_end = blob_end.next_multiple_of(align) + size;
        field(line.expect(b'`'))?;
        globals.push(global);
    }
    field(line.end())?;
    for global in &globals {
        if let Global::Pointer { base, offset, .. } = global
            && !matches!(globals.get(*base),Some(Global::Bytes(bytes, _)) if *offset <= bytes.len())
        {
            return Err(invalid("CBC global pointer outside its byte array"));
        }
    }
    Ok(globals)
}

fn function_header(mut line: Cursor<'_>, types: &[Type], entry: bool) -> io::Result<Header> {
    field(line.expect(b'A'))?;
    let args = field(line.fixed(1))?;
    let ret = field(line.number())?;
    if entry && (args != 0 || ret != I32) {
        return Err(unsupported("entry signature"));
    }
    let result = if ret == 0 {
        None
    } else {
        Some(Width::new(ret)?)
    };
    field(line.expect(b'L'))?;
    let count = args
        .checked_add(field(line.number())?)
        .ok_or_else(|| invalid("invalid CBC local count"))?;
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
    let args = slots[..args as usize]
        .iter()
        .map(|s| {
            if s.addressable {
                return Err(unsupported("addressable function argument"));
            }
            if s.width.is_some() || s.ty == BYTE_POINTER {
                Ok(s.ty)
            } else {
                Err(unsupported("function argument type"))
            }
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok(Header {
        signature: Signature { args, result },
        slots,
        instructions: instructions as usize,
        blocks: blocks as usize,
    })
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
        let (i, width) = self.local(slots)?;
        // Both the pointer check and memory operation use the low 32 bits.
        // Accept an i32 only when stock can read its full aligned cell.
        if width != Width(64)
            && !(cfg!(target_endian = "little") && slots[i].padded_i32_cell(slots.get(i + 1)))
        {
            return Err(unsupported(
                "64-bit memory length read from a narrower register",
            ));
        }
        Ok(Value::Local(i))
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
        let Global::Pointer { base, offset, .. } = self.global(globals)? else {
            return Err(unsupported("host call without an immutable byte pointer"));
        };
        let Some(Global::Bytes(bytes, _)) = globals.get(*base) else {
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
    Call {
        target: usize,
        dest: Option<usize>,
        args: Box<[Value]>,
    },
    Return(Option<Value>),
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
    ExtractNew,
    Binary(Binary, Width, Value, Value),
    Cast {
        source: usize,
        from: Width,
        to: Width,
        sign_extend: bool,
    },
    Select(Value, Value, Value),
    Copy(Value),
    ModulePointer(u64),
    FileByte(Value),
    Find(Address, Value, Option<Value>),
    Allocate(Value),
    PointerToInt(usize),
    MemStr(Address, Value, Address, Value),
    Memory(MemoryOp),
    ByteSwap(Value, Width),
    MatchOffset(usize),
    MatchCount(usize),
    FileSize,
    SetName(Box<str>),
    Host(host::Operation),
    Pdf(pdf::Query),
}

impl Expression {
    fn eval<'a>(
        &'a self,
        locals: &mut Frame<'_>,
        scan: &Scan<'_>,
        name: &mut Option<&'a str>,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<u64>> {
        let input = scan.input;
        let value = match *self {
            Self::ModulePointer(pointer) => pointer,
            Self::ExtractNew => {
                let extract = scan
                    .extract
                    .ok_or_else(|| unsupported("extract_new without child traversal"))?;
                let Some(result) = extract()? else {
                    return Ok(None);
                };
                if result == 1 {
                    // The child name replaces any earlier setvirusname in this invocation.
                    *name = None;
                }
                u64::from(result)
            }
            Self::Host(ref op) => return op.eval(locals, scan, check),
            Self::Pdf(ref query) => u64::from(query.eval(locals, scan.pdf, check)?),
            Self::Allocate(size) => locals.allocate(size.get(locals) as usize)?,
            Self::PointerToInt(slot) => locals.pointer_integer(slot)?,
            Self::MemStr(ref haystack, hlen, ref needle, nlen) => {
                let Some(h) = memory::outcome(haystack.read(locals, hlen.get(locals) as usize))?
                else {
                    return Ok(None);
                };
                let Some(n) = memory::outcome(needle.read(locals, nlen.get(locals) as usize))?
                else {
                    return Ok(None);
                };
                if n.is_empty() {
                    u32::MAX.into()
                } else {
                    memchr::memmem::find(h, n).map_or(u32::MAX.into(), |i| i as u64)
                }
            }
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
            Self::MatchCount(i) => u64::from(scan.counts.get(i).copied().unwrap_or(0)),
            Self::MatchOffset(i) => u64::from(scan.offsets[i]),
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

fn terminator(
    line: &mut Cursor<'_>,
    slots: &[Slot],
    blocks: usize,
    result: Option<Width>,
) -> io::Result<Instruction> {
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
            let ty = Width::new(field(line.number())?)?;
            if Some(ty) != result {
                return Err(invalid("CBC return type mismatch"));
            }
            Instruction::Return(Some(line.scalar(slots, ty)?))
        }
        20 if result.is_none() => Instruction::Return(None),
        45 => Instruction::Abort,
        _ => return Err(unsupported("entry terminator")),
    })
}

struct Decode<'a> {
    signatures: &'a [Signature],
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
    if opcode == 32 {
        return direct_call(line, slots, ctx.signatures, ty, dest);
    }
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
    if opcode == 33 && ty == BYTE_POINTER {
        let slot = &slots[dest as usize];
        if slot.ty != ty
            || slot.addressable
            || field(line.fixed(1))? != 1
            || field(line.number())? != MALLOC
            || !ctx.apis.contains(&MALLOC)
        {
            return Err(unsupported("pointer-returning API call"));
        }
        return Ok(Instruction::Write(
            dest as usize,
            Expression::Allocate(line.scalar(slots, Width::WORD)?),
        ));
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
        if ty == BYTE_POINTER {
            let pointer_slot = |line: &mut Cursor<'_>| -> io::Result<usize> {
                let i = field(usize::try_from(field(line.number())?).ok())?;
                if field(slots.get(i))?.ty != BYTE_POINTER {
                    return Err(invalid("CBC pointer COPY operand type mismatch"));
                }
                Ok(i)
            };
            let source = if matches!(line.first(), Some(b'@'..=b'P')) {
                match line.global(globals)? {
                    // Stock's scalar read interprets a source at module offset zero as null.
                    Global::Zero
                    | Global::Pointer {
                        source_at_zero: true,
                        ..
                    } => Expression::Copy(Value::Constant(0)),
                    Global::Pointer { base, offset, .. } => {
                        Expression::ModulePointer(memory::module_pointer(*base, *offset)?)
                    }
                    _ => return Err(unsupported("COPY from a non-byte global pointer")),
                }
            } else {
                Expression::Copy(Value::Local(pointer_slot(line)?))
            };
            return Ok(Instruction::Write(pointer_slot(line)?, source));
        }
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
                let ty = field(line.number())?;
                let op = Binary::COMPARISON[opcode as usize - 21];
                if ty == BYTE_POINTER && matches!(opcode, 21 | 22) {
                    let mut argument = || -> io::Result<Value> {
                        if matches!(line.first(), Some(b'@'..=b'P')) {
                            if matches!(line.global(globals)?, Global::Zero) {
                                return Ok(Value::Constant(0));
                            }
                        } else {
                            let i = usize::try_from(field(line.number())?)
                                .map_err(|_| invalid("invalid CBC pointer slot"))?;
                            let slot = field(slots.get(i))?;
                            if slot.ty == BYTE_POINTER && !slot.addressable {
                                return Ok(Value::Local(i));
                            }
                        }
                        Err(unsupported("byte pointer comparison operand"))
                    };
                    let a = argument()?;
                    let b = argument()?;
                    if matches!((a, b), (Value::Local(_), Value::Local(_))) {
                        return Err(unsupported("comparison between object pointers"));
                    }
                    return Ok(Instruction::Write(
                        dest,
                        Expression::Binary(op, Width(64), a, b),
                    ));
                }
                (op, Width::new(ty)?)
            };
            Expression::Binary(op, ty, line.scalar(slots, ty)?, line.scalar(slots, ty)?)
        }
        14..=16 => {
            let (source, from) = line.local(slots)?;
            if slots[source].addressable {
                return Err(unsupported("cast from addressable local"));
            }
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
                    Global::MatchCount(i) => Some((Expression::MatchCount(*i), Width::WORD)),
                    Global::MatchOffset(i) => Some((Expression::MatchOffset(*i), Width::WORD)),
                    Global::FileSize => Some((Expression::FileSize, Width::WORD)),
                    Global::PeField(field) => Some((
                        Expression::Host(host::Operation::PeField(*field)),
                        field.width(),
                    )),
                    _ => None,
                }
            } else {
                None
            };
            if let Some((host, host_width)) = host {
                if width != host_width {
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
        50 if width.0 == 64 => {
            if matches!(line.first(), Some(b'@'..=b'P')) {
                return Err(unsupported("integer conversion of a non-register pointer"));
            }
            let slot = field(usize::try_from(field(line.number())?).ok())?;
            let operand = field(slots.get(slot))?;
            if operand.ty != BYTE_POINTER || operand.addressable {
                return Err(unsupported(
                    "integer conversion outside a byte pointer register",
                ));
            }
            Expression::PointerToInt(slot)
        }
        _ => return Err(unsupported("instruction opcode")),
    };
    Ok(Instruction::Write(dest, expr))
}

fn direct_call(
    line: &mut Cursor<'_>,
    slots: &[Slot],
    signatures: &[Signature],
    ty: u64,
    dest: u64,
) -> io::Result<Instruction> {
    let count = field(line.fixed(1))?;
    let id = field(line.number())?;
    let target = usize::try_from(id)
        .ok()
        .and_then(|i| i.checked_sub(1))
        .ok_or_else(|| invalid("invalid CBC direct-call target"))?;
    let signature = signatures
        .get(target)
        .ok_or_else(|| invalid("CBC direct-call target outside module"))?;
    if count != signature.args.len() as u64 || ty != signature.result.map_or(0, |w| u64::from(w.0))
    {
        return Err(invalid("CBC direct-call signature mismatch"));
    }
    let dest = if let Some(width) = signature.result {
        let i = usize::try_from(dest).map_err(|_| invalid("invalid CBC call destination"))?;
        if slots.get(i).and_then(|s| s.width) != Some(width) {
            return Err(invalid("CBC direct-call result type mismatch"));
        }
        Some(i)
    } else {
        None
    };
    let mut args = Vec::new();
    for &ty in &signature.args {
        let value = if ty == BYTE_POINTER {
            let i = usize::try_from(field(line.number())?)
                .map_err(|_| invalid("invalid CBC pointer argument"))?;
            if !matches!(slots.get(i), Some(slot) if slot.ty == BYTE_POINTER && !slot.addressable) {
                return Err(unsupported("direct-call pointer argument storage"));
            }
            Value::Local(i)
        } else {
            line.scalar(slots, Width::new(ty)?)?
        };
        if let Value::Local(i) = value
            && slots[i].addressable
        {
            return Err(unsupported("addressable direct-call operand"));
        }
        args.push(value);
    }
    Ok(Instruction::Call {
        target,
        dest,
        args: args.into_boxed_slice(),
    })
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
        (EXTRACT_NEW, 1) => {
            // Stock accepts an i32 label. It does not affect the child scan.
            line.scalar(slots, Width::WORD)?;
            Expression::ExtractNew
        }
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
        (MEMSTR, 4) => Expression::MemStr(
            Address::decode(line, slots, globals, false)?,
            line.scalar(slots, Width::WORD)?,
            Address::decode(line, slots, globals, false)?,
            line.scalar(slots, Width::WORD)?,
        ),
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
        (DCONF_LEVEL, 0) => Expression::Copy(Value::Constant(PINNED_DCONF_LEVEL)),
        _ if pdf::declaration(id).is_some() => {
            Expression::Pdf(pdf::Query::decode(id, count, line, slots)?)
        }
        (ENGINE_LEVEL, 0) => {
            Expression::Copy(Value::Constant(ctx.engine_level & u64::from(u32::MAX)))
        }
        _ if matches!(id, PE_SECTION | host::DISASM) || host::declaration(id).is_some() => {
            Expression::Host(host::decode(id, count, line, slots, globals)?)
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
                program.run(&[], &[0; 64], &[], false, TEST_TIMEOUT, || {
                    steps += 1;
                    Ok(())
                })?,
                calls.then_some("Local.Receipt")
            );
            assert_eq!(steps, if calls { 2 } else { 1 });
            assert!(
                program
                    .run(&[], &[0; 64], &[], false, TEST_TIMEOUT, || Err(
                        io::Error::other("cancelled")
                    ))
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn pdf_hook_requires_an_unconditional_name_and_preserves_return_status() -> io::Result<()> {
        let context = PdfHookContext {
            phase: super::super::PdfPhase::Pre,
            flags: None,
            objects: Some(&[]),
            start: 0,
            size: 0,
        };
        for calls in [false, true] {
            let mut module = sample(calls);
            module[0] =
                module[0].replacen(&number(LOGICAL_HOOK, false), &number(PDF_HOOK, false), 1);
            assert_eq!(
                Program::compile(module.join("\n").as_bytes(), 213)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
            module[1] = "ReceiptPdfHook".into();
            module[6] = module[6].replace(
                &(number(9, true) + &fixed(4, 1) + "E"),
                &(number(BREAK_RESULT, true) + &fixed(4, 1) + "E"),
            );
            let program = Program::compile(module.join("\n").as_bytes(), 213)?.unwrap();
            assert!(program.is_pdf_hook());
            assert_eq!(
                program.run_pdf(&[], context, false, TEST_TIMEOUT, || Ok(()))?,
                if calls {
                    PdfHookResult::Found("Local.Receipt")
                } else {
                    PdfHookResult::Break
                }
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
        unsupported[6] = unsupported[6].replacen(&fixed(33, 2), &fixed(49, 2), 1);
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
        let result = program.run(&[], &[0; 64], &[], false, TEST_TIMEOUT, || {
            steps += 1;
            Ok(())
        })?;
        assert_eq!(result, Some("Local.Receipt"));
        assert_eq!(steps, 13);
        let mut steps = 0;
        let error = program
            .run(&[], &[0; 64], &[], false, TEST_TIMEOUT, || {
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
    fn expands_zero_byte_arrays_within_the_module_budget() -> io::Result<()> {
        let table = |count| {
            let mut row = "G".to_owned() + &number(0, false) + &number(count, false);
            for _ in 0..count {
                row += &(number(69, false) + "@`");
            }
            row
        };
        let row = table(1);
        let decoded = globals(Cursor(row.as_bytes()), &[Type::Bytes(7)], LOGICAL_HOOK)?;
        assert!(matches!(&decoded[..], [Global::Bytes(bytes, 0)] if bytes.as_ref() == [0;7]));
        let row = table(2);
        assert!(
            globals(
                Cursor(row.as_bytes()),
                &[Type::Bytes(MAX_MEMBER_BYTES as usize / 2 + 1)],
                LOGICAL_HOOK,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn checks_forward_calls_and_returns_to_the_following_instruction() -> io::Result<()> {
        let n = |v| number(v, false);
        let word = |v| number(v, true) + &fixed(4, 1);
        let op = |ty, dest, opcode| n(ty) + &n(dest) + &fixed(opcode, 2);
        let call = |target, value: String| fixed(1, 1) + &n(target) + &value;
        let mut module = sample(true);
        let magic = n(0x53e5493e9f3d1c30);
        module[0] = module[0].replace(&(n(1) + &magic), &(n(2) + &magic));
        let slots = |types: &[u64]| {
            types
                .iter()
                .map(|&t| n(t) + &fixed(0, 1))
                .collect::<String>()
        };
        module[5] = "A".to_owned()
            + &fixed(0, 1)
            + &n(32)
            + "L"
            + &n(2)
            + &slots(&[32, 1])
            + "F"
            + &n(6)
            + &n(3);
        let hit = module[6].strip_suffix('E').unwrap().to_owned();
        let root = |target, value| {
            "B".to_owned()
                + &op(32, 0, 32)
                + &call(target, word(value))
                + &op(1, 1, 21)
                + &n(32)
                + &n(0)
                + &word(42)
                + "T"
                + &fixed(17, 2)
                + &n(1)
                + &n(1)
                + &n(2)
        };
        let helper = "A".to_owned()
            + &fixed(1, 1)
            + &n(32)
            + "L"
            + &n(1)
            + &slots(&[32, 32])
            + "F"
            + &n(2)
            + &n(1);
        let ret = "T".to_owned() + &fixed(19, 2) + &n(32) + &n(1) + "E";
        module.splice(
            6..7,
            [
                root(2, 41),
                hit,
                "BT".to_owned() + &fixed(19, 2) + &n(32) + &word(7) + "E",
                helper,
                "B".to_owned() + &op(32, 1, 1) + &n(0) + &word(1) + &ret,
            ],
        );
        let compile =
            |m: &[String]| Program::compile(m.join("\n").as_bytes(), 213).map(Option::unwrap);
        assert_eq!(
            compile(&module)?.run(&[], &[0; 64], &[], false, TEST_TIMEOUT, || Ok(()))?,
            Some("Local.Receipt")
        );
        module[6] = root(2, 40);
        assert_eq!(
            compile(&module)?.run(&[], &[0; 64], &[], false, TEST_TIMEOUT, || Ok(()))?,
            None
        );
        module[6] = root(3, 41);
        assert!(compile(&module).is_err());
        module[6] = root(2, 41);
        module[10] = "B".to_owned() + &op(32, 1, 32) + &call(2, n(0)) + &ret;
        let error = compile(&module)?
            .run(&[], &[0; 64], &[], false, TEST_TIMEOUT, || Ok(()))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
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
                    signatures: &[],
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
                .eval(
                    outputs,
                    &Scan {
                        input: &[],
                        offsets: &[0; 64],
                        counts: &[],
                        debug: false,
                        pdf: None,
                        output: None,
                        extract: None,
                        has_entry: Default::default(),
                        pe: Default::default(),
                    },
                    &mut None,
                    &mut || Ok(()),
                )?
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
                &Scan {
                    input: &input,
                    offsets: &offsets,
                    counts: &[],
                    debug: false,
                    pdf: None,
                    output: None,
                    extract: None,
                    has_entry: Default::default(),
                    pe: Default::default(),
                },
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
                &Scan {
                    input: &input,
                    offsets: &[0; 64],
                    counts: &[],
                    debug: false,
                    pdf: None,
                    output: None,
                    extract: None,
                    has_entry: Default::default(),
                    pe: Default::default(),
                },
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
            program.run(&[], &[0; 64], &[], false, TEST_TIMEOUT, || Ok(()))?,
            Some("BC.Clamav-Unit-Test-Signature")
        );
        Ok(())
    }
}
