//! A single-block logical bytecode entry point with constant data and no host memory access.
use super::{Cursor, MAX_MEMBER_BYTES, invalid};
use std::{io, str};

const LOGICAL_HOOK: u64 = 256;
const SET_VIRUS_NAME: u64 = 5;
const I32: u64 = 32;
const BYTE_POINTER: u64 = 65;
const FIRST_USER_TYPE: usize = 69;

#[derive(Debug)]
pub struct Program {
    trigger: Box<str>,
    // The only supported side effect has constant arguments. Resolve them once at load time.
    set_name: Option<Box<str>>,
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
        let has_api = api(line()?, &types)?;
        let globals = globals(line()?, &types)?;
        let function = line()?;
        if function.first() == Some(b'D') {
            return Err(unsupported("debug metadata"));
        }
        let (locals, instructions) = entry(function)?;
        let set_name = block(line()?, locals, instructions, has_api, &globals)?;
        if lines.next().and_then(|s| s.first()) != Some(&b'S') {
            return Err(invalid("missing CBC source boundary"));
        }
        Ok(Some(Self {
            trigger: trigger.into(),
            set_name,
        }))
    }

    pub fn trigger(&self) -> &str {
        &self.trigger
    }

    /// Run the optional setvirusname call and the return, checking the deadline at each instruction.
    pub fn run(&self, mut check: impl FnMut() -> io::Result<()>) -> io::Result<Option<&str>> {
        if self.set_name.is_some() {
            check()?;
        }
        check()?;
        Ok(self.set_name.as_deref())
    }
}

enum Type {
    Bytes(usize),
    Pointer(u64),
    SetNameFunction,
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
                if field(line.number())? != 3
                    || field(line.number())? != I32
                    || field(line.number())? != BYTE_POINTER
                    || field(line.number())? != I32
                {
                    return Err(unsupported("function prototype"));
                }
                Type::SetNameFunction
            }
            4 => {
                let n = field(line.number())?;
                if field(line.number())? != 8 || n > MAX_MEMBER_BYTES {
                    return Err(unsupported("array type or length"));
                }
                Type::Bytes(usize::try_from(n).map_err(|_| invalid("invalid array length"))?)
            }
            5 => Type::Pointer(field(line.number())?),
            _ => return Err(unsupported("type kind")),
        };
        types.push(ty);
    }
    field(line.end())?;
    for ty in &types {
        if let Type::Pointer(id) = ty
            && !matches!(*id, 8 | BYTE_POINTER)
            && !matches!(user_type(&types, *id), Some(Type::Bytes(_)))
        {
            return Err(unsupported("pointer type"));
        }
    }
    Ok(types)
}

fn api(mut line: Cursor<'_>, types: &[Type]) -> io::Result<bool> {
    field(line.expect(b'E'))?;
    let max_id = field(line.number())?;
    let count = field(line.number())?;
    match (max_id, count) {
        (0, 0) => {}
        (SET_VIRUS_NAME, 1) => {
            if field(line.number())? != SET_VIRUS_NAME
                || !matches!(
                    user_type(types, field(line.number())?),
                    Some(Type::SetNameFunction)
                )
            {
                return Err(unsupported("API declaration"));
            }
            let encoded = field(line.string())?;
            let name = encoded
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| ((pair[1] & 15) << 4) | (pair[0] & 15));
            if !name.eq(b"setvirusname\0".iter().copied()) {
                return Err(invalid("unexpected CBC name for setvirusname API ID"));
            }
        }
        _ => return Err(unsupported("API table")),
    }
    field(line.end())?;
    Ok(count == 1)
}

enum Global {
    Zero,
    Bytes(Vec<u8>),
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
    if field(line.number())? != 0 {
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
                Global::Bytes(bytes)
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

fn entry(mut line: Cursor<'_>) -> io::Result<(u64, u64)> {
    field(line.expect(b'A'))?;
    if field(line.fixed(1))? != 0 || field(line.number())? != I32 {
        return Err(unsupported("entry signature"));
    }
    field(line.expect(b'L'))?;
    let locals = field(line.number())?;
    if locals > 1 {
        return Err(unsupported("entry locals"));
    }
    if locals == 1 && (field(line.number())? != I32 || field(line.fixed(1))? != 0) {
        return Err(unsupported("local type"));
    }
    field(line.expect(b'F'))?;
    let instructions = field(line.number())?;
    if !(1..=2).contains(&instructions) || field(line.number())? != 1 {
        return Err(unsupported("instruction count or control flow"));
    }
    field(line.end())?;
    Ok((locals, instructions))
}

fn name(globals: &[Global], id: usize, length: u32) -> io::Result<Box<str>> {
    let Some(Global::Pointer { base, offset }) = globals.get(id) else {
        return Err(invalid("setvirusname expects a global byte pointer"));
    };
    let Some(Global::Bytes(bytes)) = globals.get(*base) else {
        return Err(invalid("invalid CBC name array"));
    };
    let bytes = field(bytes.get(*offset..))?;
    if u64::from(length) > bytes.len() as u64 {
        return Err(invalid("setvirusname length exceeds its global array"));
    }
    // The stock VM checks the supplied length, then the API reads a NUL-terminated name.
    let nul = field(bytes.iter().position(|&b| b == 0))?;
    let name = str::from_utf8(&bytes[..nul]).map_err(|_| invalid("invalid CBC detection name"))?;
    if name.is_empty() || name.bytes().any(|b| b.is_ascii_control()) {
        return Err(invalid("empty or control-containing CBC detection name"));
    }
    Ok(name.into())
}

fn block(
    mut line: Cursor<'_>,
    locals: u64,
    instructions: u64,
    has_api: bool,
    globals: &[Global],
) -> io::Result<Option<Box<str>>> {
    field(line.expect(b'B'))?;
    let mut set_name = None;
    if instructions == 2 {
        if field(line.number())? != I32 || field(line.number())? != 0 || locals != 1 {
            return Err(unsupported("call destination"));
        }
        if field(line.fixed(2))? != 33 {
            return Err(unsupported("instruction before return"));
        }
        if !has_api || field(line.fixed(1))? != 2 || field(line.number())? != SET_VIRUS_NAME {
            return Err(unsupported("host call"));
        }
        let id = line.index_literal()?;
        if field(line.fixed(1))? != 0 {
            return Err(unsupported("non-global name operand"));
        }
        set_name = Some(name(globals, id, line.i32_literal()?)?);
    }
    field(line.expect(b'T'))?;
    if field(line.fixed(2))? != 19 || field(line.number())? != I32 {
        return Err(unsupported("entry terminator"));
    }
    if matches!(line.first(), Some(b'@'..=b'P')) {
        line.i32_literal()?;
    } else if set_name.is_none() || field(line.number())? != 0 {
        return Err(unsupported("return value"));
    }
    field(line.expect(b'E'))?;
    field(line.end())?;
    Ok(set_name)
}

#[cfg(test)]
mod tests {
    use super::*;

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
                program.run(|| {
                    steps += 1;
                    Ok(())
                })?,
                calls.then_some("Local.Receipt")
            );
            assert_eq!(steps, if calls { 2 } else { 1 });
            assert!(program.run(|| Err(io::Error::other("cancelled"))).is_err());
        }
        Ok(())
    }

    #[test]
    fn checks_skip_windows_and_rejects_other_operations() {
        let text = sample(true).join("\n");
        assert!(Program::compile(text.as_bytes(), 55).unwrap().is_none());
        assert!(Program::compile(b"ClamBCai", 213).unwrap().is_none()); // Format 9.
        let mut unsupported = sample(true);
        unsupported[6] = unsupported[6].replacen(&fixed(33, 2), &fixed(1, 2), 1);
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
    #[ignore = "requires the pinned upstream harmless CBC fixture"]
    fn stock_marker() -> io::Result<()> {
        let path = std::env::var_os("BARNACLE_CBC_FIXTURE").ok_or_else(|| {
            io::Error::other("set BARNACLE_CBC_FIXTURE to the pinned stock fixture")
        })?;
        let data = std::fs::read(path)?;
        let program = Program::compile(&data, 213)?.unwrap();
        assert_eq!(
            program.run(|| Ok(()))?,
            Some("BC.Clamav-Unit-Test-Signature")
        );
        Ok(())
    }
}
