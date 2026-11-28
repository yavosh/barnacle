//! Inspect the bytecode requirements of the verified ClamAV database.
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io::{self, Read};
use std::path::Path;

mod program;
pub use program::Program;

pub const PINNED_ARCHIVE: (&str, u64, &str) = (
    "bytecode.cvd",
    281_702,
    "6d4aa01f219e988060fc419f495d07f27e0cdf1a2cccc065971da922c76f7ffb",
);
pub const MAX_MEMBER_BYTES: u64 = 1024 * 1024;

fn visit_verified_members(
    input: impl Read,
    mut visit: impl FnMut(&Path, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let (name, length, digest) = PINNED_ARCHIVE;
    let mut bytes = Vec::new();
    input.take(length + 1).read_to_end(&mut bytes)?;
    let actual: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if bytes.len() as u64 != length || actual != digest {
        return Err(invalid(format!(
            "{name}: SHA-256 differs from the verified generation"
        )));
    }

    let mut archive = tar::Archive::new(GzDecoder::new(&bytes[512..]));
    let mut contents = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.extension() != Some(OsStr::new("cbc")) {
            continue;
        }
        let mut components = path.components();
        if !matches!(
            (components.next(), components.next()),
            (Some(std::path::Component::Normal(_)), None)
        ) || !entry.header().entry_type().is_file()
            || entry.size() > MAX_MEMBER_BYTES
        {
            return Err(invalid("invalid bytecode archive member"));
        }
        contents.clear();
        entry.read_to_end(&mut contents)?;
        visit(&path, &contents)?;
    }
    Ok(())
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Inventory {
    pub modules: usize,
    pub formats: BTreeMap<u64, usize>,
    pub hooks: BTreeMap<u64, usize>,
    pub eligible_hooks: BTreeMap<u64, usize>,
    pub engine_windows: BTreeMap<(u64, u64), usize>,
    pub outside_engine_window: usize,
    pub unsupported_formats: usize,
    pub functions: usize,
    pub instructions: usize,
    pub opcodes: BTreeSet<u64>,
    pub apis: BTreeMap<u64, String>,
    pub compiled: usize,
    pub compile_errors: BTreeMap<String, usize>,
}

impl Inventory {
    /// Inspect the pinned archive after checking its complete SHA-256.
    pub fn from_archive(input: impl Read, engine_level: u64) -> io::Result<Self> {
        let mut result = Self::default();
        visit_verified_members(input, |path, contents| {
            result.inspect(contents, engine_level).ok_or_else(|| {
                invalid(format!("invalid bytecode inventory for {}", path.display()))
            })?;
            match Program::compile(contents, engine_level) {
                Ok(Some(_)) => result.compiled += 1,
                Ok(None) => {}
                Err(error) => *result.compile_errors.entry(error.to_string()).or_default() += 1,
            }
            Ok(())
        })?;
        Ok(result)
    }

    fn inspect(&mut self, contents: &[u8], engine_level: u64) -> Option<()> {
        let mut lines = contents.split(|&byte| byte == b'\n').map(Cursor);
        let mut header = lines.next()?;
        header.0 = header.0.strip_prefix(b"ClamBC")?;
        let format = header.number()?;
        self.modules += 1;
        *self.formats.entry(format).or_default() += 1;
        if !matches!(format, 6 | 7) {
            self.unsupported_formats += 1;
            return Some(());
        }
        header.number()?; // Compiler timestamp.
        header.string()?; // Author.
        header.number()?; // Target exclusion.
        let hook = header.number()?;
        let min = header.number()?;
        let max = header.number()?;
        *self.hooks.entry(hook).or_default() += 1;
        *self.engine_windows.entry((min, max)).or_default() += 1;
        if (min != 0 && min > engine_level) || (max != 0 && max < engine_level) {
            self.outside_engine_window += 1;
            return Some(());
        }
        *self.eligible_hooks.entry(hook).or_default() += 1;
        header.number()?; // Declared resource limit.
        header.string()?; // Compiler version.
        header.number()?; // Type count.
        let functions = usize::try_from(header.number()?).ok()?;
        if header.number()? != 0x53e5493e9f3d1c30 || header.fixed(2)? != 42 {
            return None;
        }
        header.expect(b':')?;
        // The text after the colon is the compiler's line buffer size hint.
        std::str::from_utf8(header.0).ok()?.parse::<usize>().ok()?;
        lines.next()?; // Logical trigger or hook name.
        lines.next()?.expect(b'T')?;
        self.inspect_apis(lines.next()?)?;
        lines.next()?.expect(b'G')?;

        let mut lines = lines.peekable();
        while lines.peek().is_some_and(|line| line.first() == Some(b'D')) {
            lines.next(); // Debug metadata precedes the functions.
        }
        for _ in 0..functions {
            let (declared, blocks) = function_header(lines.next()?)?;
            let mut count = 0;
            for block in 0..blocks {
                count += self.inspect_block(lines.next()?, block + 1 == blocks, declared)?;
                if count > declared {
                    return None;
                }
            }
            if count != declared {
                return None;
            }
            self.instructions += count;
        }
        lines.next()?.expect(b'S')?; // Embedded source follows the instruction stream.
        self.functions += functions;
        Some(())
    }

    fn inspect_apis(&mut self, mut line: Cursor<'_>) -> Option<()> {
        line.expect(b'E')?;
        let max = line.number()?;
        let entries = line.number()?;
        if entries > max {
            return None;
        }
        for _ in 0..entries {
            let id = line.number()?;
            line.number()?; // API function type.
            let encoded = line.string()?.strip_suffix(b"``")?;
            let name: Vec<u8> = encoded
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| (pair[1] & 15) << 4 | (pair[0] & 15))
                .collect();
            if id == 0 || id > max || !name.is_ascii() {
                return None;
            }
            let name = String::from_utf8(name).ok()?;
            if let Some(previous) = self.apis.insert(id, name.clone())
                && previous != name
            {
                return None;
            }
        }
        line.end()
    }

    fn inspect_block(
        &mut self,
        mut line: Cursor<'_>,
        final_block: bool,
        function_count: usize,
    ) -> Option<usize> {
        line.expect(b'B')?;
        let mut count = 0;
        loop {
            let end = line.first() == Some(b'T');
            if end {
                line.expect(b'T')?;
            } else {
                line.number()?; // Instruction type.
                line.number()?; // Destination.
            }
            let opcode = line.fixed(2)?;
            let operands = match opcode {
                1..=13 | 34 | 38 | 49 => 2, // Arithmetic, copy, store, pointer difference.
                14..=16 | 39 | 46..=48 | 50 => 1, // Cast, load, byte swap, pointer conversion.
                17 => {
                    line.operand()?;
                    line.number()?; // True branch.
                    line.number()?; // False branch.
                    0
                }
                18 => {
                    line.number()?; // Jump destination.
                    0
                }
                19 | 21..=30 => {
                    line.number()?; // Return or comparison type.
                    if opcode == 19 { 1 } else { 2 }
                }
                20 | 44 | 45 => 0, // Void return, endianness, abort.
                31 | 40..=43 => 3, // Select and memory operations.
                32 | 33 => {
                    let count = line.fixed(1)?;
                    line.number()?; // Direct function or host API ID.
                    count
                }
                35..=37 => {
                    let count = if opcode == 37 { line.fixed(1)? + 1 } else { 2 };
                    line.number()?; // Pointer element type.
                    count
                }
                _ => return None,
            };
            for _ in 0..operands {
                line.operand()?;
            }
            self.opcodes.insert(opcode);
            count += 1;
            if end {
                break;
            }
        }
        if final_block {
            line.expect(b'E')?;
        }
        if line.first() == Some(b'D') {
            line.take(3)?; // Debug marker and its two fixed digits.
            let nodes = usize::try_from(line.number()?).ok()?;
            if nodes != function_count {
                return None;
            }
            for _ in 0..nodes {
                line.number()?;
            }
        }
        line.end()?;
        Some(count)
    }
}

fn function_header(mut line: Cursor<'_>) -> Option<(usize, usize)> {
    line.expect(b'A')?;
    let arguments = line.fixed(1)?;
    line.number()?; // Return type.
    line.expect(b'L')?;
    let values = arguments.checked_add(line.number()?)?;
    for _ in 0..values {
        line.number()?;
        line.fixed(1)?;
    }
    line.expect(b'F')?;
    let instructions = usize::try_from(line.number()?).ok()?;
    let blocks = usize::try_from(line.number()?).ok()?;
    line.end()?;
    Some((instructions, blocks))
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn first(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (bytes, rest) = self.0.split_at_checked(count)?;
        self.0 = rest;
        Some(bytes)
    }

    fn expect(&mut self, byte: u8) -> Option<()> {
        (self.take(1)? == [byte]).then_some(())
    }

    fn end(&self) -> Option<()> {
        self.0.is_empty().then_some(())
    }

    fn number(&mut self) -> Option<u64> {
        let count = self.take(1)?[0].checked_sub(b'`')?;
        self.fixed(usize::from(count))
    }

    fn fixed(&mut self, count: usize) -> Option<u64> {
        if count > 16 {
            return None;
        }
        let mut number = 0;
        for (index, &byte) in self.take(count)?.iter().enumerate() {
            if !(b'`'..=b'o').contains(&byte) {
                return None;
            }
            number |= u64::from(byte & 15) << (4 * index);
        }
        Some(number)
    }

    fn operand(&mut self) -> Option<()> {
        if matches!(self.first()?, b'@'..=b'P') {
            let digits = self.take(1)?[0] - b'@';
            self.fixed(usize::from(digits))?;
            self.fixed(1)?; // Constant width, or zero for a global reference.
        } else {
            self.number()?;
        }
        Some(())
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        self.expect(b'|')?;
        let len = usize::try_from(self.number()?).ok()?;
        let encoded = self.take(len.checked_mul(2)?)?;
        (encoded.is_empty()
            || encoded.ends_with(b"``") && encoded.iter().all(|b| (b'`'..=b'o').contains(b)))
        .then_some(encoded)
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(min: u8, max: u8) -> Vec<u8> {
        // Timestamp, author, target exclusion, and hook ID (256).
        let mut bytes = b"ClamBCag`|``c``a".to_vec();
        for level in [min, max] {
            bytes.extend_from_slice(&[b'b', b'`' + (level & 15), b'`' + (level >> 4)]);
        }
        // Resource limit, compiler version, type count, function count, and magic.
        bytes.extend_from_slice(b"`|`aeaap`clamcoincidencejb:4096\n");
        bytes
    }

    #[test]
    fn reads_an_instruction_and_counts_a_skipped_window() {
        let mut contents = header(56, 0);
        contents.extend_from_slice(b"InertHook\nT\nE``\nG\nA`b`bL`Faaaa\nBTcab`b@dE\nS\n");
        let mut inventory = Inventory::default();
        assert_eq!(inventory.inspect(&contents, 213), Some(()));
        assert_eq!(inventory.hooks, BTreeMap::from([(256, 1)]));
        assert_eq!(inventory.formats, BTreeMap::from([(7, 1)]));
        assert_eq!(inventory.functions, 1);
        assert_eq!(inventory.instructions, 1);
        assert_eq!(inventory.opcodes, BTreeSet::from([19]));

        let mut skipped = Inventory::default();
        assert_eq!(skipped.inspect(&contents, 55), Some(()));
        assert_eq!(skipped.outside_engine_window, 1);
        assert_eq!(skipped.instructions, 0);
    }

    #[test]
    fn rejects_truncated_instructions_and_unverified_archives() {
        let mut contents = header(56, 0);
        contents.extend_from_slice(b"InertHook\nT\nE``\nG\nA`b`bL`Faaaa\nBTcab`b@\nS\n");
        assert_eq!(Inventory::default().inspect(&contents, 213), None);
        assert!(Inventory::from_archive(&contents[..], 213).is_err());
    }

    #[test]
    #[ignore = "set BARNACLE_CVD_DIR to the verified FreshClam snapshot"]
    fn matches_stock_archive_inventory() -> io::Result<()> {
        use std::fs::File;
        use std::io::Write;

        let dir = std::path::PathBuf::from(std::env::var_os("BARNACLE_CVD_DIR").unwrap());
        let archive = dir.join(PINNED_ARCHIVE.0);
        let engine_level = u64::from(crate::PINNED_FLEVEL);
        let found = Inventory::from_archive(File::open(&archive)?, engine_level)?;
        assert_eq!(found.modules, 85);
        assert_eq!(found.formats, BTreeMap::from([(6, 10), (7, 75)]));
        assert_eq!(found.unsupported_formats, 0);
        assert_eq!(found.outside_engine_window, 3);
        assert_eq!(
            found.eligible_hooks,
            BTreeMap::from([(256, 72), (257, 6), (258, 2), (259, 2)])
        );
        assert_eq!(found.functions, 115);
        assert_eq!(found.instructions, 15_034);
        assert_eq!(found.opcodes.len(), 44);
        assert_eq!(found.apis.len(), 28);
        assert_eq!(found.compiled, 65);
        assert_eq!(found.compile_errors.values().sum::<usize>(), 17);

        let scratch = tempfile::tempdir()?;
        let mut sources = Vec::new();
        visit_verified_members(File::open(&archive)?, |path, contents| {
            if matches!(Program::compile(contents, engine_level), Ok(Some(_))) {
                let path = scratch.path().join(path);
                File::create_new(&path)?.write_all(contents)?;
                sources.push(path);
            }
            Ok(())
        })?;
        let paths: Vec<_> = sources.iter().map(|path| (path.as_path(), true)).collect();
        let index = crate::body::LogicalIndex::load_with(
            &paths,
            crate::PINNED_FLEVEL,
            &crate::IgnoreSet::default(),
            |path| File::open(path),
        )?;
        assert_eq!(index.rule_count(), found.compiled);
        Ok(())
    }
}
