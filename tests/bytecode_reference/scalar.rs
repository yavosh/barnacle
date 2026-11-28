//! Generate private logical CBCs for harmless text receipts.
use std::fmt::Write;

pub const NAME: &str = "Local.Bytecode.Receipt";
pub const EXTRACTED_NOTE: &[u8] = b"Ordinary extracted ledger note";
const RECEIPT_TRIGGER: &str = "0;72656365697074";
const ADDRESSABLE: u64 = 1 << 15;
const READ: u64 = 2;
const SEEK: u64 = 4;
const SET_NAME: u64 = 5;
const DEBUG_STRING: u64 = 6;
const DEBUG_UINT: u64 = 7;
const PE_RAW_OFFSET: u64 = 15;
const FIND: u64 = 16;
const BYTE_AT: u64 = 17;
const ALLOCATE: u64 = 18;
const PE_SECTION: u64 = 20;
const READ_NUMBER: u64 = 23;
const RUNTIME_ERROR: u64 = 42;
const MEMORY_SEARCH: u64 = 51;
const DEBUG_START: u64 = 54;
const DEBUG_BYTES: u64 = 55;
const FIND_LIMIT: u64 = 65;
const ENGINE_LEVEL: u64 = 66;

fn fixed(value: u64, digits: usize) -> String {
    (0..digits)
        .map(|position| char::from(0x60 | ((value >> (position * 4)) & 15) as u8))
        .collect()
}

fn number(value: u64) -> String {
    let digits = (64 - value.leading_zeros()).div_ceil(4) as usize;
    format!(
        "{}{}",
        char::from(0x60 + digits as u8),
        fixed(value, digits)
    )
}

fn immediate(value: u64, width: u64) -> String {
    let mut encoded = number(value).into_bytes();
    encoded[0] -= 0x20;
    let mut encoded = String::from_utf8(encoded).unwrap();
    if width != 0 {
        encoded += &fixed(width, 1);
    }
    encoded
}

fn string(value: &str) -> String {
    let encoded: String = value
        .bytes()
        .chain([0])
        .map(|byte| fixed(u64::from(byte), 2))
        .collect();
    format!("|{}{encoded}", number(value.len() as u64 + 1))
}

fn op(width: u64, output: u64, opcode: u64, args: &[String]) -> String {
    format!(
        "{}{}{}{}",
        number(width),
        number(output),
        fixed(opcode, 2),
        args.concat()
    )
}

fn call(output: u64, id: u64, args: &[String]) -> String {
    call_with_type(32, output, id, args)
}

fn call_with_type(ty: u64, output: u64, id: u64, args: &[String]) -> String {
    let arguments = fixed(args.len() as u64, 1) + &number(id) + &args.concat();
    op(ty, output, 33, &[arguments])
}

fn call_direct(output: u64, id: u64, args: &[String]) -> String {
    let arguments = fixed(args.len() as u64, 1) + &number(id) + &args.concat();
    op(32, output, 32, &[arguments])
}

fn branch(condition: u64, yes: u64, no: u64) -> String {
    format!(
        "T{}{}{}{}",
        fixed(17, 2),
        number(condition),
        number(yes),
        number(no)
    )
}

fn ret() -> String {
    format!("T{}{}{}", fixed(19, 2), number(32), immediate(7, 4))
}

fn ret_local(local: u64) -> String {
    format!("T{}{}{}", fixed(19, 2), number(32), number(local))
}

fn report(output: u64) -> String {
    call(
        output,
        SET_NAME,
        &[pointer(2), immediate(NAME.len() as u64, 4)],
    )
}

fn pointer(index: u64) -> String {
    immediate(index, 0) + "`"
}

fn callable(params: &[u64]) -> String {
    let mut row = fixed(1, 1) + &number(params.len() as u64);
    for &width in params {
        row += &number(width);
    }
    row
}

fn array(len: usize, width: u64) -> String {
    fixed(4, 1) + &number(len as u64) + &number(width)
}

fn global_array(output: &mut String, type_id: u64, contents: &[u8]) {
    *output += &number(type_id);
    for &byte in contents {
        *output += &immediate(u64::from(byte), 0);
    }
    output.push('`');
}

fn global_pointer(output: &mut String, type_id: u64, base: u64, displacement: u64) {
    *output += &number(type_id);
    *output += &immediate(displacement, 0);
    *output += &immediate(base, 0);
    output.push('`');
}

fn image(
    trigger: &str,
    types: &[String],
    apis: &[(u64, u64, &str)],
    globals: String,
    locals: &[u64],
    blocks: &[Vec<String>],
) -> String {
    module(
        trigger,
        types,
        apis,
        globals,
        &[Function {
            args: 0,
            slots: locals,
            blocks,
        }],
    )
}

struct Function<'a> {
    args: usize,
    slots: &'a [u64],
    blocks: &'a [Vec<String>],
}

fn module(
    trigger: &str,
    types: &[String],
    apis: &[(u64, u64, &str)],
    globals: String,
    functions: &[Function<'_>],
) -> String {
    program(
        256,
        &format!("Local.Receipt.Trigger.{{}};Target:0;{trigger}"),
        types,
        apis,
        globals,
        functions,
    )
}

fn program(
    hook: u64,
    title: &str,
    types: &[String],
    apis: &[(u64, u64, &str)],
    globals: String,
    functions: &[Function<'_>],
) -> String {
    let mut head = String::from("ClamBC");
    for field in [
        number(7),
        number(0),
        string("Barnacle"),
        number(0),
        number(hook),
        number(56),
        number(0),
        number(0),
        string("Barnacle Rust fixture"),
        number(5 + types.len() as u64),
        number(functions.len() as u64),
        number(0x53e5493e9f3d1c30),
        fixed(42, 2),
    ] {
        head += &field;
    }
    let mut api = format!(
        "E{}{}",
        number(apis.last().unwrap().0),
        number(apis.len() as u64)
    );
    for &(id, type_id, name) in apis {
        api += &(number(id) + &number(type_id) + &string(name));
    }
    let mut cbc = format!(
        "{head}:4096\n{title}\nT{}{}\n{api}\n{globals}\n",
        fixed(69, 2),
        types.concat()
    );
    for function in functions {
        write!(
            cbc,
            "A{}{}L{}",
            fixed(function.args as u64, 1),
            number(32),
            number((function.slots.len() - function.args) as u64)
        )
        .unwrap();
        for &local in function.slots {
            cbc += &(number(local & !ADDRESSABLE) + &fixed(u64::from(local & ADDRESSABLE != 0), 1));
        }
        let instructions: usize = function.blocks.iter().map(Vec::len).sum();
        writeln!(
            cbc,
            "F{}{}",
            number(instructions as u64),
            number(function.blocks.len() as u64)
        )
        .unwrap();
        for (i, block) in function.blocks.iter().enumerate() {
            let end = if i + 1 == function.blocks.len() {
                "E"
            } else {
                ""
            };
            writeln!(cbc, "B{}{end}", block.concat()).unwrap();
        }
    }
    cbc += "S\n";
    cbc
}

pub struct PdfProbe {
    pub phase: u64,
    pub flags: u64,
    pub first_offset: Option<usize>,
    pub first_size: usize,
    pub first_byte: u8,
    pub stop_pdf: bool,
}

pub fn pdf_hook(probe: PdfProbe) -> String {
    const DCONF_LEVEL: u64 = 67;
    const PDF_FLAGS: u64 = 78;
    const PDF_LOOKUP: u64 = 80;
    const PDF_SIZE: u64 = 81;
    const PDF_OFFSET: u64 = 86;
    const PDF_PHASE: u64 = 87;
    let equals = |dest, value| op(1, dest, 21, &[number(32), number(0), immediate(value, 4)]);
    let invalid = u64::from(u32::MAX);
    let mut checks = Vec::new();
    for (api, arg, value) in [
        (DCONF_LEVEL, None, 213),
        (PDF_FLAGS, None, probe.flags),
        (
            PDF_LOOKUP,
            Some(1 << 8),
            if probe.first_offset.is_some() {
                0
            } else {
                invalid
            },
        ),
        (PDF_LOOKUP, Some(120 << 8), invalid),
        (PDF_SIZE, Some(0), probe.first_size as u64),
        (
            PDF_OFFSET,
            Some(0),
            probe.first_offset.map_or(invalid, |i| i as u64),
        ),
        (BYTE_AT, Some(0), u64::from(probe.first_byte)),
    ] {
        let args = arg.map(|value| immediate(value, 4));
        checks.push(call(0, api, args.as_slice()));
        checks.push(equals(2, value));
        checks.push(op(1, 1, 11, &[number(1), number(2)]));
    }
    checks.push(branch(1, 2, 3));
    let success = if probe.stop_pdf {
        vec![format!(
            "T{}{}{}",
            fixed(19, 2),
            number(32),
            immediate(0xcea5e, 4)
        )]
    } else {
        vec![report(0), ret()]
    };
    program(
        258,
        "Local.Receipt.PdfHook",
        &[
            callable(&[32, 65, 32]),
            callable(&[32]),
            callable(&[32, 32]),
            array(NAME.len() + 1, 8),
        ],
        &[
            (SET_NAME, 69, "setvirusname"),
            (BYTE_AT, 71, "file_byteat"),
            (DCONF_LEVEL, 70, "engine_dconf_level"),
            (PDF_FLAGS, 70, "pdf_get_flags"),
            (PDF_LOOKUP, 71, "pdf_lookupobj"),
            (PDF_SIZE, 71, "pdf_getobjsize"),
            (PDF_OFFSET, 71, "pdf_get_offset"),
            (PDF_PHASE, 70, "pdf_get_phase"),
        ],
        name_globals(0, 3, 72),
        &[Function {
            args: 0,
            slots: &[32, 1, 1],
            blocks: &[
                vec![
                    call(0, PDF_PHASE, &[]),
                    equals(1, probe.phase),
                    branch(1, 1, 3),
                ],
                checks,
                success,
                vec![ret()],
            ],
        }],
    )
}

fn name_globals(max_host: u64, globals_count: u64, name_type: u64) -> String {
    let mut row = format!(
        "G{}{}{}@`",
        number(max_host),
        number(globals_count),
        number(0)
    );
    let contents = [NAME.as_bytes(), &[0]].concat();
    global_array(&mut row, name_type, &contents);
    global_pointer(&mut row, 65, 1, 0);
    row
}

pub fn match_icon(target: u8, prefilter: Option<&str>, group: &[u8], expected: u32) -> String {
    let mut globals = name_globals(0, 5, 71);
    global_array(&mut globals, 72, group);
    global_pointer(&mut globals, 65, 3, 0);
    let conditions = prefilter.map_or_else(String::new, |g| format!(",IconGroup1:{g}"));
    program(
        256,
        &format!("Local.Icon.Trigger.{{}};Engine:81-255,Target:{target}{conditions};0;0:4d5a"),
        &[
            callable(&[32, 65, 32]),
            callable(&[32, 65, 32, 65, 32]),
            array(NAME.len() + 1, 8),
            array(group.len(), 8),
        ],
        &[(SET_NAME, 69, "setvirusname"), (89, 70, "matchicon")],
        globals,
        &[Function {
            args: 0,
            slots: &[32, 1],
            blocks: &[
                vec![
                    call(
                        0,
                        89,
                        &[
                            pointer(4),
                            immediate(0, 4),
                            pointer(4),
                            immediate(group.len() as u64, 4),
                        ],
                    ),
                    op(
                        1,
                        1,
                        21,
                        &[number(32), number(0), immediate(u64::from(expected), 4)],
                    ),
                    branch(1, 1, 2),
                ],
                vec![report(0), ret()],
                vec![ret()],
            ],
        }],
    )
}

pub fn pe_all_break() -> String {
    program(
        259,
        "Local.Receipt.Stop.{};Target:1;0;544:72656365697074",
        &[callable(&[32, 65, 32]), array(NAME.len() + 1, 8)],
        &[(SET_NAME, 69, "setvirusname")],
        name_globals(0x8000, 3, 70),
        &[Function {
            args: 0,
            slots: &[32],
            blocks: &[vec![format!(
                "T{}{}{}",
                fixed(19, 2),
                number(32),
                immediate(0xcea5e, 4)
            )]],
        }],
    )
}

pub enum WriteFinish {
    Return,
    Result(u32),
    Report,
    Check(u32),
    Abort,
}

pub fn write_probe(finish: WriteFinish) -> String {
    output_probe(
        256,
        &format!("Local.Receipt.Trigger.{{}};Target:0;{RECEIPT_TRIGGER}"),
        finish,
    )
}

pub fn output_probe(hook: u64, title: &str, finish: WriteFinish) -> String {
    const WRITE: u64 = 3;
    let split = 11;
    let mut globals = name_globals(0, 6, 70);
    global_array(&mut globals, 71, EXTRACTED_NOTE);
    global_pointer(&mut globals, 65, 3, 0);
    global_pointer(&mut globals, 65, 3, split);
    let mut instructions = vec![
        call(0, WRITE, &[pointer(4), immediate(split, 4)]),
        call(
            1,
            WRITE,
            &[
                pointer(5),
                immediate(EXTRACTED_NOTE.len() as u64 - split, 4),
            ],
        ),
    ];
    let blocks = match finish {
        WriteFinish::Check(second) => {
            instructions.extend([
                op(1, 3, 21, &[number(32), number(0), immediate(split, 4)]),
                op(
                    1,
                    4,
                    21,
                    &[number(32), number(1), immediate(second.into(), 4)],
                ),
                op(1, 3, 11, &[number(3), number(4)]),
                branch(3, 1, 2),
            ]);
            vec![instructions, vec![report(2), ret()], vec![ret()]]
        }
        other => {
            if matches!(other, WriteFinish::Report) {
                instructions.push(report(2));
            }
            instructions.push(match other {
                WriteFinish::Abort => format!("T{}", fixed(45, 2)),
                WriteFinish::Result(value) => format!(
                    "T{}{}{}",
                    fixed(19, 2),
                    number(32),
                    immediate(value.into(), 4)
                ),
                _ => ret(),
            });
            vec![instructions]
        }
    };
    program(
        hook,
        title,
        &[
            callable(&[32, 65, 32]),
            array(NAME.len() + 1, 8),
            array(EXTRACTED_NOTE.len(), 8),
        ],
        &[(WRITE, 69, "write"), (SET_NAME, 69, "setvirusname")],
        globals,
        &[Function {
            args: 0,
            slots: &[32, 32, 32, 1, 1],
            blocks: &blocks,
        }],
    )
}

pub fn pe_all_hook() -> String {
    let mut globals = name_globals(0x8005, 11, 71);
    global_pointer(&mut globals, 67, 0x8000, 0);
    global_pointer(&mut globals, 67, 0x8005, 0);
    for offset in [4, 52, 280, 632] {
        global_pointer(&mut globals, 67, 0x8003, offset);
    }
    for offset in [32, 264] {
        global_pointer(&mut globals, 66, 0x8003, offset);
    }
    let equals = |dest, value| op(1, dest, 21, &[number(32), number(0), immediate(value, 4)]);
    let combine = || op(1, 1, 11, &[number(1), number(2)]);
    let mut checks = vec![
        call(0, PE_RAW_OFFSET, &[immediate(0x1020, 4)]),
        equals(1, 544),
        call(0, BYTE_AT, &[immediate(551, 4)]),
        equals(2, u64::from(b'Y')),
        combine(),
    ];
    // Match count, match offset, raw entry, both entry RVAs, and PE header offset.
    for (index, expected) in [(3, 0), (4, 0), (5, 544), (6, 0x1020), (7, 0x1020), (8, 128)] {
        checks.extend([
            op(32, 0, 39, &[pointer(index)]),
            equals(2, expected),
            combine(),
        ]);
    }
    for (index, expected) in [(9, 224), (10, 0x10b)] {
        checks.extend([
            op(16, 3, 39, &[pointer(index)]),
            op(1, 2, 21, &[number(16), number(3), immediate(expected, 2)]),
            combine(),
        ]);
    }
    checks.push(branch(1, 1, 2));
    program(
        259,
        "Local.Receipt.Prefilter.{};Target:1;0;544:72656365697074",
        &[
            callable(&[32, 65, 32]),
            callable(&[32, 32]),
            array(NAME.len() + 1, 8),
            array(64, 32),
        ],
        &[
            (SET_NAME, 69, "setvirusname"),
            (PE_RAW_OFFSET, 70, "pe_rawaddr"),
            (BYTE_AT, 70, "file_byteat"),
        ],
        globals,
        &[Function {
            args: 0,
            slots: &[32, 1, 1, 16],
            blocks: &[checks, vec![report(0), ret()], vec![ret()]],
        }],
    )
}

/// Read the byte after the first trigger and compare the reported engine level.
pub fn first_match() -> String {
    let mut globals = name_globals(0x8005, 5, 72);
    global_pointer(&mut globals, 67, 0x8005, 0);
    global_pointer(&mut globals, 67, 0x8005, 4);
    image(
        "0&(1=0|1>0);72656365697074;6472616674",
        &[
            callable(&[32, 65, 32]),
            callable(&[32, 32]),
            callable(&[32]),
            array(NAME.len() + 1, 8),
            array(64, 32),
        ],
        &[
            (SET_NAME, 69, "setvirusname"),
            (BYTE_AT, 70, "file_byteat"),
            (ENGINE_LEVEL, 71, "engine_functionality_level"),
        ],
        globals,
        &[32, 32, 32, 1, 32, 1, 1, 32, 1, 1, 32],
        &[
            vec![
                op(32, 0, 39, &[pointer(3)]),
                op(32, 1, 1, &[number(0), immediate(7, 4)]),
                call(2, BYTE_AT, &[number(1)]),
                op(
                    1,
                    3,
                    21,
                    &[number(32), number(2), immediate(u64::from(b'Y'), 4)],
                ),
                call(4, ENGINE_LEVEL, &[]),
                op(1, 5, 21, &[number(32), number(4), immediate(213, 4)]),
                op(1, 6, 11, &[number(3), number(5)]),
                op(32, 7, 39, &[pointer(4)]),
                op(
                    1,
                    8,
                    21,
                    &[number(32), number(7), immediate(0xffff_fffe, 4)],
                ),
                op(1, 9, 11, &[number(6), number(8)]),
                branch(9, 1, 2),
            ],
            vec![report(10), ret()],
            vec![ret()],
        ],
    )
}

/// Scan fixed read windows for a tiny public marker while respecting an absolute limit.
pub fn find() -> String {
    let mut globals = name_globals(0, 5, 71);
    global_array(&mut globals, 72, b"ABC");
    global_pointer(&mut globals, 65, 3, 0);
    image(
        RECEIPT_TRIGGER,
        &[
            callable(&[32, 65, 32]),
            callable(&[32, 65, 32, 32]),
            array(NAME.len() + 1, 8),
            array(3, 8),
        ],
        &[
            (SET_NAME, 69, "setvirusname"),
            (FIND_LIMIT, 70, "file_find_limit"),
        ],
        globals,
        &[32, 1, 32],
        &[
            vec![
                call(
                    0,
                    FIND_LIMIT,
                    &[pointer(4), immediate(3, 4), immediate(4_105, 4)],
                ),
                op(
                    1,
                    1,
                    22,
                    &[number(32), number(0), immediate(u64::from(u32::MAX), 4)],
                ),
                branch(1, 1, 2),
            ],
            vec![report(2), ret()],
            vec![ret()],
        ],
    )
}

/// End after a bounded counter loop, even when the entire bytecode timeout is available.
pub fn counted_loop(iterations: u64) -> String {
    image(
        RECEIPT_TRIGGER,
        &[callable(&[32, 65, 32]), array(NAME.len() + 1, 8)],
        &[(SET_NAME, 69, "setvirusname")],
        name_globals(0, 3, 70),
        &[32, 1, 32],
        &[
            vec![
                op(32, 0, 1, &[immediate(0, 4), immediate(0, 4)]),
                format!("T{}{}", fixed(18, 2), number(1)),
            ],
            vec![
                op(32, 0, 1, &[number(0), immediate(1, 4)]),
                op(1, 1, 25, &[number(32), number(0), immediate(iterations, 4)]),
                branch(1, 1, 2),
            ],
            vec![report(2), ret()],
        ],
    )
}

/// Compare the stock interpreter's signed i1 and sign-extension behavior.
pub fn scalar_widths() -> String {
    image(
        RECEIPT_TRIGGER,
        &[callable(&[32, 65, 32]), array(NAME.len() + 1, 8)],
        &[(SET_NAME, 69, "setvirusname")],
        name_globals(0, 3, 70),
        &[1, 32, 1, 1, 1, 1, 32],
        &[
            vec![
                op(1, 0, 11, &[immediate(1, 1), immediate(1, 1)]),
                op(32, 1, 15, &[number(0)]),
                op(
                    1,
                    2,
                    21,
                    &[number(32), number(1), immediate(u64::from(u32::MAX), 4)],
                ),
                op(1, 3, 30, &[number(1), number(0), immediate(0, 1)]),
                op(1, 4, 13, &[number(3), immediate(1, 1)]),
                op(1, 5, 11, &[number(2), number(4)]),
                branch(5, 1, 2),
            ],
            vec![report(6), ret()],
            vec![ret()],
        ],
    )
}

/// Seek past the trigger, read a word into an addressable local, and interpret it.
pub fn read_word() -> String {
    let mut read = vec![
        call(2, SEEK, &[immediate(7, 4), immediate(0, 4)]),
        op(65, 1, 36, &[number(73), number(0), immediate(0, 4)]),
        call(3, READ, &[number(1), immediate(2, 4)]),
        op(16, 4, 39, &[number(1)]),
        op(16, 5, 46, &[number(4)]),
        op(1, 6, 44, &[]),
        op(16, 7, 31, &[number(6), number(4), number(5)]),
        // The pointer moves by one byte, then STORE overwrites that byte.
        op(65, 8, 35, &[number(65), number(1), immediate(1, 4)]),
        op(8, 0, 38, &[immediate(u64::from(b'Y'), 1), number(8)]),
        op(8, 9, 39, &[number(8)]),
        // A zero-distance seek observes the position reached by the read.
        call(10, SEEK, &[immediate(0, 4), immediate(1, 4)]),
    ];
    for (destination, width, value, expected) in [
        (11, 32, 2, 7),
        (12, 32, 3, 2),
        (13, 16, 7, 0x4142),
        (14, 8, 9, u64::from(b'Y')),
        (15, 32, 10, 9),
    ] {
        read.push(op(
            1,
            destination,
            21,
            &[number(width), number(value), immediate(expected, width / 8)],
        ));
    }
    for (dest, left, right) in [(16, 11, 12), (17, 13, 14), (18, 16, 17), (19, 18, 15)] {
        read.push(op(1, dest, 11, &[number(left), number(right)]));
    }
    read.push(branch(19, 1, 2));
    image(
        RECEIPT_TRIGGER,
        &[
            callable(&[32, 65, 32]),
            callable(&[32, 32, 32]),
            array(NAME.len() + 1, 8),
            array(2, 8),
            fixed(5, 1) + &number(72),
        ],
        &[
            (READ, 69, "read"),
            (SEEK, 70, "seek"),
            (SET_NAME, 69, "setvirusname"),
        ],
        name_globals(0, 3, 71),
        &[
            ADDRESSABLE | 72,
            65,
            32,
            32,
            16,
            16,
            1,
            16,
            65,
            8,
            32,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            32,
        ],
        &[read, vec![report(20), ret()], vec![ret()]],
    )
}

/// Search from EOF minus four and confirm that searching leaves the cursor at that position.
pub fn cursor_search() -> String {
    let mut globals = name_globals(0, 5, 71);
    global_array(&mut globals, 72, b"ABC");
    global_pointer(&mut globals, 65, 3, 0);
    image(
        RECEIPT_TRIGGER,
        &[
            callable(&[32, 65, 32]),
            callable(&[32, 32, 32]),
            array(NAME.len() + 1, 8),
            array(3, 8),
        ],
        &[
            (SEEK, 70, "seek"),
            (SET_NAME, 69, "setvirusname"),
            (FIND, 69, "file_find"),
        ],
        globals,
        &[32, 32, 32, 1, 1, 1, 32],
        &[
            vec![
                call(
                    0,
                    SEEK,
                    &[immediate(u64::from((-4i32) as u32), 4), immediate(2, 4)],
                ),
                call(1, FIND, &[pointer(4), immediate(3, 4)]),
                call(2, SEEK, &[immediate(0, 4), immediate(1, 4)]),
                op(1, 3, 21, &[number(32), number(0), number(2)]),
                op(1, 4, 21, &[number(32), number(0), number(1)]),
                op(1, 5, 11, &[number(3), number(4)]),
                branch(5, 1, 2),
            ],
            vec![report(6), ret()],
            vec![ret()],
        ],
    )
}

/// Read one byte directly into a scalar that is also read as an instruction operand.
pub fn direct_read() -> String {
    image(
        RECEIPT_TRIGGER,
        &[
            callable(&[32, 65, 32]),
            callable(&[32, 32, 32]),
            array(NAME.len() + 1, 8),
        ],
        &[
            (READ, 69, "read"),
            (SEEK, 70, "seek"),
            (SET_NAME, 69, "setvirusname"),
        ],
        name_globals(0, 3, 71),
        &[ADDRESSABLE | 8, 32, 32, 1, 1, 1, 32],
        &[
            vec![
                call(1, SEEK, &[immediate(7, 4), immediate(0, 4)]),
                call(2, READ, &[number(0), immediate(1, 4)]),
                op(1, 3, 21, &[number(32), number(2), immediate(1, 4)]),
                op(
                    1,
                    4,
                    21,
                    &[number(8), number(0), immediate(u64::from(b'Q'), 1)],
                ),
                op(1, 5, 11, &[number(3), number(4)]),
                branch(5, 1, 2),
            ],
            vec![report(6), ret()],
            vec![ret()],
        ],
    )
}

/// Report when the selected PNG subsignature count is zero.
pub fn image_count(slot: u64) -> String {
    let mut globals = name_globals(0x8000, 4, 70);
    global_pointer(&mut globals, 67, 0x8000, slot * 4);
    image(
        "0|1;0:89504e470d0a1a0a;fuzzy_img#e3f302e2c0e7ec51#0",
        &[
            callable(&[32, 65, 32]),
            array(NAME.len() + 1, 8),
            array(64, 32),
        ],
        &[(SET_NAME, 69, "setvirusname")],
        globals,
        &[32, 1],
        &[
            vec![
                op(32, 0, 39, &[pointer(3)]),
                op(1, 1, 21, &[number(32), number(0), immediate(0, 4)]),
                branch(1, 1, 2),
            ],
            vec![report(0), ret()],
            vec![ret()],
        ],
    )
    .replacen("Target:0;", "Engine:150-255,Target:5;", 1)
}

/// Observe the current file size, two matches, and a zero for an unused counter.
pub fn scan_metadata() -> String {
    let mut globals = name_globals(0x8004, 6, 70);
    global_pointer(&mut globals, 67, 0x8000, 0);
    global_pointer(&mut globals, 67, 0x8000, 4);
    global_pointer(&mut globals, 67, 0x8004, 0);
    image(
        RECEIPT_TRIGGER,
        &[
            callable(&[32, 65, 32]),
            array(NAME.len() + 1, 8),
            array(64, 32),
            array(1, 32),
        ],
        &[(SET_NAME, 69, "setvirusname")],
        globals,
        &[32, 32, 32, 1, 1, 1, 1, 1, 32],
        &[
            vec![
                op(32, 0, 39, &[pointer(3)]),
                op(32, 1, 39, &[pointer(4)]),
                op(32, 2, 39, &[pointer(5)]),
                op(1, 3, 21, &[number(32), number(0), immediate(2, 4)]),
                op(1, 4, 21, &[number(32), number(1), immediate(0, 4)]),
                op(1, 5, 21, &[number(32), number(2), immediate(24, 4)]),
                op(1, 6, 11, &[number(3), number(4)]),
                op(1, 7, 11, &[number(6), number(5)]),
                branch(7, 1, 2),
            ],
            vec![report(8), ret()],
            vec![ret()],
        ],
    )
}

/// Compare the active map while a script is matched after whitespace collapse.
pub fn normalized_script(mapped: bool) -> String {
    let mut globals = name_globals(0x8004, 4, 71);
    global_pointer(&mut globals, 67, 0x8004, 0);
    let (expected_size, first_byte) = if mapped { (14, b'r') } else { (17, b'R') };
    let program = image(
        "0;7265636569707420706164646564",
        &[
            callable(&[32, 65, 32]),
            callable(&[32, 32]),
            array(NAME.len() + 1, 8),
            array(1, 32),
        ],
        &[(SET_NAME, 69, "setvirusname"), (BYTE_AT, 70, "file_byteat")],
        globals,
        &[32, 32, 1, 1, 1, 32],
        &[
            vec![
                op(32, 0, 39, &[pointer(3)]),
                call(1, BYTE_AT, &[immediate(0, 4)]),
                op(
                    1,
                    2,
                    21,
                    &[number(32), number(0), immediate(expected_size, 4)],
                ),
                op(
                    1,
                    3,
                    21,
                    &[number(32), number(1), immediate(u64::from(first_byte), 4)],
                ),
                op(1, 4, 11, &[number(2), number(3)]),
                branch(4, 1, 2),
            ],
            vec![report(5), ret()],
            vec![ret()],
        ],
    );
    if mapped {
        program.replacen("Target:0", "Target:7", 1)
    } else {
        program
    }
}

pub fn numeric_read(radix: u64, value: u32, position: u64) -> String {
    image(
        RECEIPT_TRIGGER,
        &[
            callable(&[32, 65, 32]),
            callable(&[32, 32, 32]),
            callable(&[32, 32]),
            array(NAME.len() + 1, 8),
        ],
        &[
            (SEEK, 70, "seek"),
            (SET_NAME, 69, "setvirusname"),
            (READ_NUMBER, 71, "read_number"),
        ],
        name_globals(0, 3, 72),
        &[32, 32, 32, 1, 1, 1, 32],
        &[
            vec![
                call(0, SEEK, &[immediate(7, 4), immediate(0, 4)]),
                call(1, READ_NUMBER, &[immediate(radix, 4)]),
                call(2, SEEK, &[immediate(0, 4), immediate(1, 4)]),
                op(
                    1,
                    3,
                    21,
                    &[number(32), number(1), immediate(value.into(), 4)],
                ),
                op(1, 4, 21, &[number(32), number(2), immediate(position, 4)]),
                op(1, 5, 11, &[number(3), number(4)]),
                branch(5, 1, 2),
            ],
            vec![report(6), ret()],
            vec![ret()],
        ],
    )
}

pub fn diagnostics(debug: bool) -> String {
    let mut globals = name_globals(0, 5, 71);
    global_array(&mut globals, 72, b"note\0");
    global_pointer(&mut globals, 65, 3, 0);
    let text = [pointer(4), immediate(4, 4)];
    let printed_number = if debug { 3 } else { 0 };
    let printed_bytes = if debug { 4 } else { 0 };
    image(
        RECEIPT_TRIGGER,
        &[
            callable(&[32, 65, 32]),
            callable(&[32, 32]),
            array(NAME.len() + 1, 8),
            array(5, 8),
        ],
        &[
            (SET_NAME, 69, "setvirusname"),
            (DEBUG_STRING, 69, "debug_print_str"),
            (DEBUG_UINT, 70, "debug_print_uint"),
            (RUNTIME_ERROR, 70, "bytecode_rt_error"),
            (DEBUG_START, 69, "debug_print_str_start"),
            (DEBUG_BYTES, 69, "debug_print_str_nonl"),
        ],
        globals,
        &[32, 32, 32, 32, 32, 1, 1, 1, 32],
        &[
            vec![
                call(0, DEBUG_STRING, &text),
                call(1, DEBUG_START, &text),
                call(2, DEBUG_UINT, &[immediate(u64::from((-12i32) as u32), 4)]),
                call(3, DEBUG_BYTES, &text),
                call(4, RUNTIME_ERROR, &[immediate(9 << 8 | 2, 4)]),
                op(
                    1,
                    5,
                    21,
                    &[number(32), number(2), immediate(printed_number, 4)],
                ),
                op(
                    1,
                    6,
                    21,
                    &[number(32), number(3), immediate(printed_bytes, 4)],
                ),
                op(1, 7, 11, &[number(5), number(6)]),
                branch(7, 1, 2),
            ],
            vec![report(8), ret()],
            vec![ret()],
        ],
    )
}

/// Pass a scalar argument through a helper that calls a second function.
pub fn direct_calls() -> String {
    module(
        RECEIPT_TRIGGER,
        &[
            callable(&[32, 65, 32]),
            callable(&[32, 32, 32]),
            array(NAME.len() + 1, 8),
        ],
        &[
            (READ, 69, "read"),
            (SEEK, 70, "seek"),
            (SET_NAME, 69, "setvirusname"),
        ],
        name_globals(0, 3, 71),
        &[
            Function {
                args: 0,
                slots: &[32, 32, 32, 1, 1, 1, 32],
                blocks: &[
                    vec![
                        call(0, SEEK, &[immediate(7, 4), immediate(0, 4)]),
                        call_direct(1, 2, &[immediate(5, 4)]),
                        call(2, SEEK, &[immediate(0, 4), immediate(1, 4)]),
                        op(
                            1,
                            3,
                            21,
                            &[number(32), number(1), immediate(u64::from(b'Q') + 5, 4)],
                        ),
                        op(1, 4, 21, &[number(32), number(2), immediate(8, 4)]),
                        op(1, 5, 11, &[number(3), number(4)]),
                        branch(5, 1, 2),
                    ],
                    vec![report(6), ret()],
                    vec![ret()],
                ],
            },
            Function {
                args: 1,
                slots: &[32, 32, 32],
                blocks: &[vec![
                    call_direct(1, 3, &[]),
                    op(32, 2, 1, &[number(0), number(1)]),
                    ret_local(2),
                ]],
            },
            Function {
                args: 0,
                slots: &[ADDRESSABLE | 8, 32, 8, 32],
                blocks: &[vec![
                    call(1, READ, &[number(0), immediate(1, 4)]),
                    op(8, 2, 39, &[number(0)]),
                    op(32, 3, 16, &[number(2)]),
                    ret_local(3),
                ]],
            },
        ],
    )
}

/// Compare the complete disassembly record and returned offset supplied after the receipt.
pub fn disasm_record() -> String {
    const DISASM: u64 = 8;
    let mut record = fixed(3, 1) + &number(6);
    for field in [16, 8, 8, 8, 74, 72] {
        record += &number(field);
    }
    image(
        RECEIPT_TRIGGER,
        &[
            callable(&[32, 32, 32]),
            callable(&[32, 65, 32]),
            array(NAME.len() + 1, 8),
            array(29, 8),
            array(10, 8),
            array(3, 73),
            record,
            fixed(5, 1) + &number(75),
            callable(&[32, 76, 32]),
            array(64, 8),
        ],
        &[
            (READ, 70, "read"),
            (SEEK, 69, "seek"),
            (SET_NAME, 70, "setvirusname"),
            (DISASM, 77, "disasm_x86"),
        ],
        name_globals(0, 3, 71),
        &[
            ADDRESSABLE | 75,
            ADDRESSABLE | 78,
            ADDRESSABLE | 32,
            32,
            32,
            32,
            1,
            1,
            32,
        ],
        &[
            vec![
                call(3, SEEK, &[immediate(7, 4), immediate(0, 4)]),
                call(3, READ, &[number(2), immediate(4, 4)]),
                call(3, READ, &[number(1), immediate(64, 4)]),
                op(0, 0, 40, &[number(0), immediate(0xa5, 1), immediate(64, 8)]),
                call(4, DISASM, &[number(0), immediate(0, 4)]),
                call(5, SEEK, &[immediate(0, 4), immediate(1, 4)]),
                op(1, 6, 21, &[number(32), number(4), number(2)]),
                op(1, 7, 21, &[number(32), number(5), immediate(75, 4)]),
                op(1, 6, 11, &[number(6), number(7)]),
                op(32, 3, 43, &[number(0), number(1), immediate(64, 4)]),
                op(1, 7, 21, &[number(32), number(3), immediate(0, 4)]),
                op(1, 6, 11, &[number(6), number(7)]),
                branch(6, 1, 2),
            ],
            vec![report(8), ret()],
            vec![ret()],
        ],
    )
}

pub fn heap_pointer_integers() -> String {
    let cast = |dest, src| op(64, dest, 50, &[number(src)]);
    let eq = |dest, lhs, rhs| op(1, dest, 21, &[number(64), number(lhs), rhs]);
    image(
        RECEIPT_TRIGGER,
        &[
            callable(&[32, 65, 32]),
            callable(&[32, 32]),
            callable(&[65, 32]),
            array(NAME.len() + 1, 8),
        ],
        &[
            (SET_NAME, 69, "setvirusname"),
            (BYTE_AT, 70, "file_byteat"),
            (ALLOCATE, 71, "malloc"),
        ],
        name_globals(0, 3, 72),
        &[65, 65, 64, 64, 64, 64, 64, 32, 64, 1, 1, 65, 64, 32],
        &[
            vec![
                call_with_type(65, 0, ALLOCATE, &[immediate(12, 4)]),
                op(65, 1, 35, &[number(65), number(0), immediate(4, 4)]),
                cast(2, 0),
                cast(3, 1),
                op(64, 4, 2, &[number(3), number(2)]),
                // Each pointer has an object ID in its high 32 bits.
                eq(9, 2, immediate(8 << 32, 8)),
                cast(5, 1),
                eq(10, 3, number(5)),
                op(1, 9, 11, &[number(9), number(10)]),
                // The first subtraction wraps before the base address cancels.
                op(64, 5, 2, &[immediate(4, 8), number(3)]),
                op(64, 6, 1, &[number(5), number(2)]),
                eq(10, 6, immediate(0, 8)),
                op(1, 9, 11, &[number(9), number(10)]),
                call_with_type(65, 11, ALLOCATE, &[immediate(0, 4)]),
                cast(12, 11),
                eq(10, 12, immediate(0, 8)),
                op(1, 9, 11, &[number(9), number(10)]),
                call_with_type(65, 11, ALLOCATE, &[immediate(8, 4)]),
                cast(12, 11),
                eq(10, 12, immediate(9 << 32, 8)),
                op(1, 9, 11, &[number(9), number(10)]),
                call(7, BYTE_AT, &[immediate(7, 4)]),
                op(64, 8, 16, &[number(7)]),
                eq(10, 4, number(8)),
                op(1, 9, 11, &[number(9), number(10)]),
                branch(9, 1, 2),
            ],
            vec![report(13), ret()],
            vec![ret()],
        ],
    )
}

pub fn heap_search() -> String {
    let mut globals = name_globals(0, 5, 73);
    global_array(&mut globals, 74, b"!AY");
    global_pointer(&mut globals, 65, 3, 0);
    module(
        RECEIPT_TRIGGER,
        &[
            callable(&[32, 65, 32]),
            callable(&[32, 32, 32]),
            callable(&[65, 32]),
            callable(&[32, 65, 32, 65, 32]),
            array(NAME.len() + 1, 8),
            array(3, 8),
        ],
        &[
            (READ, 69, "read"),
            (SEEK, 70, "seek"),
            (SET_NAME, 69, "setvirusname"),
            (ALLOCATE, 71, "malloc"),
            (MEMORY_SEARCH, 72, "memstr"),
        ],
        globals,
        &[
            Function {
                args: 0,
                slots: &[32, 65, 32, 32, 32, 1, 32],
                blocks: &[
                    vec![
                        call(0, SEEK, &[immediate(7, 4), immediate(0, 4)]),
                        call_with_type(65, 1, ALLOCATE, &[immediate(8, 4)]),
                        call(2, READ, &[number(1), immediate(4, 4)]),
                        op(1, 5, 21, &[number(32), number(2), immediate(4, 4)]),
                        branch(5, 1, 3),
                    ],
                    vec![
                        call_direct(3, 2, &[number(1)]),
                        call(
                            4,
                            MEMORY_SEARCH,
                            &[number(1), immediate(4, 4), pointer(4), immediate(3, 4)],
                        ),
                        op(1, 5, 21, &[number(32), number(4), immediate(1, 4)]),
                        branch(5, 2, 3),
                    ],
                    vec![report(6), ret()],
                    vec![ret()],
                ],
            },
            Function {
                args: 1,
                slots: &[65, 65],
                blocks: &[vec![
                    op(65, 1, 35, &[number(65), number(0), immediate(1, 4)]),
                    op(8, 0, 38, &[immediate(u64::from(b'!'), 1), number(1)]),
                    ret(),
                ]],
            },
        ],
    )
}

pub fn pe_metadata(target: u8) -> String {
    let mut globals = name_globals(0x8003, 5, 75);
    global_pointer(&mut globals, 66, 0x8003, 8);
    global_pointer(&mut globals, 67, 0x8003, 4);
    let mut comparisons = vec![
        call(1, PE_SECTION, &[number(0), immediate(0, 4)]),
        call(2, PE_SECTION, &[number(0), immediate(1, 4)]),
        call(7, PE_RAW_OFFSET, &[immediate(0x1020, 4)]),
        call(8, PE_RAW_OFFSET, &[immediate(0x1200, 4)]),
        call(9, PE_RAW_OFFSET, &[immediate(128, 4)]),
        op(16, 18, 39, &[pointer(3)]),
        op(32, 19, 39, &[pointer(4)]),
    ];
    for (bit, register, bits, expect) in [
        (10, 1, 32, 0),
        (11, 2, 32, u64::from(u32::MAX)),
        (14, 7, 32, 544),
        (15, 8, 32, u64::from(u32::MAX)),
        (16, 9, 32, 128),
        (20, 18, 16, 1),
        (21, 19, 32, 0),
    ] {
        comparisons.push(op(
            1,
            bit,
            21,
            &[number(bits), number(register), immediate(expect, bits / 8)],
        ));
        if bit > 10 {
            comparisons.push(op(1, 10, 11, &[number(10), number(bit)]));
        }
    }
    for (index, field) in [4096, 4096, 512, 512, 0x40000040, 4096, 512, 512, 512]
        .into_iter()
        .enumerate()
    {
        comparisons.extend([
            op(
                65,
                3,
                36,
                &[number(74), number(0), immediate((index * 4) as u64, 4)],
            ),
            op(32, 4, 39, &[number(3)]),
            op(1, 11, 21, &[number(32), number(4), immediate(field, 4)]),
            op(1, 10, 11, &[number(10), number(11)]),
        ]);
    }
    comparisons.push(branch(10, 1, 2));
    image(
        "0;544:72656365697074",
        &[
            callable(&[32, 65, 32]),
            fixed(3, 1) + &number(9) + &number(32).repeat(9),
            fixed(5, 1) + &number(70),
            callable(&[32, 71, 32]),
            array(36, 8),
            fixed(5, 1) + &number(73),
            array(NAME.len() + 1, 8),
            callable(&[32, 32]),
        ],
        &[
            (SET_NAME, 69, "setvirusname"),
            (PE_RAW_OFFSET, 76, "pe_rawaddr"),
            (PE_SECTION, 72, "get_pe_section"),
        ],
        globals,
        &[
            ADDRESSABLE | 73,
            32,
            32,
            65,
            32,
            65,
            32,
            32,
            32,
            32,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            32,
            16,
            32,
            1,
            1,
        ],
        &[comparisons, vec![report(17), ret()], vec![ret()]],
    )
    .replacen("Target:0;", &format!("Target:{target};"), 1)
}
