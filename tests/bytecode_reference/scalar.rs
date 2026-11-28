//! Generate private logical CBCs for harmless text receipts.
use std::fmt::Write;

pub const NAME: &str = "Local.Bytecode.Receipt";
const RECEIPT_TRIGGER: &str = "0;72656365697074";
const SET_NAME: u64 = 5;
const BYTE_AT: u64 = 17;
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
    let arguments = fixed(args.len() as u64, 1) + &number(id) + &args.concat();
    op(32, output, 33, &[arguments])
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
    let mut head = String::from("ClamBC");
    for field in [
        number(7),
        number(0),
        string("Barnacle"),
        number(0),
        number(256),
        number(56),
        number(0),
        number(0),
        string("Barnacle Rust fixture"),
        number(5 + types.len() as u64),
        number(1),
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
    let mut entry = format!(
        "A{}{}L{}",
        fixed(0, 1),
        number(32),
        number(locals.len() as u64)
    );
    for &width in locals {
        entry += &(number(width) + &fixed(0, 1));
    }
    let instructions: usize = blocks.iter().map(Vec::len).sum();
    entry += &(String::from("F") + &number(instructions as u64) + &number(blocks.len() as u64));
    let mut cbc = format!(
        "{head}:4096\nLocal.Receipt.Trigger.{{}};Target:0;{trigger}\nT{}{}\n{api}\n{globals}\n{entry}\n",
        fixed(69, 2),
        types.concat()
    );
    for (i, block) in blocks.iter().enumerate() {
        let end = if i + 1 == blocks.len() { "E" } else { "" };
        writeln!(cbc, "B{}{end}", block.concat()).unwrap();
    }
    cbc += "S\n";
    cbc
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
