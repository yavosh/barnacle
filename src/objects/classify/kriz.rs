use crate::body::ObjectContext;

const EXTENT: usize = 0x0fd2;

pub(super) fn detect(context: &ObjectContext, bytes: &[u8]) -> Option<&'static str> {
    let ep = context.entry_in_last_pe_section(EXTENT)?;
    let entry = bytes.get(ep..)?.first_chunk::<200>()?;
    if entry[1..3] != [0x9c, 0x60] {
        return None;
    }
    // The reference stops each step when fewer than seven bytes remain.
    let window = |at: usize| entry.get(at..)?.first_chunk::<7>();
    let call = skip_noise(entry, 3, &[], false)?;
    let &[0xe8, skip, 0, 0, 0, _, _] = window(call)? else {
        return None;
    };
    if skip == 0xff {
        return None;
    }
    let pop = call + 5 + usize::from(skip);
    let pointer = window(pop)?[0].checked_sub(0x58)?;
    if pointer > 7 || pointer == 4 {
        return None;
    }
    let init = skip_noise(entry, pop + 1, &[pointer], true)?;
    let &[op, a, b, c, d, _, _] = window(init)?;
    let counter = op.checked_sub(0xb8)?;
    if counter > 7 || counter == 4 || u32::from_le_bytes([a, b, c, d]) != EXTENT as u32 {
        return None;
    }
    let registers = [pointer, counter];
    let prefix = skip_noise(entry, init + 5, &registers, false)?;
    let xor = prefix + usize::from(entry[prefix] == 0x3e);
    if window(xor)?[..2] != [0x80, 0xb0 + pointer] {
        return None;
    }
    let decrement = skip_noise(entry, xor + 7, &registers, false)?;
    if entry[decrement] != 0x48 + pointer {
        return None;
    }
    let tail = skip_noise(entry, decrement + 1, &registers, false)?;
    let &[op, 0x75, displacement, ..] = window(tail)? else {
        return None;
    };
    // Stock compares the signed displacement relative to the counter decrement.
    let target = tail.checked_add_signed(isize::from(displacement as i8))?;
    (op == 0x48 + counter && (init + 2..=xor).contains(&target)).then_some("Heuristics.W32.Kriz")
}

fn skip_noise(
    entry: &[u8; 200],
    mut at: usize,
    protected: &[u8],
    seek_counter: bool,
) -> Option<usize> {
    loop {
        let &[op, a, b, c, d, _, _] = entry.get(at..)?.first_chunk::<7>()?;
        let register = op & 7;
        at += match op {
            0x81 => 6,
            0xb8..=0xbf
                if register != 4
                    && !protected.contains(&register)
                    && !(seek_counter && u32::from_le_bytes([a, b, c, d]) == EXTENT as u32) =>
            {
                5
            }
            0x48..=0x4f if register != 4 && !protected.contains(&register) => 1,
            _ => return Some(at),
        };
    }
}
