//! Selected legacy x86 encodings in the pinned ClamAV disassembly record format.

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Invalid,
    Unsupported,
}

type Operand = [u8; 10];
type Result<T> = std::result::Result<T, Error>;

const NO_REGISTER: u8 = 54;
const ARITHMETIC: [u16; 8] = [5, 119, 6, 147, 7, 181, 195, 43]; // ADD, OR, ADC, SBB, AND, SUB, XOR, CMP

struct Reader<'a> {
    bytes: &'a [u8],
    used: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8> {
        let value = *self.bytes.get(self.used).ok_or(Error::Invalid)?;
        self.used += 1;
        Ok(value)
    }

    fn signed(&mut self, size: u8) -> Result<i32> {
        let mut bytes = [0; 4];
        for b in &mut bytes[..1 << size] {
            *b = self.byte()?;
        }
        Ok(match size {
            0 => i32::from(bytes[0] as i8),
            1 => i32::from(i16::from_le_bytes([bytes[0], bytes[1]])),
            _ => i32::from_le_bytes(bytes),
        })
    }

    fn immediate(&mut self, size: u8, relative: bool) -> Result<Operand> {
        let mut operand = [0; 10];
        operand[0] = if relative { 2 } else { 1 };
        operand[1] = size;
        operand[2..].copy_from_slice(&i64::from(self.signed(size)?).to_le_bytes());
        Ok(operand)
    }

    fn modrm(&mut self, size: u8, address16: bool) -> Result<(u8, Operand)> {
        let descriptor = self.byte()?;
        let mode = descriptor >> 6;
        let extension = (descriptor >> 3) & 7;
        let rm = descriptor & 7;
        if mode == 3 {
            return Ok((extension, register(rm, size)));
        }

        let mut operand = [0; 10];
        operand[0] = 4;
        operand[1] = size;
        let displacement_only = mode == 0 && rm == if address16 { 6 } else { 5 };
        let mut full_displacement = mode == 2 || displacement_only;
        let (index, base, scale) = if address16 && displacement_only {
            // In this encoding stock leaves the second register byte zero.
            (NO_REGISTER, 0, 0)
        } else if address16 {
            let (index, base) = match rm {
                0 => (11, 14),
                1 => (11, 15),
                2 => (13, 14),
                3 => (13, 15),
                4 => (14, NO_REGISTER),
                5 => (15, NO_REGISTER),
                6 => (13, NO_REGISTER),
                _ => (11, NO_REGISTER),
            };
            (index, base, 1)
        } else if rm == 4 {
            let sib = self.byte()?;
            let index = (sib >> 3) & 7;
            let mut base = sib & 7;
            if mode == 0 && base == 5 {
                base = NO_REGISTER;
                full_displacement = true;
            }
            if index == 4 {
                (base, NO_REGISTER, u8::from(base != NO_REGISTER))
            } else {
                (index, base, 1 << (sib >> 6))
            }
        } else if displacement_only {
            (NO_REGISTER, NO_REGISTER, 0)
        } else {
            (rm, NO_REGISTER, 1)
        };
        operand[2..5].copy_from_slice(&[index, base, scale]);
        let displacement = if full_displacement {
            self.signed(if address16 { 1 } else { 2 })?
        } else if mode == 1 {
            self.signed(0)?
        } else {
            0
        };
        operand[6..].copy_from_slice(&displacement.to_le_bytes());
        Ok((extension, operand))
    }
}

fn register(index: u8, size: u8) -> Operand {
    let mut operand = [0; 10];
    operand[0] = 3;
    operand[1] = match size {
        0 if index < 4 => 20 + index,
        0 => 12 + index,
        1 => 8 + index,
        _ => index,
    };
    operand
}

/// Decode one record. The host leaves its cursor in place after this call.
pub(super) fn decode(bytes: &[u8]) -> Result<(usize, [u8; 64])> {
    let mut input = Reader {
        bytes: &bytes[..bytes.len().min(32)],
        used: 0,
    };
    let mut record = [0; 64];
    let opcode = loop {
        let byte = input.byte()?;
        match byte {
            0x66 => record[2] = 1,
            0x67 => record[3] = 1,
            0x26 | 0x2e | 0x36 | 0x3e => record[4] = 24 + ((byte - 0x26) >> 3),
            0x64 | 0x65 => record[4] = 28 + (byte - 0x64),
            _ => break byte,
        }
    };
    let wide = 2 - record[2];
    let size = if opcode & 1 == 0 { 0 } else { wide };
    let address16 = record[3] != 0;
    let mut args = [[0; 10]; 3];
    let operation = match opcode {
        0x00..=0x3d if opcode & 7 <= 5 => {
            let form = opcode & 7;
            if form < 4 {
                let (reg, rm) = input.modrm(size, address16)?;
                let reverse = usize::from(form >= 2);
                args[reverse] = rm;
                args[1 - reverse] = register(reg, size);
            } else {
                args[0] = register(0, size);
                args[1] = input.immediate(size, false)?;
            }
            ARITHMETIC[usize::from(opcode >> 3)]
        }
        0x0f => {
            let second = input.byte()?;
            match second {
                0x40..=0x4f | 0xaf | 0xb6 | 0xb7 | 0xbe | 0xbf => {
                    let source_size = if matches!(second, 0xb6 | 0xb7 | 0xbe | 0xbf) {
                        second & 1
                    } else {
                        wide
                    };
                    let (reg, rm) = input.modrm(source_size, address16)?;
                    args[0] = register(reg, wide);
                    args[1] = rm;
                    match second {
                        0xaf => 58,                         // IMUL
                        0xb6 | 0xb7 => 114,                 // MOVZX
                        0xbe | 0xbf => 113,                 // MOVSX
                        _ => 27 + u16::from(second - 0x40), // CMOVcc
                    }
                }
                0x80..=0x8f => {
                    args[0] = input.immediate(wide, true)?;
                    70 + u16::from(second - 0x80)
                }
                0xa4 | 0xa5 | 0xac | 0xad => {
                    let (reg, rm) = input.modrm(wide, address16)?;
                    args[0] = rm;
                    args[1] = register(reg, wide);
                    args[2] = if second & 1 == 0 {
                        input.immediate(0, false)?
                    } else {
                        register(1, 0)
                    };
                    if second < 0xac { 170 } else { 172 } // SHLD, SHRD
                }
                0xc8..=0xcf => {
                    // Stock keeps the register 32-bit with an operand-size prefix.
                    args[0] = register(second & 7, 2);
                    12 // BSWAP
                }
                _ => return Err(Error::Unsupported),
            }
        }
        0x40..=0x5f => {
            args[0] = register(opcode & 7, wide);
            [59, 52, 124, 129][usize::from((opcode - 0x40) >> 3)]
        }
        0x60 => 125 + u16::from(record[2]), // PUSHAD, PUSHA
        0x68 | 0x6a => {
            args[0] = input.immediate(if opcode == 0x68 { wide } else { 0 }, false)?;
            124
        }
        0x69 | 0x6b => {
            let (reg, rm) = input.modrm(wide, address16)?;
            args[0] = register(reg, wide);
            args[1] = rm;
            args[2] = input.immediate(if opcode == 0x69 { wide } else { 0 }, false)?;
            58
        }
        0x6c..=0x6f | 0xa4..=0xa7 | 0xaa..=0xaf => {
            // Stock omits implicit string operands and reports the element width in the opcode.
            let dword: u16 = match opcode & !1 {
                0x6c => 61,  // INS
                0x6e => 121, // OUTS
                0xa4 => 110, // MOVS
                0xa6 => 44,  // CMPS
                0xaa => 174, // STOS
                0xac => 99,  // LODS
                _ => 148,    // SCAS
            };
            dword
                + if opcode & 1 == 0 {
                    2
                } else {
                    u16::from(record[2])
                }
        }
        0x70..=0x7f => {
            args[0] = input.immediate(0, true)?;
            u16::from(opcode - 0x70) + 70
        }
        0x80..=0x83 => {
            let (extension, rm) = input.modrm(size, address16)?;
            args[0] = rm;
            args[1] = input.immediate(if opcode == 0x81 { wide } else { 0 }, false)?;
            ARITHMETIC[usize::from(extension)]
        }
        0x84..=0x8b | 0x8d => {
            let (reg, rm) = input.modrm(size, address16)?;
            let reverse = usize::from(opcode >= 0x8a);
            if opcode == 0x8d && rm[0] != 4 {
                return Err(Error::Invalid);
            }
            args[reverse] = rm;
            args[1 - reverse] = register(reg, size);
            match opcode {
                0x84 | 0x85 => 186, // TEST
                0x86 | 0x87 => 193, // XCHG
                0x8d => 93,         // LEA
                _ => 109,           // MOV
            }
        }
        0x90 => 117,
        0x91..=0x97 => {
            args[0] = register(opcode & 7, wide);
            args[1] = register(0, wide);
            193
        }
        0xa0..=0xa3 => {
            let memory = usize::from(opcode < 0xa2);
            args[1 - memory] = register(0, size);
            args[memory][..4].copy_from_slice(&[4, size, NO_REGISTER, NO_REGISTER]);
            let length = if address16 { 2 } else { 4 };
            for out in &mut args[memory][6..6 + length] {
                *out = input.byte()?;
            }
            109 // MOV accumulator to/from an absolute memory offset
        }
        0xa8 | 0xa9 => {
            args[0] = register(0, size);
            args[1] = input.immediate(size, false)?;
            186
        }
        0xb0..=0xbf => {
            let size = if opcode < 0xb8 { 0 } else { wide };
            args[0] = register(opcode & 7, size);
            args[1] = input.immediate(size, false)?;
            109
        }
        0xc0 | 0xc1 | 0xd0..=0xd3 => {
            let (extension, rm) = input.modrm(size, address16)?;
            args[0] = rm;
            let operation = match extension {
                0 => 142, // ROL
                1 => 143, // ROR
                2 => 133, // RCL
                3 => 134, // RCR
                4 => 169, // SHL
                5 => 171, // SHR
                7 => 146, // SAR
                _ => return Err(Error::Invalid),
            };
            args[1] = match opcode {
                0xc0 | 0xc1 => input.immediate(0, false)?,
                // Stock reports the implicit count of one as a word-sized immediate.
                0xd0 | 0xd1 => [1, 1, 1, 0, 0, 0, 0, 0, 0, 0],
                _ => register(1, 0), // CL
            };
            operation
        }
        0xc2 => {
            args[0] = input.immediate(1, false)?;
            141
        }
        0xc3 => 141,
        0xc6 | 0xc7 => {
            let (extension, rm) = input.modrm(size, address16)?;
            if extension != 0 {
                return Err(Error::Invalid);
            }
            args[0] = rm;
            args[1] = input.immediate(size, false)?;
            109
        }
        0xc9 => 94,
        0xe8 | 0xe9 | 0xeb => {
            args[0] = input.immediate(if opcode == 0xeb { 0 } else { wide }, true)?;
            if opcode == 0xe8 { 17 } else { 86 }
        }
        // The stock decoder reports these prefixes as separate operations.
        0xf0 => 98,
        0xf2 => 139,
        0xf3 => 138,
        0xf6 | 0xf7 => {
            let (extension, rm) = input.modrm(size, address16)?;
            args[0] = rm;
            match extension {
                0 => {
                    args[1] = input.immediate(size, false)?;
                    186 // TEST
                }
                2 => 118, // NOT
                3 => 116, // NEG
                4 => 115, // MUL
                5 => 58,  // IMUL
                6 => 53,  // DIV
                7 => 57,  // IDIV
                _ => return Err(Error::Invalid),
            }
        }
        0xf8 => 22,
        0xf9 => 178,
        0xfc => 23,
        0xfd => 179,
        0xfe | 0xff => {
            let (extension, rm) = input.modrm(size, address16)?;
            args[0] = rm;
            match extension {
                0 => 59, // INC
                1 => 52, // DEC
                2..=6 if opcode == 0xff => return Err(Error::Unsupported),
                _ => return Err(Error::Invalid),
            }
        }
        _ => return Err(Error::Unsupported),
    };
    record[..2].copy_from_slice(&operation.to_le_bytes());
    for (i, arg) in args.iter().enumerate() {
        let offset = 5 + i * 10;
        record[offset..offset + 10].copy_from_slice(arg);
    }
    Ok((input.used, record))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_unimplemented_encodings_from_short_input() {
        assert_eq!(decode(&[0xd9, 0xe8]), Err(Error::Unsupported)); // FLD1
        assert_eq!(decode(&[0xb9, 1]), Err(Error::Invalid)); // Short MOV immediate.
    }
}
