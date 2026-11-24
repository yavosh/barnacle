//! Target identifiers and object-relative offsets for ClamAV 1.4.3 body rules.
use std::io;
use std::ops::RangeInclusive;

mod executable;
use executable::Executable;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Target {
    Generic = 0,
    Pe = 1,
    Ole2 = 2,
    Html = 3,
    Mail = 4,
    Graphics = 5,
    Elf = 6,
    Ascii = 7,
    MachO = 9,
    Pdf = 10,
    Flash = 11,
    Java = 12,
    Internal = 13,
    Other = 14,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn decimal(value: &str) -> io::Result<u32> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(format!(
            "expected unsigned decimal number: {value}"
        )));
    }
    value
        .parse()
        .map_err(|_| invalid(format!("number exceeds 32 bits: {value}")))
}

impl Target {
    pub fn id(self) -> u8 {
        self as u8
    }

    pub fn parse(id: &str) -> io::Result<Self> {
        match decimal(id)? {
            0 => Ok(Self::Generic),
            1 => Ok(Self::Pe),
            2 => Ok(Self::Ole2),
            3 => Ok(Self::Html),
            4 => Ok(Self::Mail),
            5 => Ok(Self::Graphics),
            6 => Ok(Self::Elf),
            7 => Ok(Self::Ascii),
            9 => Ok(Self::MachO),
            10 => Ok(Self::Pdf),
            11 => Ok(Self::Flash),
            12 => Ok(Self::Java),
            13 => Ok(Self::Internal),
            14 => Ok(Self::Other),
            _ => Err(invalid(format!("unsupported signature target: {id}"))),
        }
    }

    fn executable(self) -> bool {
        matches!(self, Self::Pe | Self::Elf | Self::MachO)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Base {
    Any,
    Absolute,
    End,
    EntryPlus,
    EntryMinus,
    LastSection,
    Section(u32),
    EntireSection(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Offset {
    base: Base,
    displacement: u32,
    shift: u32,
}

impl Offset {
    pub(super) fn is_relative(&self) -> bool {
        !matches!(self.base, Base::Any | Base::Absolute)
    }

    pub fn parse(text: &str, target: Target) -> io::Result<Self> {
        if text.len() > 64 {
            return Err(invalid("offset exceeds 64 bytes"));
        }
        if text == "*" {
            return Ok(Self {
                base: Base::Any,
                displacement: 0,
                shift: 0,
            });
        }
        let (position, shift) = match text.split_once(',') {
            Some((position, shift)) => (position, decimal(shift)?),
            None => (text, 0),
        };
        let (base, displacement) = if let Some(n) = position.strip_prefix("EOF-") {
            (Base::End, decimal(n)?)
        } else if position.starts_with(['E', 'S']) {
            if !target.executable() {
                return Err(invalid(format!(
                    "executable offset on target {}: {text}",
                    target.id()
                )));
            }
            if let Some(n) = position.strip_prefix("EP+") {
                (Base::EntryPlus, decimal(n)?)
            } else if let Some(n) = position.strip_prefix("EP-") {
                (Base::EntryMinus, decimal(n)?)
            } else if let Some(n) = position.strip_prefix("SL+") {
                (Base::LastSection, decimal(n)?)
            } else if let Some(n) = position.strip_prefix("SE") {
                (Base::EntireSection(decimal(n)?), 0)
            } else if let Some((index, displacement)) =
                position.strip_prefix('S').and_then(|s| s.split_once('+'))
            {
                (Base::Section(decimal(index)?), decimal(displacement)?)
            } else {
                return Err(invalid(format!("unsupported offset: {text}")));
            }
        } else {
            (Base::Absolute, decimal(position)?)
        };
        Ok(Self {
            base,
            displacement,
            shift,
        })
    }
}

/// Describes one raw, extracted, or normalized object. Offset zero belongs to that object.
#[derive(Clone, Debug)]
pub struct ObjectContext {
    target: Target,
    exe: Option<Executable>,
}

impl ObjectContext {
    /// Infer raw targets with unambiguous header markers from the pinned built-in file types.
    /// Target 7 applies to a normalized ASCII object. Raw text only selects generic rules.
    pub fn raw(bytes: &[u8]) -> Self {
        use Target::*;
        let target = match bytes {
            [b'M', b'Z', ..] => Pe,
            [0x7f, b'E', b'L', b'F', ..] => Elf,
            [0xce | 0xcf, 0xfa, 0xed, 0xfe, ..] | [0xfe, 0xed, 0xfa, 0xce | 0xcf, ..] => MachO,
            [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0..=31, ..] => MachO,
            [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 32..=63, ..] => Java,
            [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, ..] => Ole2,
            [b'%', b'P', b'D', b'F', b'-', ..] => Pdf,
            [b'F' | b'C' | b'Z', b'W', b'S', ..] => Flash,
            [b'B', b'M', ..]
            | [b'G', b'I', b'F', ..]
            | [0x89, b'P', b'N', b'G', ..]
            | [0xff, 0xd8, 0xff, ..]
            | [b'I', b'I', 42, 0, ..]
            | [b'M', b'M', ..]
            | [0, 0, 0, 12, b'j', b'P', 32, 32, 13, 10, 0x87, 10, ..] => Graphics,
            _ if bytes.starts_with(b"From ")
                || bytes.starts_with(b"Received: ")
                || bytes.starts_with(b"From: ") =>
            {
                Mail
            }
            _ => Generic,
        };
        Self::typed(target, bytes)
    }

    /// Use the type supplied by the caller that produced this object's bytes.
    pub fn typed(target: Target, bytes: &[u8]) -> Self {
        let exe = match target {
            Target::Pe => executable::pe(bytes),
            Target::Elf => executable::elf(bytes),
            Target::MachO => executable::macho(bytes),
            _ => None,
        };
        Self { target, exe }
    }

    pub fn target(&self) -> Target {
        self.target
    }

    pub fn is_valid_pe(&self) -> bool {
        self.target == Target::Pe && self.exe.is_some()
    }

    pub(crate) fn has_executable_layout(&self) -> bool {
        self.exe.is_some()
    }

    pub(crate) fn pe_overlay(&self) -> Option<usize> {
        self.exe.as_ref()?.pe_overlay
    }

    pub fn accepts(&self, target: Target) -> bool {
        target == Target::Generic || target == self.target
    }

    /// Inclusive range of eligible pattern starts, clipped to the object.
    pub fn offset_range(&self, offset: &Offset, size: usize) -> Option<RangeInclusive<usize>> {
        let n = offset.displacement as usize;
        let mut shift = offset.shift as usize;
        let exe = self.exe.as_ref();
        let start = match offset.base {
            Base::Any => return Some(0..=size),
            Base::Absolute => n,
            Base::End if self.target.executable() && exe.is_none() => return None,
            Base::End => size.checked_sub(n)?,
            Base::EntryPlus => exe?.entry.checked_add(n)?,
            Base::EntryMinus => exe?.entry.checked_sub(n)?,
            Base::LastSection => exe?.sections.last()?.raw.checked_add(n)?,
            Base::Section(i) => exe?.sections.get(i as usize)?.raw.checked_add(n)?,
            Base::EntireSection(i) => {
                let sec = exe?.sections.get(i as usize)?;
                // cli_caloff includes raw + raw_size + MaxShift as the last start.
                shift = shift.checked_add(sec.size)?;
                sec.raw
            }
        };
        (start <= size).then(|| start..=start.saturating_add(shift).min(size))
    }
}
