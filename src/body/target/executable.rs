//! File offsets used by the pinned PE, ELF and thin Mach-O matchers.
#[derive(Clone, Debug)]
pub(super) struct Section {
    pub(super) raw: usize,
    pub(super) size: usize,
}

#[derive(Clone, Debug)]
pub(super) struct Executable {
    pub(super) entry: usize,
    pub(super) sections: Vec<Section>,
    pub(super) pe_overlay: Option<usize>,
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, bytes: &[u8], offset: usize) -> Option<usize> {
        let v = bytes.get(offset..)?.first_chunk::<2>()?;
        Some(match self {
            Self::Little => u16::from_le_bytes(*v),
            Self::Big => u16::from_be_bytes(*v),
        } as usize)
    }

    fn u32(self, bytes: &[u8], offset: usize) -> Option<usize> {
        let v = bytes.get(offset..)?.first_chunk::<4>()?;
        Some(match self {
            Self::Little => u32::from_le_bytes(*v),
            Self::Big => u32::from_be_bytes(*v),
        } as usize)
    }

    fn word(self, bytes: &[u8], offset: usize, wide: bool) -> Option<usize> {
        if !wide {
            return self.u32(bytes, offset);
        }
        let v = bytes.get(offset..)?.first_chunk::<8>()?;
        usize::try_from(match self {
            Self::Little => u64::from_le_bytes(*v),
            Self::Big => u64::from_be_bytes(*v),
        })
        .ok()
    }
}

fn down(n: usize, align: usize) -> usize {
    n - n.checked_rem(align).unwrap_or(0)
}

fn up(n: usize, align: usize) -> Option<usize> {
    match n.checked_rem(align) {
        None | Some(0) => Some(n),
        Some(remainder) => n.checked_add(align - remainder),
    }
}

pub(super) fn pe(bytes: &[u8]) -> Option<Executable> {
    let e = Endian::Little;
    if !bytes.starts_with(b"MZ") {
        return None;
    }
    let header = bytes.get(e.u32(bytes, 60)?..)?;
    if !header.starts_with(b"PE\0\0") {
        return None;
    }
    let count = e.u16(header, 6)?;
    if count == 0 {
        return None;
    }
    let opt_size = e.u16(header, 20)?;
    let (opt, table) = header.get(24..)?.split_at_checked(opt_size)?;
    let standard = match e.u16(opt, 0)? {
        0x10b => 96,
        0x20b => 112,
        _ => return None,
    };
    let dirs = e.u32(opt, standard - 4)?.min(16);
    opt.get(..standard + 8 * dirs)?;
    let sections = table.get(..count * 40)?.as_chunks::<40>().0;
    let entry = e.u32(opt, 16)?;
    let salign = e.u32(opt, 32)?;
    let header_bytes = up(e.u32(opt, 60)?, salign)?;
    let mut falign = e.u32(opt, 36)?;
    if falign != 0 && falign != 512 {
        for h in sections {
            let raw = e.u32(h, 20)?;
            if e.u32(h, 16)? != 0 && !raw.is_multiple_of(falign) && raw.is_multiple_of(512) {
                falign = 512;
                break;
            }
        }
    }

    let mut result = Vec::with_capacity(count);
    let mut mapped_entry = None;
    let mut high_rva = 0;
    let mut pe_overlay = None;
    for h in sections {
        let rva = e.u32(h, 12)?;
        let pointer = e.u32(h, 20)?;
        let declared = e.u32(h, 16)?;
        let raw = down(pointer, falign);
        let size = if pointer >= bytes.len() {
            0
        } else {
            up(declared, falign)?.min(bytes.len() - raw)
        };
        if rva > i32::MAX as usize
            || e.u32(h, 8)? > i32::MAX as usize
            || (size != 0 && (pointer > i32::MAX as usize || declared > i32::MAX as usize))
        {
            return None;
        }
        let aligned_rva = down(rva, salign);
        // The first section initializes the reference extent. Only a later section can start an overlay.
        let end = aligned_rva.checked_add(size)?;
        if result.is_empty() || end > high_rva {
            high_rva = end;
            if !result.is_empty() {
                pe_overlay = raw
                    .checked_add(size)
                    .filter(|&offset| offset != 0 && offset < bytes.len());
            }
        }
        if let Some(delta) = entry.checked_sub(aligned_rva)
            && delta < size
        {
            // The reference selects the last section containing the entry point.
            mapped_entry = Some(raw + delta);
        }
        result.push(Section { raw, size });
    }

    let entry = if entry < header_bytes {
        (entry < bytes.len()).then_some(entry)?
    } else {
        mapped_entry?
    };
    Some(Executable {
        entry,
        sections: result,
        pe_overlay,
    })
}

pub(super) fn elf(bytes: &[u8]) -> Option<Executable> {
    if !bytes.starts_with(b"\x7fELF") {
        return None;
    }
    let wide = match bytes.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let e = match bytes.get(5)? {
        1 => Endian::Little,
        2 => Endian::Big,
        _ => return None,
    };
    let header_size = if wide { 64 } else { 52 };
    let h = bytes.get(..header_size)?;
    let entry = e.word(h, 24, wide)?;
    let phnum = e.u16(h, header_size - 8)?;
    if phnum > 128 {
        return None;
    }
    let entry = if phnum == 0 || entry == 0 {
        0
    } else {
        let stride = if wide { 56 } else { 32 };
        if e.u16(h, header_size - 10)? != stride {
            return None;
        }
        let phoff = e.word(h, if wide { 32 } else { 28 }, wide)?;
        let headers = bytes.get(phoff..)?.get(..phnum * stride)?;
        headers.chunks_exact(stride).find_map(|ph| {
            let va = e.word(ph, if wide { 16 } else { 8 }, wide)?;
            let delta = entry.checked_sub(va)?;
            let size = e.word(ph, if wide { 40 } else { 20 }, wide)?;
            if delta >= size {
                return None;
            }
            e.word(ph, if wide { 8 } else { 4 }, wide)?
                .checked_add(delta)
        })?
    };

    let count = e.u16(h, header_size - 4)?;
    let stride = if wide { 64 } else { 40 };
    if count > 256 || e.u16(h, header_size - 6)? != stride {
        return None;
    }
    let mut sections = Vec::with_capacity(count);
    if count != 0 {
        let shoff = e.word(h, if wide { 40 } else { 32 }, wide)?;
        let table = bytes.get(shoff..)?.get(..count * stride)?;
        for s in table.chunks_exact(stride) {
            sections.push(Section {
                raw: e.word(s, if wide { 24 } else { 16 }, wide)? as u32 as usize,
                size: e.word(s, if wide { 32 } else { 20 }, wide)? as u32 as usize,
            });
        }
    }
    Some(Executable {
        entry: entry as u32 as usize,
        sections,
        pe_overlay: None,
    })
}

pub(super) fn macho(bytes: &[u8]) -> Option<Executable> {
    let (e, wide) = match bytes.first_chunk::<4>()? {
        [0xce, 0xfa, 0xed, 0xfe] => (Endian::Little, false),
        [0xcf, 0xfa, 0xed, 0xfe] => (Endian::Little, true),
        [0xfe, 0xed, 0xfa, 0xce] => (Endian::Big, false),
        [0xfe, 0xed, 0xfa, 0xcf] => (Endian::Big, true),
        _ => return None,
    };
    let cpu = e.u32(bytes, 4)?;
    let count = e.u32(bytes, 16)?;
    if !(1..=1024).contains(&count) {
        return None;
    }
    let mut next = bytes.get(if wide { 32 } else { 28 }..)?;
    let mut sections = Vec::new();
    let ppc = matches!(cpu, 18 | 0x0100_0012);
    let mut ppc_addresses = Vec::new();
    let mut entry = 0;
    for _ in 0..count {
        let op = e.u32(next, 0)?;
        let size = e.u32(next, 4)?;
        if size < 8 {
            return None;
        }
        let (cmd, tail) = next.split_at_checked(size)?;
        next = tail;
        if op == if wide { 0x19 } else { 1 } {
            let base = if wide { 72 } else { 56 };
            let stride = if wide { 80 } else { 68 };
            let n = e.u32(cmd, base - 8)?;
            if n > 255 {
                return None;
            }
            let table = cmd.get(base..)?.get(..n * stride)?;
            for s in table.chunks_exact(stride) {
                let address = e.word(s, 32, wide)?;
                let sz = e.word(s, if wide { 40 } else { 36 }, wide)?;
                let file_field = if wide { 48 } else { 40 };
                let raw = e.u32(s, file_field)?;
                let power = e.u32(s, file_field + 4)?;
                if power >= 32 {
                    return None;
                }
                // Stock stores Mach-O section addresses and lengths as 32-bit values.
                if ppc {
                    ppc_addresses.push((address as u32 as usize, sz as u32 as usize));
                }
                sections.push(Section {
                    raw,
                    size: up(sz as u32 as usize, 1usize << power)?,
                });
            }
        } else if matches!(op, 4 | 5) && ppc {
            // The reference only extracts a nonzero PC from PowerPC thread commands.
            cmd.get(..if cpu == 18 { 176 } else { 328 })?;
            entry = e.word(cmd, 16, cpu != 18)? as u32 as usize;
        }
    }
    if entry != 0 && !sections.is_empty() {
        entry = ppc_addresses
            .iter()
            .zip(&sections)
            .find_map(|(&(address, length), s)| {
                let delta = entry.checked_sub(address)?;
                (delta < length).then(|| s.raw.checked_add(delta)).flatten()
            })?;
    }
    Some(Executable {
        entry,
        sections,
        pe_overlay: None,
    })
}
