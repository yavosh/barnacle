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
    pub(super) last_pe_section: Option<u16>,
    pub(super) multiple_pe_sections: bool,
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
    read_pe(bytes, |_, _, _, _| Some(())).map(|(executable, _)| executable)
}

struct PeHeaders {
    size: usize,
    entry_rva: u32,
    offset: u32,
    optional_size: u16,
    optional_magic: u16,
}

pub(crate) struct PeMetadata {
    sections: Vec<[u32; 9]>,
    entry: u32,
    pub(crate) base_of_data: Option<u32>,
    pub(crate) resource_rva: u32,
    pub(crate) resource_size: u32,
    headers: PeHeaders,
    file_size: usize,
}

impl PeMetadata {
    pub(crate) fn entry(&self) -> u32 {
        self.entry
    }

    pub(crate) fn entry_rva(&self) -> u32 {
        self.headers.entry_rva
    }

    pub(crate) fn header_offset(&self) -> u32 {
        self.headers.offset
    }

    pub(crate) fn optional_size(&self) -> u16 {
        self.headers.optional_size
    }

    pub(crate) fn optional_magic(&self) -> u16 {
        self.headers.optional_magic
    }

    pub(crate) fn section_count(&self) -> u16 {
        self.sections.len() as u16
    }

    pub(crate) fn section(&self, index: usize) -> Option<[u32; 9]> {
        self.sections.get(index).copied()
    }

    pub(crate) fn raw_offset(&self, rva: u32) -> Option<u32> {
        if (rva as usize) < self.headers.size {
            return ((rva as usize) < self.file_size).then_some(rva);
        }
        self.sections
            .iter()
            .rev()
            .find_map(|&[base, _, raw, size, ..]| {
                let delta = rva.checked_sub(base)?;
                if delta >= size {
                    return None;
                }
                raw.checked_add(delta)
            })
    }
}

pub(crate) fn pe_metadata(bytes: &[u8]) -> Option<PeMetadata> {
    let mut sections = Vec::new();
    let (executable, headers) = read_pe(bytes, |header, salign, rva, mapped| {
        let e = Endian::Little;
        let urva = e.u32(header, 12)?;
        let uvsz = e.u32(header, 8)?;
        let uraw = e.u32(header, 20)?;
        let ursz = e.u32(header, 16)?.min(bytes.len().saturating_sub(uraw));
        let vsz = up(
            if uvsz == 0 && mapped.size != 0 {
                ursz
            } else {
                uvsz
            },
            salign,
        )?;
        // The host record stores aligned fields before the original header fields.
        let fields = [
            rva,
            vsz,
            mapped.raw,
            mapped.size,
            e.u32(header, 36)?,
            urva,
            uvsz,
            uraw,
            ursz,
        ];
        let mut section = [0; 9];
        for (output, field) in section.iter_mut().zip(fields) {
            *output = u32::try_from(field).ok()?;
        }
        sections.push(section);
        Some(())
    })?;
    // The PE32+ header places ImageBase where PE32 stores BaseOfData.
    let base_of_data = if headers.optional_magic == 0x10b {
        let header = bytes.get(headers.offset as usize..)?;
        Some(Endian::Little.u32(header, 24 + 24)? as u32)
    } else {
        None
    };
    let header = bytes.get(headers.offset as usize..)?;
    let optional = header
        .get(24..)?
        .get(..usize::from(headers.optional_size))?;
    let standard = if headers.optional_magic == 0x10b {
        96
    } else {
        112
    };
    let (resource_rva, resource_size) = if Endian::Little.u32(optional, standard - 4)? > 2 {
        (
            Endian::Little.u32(optional, standard + 16)? as u32,
            Endian::Little.u32(optional, standard + 20)? as u32,
        )
    } else {
        (0, 0)
    };
    Some(PeMetadata {
        sections,
        base_of_data,
        resource_rva,
        resource_size,
        entry: u32::try_from(executable.entry).ok()?,
        headers,
        file_size: bytes.len(),
    })
}

fn read_pe(
    bytes: &[u8],
    mut record: impl FnMut(&[u8; 40], usize, usize, &Section) -> Option<()>,
) -> Option<(Executable, PeHeaders)> {
    let e = Endian::Little;
    if !bytes.starts_with(b"MZ") {
        return None;
    }
    let offset = e.u32(bytes, 60)?;
    let header = bytes.get(offset..)?;
    if !header.starts_with(b"PE\0\0") {
        return None;
    }
    let count = e.u16(header, 6)?;
    if count == 0 {
        return None;
    }
    let opt_size = e.u16(header, 20)?;
    let (opt, table) = header.get(24..)?.split_at_checked(opt_size)?;
    let optional_magic = e.u16(opt, 0)?;
    let standard = match optional_magic {
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
    let mut last_pe_section = None;
    let mut multiple_pe_sections = false;
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
        // The PE scanner removes on-disk sections starting past EOF. Its raw matcher retains them.
        if size != 0 || declared == 0 {
            multiple_pe_sections = last_pe_section.is_some();
            last_pe_section = Some(result.len() as u16);
        }
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
        let section = Section { raw, size };
        record(h, salign, aligned_rva, &section)?;
        result.push(section);
    }

    let raw_entry = if entry < header_bytes {
        (entry < bytes.len()).then_some(entry)?
    } else {
        mapped_entry?
    };
    Some((
        Executable {
            entry: raw_entry,
            sections: result,
            pe_overlay,
            last_pe_section,
            multiple_pe_sections,
        },
        PeHeaders {
            size: header_bytes,
            entry_rva: entry as u32,
            offset: offset as u32,
            optional_size: opt_size as u16,
            optional_magic: optional_magic as u16,
        },
    ))
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
        last_pe_section: None,
        multiple_pe_sections: false,
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
        last_pe_section: None,
        multiple_pe_sections: false,
    })
}
