use super::udf;
use super::{
    ChildSink, Handling, HookControl, InputKind, Options, archive, iso, office, ole, onenote,
    partition, pdf, rtf, swf, text, xml,
};
use crate::body::{HandlerType, ObjectContext, Target};
use std::io;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Parser {
    Archive,
    Zip,
    AutoIt,
    Rtf,
    Mail,
    Tnef,
    Uuencoded,
    Html { big_endian: bool },
    Utf16Html,
    Pdf,
    Ole2,
    HwpOle2,
    Hwp3,
    Swf,
    OneNote,
    Image,
    Raw,
    Iso(iso::Layout),
    Udf,
    Partition,
    HfsPlus,
    UniversalMachO,
    ThinMachO,
    Pe,
    Elf { has_layout: bool },
    PartitionMap(&'static str),
    Xml(xml::Format),
    Xdp,
    Text,
    Script,
    None,
}

pub(super) struct FileType {
    pub name: &'static str,
    pub context: ObjectContext,
    pub parser: Parser,
}

// The pinned default file types omit these media and database formats from raw scans.
pub(super) fn ignored(bytes: &[u8]) -> bool {
    bytes.starts_with(b"ID3")
        || bytes.starts_with(b"OggS")
        || bytes.starts_with(b"SQLite format 3\0")
        || bytes.starts_with(b".RMF")
}

impl FileType {
    pub fn before_raw(
        &self,
        bytes: &[u8],
        options: &Options,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Handling> {
        if options.heuristic_alerts
            && matches!(self.name, "CL_TYPE_BINARY_DATA" | "CL_TYPE_TEXT_UTF16BE")
            && mydoom_log(bytes)
            && sink.report_heuristic("Heuristics.Worm.Mydoom.M.log")
        {
            return Ok(Handling::Stopped);
        }
        self.parser.before_raw(bytes, options, sink)
    }

    pub fn classify(bytes: &[u8], kind: InputKind, sink: &mut dyn ChildSink) -> io::Result<Self> {
        match kind {
            InputKind::Normalized(target) => return Ok(Self::typed(bytes, target, Parser::None)),
            InputKind::Handler(handler) => {
                return Ok(match handler {
                    HandlerType::Graphics => Self {
                        name: "CL_TYPE_GRAPHICS",
                        context: ObjectContext::typed(Target::Graphics, bytes),
                        parser: Parser::Image,
                    },
                    HandlerType::Pdf => Self::typed(bytes, Target::Pdf, Parser::Pdf),
                    HandlerType::Script => Self::generic(bytes, "CL_TYPE_SCRIPT", Parser::Script),
                    HandlerType::Zip => Self::generic(bytes, "CL_TYPE_ZIP", Parser::Zip),
                });
            }
            InputKind::Partition => {
                let (name, parser) = match bytes.get(1024..1028) {
                    Some(b"H+\x00\x04" | b"HX\x00\x05") => {
                        ("CL_TYPE_PART_HFSPLUS", Parser::HfsPlus)
                    }
                    _ => ("CL_TYPE_PART_ANY", Parser::Partition),
                };
                return Ok(Self::generic(bytes, name, parser));
            }
            InputKind::File | InputKind::MailboxLetter => {}
        }
        if let Some(name) = partition::initial(bytes) {
            return Ok(Self::generic(bytes, name, Parser::PartitionMap(name)));
        }
        if bytes.starts_with(b"RIFF") || bytes.starts_with(b"RIFX") {
            // Stock has an additional pre-match pass for animated cursors.
            let parser = if bytes.get(8..12) == Some(b"ACON") {
                Parser::None
            } else {
                Parser::Raw
            };
            return Ok(Self::generic(bytes, "CL_TYPE_RIFF", parser));
        }
        if let Some(layout) = iso::Layout::recognize(bytes) {
            return Ok(Self::generic(
                bytes,
                text::file_type(bytes),
                Parser::Iso(layout),
            ));
        }
        if bytes.get(4..12) == Some(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
            return Ok(Self::generic(bytes, "CL_TYPE_HWPOLE2", Parser::HwpOle2));
        }
        if bytes.starts_with(b"HWP Document File V3.00 \x1a\x01\x02\x03\x04\x05") {
            return Ok(Self::generic(bytes, "CL_TYPE_HWP3", Parser::Hwp3));
        }
        if onenote::recognizes(bytes) {
            return Ok(Self::generic(bytes, "CL_TYPE_ONENOTE", Parser::OneNote));
        }
        if super::autoit::recognized(bytes) {
            return Ok(Self::generic(bytes, "CL_TYPE_AUTOIT", Parser::AutoIt));
        }
        if let Some(mut name) = archive::file_type(bytes) {
            if name == "CL_TYPE_ZIP" {
                name = office::classify(bytes, sink)?;
            }
            return Ok(Self::generic(bytes, name, Parser::Archive));
        }
        if bytes.starts_with(b"[aliases]") && text::file_type(bytes) == "CL_TYPE_TEXT_ASCII" {
            // The pinned engine retains the POSIX TAR type for this legacy text header.
            return Ok(Self::generic(bytes, "CL_TYPE_POSIX_TAR", Parser::Raw));
        }
        if bytes.starts_with(b"{\\rt") {
            return Ok(Self::generic(bytes, "CL_TYPE_RTF", Parser::Rtf));
        }
        if let Some(name) = text::container_type(bytes) {
            let parser = if name == "CL_TYPE_TNEF" {
                Parser::Tnef
            } else {
                Parser::Uuencoded
            };
            return Ok(Self::generic(bytes, name, parser));
        }
        let context = ObjectContext::raw(bytes);
        if context.target() == Target::MachO && super::macho::recognized(bytes) {
            return Ok(Self {
                name: "CL_TYPE_MACHO_UNIBIN",
                context,
                parser: Parser::UniversalMachO,
            });
        }
        if matches!(context.target(), Target::Generic | Target::Mail) {
            if pdf::header_type(bytes) {
                return Ok(Self::typed(bytes, Target::Pdf, Parser::Pdf));
            }
            if super::xdp::recognizes(bytes) {
                return Ok(Self::generic(bytes, "CL_TYPE_XDP", Parser::Xdp));
            }
            if let Some(format) = xml::Format::recognize(bytes) {
                return Ok(Self::generic(bytes, format.name(), Parser::Xml(format)));
            }
            match text::parser(bytes) {
                Some(Parser::Utf16Html) => {
                    return Ok(Self::generic(
                        bytes,
                        "CL_TYPE_HTML_UTF16",
                        Parser::Utf16Html,
                    ));
                }
                Some(html @ Parser::Html { .. }) => {
                    return Ok(Self::typed(bytes, Target::Html, html));
                }
                Some(Parser::Mail) => return Ok(Self::typed(bytes, Target::Mail, Parser::Mail)),
                _ => {}
            }
        }
        let name = Self::name(context.target(), bytes);
        let parser = match context.target() {
            Target::Generic if name == "CL_TYPE_BINARY_DATA" && udf::recognized(bytes) => {
                Parser::Udf
            }
            Target::Pdf => Parser::Pdf,
            Target::Pe if context.is_valid_pe() => Parser::Pe,
            Target::MachO if context.has_executable_layout() => Parser::ThinMachO,
            Target::Elf => Parser::Elf {
                has_layout: context.has_executable_layout(),
            },
            Target::Ole2 => Parser::Ole2,
            Target::Flash => Parser::Swf,
            Target::Graphics => Parser::Image,
            Target::Java => Parser::Raw,
            Target::Generic if name.starts_with("CL_TYPE_TEXT_") => Parser::Text,
            _ => Parser::None,
        };
        Ok(Self {
            name,
            context,
            parser,
        })
    }

    fn generic(bytes: &[u8], name: &'static str, parser: Parser) -> Self {
        Self {
            name,
            context: ObjectContext::typed(Target::Generic, bytes),
            parser,
        }
    }

    fn typed(bytes: &[u8], target: Target, parser: Parser) -> Self {
        Self {
            name: Self::name(target, bytes),
            context: ObjectContext::typed(target, bytes),
            parser,
        }
    }

    fn name(target: Target, bytes: &[u8]) -> &'static str {
        match target {
            Target::Html => "CL_TYPE_HTML",
            Target::Mail => "CL_TYPE_MAIL",
            Target::Pe => "CL_TYPE_MSEXE",
            Target::Elf => "CL_TYPE_ELF",
            Target::MachO => "CL_TYPE_MACHO",
            Target::Java => "CL_TYPE_JAVA",
            Target::Ole2 => "CL_TYPE_MSOLE2",
            Target::Flash => "CL_TYPE_SWF",
            Target::Graphics => match bytes {
                [0x89, b'P', b'N', b'G', ..] => "CL_TYPE_PNG",
                [b'G', b'I', b'F', ..] => "CL_TYPE_GIF",
                [0xff, 0xd8, 0xff, ..] => "CL_TYPE_JPEG",
                [b'I', b'I', 42, 0, ..] | [b'M', b'M', ..] => "CL_TYPE_TIFF",
                _ => "CL_TYPE_GRAPHICS",
            },
            Target::Pdf => "CL_TYPE_PDF",
            Target::Ascii => "CL_TYPE_TEXT_ASCII",
            Target::Generic => text::file_type(bytes),
            _ => "CL_TYPE_ANY",
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Disk {
    Iso(iso::Layout),
    Udf,
    Dmg,
    PartitionMap(&'static str),
}

impl Disk {
    pub fn name(self) -> &'static str {
        match self {
            Self::Iso(_) => "CL_TYPE_ISO9660",
            Self::Udf => "CL_TYPE_UDF",
            Self::Dmg => "CL_TYPE_DMG",
            Self::PartitionMap(name) => name,
        }
    }

    pub fn extract(self, bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
        match self {
            Self::Iso(layout) => iso::extract(bytes, layout, sink),
            Self::Udf => udf::extract(bytes, sink),
            Self::Dmg => super::dmg::extract(bytes, sink),
            Self::PartitionMap(name) => partition::extract(name, bytes, sink),
        }
    }
}

fn mydoom_log(bytes: &[u8]) -> bool {
    let Some(records) = bytes.get(..64) else {
        return false;
    };
    // The reference screens up to five leading words as the file grows.
    let screened = (bytes.len() / 32).min(5);
    let (words, _) = records.as_chunks::<4>();
    if words[..screened].contains(&[0xff; 4]) {
        return false;
    }
    words.as_chunks::<8>().0.iter().all(|record| {
        let header = u32::from_be_bytes(record[0]);
        let sum = record[1..].iter().fold(0u32, |sum, &word| {
            sum.wrapping_add(u32::from_be_bytes(word) ^ !header)
        });
        sum == header
    })
}

impl Parser {
    pub fn disk_descriptor(self) -> Option<(usize, Disk)> {
        match self {
            Self::Iso(layout) => Some((layout.descriptor_offset(), Disk::Iso(layout))),
            Self::Udf => Some((udf::RECOGNITION, Disk::Udf)),
            _ => None,
        }
    }

    fn before_raw(
        self,
        bytes: &[u8],
        options: &Options,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Handling> {
        match self {
            Self::AutoIt if options.scan_archive => super::autoit::extract(bytes, sink),
            Self::Archive if options.scan_archive => archive::extract(bytes, sink),
            Self::Zip if options.scan_archive => archive::zip_extract(bytes, sink),
            Self::UniversalMachO => super::macho::extract(bytes, sink),
            Self::Elf { has_layout: false } if options.scan_elf => Ok(Handling::Incomplete),
            Self::HfsPlus if options.scan_archive => super::hfs::extract(bytes, sink),
            Self::PartitionMap(name) if options.scan_archive => {
                partition::extract(name, bytes, sink)
            }
            Self::Xml(format) if options.scan_xml_docs => format.extract(bytes, sink),
            Self::Xdp if options.scan_pdf => super::xdp::extract(bytes, sink),
            Self::Rtf if options.scan_archive => rtf::extract(bytes, sink),
            Self::Ole2 if options.scan_ole2 => ole::extract(bytes, sink),
            Self::HwpOle2 if options.scan_ole2 => ole::wrapped(bytes, sink),
            Self::Hwp3 if options.scan_hwp3 => {
                super::hwp3::extract(bytes, options.max_rec_hwp3, sink)
            }
            Self::Swf if options.scan_swf => swf::extract(bytes, sink),
            Self::OneNote if options.scan_onenote => onenote::extract(bytes, sink),
            // A broken-media check can precede the raw winner. The default
            // profile only computes image metadata for the logical matcher.
            Self::Image if options.scan_image && options.alert_broken_media => {
                Ok(Handling::Incomplete)
            }
            Self::Mail | Self::Tnef if options.scan_mail => text::before_raw(self, bytes, sink),
            Self::Html { .. } | Self::Utf16Html if options.scan_html => {
                text::before_raw(self, bytes, sink)
            }
            Self::Uuencoded => text::before_raw(self, bytes, sink),
            Self::Script if options.scan_normalized_script => text::script(bytes, sink),
            // These formats use the ordinary raw matcher after any enabled parser.
            Self::Archive
            | Self::Zip
            | Self::Script
            | Self::AutoIt
            | Self::ThinMachO
            | Self::Pe
            | Self::Elf { .. }
            | Self::Rtf
            | Self::Ole2
            | Self::HwpOle2
            | Self::Hwp3
            | Self::Swf
            | Self::OneNote
            | Self::Image
            | Self::Raw
            | Self::Iso(_)
            | Self::Udf
            | Self::Partition
            | Self::PartitionMap(_)
            | Self::Xml(_)
            | Self::Xdp
            | Self::HfsPlus
            | Self::Mail
            | Self::Tnef
            | Self::Html { .. }
            | Self::Utf16Html
            | Self::Pdf => Ok(Handling::Complete),
            Self::Text | Self::None => Ok(Handling::Unrecognized),
        }
    }
}

impl FileType {
    pub fn after_raw(
        &self,
        bytes: &[u8],
        options: &Options,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Handling> {
        match self.parser {
            Parser::Pe if options.scan_pe => {
                let Some(header) = pe32_header(bytes) else {
                    return Ok(Handling::Unrecognized);
                };
                let earlier = match self.context.pe_overlay() {
                    Some(start) => super::installer::legacy(&bytes[start..], sink)?,
                    None => Handling::Unrecognized,
                };
                if matches!(earlier, Handling::Incomplete | Handling::Stopped) {
                    return Ok(earlier);
                }
                match sink.run_pe_all_hooks(bytes)? {
                    HookControl::Found => return Ok(Handling::Stopped),
                    HookControl::Break => return Ok(Handling::Complete),
                    HookControl::Continue => (),
                }
                if options.heuristic_alerts
                    && u16::from_le_bytes([header[22], header[23]]) & 0x2000 == 0
                {
                    let parite = self
                        .context
                        .last_section_entry()
                        .filter(|&ep| parite(&bytes[ep..]))
                        .map(|_| "Heuristics.W32.Parite.B");
                    let magistr = || {
                        self.context
                            .last_pe_section()
                            .and_then(|section| magistr(bytes, header, section))
                    };
                    // Immediate reporting takes the first PE alert. Use a stable order when deferring both.
                    let name = if options.heuristic_scan_precedence {
                        parite.or_else(magistr)
                    } else {
                        magistr().or(parite)
                    };
                    if name.is_some_and(|name| sink.report_heuristic(name)) {
                        return Ok(Handling::Stopped);
                    }
                }
                match super::upx::extract(bytes, sink)? {
                    Handling::Unrecognized => Ok(earlier),
                    unpacked => Ok(unpacked),
                }
            }
            Parser::Pdf if options.scan_pdf => pdf::extract(bytes, options, sink),
            Parser::Text if options.scan_html && options.scan_normalized_script => {
                text::after_raw(bytes, sink)
            }
            _ => Ok(Handling::Unrecognized),
        }
    }
}

fn pe32_header(bytes: &[u8]) -> Option<&[u8]> {
    let pointer = bytes.get(0x3c..)?.first_chunk::<4>()?;
    let header = bytes.get(u32::from_le_bytes(*pointer) as usize..)?;
    (header.get(24..26)? == [0x0b, 0x01]).then_some(header)
}

fn magistr(
    bytes: &[u8],
    header: &[u8],
    (index, raw, size): (usize, usize, usize),
) -> Option<&'static str> {
    let table = 24 + usize::from(u16::from_le_bytes([header[20], header[21]]));
    let section = header.get(table + 40 * index..)?.first_chunk::<40>()?;
    let (words, _) = section.as_chunks::<4>();
    if u32::from_le_bytes(words[9]) & 0x80000000 == 0 {
        return None;
    }
    let original_raw = u32::from_le_bytes(words[5]) as usize;
    let original_size =
        (u32::from_le_bytes(words[4]) as usize).min(bytes.len().saturating_sub(original_raw));
    let virtual_size = u32::from_le_bytes(words[2]) as usize;
    magistr_record(bytes.get(raw..)?, virtual_size, size, original_size)
}

fn magistr_record(
    data: &[u8],
    virtual_size: usize,
    mapped_size: usize,
    original_size: usize,
) -> Option<&'static str> {
    let size = mapped_size.max(original_size);
    let damaged = mapped_size < original_size;
    let (tail, label, name) = match virtual_size & 0xff {
        0xec if virtual_size >= 0x612c && size >= 0x612c => (
            0x7000,
            b"\xe8\x2c\x61\0\0",
            if damaged {
                "Heuristics.W32.Magistr.A.dam"
            } else {
                "Heuristics.W32.Magistr.A"
            },
        ),
        0xed if virtual_size >= 0x7000 && size >= 0x7000 => (
            0x8000,
            b"\xe8\x04\x72\0\0",
            if damaged {
                "Heuristics.W32.Magistr.B.dam"
            } else {
                "Heuristics.W32.Magistr.B"
            },
        ),
        _ => return None,
    };
    let window = data
        .get(size.saturating_sub(tail)..)?
        .first_chunk::<4096>()?;
    memchr::memmem::find(&window[..4091], label).map(|_| name)
}

fn parite(entry: &[u8]) -> bool {
    const LABEL: &[u8] = b"GetProcAddress\0";
    let Some(window) = entry.first_chunk::<4096>() else {
        return false;
    };
    let Some(label) = memchr::memmem::find(&window[..4040], LABEL) else {
        return false;
    };
    // The first label selects the three pairs of little-endian words.
    let start = label + LABEL.len();
    let (words, _) = window[start..start + 24].as_chunks::<4>();
    let (pairs, _) = words.as_chunks::<2>();
    pairs
        .iter()
        .zip([0x505a4f, 0xffffb, 0xb8])
        .all(|(&[left, right], difference)| {
            u32::from_le_bytes(left) ^ u32::from_le_bytes(right) == difference
        })
}

#[cfg(test)]
mod tests {
    use super::magistr_record;

    #[test]
    fn magistr_damaged_names_use_the_larger_original_size() {
        let mut data = vec![0; 0x9000];
        for (virtual_size, start, word, expected) in [
            (0x61ec, 0x2000, 0x612cu32, "Heuristics.W32.Magistr.A.dam"),
            (0x70ed, 0x1000, 0x7204, "Heuristics.W32.Magistr.B.dam"),
        ] {
            data.fill(0);
            data[start] = 232;
            data[start + 1..start + 5].copy_from_slice(&word.to_le_bytes());
            assert_eq!(
                magistr_record(&data, virtual_size, 4096, data.len()),
                Some(expected)
            );
        }
    }
}
