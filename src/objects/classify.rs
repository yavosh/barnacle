use super::udf;
use super::{
    ChildSink, Handling, InputKind, Options, archive, iso, office, ole, onenote, partition, pdf,
    rtf, swf, text, xml,
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
    Pe { overlay: Option<usize> },
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
            Target::Pe if context.is_valid_pe() => Parser::Pe {
                overlay: context.pe_overlay(),
            },
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
            | Self::Pe { .. }
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

    pub fn after_raw(
        self,
        bytes: &[u8],
        options: &Options,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Handling> {
        match self {
            Self::Pe { overlay } if options.scan_pe => {
                let earlier = match overlay {
                    Some(start) => super::installer::legacy(&bytes[start..], sink)?,
                    None => Handling::Unrecognized,
                };
                if matches!(earlier, Handling::Incomplete | Handling::Stopped) {
                    return Ok(earlier);
                }
                match sink.run_pe_all_hooks(bytes)? {
                    Handling::Unrecognized => Ok(earlier),
                    result => Ok(result),
                }
            }
            Self::Pdf if options.scan_pdf => pdf::extract(bytes, options, sink),
            Self::Text if options.scan_html && options.scan_normalized_script => {
                text::after_raw(bytes, sink)
            }
            _ => Ok(Handling::Unrecognized),
        }
    }
}

pub(super) fn pe32_optional_header(bytes: &[u8]) -> bool {
    let Some(pointer) = bytes.get(0x3c..).and_then(<[u8]>::first_chunk::<4>) else {
        return false;
    };
    (u32::from_le_bytes(*pointer) as usize)
        .checked_add(24)
        .and_then(|offset| bytes.get(offset..))
        .is_some_and(|optional| optional.starts_with(b"\x0b\x01"))
}
