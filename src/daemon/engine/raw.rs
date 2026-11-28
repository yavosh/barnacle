//! Conservative admission to the pinned engine's raw whole-file match stage.
//! ClamAV 1.4.3 runs format parsers before that stage and skips some types entirely.
//! These guards deliberately accept fewer files than the built-in filetypes_int.h.
//! External type definitions are never used with this path.

/// This is CL_FILE_MBUFF_SIZE in the pinned engine's filetypes.h.
pub(super) const HEADER_SIZE: usize = 1024;

pub(super) fn eligible(header: &[u8], file_type: &str) -> bool {
    if header.len() <= 5 {
        return false;
    }
    // Guard fixed-offset-zero built-in types. Most use a leading pair here. Python
    // bytecode uses CR LF at bytes 2 and 3 instead. Include BOMs for encoded text.
    const PREFIXES: &[&[u8; 2]] = &[
        b"\x1f\x8b",
        b"#@",
        b"%!",
        b"%P",
        b"(T",
        b".R",
        b"07",
        b"7z",
        b"7\x7f",
        b">F",
        b"AL",
        b"BM",
        b"BZ",
        b"CW",
        b"Da",
        b"EG",
        b"En",
        b"ER",
        b"FW",
        b"Fo",
        b"Fr",
        b"GI",
        b"Hi",
        b"ID",
        b"II",
        b"IT",
        b"L\0",
        b"MM",
        b"MS",
        b"MZ",
        b"Me",
        b"Og",
        b"PK",
        b"RI",
        b"Ra",
        b"SI",
        b"SQ",
        b"SY",
        b"SZ",
        b"Su",
        b"To",
        b"X-",
        b"ZW",
        b"[a",
        b"\x60\xea",
        b"q\xc7",
        b"v:",
        b"xa",
        b"x\x9f",
        b"{\n",
        b"{ ",
        b"{\\",
        b"\x7fE",
        b"\x89P",
        b"\xb6\xb9",
        b"\xc7q",
        b"\xce\xfa",
        b"\xcf\xfa",
        b"\xd0\xcf",
        b"\xd9\xd5",
        b"\xe4R",
        b"\xfd7",
        b"\xfe\xed",
        b"\xff\xd8",
        b"\xff\xfb",
        b"\xef\xbb",
        b"\xfe\xff",
        b"\xff\xfe",
    ];
    // The built-in types with two leading NULs are JPEG2000 and MPEG.
    // A zero-filled sector alone does not select either format.
    let zero_prefix = header.starts_with(b"\0\0\0\x0cjP  \r\n\x87\n")
        || matches!(
            header[..4],
            [0, 0, 1, 0xb3 | 0xba] | [0, 0, 0xfe, 0xff] | [0, 0, 0xff, 0xfe]
        );
    // Stock's universal Mach-O and Java definitions cover only values 0 through 63.
    let java_or_universal = matches!(header, [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0..=63, ..]);
    if zero_prefix
        || java_or_universal
        || PREFIXES.iter().any(|prefix| header.starts_with(*prefix))
        || [
            b"Received: ".as_slice(),
            b"Received-SPF: ",
            b"Return-Path: ",
            b"Return-path: ",
            b"Delivered-To: ",
            b"Delivery-date: ",
        ]
        .iter()
        .any(|field| header.starts_with(field))
        || header.starts_with(b"begin ")
        || header[2..4] == *b"\r\n"
        || header[1..4] == *b"\r\r\n"
        || header.get(2..4).is_some_and(|p| p == b"-l" || p == b"-p")
        || header.get(4..6) == Some(b"\xd0\xcf")
        || header.get(512..516) == Some(b"EFI ")
        || header.get(257..262) == Some(b"ustar")
    {
        return false;
    }
    // The other file-type records use content markers (some without a fixed offset).
    // Stock defers embedded archive markers to its post-raw pass. Other
    // content markers can still change the outer type before raw matching.
    const MARKERS: &[&[u8]] = &[
        b"\x01CD",
        b"\x00BE",
        b"%PDF",
        b"InstallS",
        b"\xa3H",
        b"MIME",
        b"\nFrom",
        b"\nMessage",
        b"\nReceiv",
        b"Delivered-To:",
        b"/RGB",
        b"\x19\x04\x00\x10",
    ];
    static CONTENT_MARKERS: std::sync::LazyLock<aho_corasick::AhoCorasick> =
        std::sync::LazyLock::new(|| {
            aho_corasick::AhoCorasick::builder()
                .kind(Some(aho_corasick::AhoCorasickKind::ContiguousNFA))
                .ascii_case_insensitive(true)
                .build(MARKERS)
                .expect("static raw-stage markers")
        });
    if CONTENT_MARKERS.is_match(header) || embedded_pe_or_nsis(header) {
        return false;
    }
    // The classifier already checked HTML, mail and legacy Office XML.
    // OOXML member names and namespaces do not identify a legacy document.
    let generic_xml = file_type == "CL_TYPE_TEXT_ASCII"
        && header.starts_with(b"<")
        && header
            .iter()
            .all(|b| !b.is_ascii() || b.is_ascii_graphic() || b.is_ascii_whitespace())
        && std::str::from_utf8(header)
            .err()
            .is_none_or(|e| e.error_len().is_none())
        && ![b"<%".as_slice(), b"<xdp:"]
            .iter()
            .any(|m| header.windows(m.len()).any(|s| s.eq_ignore_ascii_case(m)));
    if !generic_xml
        && header.iter().enumerate().any(|(i, &byte)| {
            byte == b'<'
                && [1, 2].iter().any(|&width| {
                    [
                        b"a ".as_slice(),
                        b"head",
                        b"html",
                        b"iframe",
                        b"img",
                        b"object",
                        b"script",
                        b"table",
                        b"%",
                        b"xdp:",
                    ]
                    .iter()
                    .any(|tag| {
                        tag.iter().enumerate().all(|(j, b)| {
                            header
                                .get(i + (j + 1) * width)
                                .is_some_and(|s| s.eq_ignore_ascii_case(b))
                        })
                    })
                })
        })
    {
        return false;
    }
    // Office document markers require an XML declaration at the beginning.
    // An ordinary plist can occur inside a disk image's binary header.
    if !generic_xml
        && (header.starts_with(b"<?")
            || header.starts_with(b"<\0?")
            || header.starts_with(b"\0<\0?"))
    {
        return false;
    }
    true
}

// The built-in content records `4d5a{60-300}50450000` and
// `efbeadde4e756c6c736f6674496e7374` need more than their leading bytes.
// Case folding keeps this check at least as broad as the reference.
fn embedded_pe_or_nsis(header: &[u8]) -> bool {
    let at = |i: usize, s: &[u8]| {
        header
            .get(i..i + s.len())
            .is_some_and(|w| w.eq_ignore_ascii_case(s))
    };
    (0..header.len()).any(|i| {
        at(i, b"\xef\xbe\xad\xdeNullsoftInst")
            || at(i, b"MZ") && (i + 62..=i + 302).any(|j| at(j, b"PE\0\0"))
    })
}

#[cfg(test)]
mod tests {
    use super::eligible;

    #[test]
    fn embedded_pe_and_nsis_need_their_complete_records() {
        let test = |bytes: &[u8]| eligible(bytes, "CL_TYPE_TEXT_UTF16BE");
        let mut header = vec![b'x'; 400];
        header[6..8].copy_from_slice(b"MZ");
        header[30..32].copy_from_slice(b"\xef\xbe");
        assert!(test(&header));
        for gap in [60, 300] {
            let mut pe = header.clone();
            pe[8 + gap..12 + gap].copy_from_slice(b"pe\0\0");
            assert!(!test(&pe), "{gap}");
        }
        for gap in [59, 301] {
            let mut pe = header.clone();
            pe[8 + gap..12 + gap].copy_from_slice(b"PE\0\0");
            assert!(test(&pe), "{gap}");
        }
        header[30..46].copy_from_slice(b"\xef\xbe\xad\xdeNullsoftInst");
        assert!(!test(&header));
    }

    #[test]
    fn content_markers_fold_ascii_inside_binary_headers() {
        let test = |bytes: &[u8]| eligible(bytes, "CL_TYPE_BINARY_DATA");
        for marker in [b"bill %pDf".as_slice(), b"bill \xa3h", b"bill\nfRoM"] {
            assert!(!test(marker));
        }
        assert!(test(b"bill %pDx"));
        assert!(test(b"bill \xa4h"));
    }

    #[test]
    fn delivery_prose_reaches_the_raw_stage() {
        let eligible = |header: &[u8]| eligible(header, "CL_TYPE_TEXT_ASCII");
        assert!(eligible(b"Depot receipt\nDelivered intact.\n"));
        assert!(eligible(b"Delivery dated Monday.\n"));
        for header in [
            b"Delivered-To: stockroom@example.invalid".as_slice(),
            b"Delivery-date: Mon, 16 Nov 2026 12:00:00 +0000",
            b"X-Inventory: recorded\ndElIvErEd-To: stockroom@example.invalid",
        ] {
            assert!(!eligible(header));
        }
    }

    #[test]
    fn powerpoint_atom_and_boot_sector_reach_the_raw_stage() {
        let eligible = |header: &[u8]| eligible(header, "CL_TYPE_BINARY_DATA");
        assert!(eligible(b"\0\0\xa0\x0f\x04\0\0\0H\0i\0"));
        for guarded in [
            b"\0\0\0\x0cjP  \r\n\x87\n".as_slice(),
            b"\0\0\x01\xb3ordinary",
            b"\0\0\x01\xbaordinary",
            b"\0\0\xfe\xff\0\0\0A",
        ] {
            assert!(!eligible(guarded));
        }
        let mut partition = [0; 516];
        partition[..4].copy_from_slice(b"\0\0\xa0\x0f");
        partition[510..512].copy_from_slice(b"\x55\xaa");
        assert!(eligible(&partition));
        partition[510..512].fill(0);
        partition[512..].copy_from_slice(b"EFI ");
        assert!(!eligible(&partition));
    }

    #[test]
    fn text_classification_and_specialized_xml_control_raw_admission() {
        let document = b"<?xml version=\"1.0\"?><report><price>30</price></report>";
        assert!(eligible(document, "CL_TYPE_TEXT_ASCII"));
        assert!(!eligible(document, "CL_TYPE_HTML"));
        assert!(!eligible(
            b"<?xml version=\"1.0\"?><Workbook/>",
            "CL_TYPE_XML_XL"
        ));
        for header in [b"<xdp:xdp/>".as_slice(), b"<% directive %>"] {
            assert!(!eligible(header, "CL_TYPE_TEXT_ASCII"));
        }
    }
}
