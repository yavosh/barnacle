//! PDF 1.5 object-stream comparisons with the pinned Debian clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/pdf_text.rs"]
mod pdf_text;
#[path = "common/zip.rs"]
mod zip;
use flate2::{Compression, write::ZlibEncoder};
use md5::{Digest, Md5};
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

const PAGE: &[u8] = b"[(Quarterly REPORT)] TJ\n";
const TEXT: &[u8] = b"quarterly report";
const ATTACHMENT: &[u8] = b"Quarterly statement from accounting.";
const PAGE_DICT: &str =
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> /Contents ";

fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut body = format!("<< {dict} /Length {}>>\nstream\n", data.len()).into_bytes();
    body.extend(data);
    body.extend(b"\nendstream");
    body
}
fn zlib(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
    z.write_all(data)?;
    z.finish()
}
struct Sample {
    file: Vec<u8>,
    directory: Vec<u8>,
    encoded: Vec<u8>,
    page_dict: Vec<u8>,
    xref: Vec<u8>,
}

fn sample(
    compact: bool,
    compressed: bool,
    contents: &str,
    physical: [usize; 3],
) -> io::Result<Sample> {
    with_member(
        compact,
        compressed,
        contents,
        physical,
        b"<< /Title (Quarterly report) >>\n",
        false,
        false,
    )
}
fn with_member(
    compact: bool,
    compressed: bool,
    contents: &str,
    physical: [usize; 3],
    extra: &[u8],
    earlier: bool,
    indirect_length: bool,
) -> io::Result<Sample> {
    let page_dict = format!("{PAGE_DICT}{contents} >>\n").into_bytes();
    let members = [
        b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(notes.txt) 4 0 R] >> >> >>\n".as_slice(),
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>\n",
        &page_dict,
        b"<< /Type /Filespec /F (notes.txt) /EF << /F 7 0 R >> >>\n",
        extra,
    ];
    let order = if earlier {
        [1, 2, 5, 3, 4]
    } else {
        [1, 2, 3, 4, 5]
    };
    pack(
        compact,
        compressed,
        physical,
        indirect_length,
        members,
        order,
    )
}

fn pack(
    compact: bool,
    compressed: bool,
    physical: [usize; 3],
    indirect_length: bool,
    members: [&[u8]; 5],
    order: [usize; 5],
) -> io::Result<Sample> {
    let mut header = String::new();
    let mut body = Vec::new();
    for &id in &order {
        header.push_str(&format!("{id} {} ", body.len()));
        body.extend_from_slice(members[id - 1]);
    }
    let first = header.len();
    let mut directory = header.into_bytes();
    directory.extend(body);
    let encoded = if compressed {
        zlib(&directory)?
    } else {
        directory.clone()
    };
    let tag = if compact {
        "/Type/ObjStm"
    } else {
        "/Type /ObjStm"
    };
    let filter = if compressed {
        "/Filter /FlateDecode"
    } else {
        ""
    };
    let dictionary = format!("{tag} /First {first} /N {} {filter}", members.len());
    let page = if indirect_length {
        [
            b"<< /Length 5 0 R >>\nstream\n".as_slice(),
            PAGE,
            b"\nendstream",
        ]
        .concat()
    } else {
        stream("", PAGE)
    };
    let streams = [
        page,
        stream("/Type /EmbeddedFile", ATTACHMENT),
        stream(&dictionary, &encoded),
    ];
    let mut pdf = b"%PDF-1.5\n%\xa9\xb3\xda\xbc\n".to_vec();
    let mut xref = vec![0u8; 10 * 7];
    xref[5..7].copy_from_slice(&65535u16.to_be_bytes());
    for (i, &id) in order.iter().enumerate() {
        let r = &mut xref[id * 7..(id + 1) * 7];
        r[0] = 2;
        r[1..5].copy_from_slice(&8u32.to_be_bytes());
        r[5..].copy_from_slice(&(i as u16).to_be_bytes());
    }
    for id in physical {
        let r = &mut xref[id * 7..(id + 1) * 7];
        r[0] = 1;
        r[1..5].copy_from_slice(&(pdf.len() as u32).to_be_bytes());
        writeln!(pdf, "{id} 0 obj")?;
        pdf.extend(&streams[id - 6]);
        pdf.extend(b"\nendobj\n");
    }
    let start = pdf.len();
    xref[9 * 7] = 1;
    xref[9 * 7 + 1..9 * 7 + 5].copy_from_slice(&(start as u32).to_be_bytes());
    pdf.extend(b"9 0 obj\n");
    let info = if members[4].starts_with(b"<<") {
        " /Info 5 0 R"
    } else {
        ""
    };
    pdf.extend(stream(
        &format!("/Type /XRef /Size 10 /Root 1 0 R{info} /W [1 4 2]"),
        &xref,
    ));
    write!(pdf, "\nendobj\nstartxref\n{start}\n%%EOF\n")?;
    Ok(Sample {
        file: pdf,
        directory,
        encoded,
        page_dict: members[2].to_vec(),
        xref,
    })
}

fn two_carriers(array_first: bool, catalog: Option<&[u8]>) -> io::Result<Vec<u8>> {
    let page = format!("{PAGE_DICT}4 0 R >>\n");
    let header = if catalog.is_some() {
        format!("3 0 1 {} ", page.len())
    } else {
        "3 0 ".into()
    };
    let first = [
        header.as_bytes(),
        page.as_bytes(),
        catalog.unwrap_or_default(),
    ]
    .concat();
    let info = format!(
        "/Type/ObjStm /First {} /N {} /Filter /FlateDecode",
        header.len(),
        1 + usize::from(catalog.is_some())
    );
    let mut objects = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()),
        (2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>".to_vec()),
        (5, stream(&info, &zlib(&first)?)),
        (
            7,
            stream(
                "/Type/ObjStm /First 4 /N 1 /Filter /FlateDecode",
                &zlib(b"4 0 [6 0 R]\n")?,
            ),
        ),
        (6, stream("", PAGE)),
    ];
    if array_first {
        objects.swap(2, 3);
    }
    let mut file = b"%PDF-1.5\n".to_vec();
    let mut xref = [[0; 7]; 9];
    xref[0][5..].copy_from_slice(&65535u16.to_be_bytes());
    for (id, parent) in [(3, 5u32), (4, 7)] {
        xref[id][0] = 2;
        xref[id][1..5].copy_from_slice(&parent.to_be_bytes());
    }
    for (id, body) in objects {
        if id == 1 && catalog.is_some() {
            xref[id][0] = 2;
            xref[id][1..5].copy_from_slice(&5u32.to_be_bytes());
            xref[id][5..].copy_from_slice(&1u16.to_be_bytes());
            continue;
        }
        xref[id][0] = 1;
        xref[id][1..5].copy_from_slice(&(file.len() as u32).to_be_bytes());
        writeln!(file, "{id} 0 obj")?;
        file.extend(body);
        file.extend(b"\nendobj\n");
    }
    let start = file.len();
    xref[8][0] = 1;
    xref[8][1..5].copy_from_slice(&(start as u32).to_be_bytes());
    file.extend(b"8 0 obj\n");
    file.extend(stream(
        "/Type /XRef /Size 9 /Root 1 0 R /W [1 4 2]",
        xref.as_flattened(),
    ));
    write!(file, "\nendobj\nstartxref\n{start}\n%%EOF\n")?;
    Ok(file)
}

const DEFERRED_PAGE: &[u8] =
    b"<< /Type /Page /Parent 2 0 R /Resources << >> /MediaBox [0 0 100 100] /Contents [] >>\n";
fn catalog_with_deferred_page(
    compressed: bool,
    page_first: bool,
    padding: usize,
) -> io::Result<(Sample, Vec<u8>)> {
    let mut catalog =
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /GoTo /D (Receipt) >> /Note (".to_vec();
    catalog.extend_from_slice(&b"Receiving inspected the inventory. ".repeat(4096));
    catalog.extend_from_slice(b") >>\n");
    let mut note = b"<< /Title (Receipt".to_vec();
    note.resize(note.len() + padding, b' ');
    note.extend_from_slice(b") >>\n");
    let order = if page_first {
        [5, 3, 2, 1, 4]
    } else {
        [5, 1, 2, 3, 4]
    };
    let sample = pack(
        true,
        compressed,
        [8, 6, 7],
        false,
        [
            &catalog,
            b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>\n",
            DEFERRED_PAGE,
            b"<< /Type /Filespec /F (notes.txt) /EF << /F 7 0 R >> >>\n",
            &note,
        ],
        order,
    )?;
    Ok((sample, catalog))
}

fn hash(bytes: &[u8], name: &str) -> String {
    let hex: String = Md5::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{hex}:{}:PdfStreams.{name}\n", bytes.len())
}
fn compare(stock: bool) -> io::Result<()> {
    let normal = sample(true, true, "6 0 R", [8, 6, 7])?;
    let array = sample(true, true, "[6 0 R]", [8, 6, 7])?;
    let empty = sample(true, true, "[]", [8, 6, 7])?;
    let late = sample(true, true, "6 0 R", [6, 8, 7])?;
    let other = sample(true, true, "6 0 R", [7, 8, 6])?;
    let spaced = sample(false, true, "6 0 R", [8, 6, 7])?;
    let stored = sample(true, false, "6 0 R", [8, 6, 7])?;
    let qpdf = include_bytes!("fixtures/pdf/qpdf-object-stream.pdf");
    let directory = hash(&normal.directory, "Directory");
    let embedded = hash(ATTACHMENT, "Attachment");
    let normalized = hash(TEXT, "Text");
    let encoded = hash(&normal.encoded, "Encoded");
    let packed_page = hash(&empty.page_dict, "EmptyPage");
    let outer = hash(&normal.file, "Outer");
    let mut both = directory.clone() + &embedded + &encoded + &hash(PAGE, "Page") + &outer;
    both.push_str("8f7e912f2ecc1bce8c00f2ffcfba5fa5:347:PdfStreams.QpdfDirectory\n");
    let check = |config: &str,
                 rules: &str,
                 logical: &str,
                 cases: &[(&str, &[u8], Option<&str>)]|
     -> io::Result<()> {
        let tmp = tempfile::tempdir_in("/tmp")?;
        let db = tmp.path().join("db");
        fs::create_dir(&db)?;
        if !rules.is_empty() {
            fs::write(db.join("local.hdb"), rules)?;
        }
        if !logical.is_empty() {
            fs::write(db.join("local.ldb"), logical)?;
        }
        let socket = tmp.path().join("sock");
        let conf = tmp.path().join("clamd.conf");
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\nSelfCheck 0\n{config}\n",
                db.display(),
                socket.display()
            ),
        )?;
        let exe = if stock {
            "/usr/sbin/clamd"
        } else {
            env!("CARGO_BIN_EXE_barnacle")
        };
        let _daemon = daemon::Daemon::start(Path::new(exe), &conf, &socket)?;
        for &(case, file, name) in cases {
            let expected = match name {
                Some(n) if n.starts_with("Heuristics.") => format!("stream: {n} FOUND\0"),
                Some(n) => format!("stream: PdfStreams.{n}.UNOFFICIAL FOUND\0"),
                None if stock => "stream: OK\0".into(),
                None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
            };
            assert_eq!(
                daemon::unix_request(&socket, &daemon::stream_frame(file)?)?,
                expected,
                "{case}: {config}"
            );
        }
        Ok(())
    };
    let page = format!("{PAGE_DICT}6 0 R >>\n");
    let mut rules = std::collections::BTreeSet::new();
    let mut destinations = Vec::new();
    for (opening, action, backward_winner) in [
        ("[3 0 R /Fit]", "[3 0 R /Fit]\n", "OpeningPage"),
        ("5 0 R", "<< /S /GoTo /D [3 0 R /Fit] >>\n", "OpeningAction"),
        ("5 0 R", "[3 0 R /FitH 72]\n", "OpeningAction"),
        (
            "<< /S /GoTo /D [3 0 R /Fit] >>",
            "[3 0 R /Fit]\n",
            "Catalog",
        ),
    ] {
        let catalog = format!(
            "<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(notes.txt) 4 0 R] >> >> /OpenAction {opening} >>\n"
        );
        rules.insert(hash(catalog.as_bytes(), "Catalog"));
        rules.insert(hash(action.as_bytes(), "OpeningAction"));
        rules.insert(hash(page.as_bytes(), "OpeningPage"));
        for (order, compact, winner) in [
            ([1, 2, 3, 4, 5], true, "Catalog"),
            ([5, 3, 2, 1, 4], true, backward_winner),
            ([1, 2, 3, 4, 5], false, "Wrapper"),
        ] {
            let sample = pack(
                compact,
                true,
                [8, 6, 7],
                false,
                [
                    catalog.as_bytes(),
                    b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>\n",
                    page.as_bytes(),
                    b"<< /Type /Filespec /F (notes.txt) /EF << /F 7 0 R >> >>\n",
                    action.as_bytes(),
                ],
                order,
            )?;
            let wrapper = zip::zip(&[("notes.pdf", &sample.file)], true, false, false)?;
            rules.insert(hash(&wrapper, "Wrapper"));
            destinations.push((wrapper, winner));
        }
    }
    let dest_rules = rules.into_iter().collect::<String>();
    let packed_cases: Vec<_> = destinations
        .iter()
        .map(|(file, winner)| ("packed opening", file.as_slice(), Some(*winner)))
        .collect();
    check("", &dest_rules, "", &packed_cases)?;
    let fixed_winner = |name| {
        destinations
            .iter()
            .map(|(file, _)| ("packed opening", file.as_slice(), Some(name)))
            .collect::<Vec<_>>()
    };
    check(
        "",
        &(dest_rules.clone() + &embedded),
        "",
        &fixed_winner("Attachment"),
    )?;
    for setting in [
        "ScanPDF no",
        "MaxFiles 3",
        "MaxRecursion 1",
        "MaxScanSize 1000",
    ] {
        check(setting, &dest_rules, "", &fixed_winner("Wrapper"))?;
    }
    check("MaxFiles 9", &dest_rules, "", &packed_cases)?;
    let mut long_cases = Vec::new();
    let mut long_rules = String::new();
    let suffix = b") /OpenAction << /S /GoTo /D /Receipt >> >>\n";
    for (size, name) in [
        (65_536, "Catalog64K"),
        (65_537, "Catalog64KPlusOne"),
        (1_048_617, "LargeCatalog"),
    ] {
        let mut catalog = b"<< /Type /Catalog /Pages 2 0 R /Note (".to_vec();
        let memo = b"Receiving confirmed the count of paper, pens, and folders. ";
        catalog.extend(
            memo.iter()
                .copied()
                .cycle()
                .take(size - catalog.len() - suffix.len()),
        );
        catalog.extend_from_slice(suffix);
        long_rules += &hash(&catalog, name);
        let sample = pack(
            true,
            true,
            [8, 6, 7],
            false,
            [
                &catalog,
                b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>\n",
                page.as_bytes(),
                b"<< /Type /Filespec /F (notes.txt) /EF << /F 7 0 R >> >>\n",
                b"<< /Title (Receipt) >>\n",
            ],
            [1, 2, 3, 4, 5],
        )?;
        if size == 65_537 {
            let exact = sample.file.len()
                + sample.directory.len()
                + PAGE.len()
                + TEXT.len()
                + ATTACHMENT.len()
                + sample.xref.len()
                + size;
            for (limit, winner) in [
                (exact, name),
                (exact - 1, "Heuristics.Limits.Exceeded.MaxScanSize"),
            ] {
                check(
                    &format!("MaxScanSize {limit}\nAlertExceedsMax yes"),
                    &long_rules,
                    "",
                    &[("last byte of packed catalog", &sample.file, Some(winner))],
                )?;
            }
        }
        long_cases.push((sample.file, Some(name)));
    }
    let mut long_page=b"<< /Type /Page /Parent 2 0 R /Contents 6 0 R /Resources << >> /MediaBox [0 0 100 100] /Note (".to_vec();
    long_page.resize(192 * 1024, b'R');
    long_page.extend_from_slice(b") >>\n");
    let mut named_action = b"<< /S /GoTo /D (".to_vec();
    named_action.resize(300 * 1024, b'P');
    named_action.extend_from_slice(b") >>\n");
    for (opening, page_body, action_body, selected, name) in [
        (
            "[3 0 R /Fit]",
            long_page.as_slice(),
            b"[3 0 R /Fit]\n".as_slice(),
            long_page.as_slice(),
            "LongPage",
        ),
        (
            "5 0 R",
            page.as_bytes(),
            named_action.as_slice(),
            named_action.as_slice(),
            "LongAction",
        ),
    ] {
        let catalog = format!("<< /Type /Catalog /Pages 2 0 R /OpenAction {opening} >>\n");
        let sample = pack(
            true,
            true,
            [8, 6, 7],
            false,
            [
                catalog.as_bytes(),
                b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>\n",
                page_body,
                b"<< /Type /Filespec /F (notes.txt) /EF << /F 7 0 R >> >>\n",
                action_body,
            ],
            [5, 3, 2, 1, 4],
        )?;
        long_rules += &hash(selected, name);
        long_cases.push((sample.file, Some(name)));
    }
    let large: Vec<_> = long_cases
        .iter()
        .map(|(file, expected)| ("catalog with long metadata", file.as_slice(), *expected))
        .collect();
    check("", &long_rules, "", &large)?;
    check(
        "",
        &(long_rules.clone() + &embedded),
        "",
        &long_cases
            .iter()
            .map(|(file, _)| {
                (
                    "attachment before large catalog",
                    file.as_slice(),
                    Some("Attachment"),
                )
            })
            .collect::<Vec<_>>(),
    )?;
    check(
        "MaxScanSize 4096\nAlertExceedsMax yes",
        &long_rules,
        "",
        &long_cases
            .iter()
            .map(|(file, _)| {
                (
                    "large catalog limits",
                    file.as_slice(),
                    Some("Heuristics.Limits.Exceeded.MaxScanSize"),
                )
            })
            .collect::<Vec<_>>(),
    )?;

    let mut ordered = Vec::new();
    for compressed in [false, true] {
        for padding in [0, 96 * 1024] {
            for page_first in [false, true] {
                let (sample, catalog) =
                    catalog_with_deferred_page(compressed, page_first, padding)?;
                ordered.push((
                    sample,
                    catalog,
                    if page_first {
                        "DeferredPage"
                    } else {
                        "DeferredCatalog"
                    },
                ));
            }
        }
    }
    let deferred_rules =
        hash(DEFERRED_PAGE, "DeferredPage") + &hash(&ordered[0].1, "DeferredCatalog");
    let cases: Vec<_> = ordered
        .iter()
        .map(|(doc, _, name)| ("deferred member order", doc.file.as_slice(), Some(*name)))
        .collect();
    check("", &deferred_rules, "", &cases)?;
    let only: Vec<_> = ordered
        .iter()
        .map(|(doc, _, _)| {
            (
                "later deferred page",
                doc.file.as_slice(),
                Some("DeferredPage"),
            )
        })
        .collect();
    check("", &hash(DEFERRED_PAGE, "DeferredPage"), "", &only)?;

    let array_first = two_carriers(true, Some(&ordered[0].1))?;
    let catalog_first = two_carriers(false, Some(&ordered[0].1))?;
    check(
        "",
        &(hash(&ordered[0].1, "DeferredCatalog") + &hash(b"[6 0 R]\n", "EarlierArray")),
        "",
        &[
            (
                "other carrier before catalog",
                &array_first,
                Some("EarlierArray"),
            ),
            (
                "catalog before other carrier",
                &catalog_first,
                Some("DeferredCatalog"),
            ),
        ],
    )?;
    let deferred = with_member(
        true,
        true,
        "5 0 R",
        [8, 6, 7],
        &pdf_text::array(70001, b""),
        true,
        false,
    )?;
    check(
        "",
        "0ac8e46820d6cfc7267923402dd7ae3e:69993:PdfStreams.LongArray\n",
        "",
        &[(
            "deferred page crosses eight normalized output blocks",
            &deferred.file,
            Some("LongArray"),
        )],
    )?;
    check(
        "",
        &both,
        "",
        &[
            ("raw PDF first", &normal.file, Some("Outer")),
            ("spaced dictionary", &spaced.file, Some("Directory")),
            ("direct object before directory", &late.file, Some("Page")),
            (
                "attachment before directory",
                &other.file,
                Some("Attachment"),
            ),
            ("unfiltered directory", &stored.file, Some("Directory")),
            ("qpdf generated directory", qpdf, Some("QpdfDirectory")),
        ],
    )?;
    check(
        "",
        &(directory.clone() + &encoded + &embedded),
        "",
        &[("decoded before attachment", &normal.file, Some("Directory"))],
    )?;
    check(
        "",
        &normalized,
        "",
        &[
            (
                "page discovered in packed dictionary",
                &normal.file,
                Some("Text"),
            ),
            ("one-element Contents array", &array.file, Some("Text")),
            ("stored dictionary", &stored.file, Some("Text")),
            ("page already visited", &late.file, None),
            ("spaced dictionary leaves page unmarked", &spaced.file, None),
            ("qpdf leaves page unmarked", qpdf, None),
        ],
    )?;
    check(
        "",
        &encoded,
        "",
        &[("compressed bytes alone", &normal.file, None)],
    )?;
    check(
        "",
        &packed_page,
        "",
        &[("empty contents array", &empty.file, Some("EmptyPage"))],
    )?;
    check(
        "",
        &(packed_page + &hash(&empty.xref, "Xref")),
        "",
        &[(
            "physical xref before packed page",
            &empty.file,
            Some("Xref"),
        )],
    )?;
    check(
        "",
        &hash(&normal.page_dict, "OrdinaryPage"),
        "",
        &[("packed page with resolved Contents", &normal.file, None)],
    )?;
    let earlier = with_member(true, true, "5 0 R", [8, 6, 7], b"[6 0 R]\n", true, false)?;
    let forward = with_member(true, true, "5 0 R", [8, 6, 7], b"[6 0 R]\n", false, false)?;
    check(
        "",
        &(hash(b"[6 0 R]\n", "Array") + &hash(&forward.page_dict, "ForwardPage")),
        "",
        &[
            (
                "reference to packed array already read",
                &earlier.file,
                Some("Array"),
            ),
            (
                "forward reference to packed array",
                &forward.file,
                Some("ForwardPage"),
            ),
        ],
    )?;
    check(
        "",
        &(hash(b"[6 0 R]\n", "Array")
            + &hash(format!("{PAGE_DICT}4 0 R >>\n").as_bytes(), "ForwardPage")),
        "",
        &[
            (
                "array in a previous carrier",
                &two_carriers(true, None)?,
                Some("Array"),
            ),
            (
                "array in a later carrier",
                &two_carriers(false, None)?,
                Some("ForwardPage"),
            ),
        ],
    )?;
    let length = format!("{}\n", PAGE.len());
    let packed_length = with_member(
        true,
        true,
        "6 0 R",
        [8, 6, 7],
        length.as_bytes(),
        false,
        true,
    )?;
    check(
        "",
        &(hash(PAGE, "Page") + &hash(&[PAGE, b"\n"].concat(), "PageLine")),
        "",
        &[(
            "physical stream with packed indirect length",
            &packed_length.file,
            Some("PageLine"),
        )],
    )?;
    let padded_length = format!(" {length}");
    let padded = with_member(
        true,
        true,
        "6 0 R",
        [8, 6, 7],
        padded_length.as_bytes(),
        false,
        true,
    )?;
    check(
        "",
        &hash(PAGE, "Page"),
        "",
        &[(
            "packed length with leading whitespace",
            &padded.file,
            Some("Page"),
        )],
    )?;
    let large_title = format!("<< /Title ({}) >>\n", "Quarterly ".repeat(10000));
    let large = with_member(
        true,
        true,
        "6 0 R",
        [8, 6, 7],
        large_title.as_bytes(),
        false,
        false,
    )?;
    check(
        "",
        &hash(&large.directory, "Large"),
        "",
        &[("large directory", &large.file, Some("Large"))],
    )?;
    check(
        "MaxFileSize 2048\nAlertExceedsMax yes",
        &normalized,
        "",
        &[("large directory expansion", &large.file, Some("Text"))],
    )?;
    let larger_title = format!("<< /Title ({}) >>\n", "Quarterly ".repeat(30000));
    let larger = with_member(
        true,
        true,
        "6 0 R",
        [8, 6, 7],
        larger_title.as_bytes(),
        false,
        false,
    )?;
    assert!(
        larger.file.len() < 4096,
        "outer PDF has {} bytes, encoded is {}",
        larger.file.len(),
        larger.encoded.len()
    );
    let spaced_large = with_member(
        false,
        true,
        "6 0 R",
        [8, 6, 7],
        larger_title.as_bytes(),
        false,
        false,
    )?;
    check(
        "MaxFileSize 4096\nAlertExceedsMax yes",
        &(hash(&larger.encoded, "Fallback") + &normalized),
        "",
        &[
            (
                "directory crossing the initial inflate buffer",
                &larger.file,
                Some("Fallback"),
            ),
            (
                "spaced carrier exceeding the initial inflate buffer",
                &spaced_large.file,
                Some("Fallback"),
            ),
        ],
    )?;
    check(
        "",
        &embedded,
        "",
        &[("qpdf attached file", qpdf, Some("Attachment"))],
    )?;
    check(
        "ScanPDF no",
        &(directory.clone() + &outer),
        "",
        &[
            ("disabled with outer rule", &normal.file, Some("Outer")),
            ("disabled PDF extractor", &spaced.file, None),
        ],
    )?;
    let budget = normal.file.len() + normal.directory.len();
    for (config, expected) in [
        ("MaxFiles 1".into(), "Heuristics.Limits.Exceeded.MaxFiles"),
        (
            "MaxRecursion 1".into(),
            "Heuristics.Limits.Exceeded.MaxRecursion",
        ),
        (format!("MaxScanSize {budget}"), "Directory"),
        (
            format!("MaxScanSize {}", budget - 1),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
    ] {
        check(
            &format!("{config}\nAlertExceedsMax yes"),
            &directory,
            "",
            &[("directory limit", &normal.file, Some(expected))],
        )?;
    }
    if stock {
        let sig = b"/Title (Quarterly report)"
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let rule =
            format!("PdfStreams.Parent;Engine:81-255,Target:0,Container:CL_TYPE_PDF;0;{sig}\n");
        check(
            "",
            "",
            &rule,
            &[("decoded stream parent", &normal.file, Some("Parent"))],
        )?;
    }
    Ok(())
}

#[test]
fn barnacle_objstm() -> io::Result<()> {
    compare(false)
}
#[test]
#[ignore = "requires pinned Debian clamd 1.4.3+dfsg-1"]
fn stock_objstm() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(true)
}

#[test]
fn packed_directory_and_deferred_page_have_pdf_parent() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let doc = sample(true, true, "[]", [8, 6, 7])?;
    let tmp = tempfile::tempdir()?;
    let mut observed = Vec::new();
    scan(
        &doc.file,
        &Options::default(),
        tmp.path(),
        |obj, _| {
            if !obj.normalized
                && obj
                    .parents
                    .last()
                    .is_some_and(|p| p.file_type == "CL_TYPE_PDF")
            {
                assert!(obj.layer.name.is_none());
                observed.push(obj.bytes.to_vec());
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(
        observed,
        [
            doc.directory,
            PAGE.to_vec(),
            ATTACHMENT.to_vec(),
            doc.xref,
            doc.page_dict
        ]
    );
    Ok(())
}

#[test]
fn retained_catalog_lifetime_and_cleanup() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    use std::cell::Cell;
    let root = tempfile::tempdir_in("/tmp")?;
    let missing = root.path().join("absent");
    let opts = Options {
        scan_html: false,
        ..Options::default()
    };
    for compressed in [false, true] {
        let scratch = if compressed { root.path() } else { &missing };
        let (doc, catalog) = catalog_with_deferred_page(compressed, false, 0)?;
        let offset = doc
            .directory
            .windows(16)
            .position(|s| s == &catalog[..16])
            .unwrap();
        for winner in ["receipt", "catalog", "cancel", "miss"] {
            let mut source = None;
            let mut visited = false;
            let cancel = Cell::new(false);
            let res = scan(
                &doc.file,
                &opts,
                scratch,
                |obj, _| {
                    if obj.normalized {
                        return Ok(Verdict::Miss);
                    }
                    if obj.bytes == doc.directory {
                        source = Some(obj.bytes.as_ptr() as usize);
                    } else if obj.bytes == ATTACHMENT {
                        if winner == "receipt" {
                            return Ok(Verdict::Found("receipt".into()));
                        }
                        cancel.set(winner == "cancel");
                    } else if obj.bytes == catalog {
                        visited = true;
                        assert_eq!(obj.bytes.as_ptr() as usize, source.unwrap() + offset);
                        if !compressed {
                            assert!(doc.file.as_ptr_range().contains(&obj.bytes.as_ptr()));
                        }
                        if winner == "catalog" {
                            return Ok(Verdict::Found("catalog".into()));
                        }
                    }
                    Ok(Verdict::Miss)
                },
                || {
                    if cancel.get() {
                        Err(io::Error::other("physical scan interrupted"))
                    } else {
                        Ok(())
                    }
                },
            );
            match winner {
                "cancel" => assert_eq!(res.unwrap_err().to_string(), "physical scan interrupted"),
                "miss" => {
                    assert!(matches!(res?, Verdict::Miss | Verdict::Incomplete));
                    assert!(visited);
                }
                _ => assert_eq!(res?, Verdict::Found(winner.into())),
            }
            assert_eq!(visited, matches!(winner, "catalog" | "miss"));
            assert!(fs::read_dir(root.path())?.next().is_none());
            #[cfg(target_os = "linux")]
            assert!(
                !fs::read_to_string("/proc/self/maps")?.contains(root.path().to_str().unwrap())
            );
        }
    }
    Ok(())
}
