//! Passive BIFF8 workbook drawings against the pinned Debian scanner.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
use barnacle::objects::{Options, Verdict, scan};
use daemon::{Daemon, stream_frame, unix_request};
use std::{
    fs,
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
};

const EXCEL: &[u8] = include_bytes!("fixtures/xls/dots.xls");
const CALC: &[u8] = include_bytes!("fixtures/xls/arithmetic.xls");
const DOTS: &[u8] = include_bytes!("fixtures/xls/dots.png");
const JPEG: &[u8] = include_bytes!("fixtures/images/blue.jpg");
const TIFF: &[u8] = include_bytes!("fixtures/images/blue.tiff");
const REPORT: &[u8] = b"-- BIFF content extracted and disassembled from CL_TYPE_MSXL .xls file because a XLM macro was found in the document\n";

fn art(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut data = flags.to_le_bytes().to_vec();
    data.extend(kind.to_le_bytes());
    data.extend((payload.len() as u32).to_le_bytes());
    data.extend(payload);
    data
}
fn picture(kind: u16, instance: u16, data: &[u8], wrapped: bool) -> Vec<u8> {
    let mut blob = vec![0; if instance & 1 == 0 { 16 } else { 32 }];
    blob.push(255);
    blob.extend(data);
    let blip = art(kind, instance << 4, &blob);
    if !wrapped {
        return blip;
    }
    let typ = match kind {
        0xf01e => 6,
        0xf01d => 5,
        0xf029 => 17,
        _ => 0,
    };
    let mut entry = vec![0; 36];
    entry[0] = typ;
    entry[1] = typ;
    entry[20..24].copy_from_slice(&(blip.len() as u32).to_le_bytes());
    entry[24] = 1;
    entry.extend(blip);
    art(0xf007, u16::from(typ) << 4 | 2, &entry)
}
fn biff(code: u16, data: &[u8]) -> Vec<u8> {
    let mut out = code.to_le_bytes().to_vec();
    out.extend((data.len() as u16).to_le_bytes());
    out.extend(data);
    out
}

fn bitmap() -> Vec<u8> {
    // A 208-pixel 24-bit row is already DWORD aligned. The first 40 bytes are BITMAPINFOHEADER.
    let mut bytes = vec![0; 40 + 208 * 130 * 3];
    bytes[..4].copy_from_slice(&40u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&208u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&130u32.to_le_bytes());
    bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
    bytes[14..16].copy_from_slice(&24u16.to_le_bytes());
    bytes
}
fn workbook(images: &[Vec<u8>], fences: &[usize], continuation: u16) -> Vec<u8> {
    let store = art(0xf001, (images.len() as u16) << 4 | 15, &images.concat());
    let group = art(0xf000, 15, &store);
    let mut raw = Vec::new();
    let mut at = 0;
    let mut code = 0xeb;
    for end in fences.iter().copied().chain([group.len()]) {
        raw.extend(biff(code, &group[at..end]));
        at = end;
        code = continuation;
    }
    raw.extend(biff(0xa, &[]));
    raw
}
fn compound(entries: &[(&str, &[u8])]) -> io::Result<Vec<u8>> {
    let mut doc =
        cfb::CompoundFile::create_with_version(cfb::Version::V3, Cursor::new(Vec::new()))?;
    for (name, data) in entries {
        let path = Path::new(name);
        doc.create_storage_all(path.parent().unwrap())?;
        doc.create_stream(path)?.write_all(data)?;
    }
    Ok(doc.into_inner().into_inner())
}
fn single(raw: &[u8]) -> io::Result<Vec<u8>> {
    compound(&[("Workbook", raw)])
}
fn hash(name: &str, data: &[u8]) -> io::Result<String> {
    Ok(format!(
        "{}:{}:Xls.{name}\n",
        barnacle::hash_reader(data)?.md5_hex(),
        data.len()
    ))
}
struct Server {
    _process: Daemon,
    _dir: tempfile::TempDir,
    sock: PathBuf,
    stock: bool,
}
impl Server {
    fn start(stock: bool, opts: &str, hdb: &str, ndb: &str, ldb: &str) -> io::Result<Self> {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        for (filename, text) in [("local.hdb", hdb), ("local.ndb", ndb), ("local.ldb", ldb)] {
            if !text.is_empty() {
                fs::write(db.join(filename), text)?;
            }
        }
        let sock = dir.path().join("sock");
        let conf = dir.path().join("clamd.conf");
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nTemporaryDirectory {}\nDisableCache yes\nSelfCheck 0\n{opts}\n",
                db.display(),
                sock.display(),
                dir.path().display()
            ),
        )?;
        let exe = if stock {
            "/usr/sbin/clamd"
        } else {
            env!("CARGO_BIN_EXE_barnacle")
        };
        let process = Daemon::start(Path::new(exe), &conf, &sock)?;
        Ok(Self {
            _process: process,
            _dir: dir,
            sock,
            stock,
        })
    }
    fn check(&self, name: &str, bytes: &[u8], expected: Option<&str>) -> io::Result<()> {
        let result = unix_request(&self.sock, &stream_frame(bytes)?)?;
        let expected = match expected {
            Some(limit) if limit.starts_with("Heuristics.") => format!("stream: {limit} FOUND\0"),
            Some(s) => format!("stream: Xls.{s}.UNOFFICIAL FOUND\0"),
            None if self.stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        assert_eq!(result, expected, "{name}");
        Ok(())
    }
}
fn compare(stock: bool) -> io::Result<()> {
    authored_metafiles(stock)?;
    let mut wb = Vec::new();
    cfb::CompoundFile::open(Cursor::new(EXCEL))?
        .open_stream("Workbook")?
        .read_to_end(&mut wb)?;
    let dots = picture(0xf01e, 0x6e0, DOTS, true);
    let jpg = picture(0xf01d, 0x46b, JPEG, true);
    let dual = workbook(&[dots.clone(), jpg.clone()], &[3, 40, 2100], 0x3c);
    let rev = workbook(&[jpg.clone(), dots.clone()], &[4, 53, 103], 0xeb);
    let dib = bitmap();
    let files =
        hash("Dots", DOTS)? + &hash("Jpeg", JPEG)? + &hash("Tiff", TIFF)? + &hash("Dib", &dib)?;
    let daemon = Server::start(
        stock,
        "",
        &(files.clone() + &hash("Workbook", &wb)? + &hash("Outer", EXCEL)?),
        "",
        "",
    )?;
    daemon.check("authored PNG before outer", EXCEL, Some("Dots"))?;
    let bare_and_inline = single(&workbook(
        &[picture(0xf01d, 0x46a, JPEG, false), dots.clone()],
        &[],
        0x3c,
    ))?;
    daemon.check(
        "nonfinal bare JPEG passes through to the inline PNG",
        &bare_and_inline,
        Some("Dots"),
    )?;
    let exact_jpeg = [JPEG, &dots[..17]].concat();
    Server::start(stock, "", &(hash("Bare", &exact_jpeg)? + &files), "", "")?.check(
        "stock includes the following 17 bytes in the bare JPEG",
        &bare_and_inline,
        Some("Bare"),
    )?;
    daemon.check(
        "CONTINUE segments including split headers",
        &single(&dual)?,
        Some("Dots"),
    )?;
    daemon.check(
        "multiple drawing-group segments",
        &single(&rev)?,
        Some("Jpeg"),
    )?;
    daemon.check(
        "direct TIFF record",
        &single(&workbook(&[picture(0xf029, 0x6e4, TIFF, false)], &[], 0x3c))?,
        Some("Tiff"),
    )?;
    let book = compound(&[("Book", &dual)])?;
    daemon.check("Book skips picture scan", &book, None)?;
    let book_hash = Server::start(
        stock,
        "",
        &(hash("Book", &book)? + &hash("RawBook", &dual)?),
        "",
        "",
    )?;
    book_hash.check("Book outer remains eligible", &book, Some("Book"))?;
    let breaks = (8192..dib.len()).step_by(8192).collect::<Vec<_>>();
    let large = single(&workbook(
        &[picture(0xf01f, 0x7a8, &dib, true)],
        &breaks,
        0x3c,
    ))?;
    daemon.check(
        "DIB with multiple continuations and disk spool",
        &large,
        Some("Dib"),
    )?;
    let only = Server::start(stock, "", &hash("Workbook", &wb)?, "", "")?;
    only.check("raw Workbook skipped", EXCEL, None)?;
    only.check("direct Workbook hash", &wb, Some("Workbook"))?;
    let outer = Server::start(
        stock,
        "",
        &(hash("Workbook", &wb)? + &hash("Outer", EXCEL)?),
        "",
        "",
    )?;
    outer.check("outer hash after pictures", EXCEL, Some("Outer"))?;
    let siblings = Server::start(stock, "", &hash("Jpeg", JPEG)?, "", "")?;
    let one = workbook(&[dots], &[], 0x3c);
    siblings.check(
        "unrelated OLE sibling omitted",
        &compound(&[("Workbook", &one), ("Sibling", JPEG)])?,
        None,
    )?;
    let mixed = single(&dual)?;
    for (options, expected) in [
        (
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                mixed.len() + JPEG.len()
            ),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
        (
            "MaxFiles 2\nAlertExceedsMax yes".into(),
            "Heuristics.Limits.Exceeded.MaxFiles",
        ),
    ] {
        Server::start(stock, &options, &hash("Jpeg", JPEG)?, "", "")?.check(
            "later picture after a limit",
            &mixed,
            Some(expected),
        )?;
    }
    let report = Server::start(
        stock,
        "",
        &(files.clone() + &hash("Report", REPORT)?),
        "",
        "",
    )?;
    report.check("report hash before PNG", EXCEL, Some("Report"))?;
    report.check(
        "authored ordinary formulas preserve the short report",
        CALC,
        Some("Report"),
    )?;
    daemon.check(
        "authored arithmetic and square root formulas before picture",
        CALC,
        Some("Dots"),
    )?;
    let integer = [0x1e, 2, 0];
    for tokens in [
        [integer.as_slice(), &[0x1e, 3, 0, 0x03]].concat(), // 2+3
        vec![0x44, 4, 0, 1, 0xc0, 0x1e, 2, 0, 0x05, 0x41, 0x14, 0], // SQRT(B5*2)
        vec![0x25, 0, 0, 3, 0, 0, 0, 0, 0, 0x19, 0x10, 0, 0], // SUM(A1:A4)
        [vec![0x1f], f64::MAX.to_le_bytes().to_vec()].concat(),
    ] {
        let mut cell = vec![0; 22];
        cell[20..22].copy_from_slice(&(tokens.len() as u16).to_le_bytes());
        cell.extend(tokens);
        let doc = single(&[biff(6, &cell), one.clone()].concat())?;
        report.check("short formula report before image", &doc, Some("Report"))?;
        daemon.check("image after short formula report", &doc, Some("Dots"))?;
    }
    // A long sum of ordinary integer literals fills the stock report buffer.
    let mut tokens = integer.to_vec();
    for _ in 0..350 {
        tokens.extend(integer);
        tokens.push(3);
    }
    let mut cell = vec![0; 22];
    cell[20..22].copy_from_slice(&(tokens.len() as u16).to_le_bytes());
    cell.extend(tokens);
    let long = single(&[biff(6, &cell), one.clone()].concat())?;
    report.check(
        "multi-block formula report cannot match its preamble hash",
        &long,
        Some("Dots"),
    )?;
    let needle = b"BIFF content extracted"
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    for (target, expected) in [(0, "ReportBody"), (7, "Dots")] {
        let rules = format!("Xls.ReportBody:{target}:*:{needle}\n");
        Server::start(stock, "", &files, &rules, "")?.check(
            "report target",
            EXCEL,
            Some(expected),
        )?;
    }
    let options = [
        ("ScanOLE2 no".into(), None),
        ("ScanImage no".into(), Some("Dots")),
        (
            "MaxRecursion 1\nAlertExceedsMax yes".into(),
            Some("Heuristics.Limits.Exceeded.MaxRecursion"),
        ),
        (
            "MaxFiles 1\nAlertExceedsMax yes".into(),
            Some("Heuristics.Limits.Exceeded.MaxFiles"),
        ),
        ("MaxFiles 2\nAlertExceedsMax yes".into(), Some("Dots")),
        (
            format!(
                "MaxFiles 1\nMaxScanSize {}\nAlertExceedsMax yes",
                EXCEL.len() + REPORT.len() - 1
            ),
            Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        ),
        (
            format!(
                "MaxFiles 1\nMaxScanSize {}\nAlertExceedsMax yes",
                EXCEL.len() + REPORT.len()
            ),
            Some("Heuristics.Limits.Exceeded.MaxFiles"),
        ),
        (
            format!("MaxFileSize {}\nAlertExceedsMax yes", EXCEL.len() - 1),
            Some("Heuristics.Limits.Exceeded.MaxFileSize"),
        ),
        (
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                EXCEL.len() + DOTS.len() - 1
            ),
            Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        ),
        (
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                EXCEL.len() + DOTS.len()
            ),
            Some("Dots"),
        ),
    ];
    for (opts, expected) in options {
        Server::start(stock, &opts, &files, "", "")?.check(&opts, EXCEL, expected)?;
    }
    let mut formula = vec![0; 22];
    formula[6..14].copy_from_slice(&3f64.to_le_bytes());
    formula[20] = 3;
    formula.extend([0x1e, 3, 0]); // An ordinary numeric formula with a cached result of three.
    let formula = biff(6, &formula);
    let small_png = include_bytes!("fixtures/images/blue.png");
    let small = picture(0xf01e, 0x6e0, small_png, true);
    let large = picture(0xf01e, 0x6e0, DOTS, true);
    for (pictures, winner, with_outer) in [
        (
            vec![large.clone()],
            "Heuristics.Limits.Exceeded.MaxScanSize",
            "Outer",
        ),
        (
            vec![large.clone(), small.clone()],
            "Heuristics.Limits.Exceeded.MaxScanSize",
            "Outer",
        ),
        (vec![small, large], "Small", "Small"),
    ] {
        let bytes = single(&[formula.as_slice(), &workbook(&pictures, &[], 0x3c)].concat())?;
        let config = format!(
            "MaxScanSize {}\nAlertExceedsMax yes",
            bytes.len() + REPORT.len() - 1
        );
        let pictures = files.clone() + &hash("Small", small_png)?;
        Server::start(stock, &config, &pictures, "", "")?.check(
            "size-only limit before formula listing",
            &bytes,
            Some(winner),
        )?;
        Server::start(
            stock,
            &config,
            &(pictures + &hash("Outer", &bytes)?),
            "",
            "",
        )?
        .check(
            "outer hash after size-limited report and pictures",
            &bytes,
            Some(with_outer),
        )?;
    }
    for prefix in [formula, biff(0xe0, &[0; 20]).repeat(113)] {
        let bytes = single(&[prefix.as_slice(), &one].concat())?;
        for (key, limit) in [
            ("MaxFiles", "Heuristics.Limits.Exceeded.MaxFiles"),
            ("MaxRecursion", "Heuristics.Limits.Exceeded.MaxRecursion"),
        ] {
            for (budget, expected) in [
                (100_000usize, limit),
                (REPORT.len(), limit),
                (REPORT.len() - 1, "Heuristics.Limits.Exceeded.MaxScanSize"),
            ] {
                let config = format!(
                    "{key} 1\nMaxScanSize {}\nAlertExceedsMax yes",
                    bytes.len() + budget
                );
                Server::start(stock, &config, &files, "", "")?.check(
                    "blocked formula or format list",
                    &bytes,
                    Some(expected),
                )?;
            }
        }
    }
    Ok(())
}

fn authored_metafiles(stock: bool) -> io::Result<()> {
    let book = include_bytes!("fixtures/xls/crate-outlines.xls");
    let wmf = "b80c156709b188c8bc263b8a0e7b256a:41:Xls.WMF\n";
    let emf = "40e48a9cff66ac7b104bd8a40ef763e2:72:Xls.EMF\n";
    let pict = "00a277a99f11444c41d1c67e7ec959f1:501:Xls.PICT\n";
    let originals = "d3958a6410d157a69a68f9a93b893bf8:48:Xls.OriginalWMF\n\
        1b40ff308054784c0f4adc36229e8aa7:132:Xls.OriginalEMF\n\
        544b96154f8d71b8cd42bc47e3a35554:534:Xls.OriginalPICT\n";
    let outer = hash("Outer", book)?;
    let all = [wmf, emf, pict, originals, &outer].concat();
    for (rules, options, expected) in [
        (all.as_str(), "", Some("WMF")),
        (emf, "", Some("EMF")),
        (pict, "", Some("PICT")),
        (originals, "", None),
        (outer.as_str(), "", Some("Outer")),
        (all.as_str(), "ScanOLE2 no", Some("Outer")),
    ] {
        Server::start(stock, options, rules, "", "")?.check("crate outlines", book, expected)?;
    }
    let drawings = Server::start(stock, "", &all, "", "")?;
    for (kind, first, expected) in [
        (0xf01bu16, 0x216u16, "WMF"),
        (0xf01a, 0x3d4, "EMF"),
        (0xf01c, 0x542, "PICT"),
    ] {
        let tag = [(first << 4).to_le_bytes(), kind.to_le_bytes()].concat();
        let start = book.windows(4).position(|bytes| bytes == tag).unwrap();
        let size = u32::from_le_bytes(book[start + 4..start + 8].try_into().unwrap()) as usize;
        let body = &book[start + 8..][..size];
        // Keep the writer's image and metadata. Add a second 16-byte identifier.
        let two = [[0x3b; 16].as_slice(), body].concat();
        for (instance, payload) in [(first, body), (first + 1, two.as_slice())] {
            let blip = art(kind, instance << 4, payload);
            let bare = single(&workbook(&[blip], &[], 0x3c))?;
            drawings.check("bare metafile", &bare, Some(expected))?;
        }
    }
    Ok(())
}

#[test]
fn barnacle_excel_pictures() -> io::Result<()> {
    compare(false)
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_excel_pictures() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(true)
}

#[test]
fn picture_parent_and_filename() -> io::Result<()> {
    let temp = tempfile::tempdir()?;
    let nested = compound(&[("Sheet/Workbook", &authored_drawing()?)])?;
    for file in [EXCEL, &nested] {
        let mut count = 0;
        scan(
            file,
            &Options::default(),
            temp.path(),
            |obj, _| {
                if obj.bytes == DOTS {
                    assert_eq!(
                        obj.parents.iter().map(|p| p.file_type).collect::<Vec<_>>(),
                        ["CL_TYPE_MSOLE2"]
                    );
                    assert_eq!(obj.layer.file_type, "CL_TYPE_PNG");
                    assert!(obj.layer.name.is_none());
                    count += 1;
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert_eq!(count, 1);
    }
    Ok(())
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_picture_parent_and_filename() -> io::Result<()> {
    let needle = DOTS[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let nested = compound(&[("Sheet/Workbook", &authored_drawing()?)])?;
    for (parent, expected) in [("CL_TYPE_MSOLE2", Some("Parent")), ("CL_TYPE_MSXL", None)] {
        let rules = format!(
            "Xls.Parent;Engine:81-255,Target:0,Container:{parent},FileSize:{0}-{0};0;{needle}\n",
            DOTS.len()
        );
        let s = Server::start(true, "", "", "", &rules)?;
        s.check(parent, EXCEL, expected)?;
        s.check(parent, &nested, expected)?;
        s.check("direct PNG", DOTS, None)?;
    }
    let s = Server::start(
        true,
        "GenerateMetadataJson yes\nLeaveTemporaryFiles yes",
        &hash("Unrelated", JPEG)?,
        "",
        "",
    )?;
    s.check("metadata", EXCEL, None)?;
    let mut dirs = vec![s._dir.path().to_path_buf()];
    let mut found = false;
    while let Some(d) = dirs.pop() {
        for f in fs::read_dir(d)? {
            let f = f?;
            if f.file_type()?.is_dir() {
                dirs.push(f.path());
            } else if f.file_name() == "metadata.json" {
                let info: serde_json::Value = serde_json::from_slice(&fs::read(f.path())?)?;
                if info["FileType"] == "CL_TYPE_MSXL" {
                    let image = &info["ContainedObjects"][0];
                    assert_eq!(image["FileType"], "CL_TYPE_PNG");
                    assert_eq!(image["FileSize"], DOTS.len());
                    assert!(image["FileName"].is_null());
                    found = true;
                }
            }
        }
    }
    assert!(found);
    Ok(())
}

fn delayed_png(size: usize, offset: u32, name: &[u8]) -> Vec<u8> {
    let mut reference = vec![0; 36];
    reference[..2].fill(6);
    reference[20..24].copy_from_slice(&(size as u32).to_le_bytes());
    reference[24] = 1;
    reference[28..32].copy_from_slice(&offset.to_le_bytes());
    reference[33] = name.len() as u8;
    reference.extend(name);
    art(0xf007, 0x62, &reference)
}

fn compare_delayed_and_multiple_workbooks(stock: bool) -> io::Result<()> {
    let raw_png = picture(0xf01e, 0x6e0, DOTS, false);
    let png = picture(0xf01e, 0x6e0, DOTS, true);
    let jpg = picture(0xf01d, 0x46a, JPEG, true);
    let delayed = delayed_png(raw_png.len(), 8, b"P\0i\0c\0\0\0");
    let delayed_only = workbook(std::slice::from_ref(&delayed), &[], 0x3c);
    let delayed_then_inline = workbook(&[delayed, jpg.clone()], &[], 0x3c);
    let trailing = single(&[delayed_then_inline.as_slice(), raw_png.as_slice()].concat())?;
    let padded = single(&[delayed_then_inline.as_slice(), &[0; 4096]].concat())?;
    let mut padded_authored = Vec::new();
    cfb::CompoundFile::open(Cursor::new(EXCEL))?
        .open_stream("Workbook")?
        .read_to_end(&mut padded_authored)?;
    padded_authored.resize(padded_authored.len() + 512, 0);
    let padded_authored = single(&padded_authored)?;
    let adjacent = single(&workbook(
        &[
            delayed_png(raw_png.len(), 0, &[]),
            raw_png.clone(),
            jpg.clone(),
        ],
        &[],
        0x3c,
    ))?;
    let delay_stream = [&[0; 8][..], raw_png.as_slice()].concat();
    let in_data = compound(&[("Workbook", &delayed_then_inline), ("Data", &delay_stream)])?;
    let in_pictures = compound(&[
        ("Workbook", &delayed_then_inline),
        ("Sheet/Pictures", &delay_stream),
    ])?;
    let png_book = workbook(&[png], &[], 0x3c);
    let jpg_book = workbook(&[jpg], &[], 0x3c);
    let root_book = compound(&[("Workbook", &png_book), ("Book", &jpg_book)])?;
    let reversed_book = compound(&[("Book", &jpg_book), ("Workbook", &png_book)])?;
    let nested = compound(&[("Sheet/Workbook", &jpg_book)])?;
    let root_and_nested = compound(&[("Workbook", &png_book), ("Sheet/Workbook", &jpg_book)])?;
    let delayed_and_nested =
        compound(&[("Workbook", &delayed_only), ("Sheet/Workbook", &jpg_book)])?;
    let empty = biff(0xa, &[]);
    let drawing_free_root = compound(&[("Workbook", &empty), ("Sheet/Workbook", &jpg_book)])?;
    let shadowed_book = compound(&[("Book", &jpg_book), ("Workbook", &empty)])?;

    let png_rule = hash("Dots", DOTS)?;
    let jpg_rule = hash("Jpeg", JPEG)?;
    let image_rules = png_rule.clone() + &jpg_rule;
    let outer = hash("Outer", &delayed_and_nested)? + &hash("Outer", &shadowed_book)?;
    let server = Server::start(stock, "", &(image_rules.clone() + &outer), "", "")?;
    for (name, file, expected) in [
        ("delayed Data followed by inline picture", &in_data, "Jpeg"),
        (
            "delayed Pictures followed by inline picture",
            &in_pictures,
            "Jpeg",
        ),
        ("delayed entry followed by a bare PNG", &adjacent, "Dots"),
        ("zero-padded Workbook", &padded, "Jpeg"),
        ("Workbook before Book", &root_book, "Dots"),
        ("Workbook before earlier Book", &reversed_book, "Dots"),
        ("nested Workbook", &nested, "Jpeg"),
        ("root before nested Workbook", &root_and_nested, "Dots"),
        (
            "delayed-only root stops nested drawing pass",
            &delayed_and_nested,
            "Outer",
        ),
        (
            "drawing-free root permits nested Workbook",
            &drawing_free_root,
            "Jpeg",
        ),
        (
            "drawing-free Workbook shadows root Book",
            &shadowed_book,
            "Outer",
        ),
    ] {
        server.check(name, file, Some(expected))?;
    }
    let png_only = Server::start(stock, "", &png_rule, "", "")?;
    png_only.check("Data delay image remains unscanned", &in_data, None)?;
    png_only.check("Pictures delay image remains unscanned", &in_pictures, None)?;
    Server::start(stock, "", &jpg_rule, "", "")?.check(
        "root picture miss permits nested Workbook",
        &root_and_nested,
        Some("Jpeg"),
    )?;
    for (count, expected) in [(2, "Heuristics.Limits.Exceeded.MaxFiles"), (3, "Jpeg")] {
        let config = format!("MaxFiles {count}\nAlertExceedsMax yes");
        Server::start(stock, &config, &jpg_rule, "", "")?.check(
            "root picture miss consumes one slot before the nested picture",
            &root_and_nested,
            Some(expected),
        )?;
    }
    let report = hash("Report", REPORT)?;
    let reports = Server::start(
        stock,
        "",
        &(image_rules.clone() + &report + &hash("Outer", &trailing)?),
        "",
        "",
    )?;
    reports.check(
        "report precedes the later inline picture",
        &in_data,
        Some("Report"),
    )?;
    reports.check(
        "bare OfficeArt after EOF leaves the outer hash eligible",
        &trailing,
        Some("Outer"),
    )?;
    reports.check(
        "zero padding changes the report hash",
        &padded,
        Some("Jpeg"),
    )?;
    reports.check(
        "authored padded Workbook keeps the picture eligible",
        &padded_authored,
        Some("Dots"),
    )?;
    let padded_report = "4135b615fd510e9d7a93ba8d19fbb979:4213:Xls.PaddedReport\n";
    Server::start(stock, "", &(image_rules.clone() + padded_report), "", "")?.check(
        "exact padded report precedes the picture",
        &padded_authored,
        Some("PaddedReport"),
    )?;
    for (options, expected) in [
        ("ScanOLE2 no".to_owned(), None),
        (
            "MaxFiles 1\nAlertExceedsMax yes".into(),
            Some("Heuristics.Limits.Exceeded.MaxFiles"),
        ),
        ("MaxFiles 2\nAlertExceedsMax yes".into(), Some("Jpeg")),
        (
            "MaxRecursion 1\nAlertExceedsMax yes".into(),
            Some("Heuristics.Limits.Exceeded.MaxRecursion"),
        ),
        (
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                in_data.len() + JPEG.len()
            ),
            Some("Jpeg"),
        ),
        (
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                in_data.len() + JPEG.len() - 1
            ),
            Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        ),
    ] {
        Server::start(stock, &options, &image_rules, "", "")?
            .check(&options, &in_data, expected)?;
    }
    Ok(())
}

#[test]
fn barnacle_delayed_and_multiple_workbooks() -> io::Result<()> {
    compare_delayed_and_multiple_workbooks(false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_delayed_and_multiple_workbooks() -> io::Result<()> {
    compare_delayed_and_multiple_workbooks(true)?;
    let png = workbook(&[picture(0xf01e, 0x6e0, DOTS, true)], &[], 0x3c);
    let jpg = workbook(&[picture(0xf01d, 0x46a, JPEG, true)], &[], 0x3c);
    let rules = hash("Dots", DOTS)? + &hash("Jpeg", JPEG)?;
    let stock = Server::start(true, "", &rules, "", "")?;
    let barnacle = Server::start(false, "", &rules, "", "")?;
    let left = ("Notes/Workbook", png.as_slice());
    let right = ("Inventory/Workbook", jpg.as_slice());
    for order in [[left, right], [right, left]] {
        let frame = stream_frame(&compound(&order)?)?;
        let expected = unix_request(&stock.sock, &frame)?;
        assert!(matches!(
            expected.as_str(),
            "stream: Xls.Dots.UNOFFICIAL FOUND\0" | "stream: Xls.Jpeg.UNOFFICIAL FOUND\0"
        ));
        assert_eq!(unix_request(&barnacle.sock, &frame)?, expected);
    }
    Ok(())
}

fn compare_mixed_office_passes(stock: bool) -> io::Result<()> {
    let workbook = workbook(&[picture(0xf01e, 0x6e0, DOTS, true)], &[], 0x3c);
    let word = b"Passive Word stream description.\n";
    let note = b"A note attached to the inventory workbook.\n";
    let slide = b"Inventory notes from the presentation attachment.\n";
    let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    zlib.write_all(slide)?;
    let compressed = [
        (slide.len() as u32).to_le_bytes().as_slice(),
        &zlib.finish()?,
    ]
    .concat();
    let presentation = art(0x1011, 0x10, &compressed);
    let mut native = b"\x02\0note.txt\0note.txt\0\0\0\0\0\0\0\0\0note.txt\0".to_vec();
    native.extend((note.len() as u32).to_le_bytes());
    native.extend(note);
    let package = [(native.len() as u32).to_le_bytes().as_slice(), &native].concat();
    let root_word = compound(&[("Workbook", &workbook), ("WordDocument", word)])?;
    let nested_workbook = compound(&[("Sheet/Workbook", &workbook), ("WordDocument", word)])?;
    let root_package = compound(&[("Workbook", &workbook), ("\x01Ole10Native", &package)])?;
    let nested_package = compound(&[("Workbook", &workbook), ("Sheet/\x01Ole10Native", &package)])?;
    let root_slide = compound(&[
        ("Workbook", &workbook),
        ("PowerPoint Document", &presentation),
    ])?;
    let root_all = compound(&[
        ("Workbook", &workbook),
        ("PowerPoint Document", &presentation),
        ("\x01Ole10Native", &package),
    ])?;
    let nested_slide = compound(&[
        ("Workbook", &workbook),
        ("Sheet/PowerPoint Document", &presentation),
    ])?;
    let nested_all = compound(&[
        ("Sheet/Workbook", &workbook),
        ("Sheet/PowerPoint Document", &presentation),
        ("Sheet/\x01Ole10Native", &package),
    ])?;
    let picture_rule = hash("Dots", DOTS)?;
    let workbook_rule = hash("Workbook", &workbook)?;
    let report_rule = hash("Report", REPORT)?;
    let attachment_rule = hash("Attachment", note)?;
    let slide_rule = hash("Slide", slide)?;
    let picture_and_raw = picture_rule.clone() + &workbook_rule;
    let all = picture_and_raw.clone() + &report_rule + &attachment_rule + &slide_rule;
    let server = Server::start(stock, "", &all, "", "")?;
    for (label, doc, expected) in [
        (
            "root Workbook report before Word raw pass",
            &root_word,
            "Report",
        ),
        (
            "raw nested Workbook before its report",
            &nested_workbook,
            "Workbook",
        ),
        ("root Package before report", &root_package, "Attachment"),
        ("root Package before PowerPoint", &root_all, "Attachment"),
        (
            "root PowerPoint attachment before report",
            &root_slide,
            "Slide",
        ),
        (
            "root report before nested Package",
            &nested_package,
            "Report",
        ),
    ] {
        server.check(label, doc, Some(expected))?;
    }
    let without_report = Server::start(stock, "", &picture_and_raw, "", "")?;
    without_report.check("root picture before raw Workbook", &root_word, Some("Dots"))?;
    without_report.check(
        "root picture before raw Package pass",
        &root_package,
        Some("Dots"),
    )?;
    let raw = Server::start(stock, "", &workbook_rule, "", "")?;
    raw.check(
        "raw Workbook is eligible after the drawing miss",
        &root_word,
        Some("Workbook"),
    )?;
    let attachment = Server::start(stock, "", &attachment_rule, "", "")?;
    attachment.check(
        "nested Package is eligible after root passes",
        &nested_package,
        Some("Attachment"),
    )?;
    let picture = Server::start(stock, "", &picture_rule, "", "")?;
    picture.check(
        "nested picture is eligible after the raw miss",
        &nested_workbook,
        Some("Dots"),
    )?;
    let children = Server::start(
        stock,
        "",
        &(picture_rule.clone() + &slide_rule + &attachment_rule),
        "",
        "",
    )?;
    children.check(
        "root drawing before nested PowerPoint",
        &nested_slide,
        Some("Dots"),
    )?;
    children.check(
        "nested Package before its sibling PowerPoint and drawing",
        &nested_all,
        Some("Attachment"),
    )?;

    let count = "MaxFiles 2\nAlertExceedsMax yes";
    let file_limit = "Heuristics.Limits.Exceeded.MaxFiles";
    let limited = Server::start(stock, count, &picture_rule, "", "")?;
    limited.check("root Word keeps the picture slot", &root_word, Some("Dots"))?;
    limited.check(
        "root Package consumes the picture slot",
        &root_package,
        Some(file_limit),
    )?;
    limited.check(
        "raw nested Workbook consumes the picture slot",
        &nested_workbook,
        Some(file_limit),
    )?;
    let outer_rule = hash("Outer", &root_package)?;
    for options in [
        "ScanOLE2 no",
        "MaxFiles 1\nAlertExceedsMax yes",
        "MaxRecursion 1\nAlertExceedsMax yes",
    ] {
        Server::start(stock, options, &(all.clone() + &outer_rule), "", "")?.check(
            "outer file remains eligible when children are excluded",
            &root_package,
            Some("Outer"),
        )?;
    }
    let exact = format!(
        "MaxScanSize {}\nMaxRecursion 1\nAlertExceedsMax yes",
        root_slide.len()
    );
    Server::start(stock, &exact, &all, "", "")?.check(
        "zero remaining bytes skip the Office passes",
        &root_slide,
        None,
    )?;
    let exact = format!(
        "MaxScanSize {}\nAlertExceedsMax yes",
        nested_all.len() + note.len()
    );
    Server::start(stock, &exact, &(all + &hash("Outer", &nested_all)?), "", "")?.check(
        "oversized raw stream stops the nested attachment pass",
        &nested_all,
        Some("Outer"),
    )?;
    for (room, limit) in [
        (note.len() - 1, "MaxScanSize"),
        (note.len(), "MaxRecursion"),
    ] {
        let config = format!(
            "MaxScanSize {}\nMaxRecursion 1\nAlertExceedsMax yes",
            root_package.len() + room
        );
        let expected = format!("Heuristics.Limits.Exceeded.{limit}");
        Server::start(stock, &config, &attachment_rule, "", "")?.check(
            "recovered Package size precedes the recursion limit",
            &root_package,
            Some(&expected),
        )?;
    }
    Ok(())
}

#[test]
fn barnacle_mixed_office_passes() -> io::Result<()> {
    compare_mixed_office_passes(false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_mixed_office_passes() -> io::Result<()> {
    compare_mixed_office_passes(true)
}

#[test]
fn unsupported_report_layout_is_incomplete() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let png = picture(0xf01e, 0x6e0, DOTS, true);
    let ordinary = workbook(std::slice::from_ref(&png), &[], 0x3c);
    let mut long = biff(0x7777, &[]).repeat(300);
    long.extend_from_slice(&ordinary);
    let verdict = scan(
        &single(&long)?,
        &Options::default(),
        tmp.path(),
        |obj, _| {
            Ok(if obj.bytes == DOTS {
                Verdict::Found("early picture".into())
            } else {
                Verdict::Miss
            })
        },
        || Ok(()),
    )?;
    assert_eq!(verdict, Verdict::Incomplete);
    Ok(())
}

#[test]
fn blocked_drawings_avoid_scratch_and_io_errors_propagate() -> io::Result<()> {
    let temp = tempfile::tempdir()?;
    let missing = temp.path().join("missing");
    let dib = bitmap();
    let breaks = (8192..dib.len()).step_by(8192).collect::<Vec<_>>();
    let file = single(&workbook(
        &[picture(0xf01f, 0x7a8, &dib, true)],
        &breaks,
        0x3c,
    ))?;
    let blocked = Options {
        max_files: 1,
        alert_exceeds_max: true,
        ..Options::default()
    };
    assert_eq!(
        scan(
            &file,
            &blocked,
            &missing,
            |_, _| Ok(Verdict::Miss),
            || Ok(())
        )?,
        Verdict::Found("Heuristics.Limits.Exceeded.MaxFiles".into())
    );
    let err = scan(
        &file,
        &Options::default(),
        &missing,
        |_, _| Ok(Verdict::Miss),
        || Ok(()),
    )
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    Ok(())
}

const LEDGER: &[u8] = include_bytes!("fixtures/xls/ledger-summary.xls");

fn authored_drawing() -> io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    cfb::CompoundFile::open(Cursor::new(CALC))?
        .open_stream("Workbook")?
        .read_to_end(&mut raw)?;
    let mut records = raw.as_slice();
    while let Some((header, rest)) = records.split_at_checked(4) {
        let n = u16::from_le_bytes([header[2], header[3]]) as usize;
        let (payload, tail) = rest.split_at(n);
        if header[..2] == [0xeb, 0] {
            return Ok([biff(0xeb, payload), biff(10, &[])].concat());
        }
        records = tail;
    }
    Err(io::Error::other("authored fixture has no drawing group"))
}

fn compare_large_reports(stock: bool) -> io::Result<()> {
    let outlines = include_bytes!("fixtures/xls/crate-outlines.xls");
    // The pinned daemon matches its preamble and the first 4,096 report bytes.
    let poi_report = "3beb549f5169220d13ee4707287885c1:4213:Xls.PoiReport\n";
    let competing = poi_report.to_owned() + &hash("WholeWorkbook", outlines)?;
    for (room, expected) in [(4212, "WholeWorkbook"), (4213, "PoiReport")] {
        let options = format!("MaxScanSize {}\nAlertExceedsMax yes", outlines.len() + room);
        Server::start(stock, &options, &competing, "", "")?.check(
            "Apache POI report cutoff and outer hash",
            outlines,
            Some(expected),
        )?;
    }
    // The pinned daemon accepted each exact hash with the picture HDB loaded at the same time.
    let rules = hash("Dots", DOTS)?
        + &hash("Preamble", REPORT)?
        + "7471d03533bdbc5afcf0628e340bbb07:4213:Xls.Sum\n6d6770fb32f9b3c0931eb6efcc1b7359:16501:Xls.Ledger\n74d3a2f47bf4f858f6abc8e065e8b55e:4213:Xls.Next\n274ef05da79cc224b17913cadb9c17a4:4213:Xls.Exact\n";
    let drawing = authored_drawing()?;
    let stream = |prefix: &[u8]| single(&[prefix, drawing.as_slice()].concat());
    let scan = Server::start(stock, "", &rules, "", "")?;
    scan.check(
        "120-row worksheet with a final SUM and a picture",
        LEDGER,
        Some("Ledger"),
    )?;
    Server::start(stock, "", &hash("Dots", DOTS)?, "", "")?.check(
        "picture after ledger report miss",
        LEDGER,
        Some("Dots"),
    )?;
    for (formats, ends, expected) in [
        (0, 125, "Preamble"),
        (11, 113, "Preamble"),
        (22, 101, "Next"),
        (75, 171, "Exact"),
    ] {
        let doc = stream(
            &[
                biff(224, &[0; 20]).repeat(formats),
                biff(10, &[]).repeat(ends),
            ]
            .concat(),
        )?;
        scan.check(
            "4095, 4096, 4097, and 8192 formatted bytes",
            &doc,
            Some(expected),
        )?;
    }
    let mut ints = vec![30, 2, 0];
    for _ in 0..350 {
        ints.extend([30, 2, 0, 3]);
    }
    let mut cell = vec![0; 22];
    cell[20..22].copy_from_slice(&(ints.len() as u16).to_le_bytes());
    cell.extend(ints);
    scan.check(
        "350-term sum report before PNG",
        &stream(&biff(6, &cell))?,
        Some("Sum"),
    )?;

    let xf = b"00e0     20   XF : Extended Format\n";
    let data = [REPORT, &xf.repeat(300)[..8192]].concat();
    let repeated = stream(&biff(224, &[0; 20]).repeat(300))?;
    let mut small_formula = vec![0; 22];
    small_formula[20] = 3;
    small_formula.extend([30, 2, 0]);
    let uncertain = stream(&[biff(6, &small_formula), biff(224, &[0; 20]).repeat(300)].concat())?;
    scan.check(
        "an uncertain formula suffix inside a flushed block",
        &uncertain,
        stock.then_some("Dots"),
    )?;
    let small_budget = format!(
        "MaxScanSize {}\nAlertExceedsMax yes",
        uncertain.len() + DOTS.len()
    );
    Server::start(stock, &small_budget, &rules, "", "")?.check(
        "known oversize report permits the picture",
        &uncertain,
        Some("Dots"),
    )?;
    let hashes = hash("Format", &data)? + &hash("Dots", DOTS)? + &hash("Outer", &repeated)?;
    let needle = xf.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let body = format!("Xls.Line:0:*:{needle}\n");
    Server::start(stock, "", &hashes, &body, "")?.check(
        "body before format report hash",
        &repeated,
        Some("Line"),
    )?;
    Server::start(stock, "", &hashes, "", "")?.check(
        "format report wins against PNG and outer hash",
        &repeated,
        Some("Format"),
    )?;
    for (files, delta, expected) in [
        (10, 0, "Format"),
        (10, -1, "Dots"),
        (1, 0, "Outer"),
        (1, -1, "Outer"),
    ] {
        let budget = (repeated.len() + data.len())
            .checked_add_signed(delta)
            .unwrap();
        let config = format!("MaxFiles {files}\nMaxScanSize {budget}\nAlertExceedsMax yes");
        Server::start(stock, &config, &hashes, "", "")?.check(
            "exact report byte budget",
            &repeated,
            Some(expected),
        )?;
        if files == 1 {
            let limit = if delta == 0 {
                "Heuristics.Limits.Exceeded.MaxFiles"
            } else {
                "Heuristics.Limits.Exceeded.MaxScanSize"
            };
            Server::start(stock, &config, &rules, "", "")?.check(
                "report size before count",
                &repeated,
                Some(limit),
            )?;
        }
    }
    for (offset, limit) in [
        (0, "Heuristics.Limits.Exceeded.MaxRecursion"),
        (-1, "Heuristics.Limits.Exceeded.MaxScanSize"),
    ] {
        let budget = (repeated.len() + data.len())
            .checked_add_signed(offset)
            .unwrap();
        let config = format!("MaxRecursion 1\nMaxScanSize {budget}\nAlertExceedsMax yes");
        Server::start(stock, &config, &rules, "", "")?.check(
            "report size before depth",
            &repeated,
            Some(limit),
        )?;
    }
    Server::start(
        stock,
        "MaxFiles 2\nAlertExceedsMax yes",
        &hash("Dots", DOTS)?,
        "",
        "",
    )?
    .check(
        "large report miss leaves a slot for the picture",
        &repeated,
        Some("Dots"),
    )?;
    let many = stream(&biff(10, &[]).repeat(4000))?;
    let file_limit = format!("MaxFileSize {}\nAlertExceedsMax yes", many.len());
    Server::start(stock, &file_limit, &hash("Other", JPEG)?, "", "")?.check(
        "report exceeds the per-file ceiling",
        &many,
        Some("Heuristics.Limits.Exceeded.MaxFileSize"),
    )?;
    Ok(())
}

#[test]
fn barnacle_large_biff_reports() -> io::Result<()> {
    compare_large_reports(false)?;
    compare_unknown_report_limits(false)
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_large_biff_reports() -> io::Result<()> {
    compare_large_reports(true)?;
    compare_unknown_report_limits(true)
}

fn compare_unknown_report_limits(stock: bool) -> io::Result<()> {
    let mut records = biff(0xe0, &[0; 20]).repeat(1400);
    for row in 0..128u16 {
        let mut data = [0; 16];
        data[..2].copy_from_slice(&row.to_le_bytes());
        // MULBLANK describes five empty cells with default formatting.
        data[14..16].copy_from_slice(&4u16.to_le_bytes());
        records.extend(biff(0x00be, &data));
    }
    records.extend(authored_drawing()?);
    let doc = single(&records)?;
    assert_eq!(doc.len(), 42496);
    let lower = REPORT.len() + 12 * 4096;
    let upper = REPORT.len() + 14 * 4096;
    let file_limit = "Heuristics.Limits.Exceeded.MaxFileSize";
    let scan_limit = "Heuristics.Limits.Exceeded.MaxScanSize";
    let miss = hash("Other", JPEG)?;
    let picture = hash("Dots", DOTS)?;
    let outer = hash("Outer", &doc)?;
    for (file, scan, reason) in [
        (doc.len(), 1 << 20, Some(file_limit)),
        (doc.len(), doc.len() + upper, Some(file_limit)),
        (doc.len(), doc.len() + lower - 1, Some(scan_limit)),
        // One endpoint crosses the scan budget. Stock's actual report fits that budget.
        (
            doc.len(),
            doc.len() + upper - 1,
            stock.then_some(file_limit),
        ),
        // The lower endpoint can enter and the upper one exceeds the per-file limit.
        (lower, 1 << 20, stock.then_some(file_limit)),
    ] {
        let opts = format!("MaxFileSize {file}\nMaxScanSize {scan}\nAlertExceedsMax yes");
        for (name, rules, result) in [
            ("limit", &miss, reason),
            ("picture", &picture, reason.map(|_| "Dots")),
            ("outer", &outer, reason.map(|_| "Outer")),
        ] {
            Server::start(stock, &opts, rules, "", "")?.check(
                &format!("{name} file={file} scan={scan}"),
                &doc,
                result,
            )?;
        }
    }
    Ok(())
}

#[test]
fn large_report_scratch_respects_admission() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let missing = tmp.path().join("missing");
    let data = single(&[biff(10, &[]).repeat(4000), authored_drawing()?].concat())?;
    for (files, budget, expected) in [
        (1, 200000, "Heuristics.Limits.Exceeded.MaxFiles"),
        (1, 66000, "Heuristics.Limits.Exceeded.MaxScanSize"),
        (10, 66000, "Heuristics.Limits.Exceeded.MaxScanSize"),
    ] {
        let o = Options {
            max_files: files,
            max_scan_size: (data.len() + budget) as u64,
            alert_exceeds_max: true,
            ..Default::default()
        };
        let v = scan(&data, &o, &missing, |_, _| Ok(Verdict::Miss), || Ok(()))?;
        assert_eq!(v, Verdict::Found(expected.into()));
    }
    let error = scan(
        &data,
        &Options::default(),
        &missing,
        |_, _| Ok(Verdict::Miss),
        || Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    Ok(())
}
