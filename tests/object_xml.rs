//! Ordinary Office 2003 and HWPML XML against the pinned reference daemon.
#[path = "common/base64.rs"]
mod base64;
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;
use md5::{Digest, Md5};
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

const FIRST: &[u8] = b"ordinary XML attachment";
const SECOND: &[u8] = b"a second XML attachment";
const A: &str = "b3JkaW5hcnkgWE1MIGF0dGFjaG1lbnQ=";
const B: &str = "YSBzZWNvbmQgWE1MIGF0dGFjaG1lbnQ=";
const WORD: &str = "w:wordDocument";
const EXCEL: &str = "Workbook";
const HWP: &str = "HWPML";

fn doc(root: &str, content: &str, offset: usize) -> Vec<u8> {
    let mut out = Vec::new();
    if root == HWP {
        out.extend([0xef, 0xbb, 0xbf]);
    }
    out.extend(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out.resize(offset.max(out.len()), b' ');
    out.extend(format!("<{root} xmlns:w=\"http://schemas.microsoft.com/office/word/2003/wordml\">{content}</{root}>").bytes());
    out
}

fn hash(bytes: &[u8], name: &str) -> String {
    let hex: String = Md5::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{hex}:{}:Local.{name}\n", bytes.len())
}

fn hwp_compressed(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes)?;
    let compressed = base64::encode(&encoder.finish()?);
    let compressed = doc(
        HWP,
        &format!(
            "<TAIL><BINDATA Compress=\"true\" Encoding=\"Base64\">{compressed}\n</BINDATA></TAIL>"
        ),
        0,
    );
    Ok(compressed)
}

struct Server {
    _dir: tempfile::TempDir,
    _process: daemon::Daemon,
    sock: std::path::PathBuf,
    stock: bool,
}

impl Server {
    fn start(stock: bool, config: &str, rules: &str, logical: &str) -> io::Result<Self> {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        if !rules.is_empty() {
            fs::write(db.join("samples.hdb"), rules)?;
        }
        if !logical.is_empty() {
            fs::write(db.join("samples.ldb"), logical)?;
        }
        let sock = dir.path().join("sock");
        let conf = dir.path().join("clamd.conf");
        fs::write(
            &conf,
            format!(
                "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nSelfCheck 0\nDisableCache yes\n{config}\n",
                sock.display(),
                db.display()
            ),
        )?;
        let exe = if stock {
            "/usr/sbin/clamd"
        } else {
            env!("CARGO_BIN_EXE_barnacle")
        };
        let process = daemon::Daemon::start(Path::new(exe), &conf, &sock)?;
        Ok(Self {
            _dir: dir,
            _process: process,
            sock,
            stock,
        })
    }

    fn check(&self, label: &str, data: &[u8], name: Option<&str>) -> io::Result<()> {
        let reply = daemon::unix_request(&self.sock, &daemon::stream_frame(data)?)?;
        let expected = match name {
            Some(n) if n.starts_with("Heuristics.") => format!("stream: {n} FOUND\0"),
            Some(n) => format!("stream: Local.{n}.UNOFFICIAL FOUND\0"),
            None if self.stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        assert_eq!(reply, expected, "{label}");
        Ok(())
    }
}

fn compare(stock: bool) -> io::Result<()> {
    let files = hash(FIRST, "First") + &hash(SECOND, "Second");
    let first = format!("<w:binData w:name=\"ordinary.txt\">\n{A}\n</w:binData>");
    let second = format!("<binData>{B}\n</binData>");
    let word = doc(
        WORD,
        &format!("<w:docOleData>{first}{second}</w:docOleData>"),
        0,
    );
    let excel = doc(EXCEL, &format!("<Worksheet>{second}{first}</Worksheet>"), 0);
    let hwp = doc(
        HWP,
        &format!(
            "<TAIL><BINDATASTORAGE><BINDATA Id=\"1\" Compress=\"false\" Encoding=\"Base64\">\n{A}\n</BINDATA></BINDATASTORAGE></TAIL>"
        ),
        0,
    );
    let mut hashes =
        files.clone() + &hash(&word, "Word") + &hash(&excel, "Excel") + &hash(&hwp, "Hwp");
    // Ordinary XML can refer to these formats without selecting their attachment handler.
    // A competing decoded attachment hash makes an incorrect classification observable.
    let mut ordinary = Vec::new();
    let version = r#"version="1.0""#;
    for (name, declaration, tag) in [
        ("WorkbookLower", version, "workbook"),
        ("WorkbookUpper", version, "WORKBOOK"),
        ("SingleQuote", "version='1.0'", "Workbook"),
        ("LongPrefix", version, "ss:Workbook xmlns:ss='urn:billing'"),
        ("WorkbookValue", version, "catalog ref='urn:Workbook'"),
        (
            "WorkbookPath",
            version,
            "catalog src='xl/workbook.xml' workbookViewId='2'",
        ),
        ("WordValue", version, "catalog format='Word.Document'"),
        (
            "WordPath",
            version,
            "catalog src='documents/wordDocument.xml'",
        ),
        (
            "HwpPath",
            version,
            "catalog src='documents/HWPML/receipt.xml'",
        ),
    ] {
        let root = tag.split_ascii_whitespace().next().unwrap();
        let body = format!("<?xml {declaration}?><{tag}><binData>{A}\n</binData></{root}>");
        hashes += &hash(body.as_bytes(), name);
        ordinary.push((name, body));
    }
    let note = format!(
        r#"<?xml version="1.0"?><report><note>Export Word.Document or HWPML</note><binData>{A}&#10;</binData></report>"#
    );
    hashes += &hash(note.as_bytes(), "OfficeNamesInText");
    ordinary.push(("OfficeNamesInText", note));
    let daemon = Server::start(stock, "", &hashes, "")?;
    for (name, body) in ordinary {
        daemon.check(name, body.as_bytes(), Some(name))?;
    }
    daemon.check("Word child before document", &word, Some("First"))?;
    daemon.check("Excel reversed children", &excel, Some("Second"))?;
    daemon.check("HWP base64", &hwp, Some("First"))?;
    let compressed = hwp_compressed(FIRST)?;
    daemon.check("HWP deflate attachment", &compressed, Some("First"))?;
    daemon.check(
        "Unknown HWP encoding retains text",
        &doc(
            HWP,
            "<TAIL><BINDATA Encoding=\"Text\">ordinary XML attachment</BINDATA></TAIL>",
            0,
        ),
        Some("First"),
    )?;
    daemon.check(
        "Word processing instruction",
        &doc(
            "document",
            &format!("<?mso-application progid=\"Word.Document\"?>{first}"),
            0,
        ),
        Some("First"),
    )?;
    daemon.check("HWP script plain",&doc(HWP,"<TAIL><SCRIPTCODE><SCRIPTSOURCE>ordinary XML attachment</SCRIPTSOURCE></SCRIPTCODE></TAIL>",0),Some("First"))?;
    daemon.check(
        "HWP body skip",
        &doc(
            HWP,
            "<BODY><SCRIPTSOURCE>ordinary XML attachment</SCRIPTSOURCE></BODY>",
            0,
        ),
        None,
    )?;
    daemon.check(
        "Office style skip",
        &doc(WORD, &format!("<w:styles>{first}</w:styles>"), 0),
        None,
    )?;
    daemon.check(
        "CDATA skip",
        &doc(EXCEL, &format!("<binData><![CDATA[{A}\n]]></binData>"), 0),
        None,
    )?;
    daemon.check(
        "One-line Base64",
        &doc(WORD, &format!("<binData>{A}</binData>"), 0),
        None,
    )?;
    daemon.check(
        "XML numeric newline",
        &doc(EXCEL, &format!("<binData>{A}&#10;</binData>"), 0),
        Some("First"),
    )?;
    daemon.check(
        "XML CRLF",
        &doc(EXCEL, &format!("<binData>{A}\r\n</binData>"), 0),
        Some("First"),
    )?;
    daemon.check(
        "Alternate case and namespace",
        &doc(EXCEL, &format!("<w:bInDaTa>{A}\n</w:bInDaTa>"), 0),
        Some("First"),
    )?;
    daemon.check("Excel boundary", &doc(EXCEL, &first, 1015), Some("First"))?;
    daemon.check("Excel later offset", &doc(EXCEL, &first, 1016), None)?;
    daemon.check(
        "Deep attachment",
        &doc(
            WORD,
            &format!("{}{}{}", "<g>".repeat(18), first, "</g>".repeat(18)),
            0,
        ),
        Some("First"),
    )?;
    daemon.check(
        "XML nesting limit",
        &doc(
            WORD,
            &format!("{}{}{}", "<g>".repeat(19), first, "</g>".repeat(19)),
            0,
        ),
        None,
    )?;
    daemon.check(
        "Word inside ZIP",
        &zip::zip(&[("document.xml", &word)], true, false, false)?,
        Some("First"),
    )?;
    for (size, expected) in [(10_000_000, Some("First")), (10_000_001, None)] {
        let long = doc(
            EXCEL,
            &format!("<Note>{}</Note>{first}", "x".repeat(size)),
            0,
        );
        daemon.check("XML text node size limit", &long, expected)?;
    }
    drop(daemon);
    let disabled = Server::start(stock, "ScanXMLDOCS no", &hashes, "")?;
    for (doc, name) in [(&word, "Word"), (&excel, "Excel"), (&hwp, "Hwp")] {
        disabled.check("ScanXMLDOCS no", doc, Some(name))?;
    }
    drop(disabled);
    let no_archives = Server::start(stock, "ScanArchive no", &files, "")?;
    no_archives.check("ScanArchive no", &word, Some("First"))?;
    drop(no_archives);
    let hex: String = FIRST.iter().map(|b| format!("{b:02x}")).collect();
    let mut logical = String::new();
    for (t, n) in [("WORD", "Word"), ("XL", "Excel"), ("HWP", "Hwp")] {
        logical.push_str(&format!(
            "Local.{n};Engine:81-255,Target:0,Container:CL_TYPE_XML_{t};0;{hex}\n"
        ));
    }
    if stock {
        let parents = Server::start(true, "", "", &logical)?;
        for (doc, name) in [(&word, "Word"), (&excel, "Excel"), (&hwp, "Hwp")] {
            parents.check("Typed parent", doc, Some(name))?;
        }
    }
    let large = vec![b'x'; 100_000];
    let large_hwp = hwp_compressed(&large)?;
    let encoded = base64::encode(&large);
    let lines = encoded
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let large_word = doc(WORD, &format!("<binData>{lines}\n</binData>"), 0);
    let big_hashes = hash(&large, "Large") + &hash(&large[..8192], "Prefix");
    let regular = Server::start(stock, "", &big_hashes, "")?;
    regular.check("Large Word XML attachment", &large_word, Some("Large"))?;
    regular.check(
        "Large compressed HWPML attachment",
        &large_hwp,
        Some("Large"),
    )?;
    drop(regular);
    let clipped = Server::start(
        stock,
        "MaxFileSize 12000\nAlertExceedsMax yes",
        &big_hashes,
        "",
    )?;
    clipped.check("HWP expansion limit", &large_hwp, Some("Prefix"))?;
    drop(clipped);
    let tiny = doc(WORD, "<binData>YQ==\n</binData>", 0);
    let small = Server::start(stock, "MaxFiles 1\nAlertExceedsMax yes", &files, "")?;
    small.check("Tiny decoded attachment", &tiny, None)?;
    drop(small);
    let first_size = word.len() + FIRST.len();
    for (cfg, expected) in [
        (
            "MaxRecursion 1".to_string(),
            "Heuristics.Limits.Exceeded.MaxRecursion",
        ),
        ("MaxFiles 1".into(), "Heuristics.Limits.Exceeded.MaxFiles"),
        ("MaxFiles 2".into(), "First"),
        (format!("MaxScanSize {first_size}"), "First"),
        (
            format!("MaxScanSize {}", first_size - 1),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
    ] {
        let limits = Server::start(stock, &format!("{cfg}\nAlertExceedsMax yes"), &files, "")?;
        limits.check(&cfg, &word, Some(expected))?;
    }
    Ok(())
}

#[test]
fn barnacle_xml_documents() -> io::Result<()> {
    compare(false)
}

#[test]
fn decoded_attachments_keep_the_xml_parent() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    for (root, tag, kind) in [
        (WORD, "w:binData", "CL_TYPE_XML_WORD"),
        (EXCEL, "binData", "CL_TYPE_XML_XL"),
        (HWP, "BINDATA", "CL_TYPE_XML_HWP"),
    ] {
        let document = doc(
            root,
            &format!("<{tag} Encoding=\"Base64\" name=\"note.txt\">{A}\n</{tag}>"),
            0,
        );
        let zipped = zip::zip(&[("member.xml", &document)], true, false, false)?;
        let verdict = scan(
            &zipped,
            &Options::default(),
            tmp.path(),
            |obj, _| {
                if !obj.normalized && obj.bytes == FIRST {
                    assert_eq!(
                        obj.parents.iter().map(|p| p.file_type).collect::<Vec<_>>(),
                        ["CL_TYPE_ZIP", kind]
                    );
                    assert_eq!(
                        obj.parents[1].name.as_deref(),
                        Some(b"member.xml".as_slice())
                    );
                    assert_eq!(obj.layer.name, None);
                    return Ok(Verdict::Found("attachment".into()));
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert_eq!(verdict, Verdict::Found("attachment".into()));
    }
    Ok(())
}
#[test]
#[ignore = "requires Debian clamd 1.4.3+dfsg-1"]
fn stock_xml_documents() -> io::Result<()> {
    let version = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(version.stdout, b"1.4.3+dfsg-1");
    compare(true)
}

fn legacy_doc(root: &str, label: &str, body: &[u8]) -> Vec<u8> {
    let mut document = Vec::new();
    if root == HWP {
        document.extend([0xef, 0xbb, 0xbf]);
    }
    document.extend(
        format!("<?xml version=\"1.0\" encoding='{label}'?><{root} xmlns:w=\"urn:word\">").bytes(),
    );
    document.extend(body);
    document.extend(format!("</{root}>").bytes());
    document
}

fn legacy_compare(stock: bool) -> io::Result<()> {
    let cases: &[(&[&str], &[u8], &str, &str)] = &[
        (
            &["ISO-8859-1", "Latin1", "iso_8859-1", "CP819"],
            b"caf\xe9 &amp; ann\xe9e &#x20ac;",
            "café & année €",
            "Latin1",
        ),
        (
            &["ISO8859-1", "L1"],
            b"report \x80 next",
            "report \u{80} next",
            "C1",
        ),
        (
            &["ISO-8859-2", "ISO8859-2", "latin2"],
            b"raport \xa3\xf3d\xbc",
            "raport Łódź",
            "Latin2",
        ),
        (
            &["Windows-1252", "CP1252"],
            b"prix \x80 et caf\xe9",
            "prix € et café",
            "Windows",
        ),
        (
            &["Windows-1251", "CP1251"],
            b"report \xcc\xe8\xf0",
            "report Мир",
            "Cyrillic",
        ),
        (
            &["EUC-KR", "EUCKR", "CP949"],
            b"report \xb0\xa1\xb3\xaa\xb4\xd9",
            "report 가나다",
            "Korean",
        ),
        (&["EUC-KR"], b"report \xa2\xe8", "report ㉾", "KoreanSymbol"),
        (
            &["CP949"],
            b"report \x81\x41",
            "report 갂",
            "ExtendedKorean",
        ),
        (
            &["Shift_JIS", "SJIS", "shift-jis", "CP932"],
            b"report \x93\xfa\x96\x7b",
            "report 日本",
            "Japanese",
        ),
        (
            &["Shift_JIS"],
            b"report \\ ~ \x81\x60",
            "report ¥ ‾ 〜",
            "Jis",
        ),
        (
            &["CP932"],
            b"report \\ ~ \x81\x60",
            "report \\ ~ ～",
            "WindowsJapanese",
        ),
        (
            &["US-ASCII", "ASCII", "UTF8"],
            b"report ABC",
            "report ABC",
            "Ascii",
        ),
    ];
    let mut rules = hash(FIRST, "First");
    for &(_, _, decoded, name) in cases {
        rules.push_str(&hash(decoded.as_bytes(), name));
    }
    let server = Server::start(stock, "", &rules, "")?;
    for &(labels, raw, _, name) in cases {
        for &label in labels {
            let data = [b"<TAIL><BINDATA>".as_slice(), raw, b"</BINDATA></TAIL>"].concat();
            server.check(label, &legacy_doc(HWP, label, &data), Some(name))?;
            let data = [
                b"<Note>".as_slice(),
                raw,
                b"</Note><binData>",
                A.as_bytes(),
                b"&#10;</binData>",
            ]
            .concat();
            for root in [WORD, EXCEL] {
                server.check(label, &legacy_doc(root, label, &data), Some("First"))?;
            }
        }
    }
    for (label, raw) in [
        ("x-unknown", b"report ABC".as_slice()),
        ("windows1252", b"prix \x80 et caf\xe9"),
        ("ks_c_5601-1987", b"report \xb0\xa1\xb3\xaa\xb4\xd9"),
        ("US-ASCII", b"report caf\xe9"),
        ("Windows-1252", b"report \x81 note"),
    ] {
        let data = [
            b"<Note>".as_slice(),
            raw,
            b"</Note><binData>",
            A.as_bytes(),
            b"\n</binData>",
        ]
        .concat();
        server.check(label, &legacy_doc(EXCEL, label, &data), None)?;
    }
    for (size, expected) in [(3_333_333, Some("First")), (3_333_334, None)] {
        let mut data = b"<Note>".to_vec();
        data.resize(data.len() + size, 0x80);
        data.extend(format!("</Note><binData>{A}\n</binData>").bytes());
        server.check(
            "converted text-node limit",
            &legacy_doc(WORD, "Windows-1252", &data),
            expected,
        )?;
    }
    drop(server);
    // Place a two-byte character across the 4096-byte conversion boundary.
    let header = legacy_doc(HWP, "Shift_JIS", b"<BINDATA>").len() - b"</HWPML>".len() - 3;
    let pad = 4095 - header;
    let raw = [
        b"<BINDATA>".as_slice(),
        &vec![b'a'; pad],
        &[0x81, 0x60, b'~', b'\\'].repeat(20_000),
        b"</BINDATA>",
    ]
    .concat();
    let expected = "a".repeat(pad) + &"〜‾¥".repeat(20_000);
    let across = Server::start(stock, "", &hash(expected.as_bytes(), "AcrossBoundary"), "")?;
    across.check(
        "multibyte input and repeated punctuation across conversion blocks",
        &legacy_doc(HWP, "Shift_JIS", &raw),
        Some("AcrossBoundary"),
    )?;
    drop(across);
    let text = "€".repeat(3000);
    let payload = [b"<BINDATA>".as_slice(), &vec![0x80; 3000], b"</BINDATA>"].concat();
    let document = legacy_doc(HWP, "windows-1252", &payload);
    let rules = hash(text.as_bytes(), "LargeLegacy") + &hash(&vec![0x80; 3000], "OriginalBytes");
    for (setting, bound, limit_name) in [
        (
            "MaxFileSize",
            text.len(),
            "Heuristics.Limits.Exceeded.MaxFileSize",
        ),
        (
            "MaxScanSize",
            document.len() + text.len(),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
    ] {
        for (limit, name) in [(bound, "LargeLegacy"), (bound - 1, limit_name)] {
            let server = Server::start(
                stock,
                &format!("{setting} {limit}\nAlertExceedsMax yes"),
                &rules,
                "",
            )?;
            server.check(
                "legacy attachment counts UTF-8 bytes",
                &document,
                Some(name),
            )?;
        }
    }
    if stock {
        let text = "prix € et café";
        let hex = text
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let rules = format!(
            "Local.LegacyParent;Engine:81-255,Target:0,Container:CL_TYPE_XML_HWP;0;{hex}\n"
        );
        let server = Server::start(true, "", "", &rules)?;
        let data = legacy_doc(HWP, "cp1252", b"<BINDATA>prix \x80 et caf\xe9</BINDATA>");
        server.check(
            "legacy parent",
            &zip::zip(&[("report.hml", &data)], true, false, false)?,
            Some("LegacyParent"),
        )?;
    }
    Ok(())
}

#[test]
fn barnacle_declared_xml_encodings() -> io::Result<()> {
    legacy_compare(false)
}
#[test]
#[ignore = "requires Debian clamd 1.4.3+dfsg-1"]
fn stock_declared_xml_encodings() -> io::Result<()> {
    let version = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(version.stdout, b"1.4.3+dfsg-1");
    legacy_compare(true)
}
#[test]
fn legacy_xml_attachment_context() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    let data = legacy_doc(
        HWP,
        "windows-1252",
        b"<BINDATA>prix \x80 et caf\xe9</BINDATA>",
    );
    let zipped = zip::zip(&[("report.hml", &data)], true, false, false)?;
    let verdict = scan(
        &zipped,
        &Options::default(),
        tmp.path(),
        |obj, _| {
            if !obj.normalized && obj.bytes == "prix € et café".as_bytes() {
                assert_eq!(
                    obj.parents.iter().map(|p| p.file_type).collect::<Vec<_>>(),
                    ["CL_TYPE_ZIP", "CL_TYPE_XML_HWP"]
                );
                assert_eq!(obj.parents[1].size, data.len());
                assert!(obj.layer.name.is_none());
                return Ok(Verdict::Found("text".into()));
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(verdict, Verdict::Found("text".into()));
    Ok(())
}

#[test]
fn large_ascii_legacy_document_can_be_cancelled_before_its_attachment() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let mut body = b"<Note>".to_vec();
    body.resize(3 * 1024 * 1024, b'x');
    body.extend(format!("</Note><binData>{A}\n</binData>").bytes());
    let document = legacy_doc(EXCEL, "Windows-1252", &body);
    let tmp = tempfile::tempdir()?;
    let mut calls = 0;
    let result = scan(
        &document,
        &Options::default(),
        tmp.path(),
        |obj, _| {
            assert_ne!(obj.bytes, FIRST);
            Ok(Verdict::Miss)
        },
        || {
            calls += 1;
            if calls == 32 {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled XML scan",
                ))
            } else {
                Ok(())
            }
        },
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    Ok(())
}

fn read_ahead_sample(
    label: &str,
    child_at: usize,
    error_at: usize,
    invalid: &[u8],
    tail: usize,
) -> Vec<u8> {
    let mut doc =
        format!("<?xml version=\"1.0\" encoding='{label}'?><Workbook><Note>").into_bytes();
    if label == "Windows-1252" {
        doc.extend(b"caf\xe9");
    }
    doc.resize(child_at - 7, b'x');
    doc.extend(format!("</Note><binData>{A}\n</binData><Note>").bytes());
    assert!(doc.len() <= error_at);
    doc.resize(error_at, b'x');
    doc.extend(invalid);
    doc.resize(doc.len() + tail, b'x');
    doc.extend(b"</Note></Workbook>");
    doc
}

fn malformed_legacy_xml(stock: bool) -> io::Result<()> {
    let child = format!("<binData>{A}\n</binData>");
    let mut cases = Vec::new();
    for invalid in [b"&nbsp;".as_slice(), b"&#0;", b"\x01"] {
        let mut leading = b"<Note>caf\xe9 ".to_vec();
        leading.extend(invalid);
        leading.extend(b"</Note>");
        leading.extend(child.as_bytes());
        cases.push((legacy_doc(EXCEL, "Windows-1252", &leading), None));
        for (gap, expected) in [(5, None), (100_000, Some("First"))] {
            let mut trailing = [child.as_bytes(), b"<Note>caf\xe9 "].concat();
            trailing.resize(trailing.len() + gap, b'x');
            trailing.extend(invalid);
            trailing.extend(b"</Note>");
            cases.push((legacy_doc(EXCEL, "Windows-1252", &trailing), expected));
        }
    }
    for note in [
        "<Note id='1' id='2'>metadata</Note>",
        "<Note id='&nbsp;'>metadata</Note>",
        "<Note id='&#0;'>metadata</Note>",
        "<Note>&#+10;</Note>",
    ] {
        cases.push((
            legacy_doc(EXCEL, "Windows-1252", format!("{note}{child}").as_bytes()),
            None,
        ));
    }
    for (gap, expected) in [(10, None), (100_000, Some("First"))] {
        let mut doc = [child.as_bytes(), b"<Note>"].concat();
        doc.resize(doc.len() + gap, b'x');
        doc.extend(b"\xff</Note>");
        cases.push((legacy_doc(EXCEL, "UTF-8", &doc), expected));
    }
    for (label, invalid) in [("Windows-1252", 0x81), ("ASCII", 0xff), ("CP932", 0xff)] {
        for (child_at, error_at, tail, expected) in [
            (100, 158, 0, Some("First")),
            (464, 524, 0, None),
            (500, 558, 0, None),
            (500, 558, 600, Some("First")),
            (500, 1008, 0, None),
            (500, 1009, 0, Some("First")),
            (500, 100_000, 0, Some("First")),
        ] {
            let doc = read_ahead_sample(label, child_at, error_at, &[invalid], tail);
            cases.push((doc, expected));
        }
    }
    // These references begin in the last byte of a parser input block.
    // The earlier attachment competes with the whole-document rule below.
    for (start, error_at, tail) in [(430, 515, 0), (900, 1027, 600)] {
        for reference in [b"&#0;".as_slice(), b"&nbsp;"] {
            let doc = read_ahead_sample("Windows-1252", start, error_at, reference, tail);
            cases.push((doc, Some("First")));
        }
    }
    let invalid_before_child = legacy_doc(
        EXCEL,
        "Windows-1252",
        format!("<Note>&nbsp;</Note>{child}").as_bytes(),
    );
    let mut rules = hash(FIRST, "First") + &hash(&invalid_before_child, "Outer");
    for (doc, expected) in &cases {
        if expected.is_some() {
            rules.push_str(&hash(doc, "Outer"));
        }
    }
    let server = Server::start(stock, "", &rules, "")?;
    for (index, (doc, expected)) in cases.iter().enumerate() {
        server.check(&format!("malformed XML read-ahead {index}"), doc, *expected)?;
    }
    server.check(
        "raw hash after unsupported XML metadata",
        &invalid_before_child,
        stock.then_some("Outer"),
    )?;
    Ok(())
}

#[test]
fn barnacle_malformed_xml_read_ahead() -> io::Result<()> {
    malformed_legacy_xml(false)
}

#[test]
#[ignore = "requires Debian clamd 1.4.3+dfsg-1"]
fn stock_malformed_xml_read_ahead() -> io::Result<()> {
    malformed_legacy_xml(true)
}

#[test]
fn xml_attribute_count_bounds_duplicate_checks() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    for (count, expected) in [
        (1024, Verdict::Found("first".into())),
        (1025, Verdict::Incomplete),
    ] {
        let attrs = (0..count).map(|i| format!(" n{i}='x'")).collect::<String>();
        let doc = legacy_doc(
            EXCEL,
            "ASCII",
            format!("<Note{attrs}/><binData>{A}\n</binData>").as_bytes(),
        );
        let result = scan(
            &doc,
            &Options::default(),
            tmp.path(),
            |obj, _| {
                Ok(if obj.bytes == FIRST {
                    Verdict::Found("first".into())
                } else {
                    Verdict::Miss
                })
            },
            || Ok(()),
        )?;
        assert_eq!(result, expected);
    }
    Ok(())
}
