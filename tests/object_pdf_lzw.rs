//! Passive LZW page and attachment streams compared with the pinned Debian clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
use daemon::{Daemon, stream_frame, unix_request};
use md5::{Digest, Md5};
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

const NOTE: &[u8] = b"benign example accounting note";
const PAGE: &[u8] = b"[(Ordinary RECEIPT)] TJ\n";
const TEXT: &[u8] = b"ordinary receipt";

// Write the PDF widths independently of the decoder. Dictionary entries are
// created between consecutive data codes, including after each clear.
fn codes(input: impl IntoIterator<Item = u16>, early: usize) -> Vec<u8> {
    let (mut width, mut available, mut first) = (9, 258usize, true);
    let (mut bits, mut rest) = (0usize, 0u32);
    let mut out = Vec::new();
    for code in input {
        rest = (rest << width) | u32::from(code);
        bits += width;
        while bits >= 8 {
            bits -= 8;
            out.push((rest >> bits) as u8);
        }
        match code {
            256 => {
                width = 9;
                available = 258;
                first = true;
            }
            257 => (),
            _ if first => first = false,
            _ if available < 4096 => {
                available += 1;
                if width < 12 && available + early == 1 << width {
                    width += 1;
                }
            }
            _ => (),
        }
    }
    if bits > 0 {
        out.push((rest << (8 - bits)) as u8);
    }
    out
}

fn literals(data: &[u8], early: usize) -> Vec<u8> {
    let words = data
        .chunks(3500)
        .flat_map(|block| std::iter::once(256).chain(block.iter().copied().map(u16::from)));
    codes(words.chain([257]), early)
}

// Each next-code reference extends the previous word by one 'A'.
fn dense(size: usize) -> Vec<u8> {
    let mut words = vec![256, u16::from(b'A')];
    let (mut written, mut length) = (1, 1);
    while written + length < size {
        words.push(257 + length as u16);
        length += 1;
        written += length;
    }
    words.extend(std::iter::repeat_n(u16::from(b'A'), size - written));
    words.push(257);
    codes(words, 1)
}

fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut body = format!("<< {dict} /Length {}>>\nstream\n", data.len()).into_bytes();
    body.extend(data);
    body.extend(b"\nendstream");
    body
}

fn pdf(page: Vec<u8>, attachment: Vec<u8>) -> Vec<u8> {
    let mut file = b"%PDF-1.5\n".to_vec();
    let mut offsets = Vec::new();
    for (i, obj) in [
        b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(notes.txt) 5 0 R] >> >> >>".to_vec(),
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 4 0 R >>".to_vec(), page,
        b"<< /Type /Filespec /F (notes.txt) /EF << /F 6 0 R >> >>".to_vec(), attachment,
    ].into_iter().enumerate() {
        offsets.push(file.len());
        writeln!(file, "{} 0 obj", i + 1).unwrap();
        file.extend(obj);
        file.extend(b"\nendobj\n");
    }
    let xref = file.len();
    file.extend(b"xref\n0 7\n0000000000 65535 f \n");
    for pos in offsets {
        writeln!(file, "{pos:010} 00000 n ").unwrap();
    }
    writeln!(
        file,
        "trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"
    )
    .unwrap();
    file
}

fn attached(dict: &str, bytes: &[u8]) -> Vec<u8> {
    pdf(stream("", b"quiet text"), stream(dict, bytes))
}

// Remove the embedded-files pointer without changing the xref offsets.
fn unreferenced(dict: &str, bytes: &[u8]) -> Vec<u8> {
    let mut doc = attached(dict, bytes);
    let reference = b"/EF << /F 6 0 R >>";
    let at = doc
        .windows(reference.len())
        .position(|p| p == reference)
        .unwrap();
    doc[at..at + reference.len()].fill(b' ');
    doc
}

fn only_attachment(dict: &str, data: &[u8]) -> Vec<u8> {
    // Skip the page's image object so it cannot record an earlier scan limit.
    pdf(
        stream("/Type /XObject /Subtype /Image", b"x"),
        stream(dict, data),
    )
}

fn hash(name: &str, data: &[u8]) -> String {
    let digest: String = Md5::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{digest}:{}:Lzw.{name}\n", data.len())
}

fn hex(data: &[u8]) -> Vec<u8> {
    let mut encoded: String = data.iter().map(|b| format!("{b:02x}")).collect();
    encoded.push('>');
    encoded.into_bytes()
}

fn compare(stock: bool) -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let root = temp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let filter = "/Type /EmbeddedFile /Filter /LZWDecode";
    let small = literals(NOTE, 1);
    let large = NOTE.repeat(250);
    let wide = literals(&large, 1);
    let late = literals(&large, 0);
    let compressed = codes([256, 65].into_iter().chain(258..=398).chain([257]), 1);
    let repeated = vec![b'A'; 142 * 143 / 2];
    let repeated_pdf = attached(filter, &compressed);
    // Reuse each growing phrase, then append a different literal to make the next entry.
    let mut words = vec![256, u16::from(b'A')];
    let mut phrase = vec![b'A'];
    let mut alphabet = phrase.clone();
    for (i, byte) in (b'B'..=b'Z').enumerate() {
        words.extend([u16::from(byte), 258 + 2 * i as u16]);
        phrase.push(byte);
        alphabet.push(byte);
        alphabet.extend(&phrase);
    }
    words.push(257);
    let alphabet_pdf = attached(filter, &codes(words, 1));
    let empty = codes([256; 16].into_iter().chain([257]), 1);
    let page = literals(PAGE, 1);
    let page_only = pdf(
        stream("/Filter /LZWDecode", &page),
        stream("", b"quiet note"),
    );
    let mut rules = hash("Note", NOTE)
        + &hash("Encoded", &small)
        + &hash("Large", &large)
        + &hash("Text", TEXT)
        + &hash("Repeat", &repeated)
        + &hash("Alphabet", &alphabet);
    rules.push_str(&hash("Empty", &empty));
    // The reference returns these 2,724 bytes from this conforming late-change stream.
    rules.push_str("e38ddec8983fe9f5b9480d2802b956b8:2724:Lzw.ReferenceLate\n");
    let mut profile = 0;
    let mut check = |config: &str,
                     rules: &str,
                     cases: &[(&str, Vec<u8>, Option<&str>)]|
     -> io::Result<()> {
        profile += 1;
        fs::write(db.join("local.hdb"), rules)?;
        let config_path = root.join(format!("{profile}.conf"));
        let sock = root.join(format!("{profile}.sock"));
        fs::write(
            &config_path,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nTemporaryDirectory {}\nDisableCache yes\nSelfCheck 0\n{config}\n",
                db.display(),
                sock.display(),
                root.display()
            ),
        )?;
        let exe = if stock {
            "/usr/sbin/clamd"
        } else {
            env!("CARGO_BIN_EXE_barnacle")
        };
        let _d = Daemon::start(Path::new(exe), &config_path, &sock)?;
        for (label, doc, verdict) in cases {
            let expect = match verdict {
                Some(v) if v.starts_with("Heuristics.") => format!("stream: {v} FOUND\0"),
                Some(v) => format!("stream: Lzw.{v}.UNOFFICIAL FOUND\0"),
                None if stock => "stream: OK\0".to_string(),
                None => {
                    "stream: Incomplete scan: unsupported detection coverage. ERROR\0".to_string()
                }
            };
            assert_eq!(unix_request(&sock, &stream_frame(doc)?)?, expect, "{label}");
        }
        Ok(())
    };
    check(
        "",
        &rules,
        &[
            (
                "empty decoded output keeps its input",
                attached(filter, &empty),
                Some("Empty"),
            ),
            (
                "literal stream without a leading clear code",
                attached(
                    filter,
                    &codes(NOTE.iter().copied().map(u16::from).chain([257]), 1),
                ),
                Some("Note"),
            ),
            (
                "complete words before a missing end code",
                attached(
                    filter,
                    &codes(
                        [256].into_iter().chain(NOTE.iter().copied().map(u16::from)),
                        1,
                    ),
                ),
                Some("Note"),
            ),
            ("embedded", attached(filter, &small), Some("Note")),
            (
                "short name",
                attached("/Type /EmbeddedFile /Filter /LZW", &small),
                Some("Note"),
            ),
            (
                "ASCIIHex then LZW",
                attached("/Type /EmbeddedFile /Filter [/AHx /LZW]", &hex(&small)),
                Some("Note"),
            ),
            (
                "LZW then ASCIIHex",
                attached(
                    "/Type /EmbeddedFile /Filter [/LZW /AHx]",
                    &literals(&hex(NOTE), 1),
                ),
                Some("Note"),
            ),
            (
                "normalized page before later attachment",
                pdf(stream("/Filter /LZWDecode", &page), stream(filter, &small)),
                Some("Text"),
            ),
            (
                "ordinary unreferenced stream",
                unreferenced("/Filter /LZWDecode", &small),
                None,
            ),
            (
                "image stream",
                attached(
                    "/Type /XObject /Subtype /Image /Width 1 /Height 30 /BitsPerComponent 8 /ColorSpace /DeviceGray /Filter /LZWDecode",
                    &small,
                ),
                None,
            ),
            (
                "default across 9 to 12 bits and resets",
                attached(filter, &wide),
                Some("Large"),
            ),
            (
                "explicit EarlyChange 1",
                attached(
                    &format!("{filter} /DecodeParms << /EarlyChange 1 >>"),
                    &wide,
                ),
                Some("Large"),
            ),
            (
                "declared zero still decodes early-change input",
                attached(
                    &format!("{filter} /DecodeParms << /EarlyChange 0 >>"),
                    &wide,
                ),
                Some("Large"),
            ),
            (
                "conforming late-change input",
                attached(
                    &format!("{filter} /DecodeParms << /EarlyChange 0 >>"),
                    &late,
                ),
                Some("ReferenceLate"),
            ),
            (
                "dictionary references including next entry",
                repeated_pdf.clone(),
                Some("Repeat"),
            ),
            ("ordered dictionary phrases", alphabet_pdf, Some("Alphabet")),
        ],
    )?;
    let competing = rules.clone() + &hash("Page", PAGE);
    check(
        "",
        &competing,
        &[(
            "decoded stream before normalized text",
            page_only.clone(),
            Some("Page"),
        )],
    )?;
    let outer = competing + &hash("Outer", &page_only);
    check(
        "",
        &outer,
        &[("whole PDF before stream", page_only.clone(), Some("Outer"))],
    )?;
    check(
        "ScanPDF no",
        &rules,
        &[("PDF extraction disabled", attached(filter, &small), None)],
    )?;
    for (key, value, expected) in [
        ("MaxFileSize", repeated.len(), "Repeat"),
        (
            "MaxFileSize",
            repeated.len() - 1,
            "Heuristics.Limits.Exceeded.MaxFileSize",
        ),
        (
            "MaxScanSize",
            repeated_pdf.len() + 10 + repeated.len(),
            "Repeat",
        ),
        (
            "MaxScanSize",
            repeated_pdf.len() + 10 + repeated.len() - 1,
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
        ("MaxRecursion", 1, "Heuristics.Limits.Exceeded.MaxRecursion"),
    ] {
        check(
            &format!("{key} {value}\nAlertExceedsMax yes"),
            &rules,
            &[(key, repeated_pdf.clone(), Some(expected))],
        )?;
    }
    const STEP: usize = 256 * 1024;
    let before = dense(STEP - 1);
    let at = dense(STEP);
    let edge_pdf = attached(filter, &at);
    let edge_rules = hash("Before", &vec![b'A'; STEP - 1])
        + &hash("Boundary", &vec![b'A'; STEP])
        + &hash("EncodedEdge", &at);
    check(
        "MaxFileSize 10000\nAlertExceedsMax yes",
        &edge_rules,
        &[
            (
                "short of the buffer rejects the decoded object",
                attached(filter, &before),
                Some("Heuristics.Limits.Exceeded.MaxFileSize"),
            ),
            (
                "full buffer falls back to encoded input",
                edge_pdf.clone(),
                Some("EncodedEdge"),
            ),
            (
                "preceding filter supplies the fallback",
                attached(
                    "/Type /EmbeddedFile /Filter [/ASCIIHexDecode /LZWDecode]",
                    &hex(&at),
                ),
                Some("EncodedEdge"),
            ),
            (
                "later filters are skipped on fallback",
                attached(
                    "/Type /EmbeddedFile /Filter [/LZWDecode /ASCIIHexDecode]",
                    &at,
                ),
                Some("EncodedEdge"),
            ),
        ],
    )?;
    for (key, bound) in [
        ("MaxFileSize", STEP * 2),
        ("MaxScanSize", edge_pdf.len() + 10 + STEP * 2),
    ] {
        for (size, expected) in [(bound - 1, "EncodedEdge"), (bound, "Boundary")] {
            check(
                &format!("{key} {size}\nAlertExceedsMax yes"),
                &edge_rules,
                &[(key, edge_pdf.clone(), Some(expected))],
            )?;
        }
    }
    let single = only_attachment(filter, &dense(100_000));
    let full_buffer = only_attachment(filter, &dense(STEP));
    let tiny = only_attachment(filter, &literals(b"word", 1));
    for (child, signature) in [
        ("MaxFiles 1", "Heuristics.Limits.Exceeded.MaxFiles"),
        ("MaxRecursion 1", "Heuristics.Limits.Exceeded.MaxRecursion"),
    ] {
        let tiny_result = (child == "MaxFiles 1").then_some(signature);
        check(
            &format!("{child}\nAlertExceedsMax yes"),
            &rules,
            &[
                ("blocked LZW attachment", single.clone(), Some(signature)),
                ("blocked tiny attachment", tiny.clone(), tiny_result),
            ],
        )?;
        for (setting, bound, size_signature) in [
            (
                "MaxFileSize",
                100_000,
                "Heuristics.Limits.Exceeded.MaxFileSize",
            ),
            (
                "MaxScanSize",
                single.len() + 100_000,
                "Heuristics.Limits.Exceeded.MaxScanSize",
            ),
        ] {
            for (cap, expected) in [(bound, signature), (bound - 1, size_signature)] {
                check(
                    &format!("{child}\n{setting} {cap}\nAlertExceedsMax yes"),
                    &rules,
                    &[(
                        "blocked attachment vs exact decoded byte limit",
                        single.clone(),
                        Some(expected),
                    )],
                )?;
            }
        }
        check(
            &format!("{child}\nMaxFileSize 400000\nAlertExceedsMax yes"),
            &edge_rules,
            &[(
                "allocation limit precedes blocked fallback",
                full_buffer.clone(),
                Some("Heuristics.Limits.Exceeded.MaxFileSize"),
            )],
        )?;
    }
    Ok(())
}

#[test]
fn lzw_clear_codes_check_cancellation() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let temp = tempfile::tempdir()?;
    let mut input = vec![256; 40_000];
    input.extend(NOTE.iter().copied().map(u16::from));
    input.push(257);
    let file = attached("/Type /EmbeddedFile /Filter /LZWDecode", &codes(input, 1));
    let mut checks = 0;
    let result = scan(
        &file,
        &Options::default(),
        temp.path(),
        |obj, _| {
            assert_ne!(obj.bytes, NOTE);
            Ok(Verdict::Miss)
        },
        || {
            checks += 1;
            if checks == 100 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok(())
        },
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    assert!(fs::read_dir(temp.path())?.next().is_none());
    Ok(())
}

#[test]
fn denied_pdf_children_do_not_need_output_scratch() -> io::Result<()> {
    use barnacle::objects::{Limit, Options, Verdict, scan};
    let temp = tempfile::tempdir()?;
    let missing = temp.path().join("missing");
    let literal = dense(100_000);
    let hex_literal = hex(&literal);
    let cases = [
        ("/Type /EmbeddedFile /Filter /LZWDecode", &literal[..]),
        (
            "/Type /EmbeddedFile /Filter [/ASCIIHexDecode /LZWDecode]",
            &hex_literal,
        ),
    ];
    for (filter, data) in cases {
        let doc = only_attachment(filter, data);
        for (files, depth, reason) in [(1, 17, Limit::MaxFiles), (1000, 1, Limit::MaxRecursion)] {
            let options = Options {
                max_files: files,
                max_recursion: depth,
                alert_exceeds_max: true,
                ..Options::default()
            };
            let actual = scan(
                &doc,
                &options,
                &missing,
                |_, _| Ok(Verdict::Miss),
                || Ok(()),
            )?;
            assert_eq!(actual, Verdict::Found(reason.signature()));
        }
        let failing = scan(
            &doc,
            &Options::default(),
            &missing,
            |_, _| Ok(Verdict::Miss),
            || Ok(()),
        );
        assert_eq!(failing.unwrap_err().kind(), io::ErrorKind::NotFound);
    }
    Ok(())
}

#[test]
fn pdf_scan_check_errors_keep_their_identity() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    for (filter, data) in [("/LZW", literals(NOTE, 1)), ("/AHx", hex(NOTE))] {
        let file = only_attachment(&format!("/Type /EmbeddedFile /Filter {filter}"), &data);
        let run = |stop: usize, kind: io::ErrorKind| {
            let mut calls = 0;
            let result = scan(
                &file,
                &Options::default(),
                tmp.path(),
                |_, _| Ok(Verdict::Miss),
                || {
                    calls += 1;
                    if calls == stop {
                        Err(io::Error::new(kind, "PDF traversal interrupted"))
                    } else {
                        Ok(())
                    }
                },
            );
            (result, calls)
        };
        let (ok, total) = run(0, io::ErrorKind::Other);
        ok?;
        for kind in [
            io::ErrorKind::InvalidData,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::UnexpectedEof,
        ] {
            for stop in 1..=total {
                let error = run(stop, kind).0.unwrap_err();
                assert_eq!(error.kind(), kind);
                assert_eq!(error.to_string(), "PDF traversal interrupted");
            }
        }
    }
    let bad = only_attachment("/Type /EmbeddedFile /Filter /AHx", b"not hexadecimal>");
    assert_eq!(
        scan(
            &bad,
            &Options::default(),
            tmp.path(),
            |_, _| Ok(Verdict::Miss),
            || Ok(())
        )?,
        Verdict::Incomplete
    );
    Ok(())
}

#[test]
fn barnacle_lzw_pdf_streams() -> io::Result<()> {
    compare(false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_lzw_pdf_streams() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(true)
}
