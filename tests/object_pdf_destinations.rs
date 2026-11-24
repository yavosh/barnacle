//! Opening a passive PDF destination exposes a dictionary at its physical position.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

const RECEIPT: &[u8] = b"Ordinary receipt total";
const PAGE: &[u8] = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 4 0 R >>";
const GOTO: &[u8] = b"<< /S /GoTo /D [3 0 R /Fit] >>";
const PAGE_STREAM: &[u8] = b"BT\n[(Invoice)] TJ\nET";

fn stream(dict: &str, content: &[u8]) -> Vec<u8> {
    let mut out = format!("<< {dict} /Length {}>>\nstream\n", content.len()).into_bytes();
    out.extend_from_slice(content);
    out.extend_from_slice(b"\nendstream");
    out
}

struct Sample {
    pdf: Vec<u8>,
    catalog: Vec<u8>,
    action: Vec<u8>,
    page: Vec<u8>,
}
fn sample(dest: &str, action: &[u8], order: &[usize], eol: &[u8]) -> io::Result<Sample> {
    sample_with_id(dest, action, order, eol, (7, 0))
}

fn sample_with_id(
    dest: &str,
    action: &[u8],
    order: &[usize],
    eol: &[u8],
    action_id: (usize, usize),
) -> io::Result<Sample> {
    let catalog=format!("<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(notes.txt) 5 0 R] >> >> {dest} >>").into_bytes();
    let hex: String = RECEIPT.iter().map(|b| format!("{b:02x}")).collect();
    let objects = [
        catalog.clone(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        PAGE.to_vec(),
        stream("", PAGE_STREAM),
        b"<< /Type /Filespec /F (notes.txt) /EF << /F 6 0 R >> >>".to_vec(),
        stream(
            "/Type /EmbeddedFile /Filter /ASCIIHexDecode",
            format!("{hex}>").as_bytes(),
        ),
        action.to_vec(),
    ];
    let mut pdf = b"%PDF-1.5\n".to_vec();
    let mut offsets = [0; 8];
    for &id in order {
        offsets[id] = pdf.len();
        let (number, generation) = if id == 7 { action_id } else { (id, 0) };
        write!(pdf, "{number} {generation} obj")?;
        pdf.extend(eol);
        pdf.extend(&objects[id - 1]);
        pdf.extend(eol);
        pdf.extend(b"endobj\n");
    }
    let xref = pdf.len();
    pdf.extend(b"xref\n0 7\n0000000000 65535 f \n");
    for offset in &offsets[1..7] {
        writeln!(pdf, "{offset:010} 00000 n ")?;
    }
    writeln!(
        pdf,
        "{} 1\n{:010} {:05} n ",
        action_id.0, offsets[7], action_id.1
    )?;
    writeln!(
        pdf,
        "trailer\n<< /Root 1 0 R /Size {} >>\nstartxref\n{xref}\n%%EOF",
        action_id.0 + 1
    )?;
    let wrapped = |body: &[u8]| [eol, body, eol].concat();
    Ok(Sample {
        pdf,
        catalog: wrapped(&catalog),
        action: wrapped(action),
        page: wrapped(PAGE),
    })
}
fn hdb(label: &str, data: &[u8]) -> io::Result<String> {
    Ok(format!(
        "{}:{}:Destination.{label}\n",
        barnacle::hash_reader(data)?.md5_hex(),
        data.len()
    ))
}

fn start(
    stock: bool,
    root: &Path,
    db: &Path,
    sock: &Path,
    options: &str,
) -> io::Result<daemon::Daemon> {
    let cfg = root.join("config");
    fs::write(
        &cfg,
        format!(
            "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n{options}\n",
            db.display(),
            sock.display()
        ),
    )?;
    daemon::Daemon::start(
        Path::new(if stock {
            "/usr/sbin/clamd"
        } else {
            env!("CARGO_BIN_EXE_barnacle")
        }),
        &cfg,
        sock,
    )
}

fn compare(stock: bool) -> io::Result<()> {
    let forwards = [1, 2, 3, 4, 5, 6, 7];
    let backwards = [7, 3, 1, 2, 4, 5, 6];
    let mut cases = Vec::new();
    for explicit in [
        "/Fit",
        "/FitB",
        "/FitH 72",
        "/FitBH null",
        "/FitV -20",
        "/FitBV 2.75",
        "/XYZ null +.5 1.25",
        "/FitR 0 0 80 90",
    ] {
        cases.push((
            "page",
            sample(
                &format!("/OpenAction [3 0 R {explicit}]"),
                GOTO,
                &forwards,
                b"\n",
            )?,
        ));
    }
    for direct in [
        "/OpenAction << /S /GoTo /D [3 0 R /Fit] >>",
        "/OpenAction << /Type /Action /D (ReceiptPage) /S /GoTo >>",
        "/OpenAction << /S /GoTo /D /Receipt >>",
    ] {
        cases.push(("catalog", sample(direct, GOTO, &forwards, b"\n")?));
    }
    for action in [GOTO, b"[3 0 R /FitH 2]", b"<< /D /Receipt /S /GoTo >>"] {
        cases.push((
            "late",
            sample("/OpenAction 7 0 R", action, &forwards, b"\n")?,
        ));
        cases.push((
            "early",
            sample("/OpenAction 7 0 R", action, &backwards, b"\r\n")?,
        ));
    }
    cases.push((
        "page",
        sample("/OpenAction [3 0 R /XYZ 4 5 1]", GOTO, &backwards, b"\r\n")?,
    ));
    cases.push((
        "early",
        sample_with_id(
            "/OpenAction 5000000 9 R",
            GOTO,
            &backwards,
            b"\n",
            (5000000, 9),
        )?,
    ));
    let base = sample("", GOTO, &forwards, b"\n")?;

    for profile in [
        "attachments",
        "objects",
        "only-action",
        "fixed",
        "outer",
        "off",
    ] {
        let tmp = tempfile::tempdir_in("/tmp")?;
        let db = tmp.path().join("db");
        fs::create_dir(&db)?;
        let mut rules = std::collections::BTreeSet::new();
        if ["attachments", "objects", "outer", "off"].contains(&profile) {
            rules.insert(hdb("Receipt", RECEIPT)?);
        }
        for (i, (kind, s)) in cases.iter().enumerate() {
            if profile == "outer" {
                rules.insert(hdb(&format!("Outer{i}"), &s.pdf)?);
            }
            if profile == "objects" {
                rules.insert(hdb("Page", &s.page)?);
                rules.insert(hdb("Action", &s.action)?);
                if *kind == "catalog" {
                    rules.insert(hdb("Catalog", &s.catalog)?);
                }
            }
            if profile == "only-action" {
                rules.insert(hdb("Action", &s.action)?);
            }
        }
        if profile == "fixed" {
            fs::write(
                db.join("local.ndb"),
                "Destination.Receipt:0:0:4f7264696e617279207265636569707420746f74616c\nDestination.WrongOffset:0:1:4f7264696e617279207265636569707420746f74616c\nDestination.Page:0:1:3c3c202f54797065202f50616765202f506172656e74\nDestination.Page:0:2:3c3c202f54797065202f50616765202f506172656e74\nDestination.Catalog:0:1:3c3c202f54797065202f436174616c6f67202f5061676573\n",
            )?;
        }
        if !rules.is_empty() {
            fs::write(db.join("local.hdb"), rules.into_iter().collect::<String>())?;
        }
        let sock = tmp.path().join("sock");
        let option = if profile == "off" { "ScanPDF no" } else { "" };
        let _daemon = start(stock, tmp.path(), &db, &sock, option)?;
        for (i, (kind, s)) in cases.iter().enumerate() {
            let winner = match profile {
                "fixed" => match *kind {
                    "page" => "Page",
                    "catalog" => "Catalog",
                    _ => "Receipt",
                }
                .to_owned(),
                "objects" => match *kind {
                    "page" => "Page",
                    "catalog" => "Catalog",
                    "early" => "Action",
                    _ => "Receipt",
                }
                .to_owned(),
                "outer" => format!("Outer{i}"),
                "off" => String::new(),
                "only-action" => if matches!(*kind, "late" | "early") {
                    "Action"
                } else {
                    ""
                }
                .into(),
                _ => "Receipt".into(),
            };
            let zip = zip::zip(&[("report.pdf", &s.pdf)], true, false, false)?;
            for bytes in [&s.pdf, &zip] {
                let reply = daemon::unix_request(&sock, &daemon::stream_frame(bytes)?)?;
                let expected = if !winner.is_empty() {
                    format!("stream: Destination.{winner}.UNOFFICIAL FOUND\0")
                } else if stock {
                    "stream: OK\0".into()
                } else {
                    "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into()
                };
                assert_eq!(reply, expected, "{profile} {kind} {i}");
            }
        }
        if profile == "only-action" {
            let reply = daemon::unix_request(&sock, &daemon::stream_frame(&base.pdf)?)?;
            assert!(!reply.contains("FOUND"), "unreferenced action: {reply}");
        }
    }
    for kind in ["page", "catalog", "early"] {
        let (_, s) = cases.iter().find(|(name, _)| *name == kind).unwrap();
        let body = match kind {
            "page" => &s.page,
            "catalog" => &s.catalog,
            _ => &s.action,
        };
        let exact = s.pdf.len() + body.len();
        for (extra, room, expected) in [
            (
                "MaxFiles 1",
                exact - 1,
                "Heuristics.Limits.Exceeded.MaxFiles",
            ),
            (
                "MaxRecursion 1",
                exact - 1,
                "Heuristics.Limits.Exceeded.MaxScanSize",
            ),
            (
                "MaxRecursion 1",
                exact,
                "Heuristics.Limits.Exceeded.MaxRecursion",
            ),
            (
                "MaxFiles 2",
                exact - 1,
                "Heuristics.Limits.Exceeded.MaxScanSize",
            ),
            ("MaxFiles 2", exact, "Destination.Body.UNOFFICIAL"),
        ] {
            let root = tempfile::tempdir_in("/tmp")?;
            let db = root.path().join("db");
            fs::create_dir(&db)?;
            fs::write(db.join("local.hdb"), hdb("Body", body)?)?;
            let sock = root.path().join("sock");
            let config = format!("AlertExceedsMax yes\nMaxScanSize {room}\n{extra}");
            let _daemon = start(stock, root.path(), &db, &sock, &config)?;
            let reply = daemon::unix_request(&sock, &daemon::stream_frame(&s.pdf)?)?;
            assert_eq!(
                reply,
                format!("stream: {expected} FOUND\0"),
                "{kind} {config}"
            );
        }
    }
    Ok(())
}
#[test]
fn unverified_actions_stay_incomplete() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let temp = tempfile::tempdir()?;
    let order = [1, 2, 3, 4, 5, 6, 7];
    for (opening, target) in [
        ("/OpenAction << /S /Named /N /NextPage >>", GOTO),
        (
            "/OpenAction << /S /GoTo /D [3 0 R /Fit] /Next << /S /Named /N /NextPage >> >>",
            GOTO,
        ),
        ("/OpenAction 7 0 R", b"<< /S /Named /N /NextPage >>"),
        ("/OpenAction 7 1 R", GOTO),
        ("/OpenAction [77 0 R /Fit]", GOTO),
        (
            "/OpenAction [7 0 R /Fit]",
            b"<< /Header << /Type /Page >> >>",
        ),
        ("/OpenAction [3 0 R /Fit] /OpenAction [3 0 R /Fit]", GOTO),
    ] {
        let pdf = sample(opening, target, &order, b"\n")?;
        let verdict = scan(
            &pdf.pdf,
            &Options::default(),
            temp.path(),
            |obj, _| {
                Ok(if obj.bytes == RECEIPT {
                    Verdict::Found("Receipt".into())
                } else {
                    Verdict::Miss
                })
            },
            || Ok(()),
        )?;
        assert_eq!(verdict, Verdict::Incomplete, "{opening}");
    }
    Ok(())
}

#[test]
fn barnacle_open_destinations() -> io::Result<()> {
    compare(false)
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_open_destinations() -> io::Result<()> {
    compare(true)
}
