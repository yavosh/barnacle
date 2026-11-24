//! Stock traversal of locally generated RFC822 forwards and contacts.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
use std::{
    fs, io,
    path::{Path, PathBuf},
};
const RECEIPT: &str = "Market receipt 041. Paid in full. Thank you.\n";
const CONTACT: &str = "BEGIN:VCARD\nVERSION:3.0\nFN:June Smith\nEND:VCARD\n";
const HEAD: &str = "From: receipts@example.invalid\nTo: office@example.invalid\nSubject: Market receipt\nMIME-Version: 1.0\n";
fn b64(bytes: &[u8]) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for group in bytes.chunks(3) {
        let a = group[0];
        let b = group.get(1).copied().unwrap_or(0);
        let c = group.get(2).copied().unwrap_or(0);
        result.push(CHARS[(a >> 2) as usize] as char);
        result.push(CHARS[((a & 3) << 4 | b >> 4) as usize] as char);
        result.push(if group.len() > 1 {
            CHARS[((b & 15) << 2 | c >> 6) as usize] as char
        } else {
            '='
        });
        result.push(if group.len() > 2 {
            CHARS[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    result
}
fn mime_base64(bytes: &[u8]) -> String {
    b64(bytes)
        .as_bytes()
        .chunks(64)
        .map(|row| std::str::from_utf8(row).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}
fn inner() -> String {
    format!(
        "{HEAD}Content-Type: multipart/mixed; boundary=receipt\n\n--receipt\nContent-Type: text/plain\n\nAttached receipt.\n--receipt\nContent-Type: application/octet-stream; name=receipt.txt\nContent-Disposition: attachment; filename=receipt.txt\nContent-Transfer-Encoding: base64\n\n{}\n--receipt--\n",
        b64(RECEIPT.as_bytes())
    )
}
fn forward(enc: &str, nested: bool) -> String {
    let inner = inner();
    let body = match enc {
        "base64" => mime_base64(inner.as_bytes()),
        "quoted-printable" => inner.replace("=", "=3D").replace(" ", "=20"),
        _ => inner,
    };
    let transfer = if enc == "none" {
        String::new()
    } else {
        format!("Content-Transfer-Encoding: {enc}\n")
    };
    let part = format!(
        "Content-Type: message/rfc822; name=forward.eml\nContent-Disposition: attachment; filename=forward.eml\n{transfer}\n{body}"
    );
    if nested {
        format!(
            "{HEAD}Content-Type: multipart/mixed; boundary=forward\n\n--forward\n{part}--forward\nContent-Type: text/vcard; name=contact.vcf\nContent-Disposition: attachment; filename=contact.vcf\nContent-Transfer-Encoding: base64\n\n{}\n--forward--\n",
            b64(CONTACT.as_bytes())
        )
    } else {
        format!("{HEAD}{part}")
    }
}
fn hash(name: &str, b: &[u8]) -> io::Result<String> {
    Ok(format!(
        "{}:{}:Fwd.{name}\n",
        barnacle::hash_reader(b)?.md5_hex(),
        b.len()
    ))
}
struct Server {
    _d: daemon::Daemon,
    _dir: tempfile::TempDir,
    sock: PathBuf,
}
impl Server {
    fn new(stock: bool, opts: &str, dbtext: &str) -> io::Result<Self> {
        Self::with_rules(stock, opts, dbtext, None)
    }
    fn with_rules(
        stock: bool,
        opts: &str,
        dbtext: &str,
        extra: Option<(&str, &str)>,
    ) -> io::Result<Self> {
        let root = tempfile::tempdir_in("/tmp")?;
        let db = root.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join("rules.hdb"), dbtext)?;
        if let Some((name, rules)) = extra {
            fs::write(db.join(name), rules)?;
        }
        let sock = root.path().join("sock");
        let tmp = root.path().join("tmp");
        fs::create_dir(&tmp)?;
        let cfg = root.path().join("cfg");
        fs::write(
            &cfg,
            format!(
                "Foreground yes\nLocalSocket {}\nDisableCache yes\nDatabaseDirectory {}\nTemporaryDirectory {}\n{opts}\n",
                sock.display(),
                db.display(),
                tmp.display()
            ),
        )?;
        let d = daemon::Daemon::start(
            Path::new(if stock {
                "/usr/sbin/clamd"
            } else {
                env!("CARGO_BIN_EXE_barnacle")
            }),
            &cfg,
            &sock,
        )?;
        Ok(Self {
            _d: d,
            _dir: root,
            sock,
        })
    }
    fn scan(&self, bytes: &[u8]) -> io::Result<String> {
        daemon::unix_request(&self.sock, &daemon::stream_frame(bytes)?)
    }
}

#[track_caller]
fn check(server: &Server, bytes: &str, expected: &str) -> io::Result<()> {
    let reply = server.scan(bytes.as_bytes())?;
    let expected = if expected == "OK" {
        "stream: OK\0".into()
    } else if expected == "Incomplete" {
        "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into()
    } else if expected.starts_with("Heuristics.") {
        format!("stream: {expected} FOUND\0")
    } else {
        format!("stream: Fwd.{expected}.UNOFFICIAL FOUND\0")
    };
    assert_eq!(reply, expected, "{bytes}");
    Ok(())
}
fn compare(stock: bool) -> io::Result<()> {
    let receipt = hash("Receipt", RECEIPT.as_bytes())?;
    let contact = hash("Contact", CONTACT.as_bytes())?;
    let inner_hash = hash("Inner", inner().as_bytes())?;
    let hdb = receipt.clone() + &contact + &inner_hash;
    let miss = if stock { "OK" } else { "Incomplete" };
    for enc in [
        "base64",
        "quoted-printable",
        "8bit",
        "binary",
        "7bit",
        "none",
    ] {
        let doc = forward(enc, true);
        let delayed = enc == "none" || enc == "7bit";
        let first = if delayed { "Contact" } else { "Receipt" };
        let server = Server::new(stock, "", &hdb)?;
        check(&server, &doc, first)?;
        let crlf = doc.replace('\n', "\r\n");
        check(&server, &crlf, first)?;
        let only_inner = Server::new(stock, "", &inner_hash)?;
        check(
            &only_inner,
            &doc,
            if enc == "7bit" && !stock {
                "Incomplete"
            } else {
                "Inner"
            },
        )?;
        let mut simple = doc.clone();
        let raw = inner();
        if ["7bit", "8bit", "binary", "none"].contains(&enc) {
            simple = simple.replace(
                &raw,
                &format!("{HEAD}Content-Type: text/plain\n\n{RECEIPT}"),
            );
            check(&server, &simple, "Contact")?;
            check(&Server::new(stock, "", &receipt)?, &simple, miss)?;
        }
        for (setting, winner) in [
            ("MaxFiles 1".into(), "Heuristics.Limits.Exceeded.MaxFiles"),
            (
                "MaxFiles 2".into(),
                if delayed { "Contact" } else { "Inner" },
            ),
            (
                "MaxRecursion 2".into(),
                if delayed { "Contact" } else { "Inner" },
            ),
            ("MaxRecursion 3".into(), first),
            (
                format!("MaxScanSize {}", doc.len() + inner().len() - 1),
                "Contact",
            ),
            (
                format!("MaxScanSize {}", doc.len() + inner().len()),
                if delayed { "Contact" } else { "Inner" },
            ),
            (
                format!(
                    "MaxFiles 1\nMaxScanSize {}",
                    doc.len()
                        + if delayed {
                            CONTACT.len()
                        } else {
                            inner().len()
                        }
                        - 1
                ),
                "Heuristics.Limits.Exceeded.MaxScanSize",
            ),
            (
                format!(
                    "MaxFiles 1\nMaxScanSize {}",
                    doc.len()
                        + if delayed {
                            CONTACT.len()
                        } else {
                            inner().len()
                        }
                ),
                "Heuristics.Limits.Exceeded.MaxFiles",
            ),
        ] {
            let opts = format!("{setting}\nAlertExceedsMax yes");
            check(&Server::new(stock, &opts, &hdb)?, &doc, winner)
                .map_err(|e| io::Error::other(format!("{enc} {opts}: {e}")))?;
        }
        check(&Server::new(stock, "ScanMail no", &hdb)?, &doc, miss)?;
    }
    let doc = forward("7bit", true);
    let (forward_only, _) = doc
        .split_once("--forward\nContent-Type: text/vcard")
        .unwrap();
    let doc = format!("{forward_only}--forward--\n");
    for (room, expected) in [
        (0, "Heuristics.Limits.Exceeded.MaxScanSize"),
        (
            200,
            if stock {
                "Heuristics.Limits.Exceeded.MaxScanSize"
            } else {
                "Incomplete"
            },
        ),
        (432, "Heuristics.Limits.Exceeded.MaxFiles"),
    ] {
        let opts = format!(
            "MaxFiles 1\nMaxScanSize {}\nAlertExceedsMax yes",
            doc.len() + room
        );
        check(&Server::new(stock, &opts, &hdb)?, &doc, expected)?;
    }

    for enc in ["7bit", "base64", "quoted-printable"] {
        let doc = forward(enc, false);
        let outer = hash("Outer", doc.as_bytes())?;
        let wanted = match enc {
            "7bit" => "Receipt",
            "base64" => "Outer",
            _ if stock => "Outer",
            _ => "Incomplete",
        };
        check(
            &Server::new(stock, "", &(hdb.clone() + &outer))?,
            &doc,
            wanted,
        )?;
    }
    let leaf = "Market=20receipt=20from=20June.\n";
    for encoded_head in [false, true] {
        let msg = format!("{HEAD}Content-Type: text/plain\n\n{leaf}");
        let msg = if encoded_head {
            msg.replace(" ", "=20")
        } else {
            msg
        };
        let outer = format!(
            "{HEAD}Content-Type: message/rfc822\nContent-Transfer-Encoding: quoted-printable\n\n{msg}"
        );
        let rules =
            hash("Wire", leaf.as_bytes())? + &hash("Decoded", b"Market receipt from June.\n")?;
        check(&Server::new(stock, "", &rules)?, &outer, "Wire")?;
    }
    Ok(())
}
#[test]
fn forwarded_mail() -> io::Result<()> {
    compare(false)?;
    compare_literal_marker(false)
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_forwarded_mail() -> io::Result<()> {
    compare(true)?;
    compare_literal_marker(true)
}

#[test]
fn forwarded_child_has_mail_parent_and_part_name() -> io::Result<()> {
    use barnacle::objects::{self, Options, Verdict};
    let temp = tempfile::tempdir()?;
    let original = inner();
    for encoding in ["base64", "quoted-printable", "8bit", "binary"] {
        let doc = forward(encoding, true);
        for named in [true, false] {
            let input = if named {
                doc.clone()
            } else {
                doc.replace("; name=forward.eml", "").replace(
                    "Content-Disposition: attachment; filename=forward.eml\n",
                    "",
                )
            };
            let mut found = false;
            objects::scan(
                input.as_bytes(),
                &Options::default(),
                temp.path(),
                |obj, _| {
                    if obj.bytes == original.as_bytes() && !obj.normalized {
                        assert_eq!(obj.layer.file_type, "CL_TYPE_MAIL");
                        assert_eq!(
                            obj.layer.name.as_deref(),
                            Some(if named {
                                b"forward.eml".as_slice()
                            } else {
                                b"textportion"
                            })
                        );
                        assert_eq!(
                            obj.parents.iter().map(|p| p.file_type).collect::<Vec<_>>(),
                            ["CL_TYPE_MAIL"]
                        );
                        found = true;
                    }
                    Ok(Verdict::Miss)
                },
                || Ok(()),
            )?;
            assert!(found);
        }
    }
    Ok(())
}

fn forwarded_attachment(inner: &[u8], mode: &str, contact: bool) -> Vec<u8> {
    multipart_forwards(&[(inner, mode, "source")], contact)
}

fn multipart_forwards(messages: &[(&[u8], &str, &str)], contact: bool) -> Vec<u8> {
    let mut doc = format!("{HEAD}Content-Type: multipart/mixed; boundary=box\n\n").into_bytes();
    for &(inner, mode, name) in messages {
        doc.extend(format!("--box\nContent-Type: message/rfc822; name={name}.eml\nContent-Disposition: attachment; filename={name}.eml\n").bytes());
        if !mode.is_empty() {
            doc.extend(format!("Content-Transfer-Encoding: {mode}\n").bytes());
        }
        doc.push(b'\n');
        doc.extend(inner);
    }
    if contact {
        doc.extend(format!("--box\nContent-Type: text/vcard; name=contact.vcf\nContent-Transfer-Encoding: base64\n\n{}\n",b64(CONTACT.as_bytes())).bytes());
    }
    doc.extend(b"--box--\n");
    doc
}

fn compare_literal_marker(stock: bool) -> io::Result<()> {
    let png = include_bytes!("fixtures/images/blue.png");
    let mut image = format!("{HEAD}Content-Type: multipart/mixed; boundary=art\n\n--art\nContent-Type: text/plain\n\nThe enclosed airmail stamp is blue.\n--art\nContent-Type: image/png; name=stamp.png\nContent-Disposition: attachment; filename=stamp.png\n\n").into_bytes();
    image.extend(png);
    image.extend(b"\n--art--\n");
    let mut messages = vec![(image, false)];
    for (line, eligible) in [
        ("A plain forwarded receipt.", false),
        ("See the Content-Transfer-Encoding guide.", false),
        (" Content-Transfer-Encoding notes follow.", false),
        ("Content-Transfer-Encoding choices are documented.", true),
        ("content-transfer-encodingNotes follow this line.", true),
        (
            "Content-Transfer-Encoding: guidance for x7bitz writers.",
            false,
        ),
        ("Content-Transfer-Encoding choices include 7BIT.", true),
    ] {
        messages.push((
            format!("{HEAD}Content-Type: text/plain\n\n{line}\n{RECEIPT}").into_bytes(),
            eligible,
        ));
    }
    for (message, eligible) in messages {
        let inner_hash = hash("Inner", &message)?;
        for mode in ["", "8bit"] {
            for contact in [false, true] {
                let doc = forwarded_attachment(&message, mode, contact);
                let db = inner_hash.clone()
                    + &hash("Png", png)?
                    + &hash("Contact", CONTACT.as_bytes())?
                    + &hash("Outer", &doc)?;
                let winner = if eligible && !(contact && mode.is_empty()) {
                    "Inner"
                } else if contact {
                    "Contact"
                } else {
                    "Outer"
                };
                let reply = Server::new(stock, "", &db)?.scan(&doc)?;
                assert_eq!(
                    reply,
                    format!("stream: Fwd.{winner}.UNOFFICIAL FOUND\0"),
                    "mode={mode:?} contact={contact} eligible={eligible}"
                );
            }
        }
    }
    Ok(())
}

const NOTE: &[u8] = b"First Letter\n";
const UU: &str = "begin 644 note.txt\n-1FER<W0@3&5T=&5R\"@\x60\x60\n\x60\nend\n";

fn uu_forward(mode: &str, contact: bool) -> (String, String, Vec<u8>) {
    let body = format!("The attached office note follows.\n{UU}Thanks for checking.\n");
    let inner = format!("{HEAD}Content-Type: text/plain\n\n{body}");
    let message = forwarded_attachment(inner.as_bytes(), mode, contact);
    (body, inner, message)
}

fn compare_recovered_note(stock: bool) -> io::Result<()> {
    let leaf = hash("Note", NOTE)?;
    let contact = hash("Contact", CONTACT.as_bytes())?;
    let mut envelopes = String::new();
    let mut raw = String::new();
    let mut samples = Vec::new();
    for mode in ["", "7bit", "8bit", "binary"] {
        for sibling in [false, true] {
            let (body, inner, bytes) = uu_forward(mode, sibling);
            if samples.is_empty() {
                raw = hash("Body", body.as_bytes())?
                    + &hash("Message", inner.as_bytes())?
                    + &hash("WireBlock", UU.as_bytes())?;
            }
            envelopes.push_str(&hash("Outer", &bytes)?);
            let crlf = std::str::from_utf8(&bytes)
                .unwrap()
                .replace('\n', "\r\n")
                .into_bytes();
            envelopes.push_str(&hash("Outer", &crlf)?);
            samples.push((bytes, sibling));
            samples.push((crlf, sibling));
        }
    }
    let with_note = envelopes.clone() + &raw + &leaf + &contact;
    let without_note = envelopes.clone() + &raw + &contact;
    for (rules, note) in [(&with_note, true), (&without_note, false)] {
        let server = Server::new(stock, "", rules)?;
        for (bytes, sibling) in &samples {
            let expected = if *sibling {
                "Contact"
            } else if note {
                "Note"
            } else {
                "Outer"
            };
            assert_eq!(
                server.scan(bytes)?,
                format!("stream: Fwd.{expected}.UNOFFICIAL FOUND\0")
            );
        }
    }
    let (_, _, bytes) = uu_forward("8bit", false);
    let marker: String = b"The attached office note follows."
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let rules = format!("Fwd.RawBody:0:*:{marker}\n");
    for (hdb, expected) in [(&with_note, "Note"), (&without_note, "RawBody")] {
        let s = Server::with_rules(stock, "", hdb, Some(("wire.ndb", &rules)))?;
        assert_eq!(
            s.scan(&bytes)?,
            format!("stream: Fwd.{expected}.UNOFFICIAL FOUND\0")
        );
    }
    for (option, extra, want) in [
        ("MaxFiles 1", 12, "Heuristics.Limits.Exceeded.MaxScanSize"),
        ("MaxFiles 1", 13, "Heuristics.Limits.Exceeded.MaxFiles"),
        (
            "MaxRecursion 1",
            12,
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
        (
            "MaxRecursion 1",
            13,
            "Heuristics.Limits.Exceeded.MaxRecursion",
        ),
        ("MaxFiles 2\nMaxRecursion 2", 13, "Fwd.Note.UNOFFICIAL"),
    ] {
        let opts = format!(
            "{option}\nMaxScanSize {}\nAlertExceedsMax yes",
            bytes.len() + extra
        );
        assert_eq!(
            Server::new(stock, &opts, &leaf)?.scan(&bytes)?,
            format!("stream: {want} FOUND\0")
        );
    }
    Ok(())
}

#[test]
fn recovered_forward_note() -> io::Result<()> {
    compare_recovered_note(false)?;
    small_note_sizes(false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_recovered_forward_note() -> io::Result<()> {
    compare_recovered_note(true)?;
    small_note_sizes(true)?;
    let (_, _, doc) = uu_forward("", false);
    let marker: String = NOTE.iter().map(|b| format!("{b:02x}")).collect();
    for (parent, found) in [("CL_TYPE_MAIL", true), ("CL_TYPE_UUENCODED", false)] {
        let rule = format!(
            "Fwd.Parent;Engine:81-255,Target:0,Container:{parent},FileSize:13-13;0;{marker}\n"
        );
        let server = Server::with_rules(
            true,
            "",
            &hash("Miss", CONTACT.as_bytes())?,
            Some(("parent.ldb", &rule)),
        )?;
        let expected = if found {
            "stream: Fwd.Parent.UNOFFICIAL FOUND\0"
        } else {
            "stream: OK\0"
        };
        assert_eq!(server.scan(&doc)?, expected);
    }
    Ok(())
}

#[test]
fn note_has_mail_parent() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    let (_, _, doc) = uu_forward("8bit", false);
    let verdict = scan(
        &doc,
        &Options::default(),
        tmp.path(),
        |obj, _| {
            if obj.bytes != NOTE {
                return Ok(Verdict::Miss);
            }
            assert_eq!(obj.parents.len(), 1);
            assert_eq!(obj.parents[0].file_type, "CL_TYPE_MAIL");
            assert_eq!(obj.layer.file_type, "CL_TYPE_TEXT_ASCII");
            assert!(obj.layer.name.is_none());
            Ok(Verdict::Found("Note".into()))
        },
        || Ok(()),
    )?;
    assert_eq!(verdict, Verdict::Found("Note".into()));
    for body in [
        format!("{UU}{UU}"),
        UU.replace("end\n", ""),
        format!("Content-Transfer-Encoding: 8bit\n\n{UU}"),
    ] {
        let inner = format!("{HEAD}Content-Type: text/plain\n\n{body}");
        let doc = forwarded_attachment(inner.as_bytes(), "", false);
        let result = scan(
            &doc,
            &Options::default(),
            tmp.path(),
            |_, _| Ok(Verdict::Miss),
            || Ok(()),
        )?;
        assert_eq!(result, Verdict::Incomplete);
    }
    Ok(())
}

fn small_note_sizes(stock: bool) -> io::Result<()> {
    for &(size, line) in &[
        (0, ""),
        (1, "!00\x60\x60\n"),
        (5, "%04)#1$4\x60\n"),
        (6, "&04)#1$5&\n"),
    ] {
        let msg =
            format!("{HEAD}Content-Type: text/plain\n\nbegin 644 note.txt\n{line}\x60\nend\n");
        let bytes = forwarded_attachment(msg.as_bytes(), "8bit", false);
        let hdb = hash("Miss", CONTACT.as_bytes())?;
        let opts = format!(
            "MaxFiles 1\nMaxScanSize {}\nAlertExceedsMax yes",
            bytes.len() + size
        );
        let expected = if size == 6 {
            "Heuristics.Limits.Exceeded.MaxFiles"
        } else if stock {
            "OK"
        } else {
            "Incomplete"
        };
        check(
            &Server::new(stock, &opts, &hdb)?,
            std::str::from_utf8(&bytes).unwrap(),
            expected,
        )?;
    }
    Ok(())
}

fn mixed_forward_note(stock: bool) -> io::Result<()> {
    let raw_text = format!("The attached note follows.\n{UU}Please keep the receipt.\n");
    let inner = inner().replace("Attached receipt.\n", &raw_text);
    // Stock retains the end line after removing the uuencoded note.
    let emitted_text = raw_text.replace(UU, "end\n");
    let emitted = inner.replace(&raw_text, &emitted_text);
    let false_matches =
        hash("OriginalForward", inner.as_bytes())? + &hash("OriginalText", raw_text.as_bytes())?;
    let rules = [
        hash("Text", emitted_text.as_bytes())?,
        hash("Receipt", RECEIPT.as_bytes())?,
        hash("Emitted", emitted.as_bytes())?,
        hash("Contact", CONTACT.as_bytes())?,
        hash("Note", NOTE)?,
    ];
    let mut base = false_matches;
    let mut samples = Vec::new();
    for wrapping in ["8bit", "binary"] {
        for contact in [false, true] {
            let wire = forwarded_attachment(inner.as_bytes(), wrapping, contact);
            let lf = std::str::from_utf8(&wire).unwrap();
            for doc in [lf.to_owned(), lf.replace('\n', "\r\n")] {
                base += &hash("Outer", doc.as_bytes())?;
                samples.push((doc, contact));
            }
        }
    }
    for (i, (alone, with_contact)) in [
        ("Text", "Text"),
        ("Receipt", "Receipt"),
        ("Emitted", "Emitted"),
        ("Note", "Contact"),
        ("Note", "Note"),
        ("Outer", "Outer"),
    ]
    .into_iter()
    .enumerate()
    {
        let server = Server::new(stock, "", &(base.clone() + &rules[i..].concat()))?;
        for (doc, contact) in &samples {
            check(&server, doc, if *contact { with_contact } else { alone })?;
        }
    }
    let doc = &samples[0].0;
    // The encoded line appears only in the original mail body.
    let encoded_line = UU.lines().nth(1).unwrap();
    let marker: String = encoded_line.bytes().map(|b| format!("{b:02x}")).collect();
    let raw_rule = format!("Fwd.WireBody:0:*:{marker}\n");
    for (hdb, expected) in [(rules[4].as_str(), "Note"), (base.as_str(), "WireBody")] {
        let server = Server::with_rules(stock, "", hdb, Some(("body.ndb", &raw_rule)))?;
        check(&server, doc, expected)?;
    }
    let file_budget = doc.len() + emitted.len();
    let prefix = "Heuristics.Limits.Exceeded.";
    for (options, i, name) in [
        (
            format!("MaxScanSize {}", file_budget - 1),
            2,
            format!("{prefix}MaxScanSize"),
        ),
        (format!("MaxScanSize {file_budget}"), 2, "Emitted".into()),
        ("MaxFiles 3".into(), 1, format!("{prefix}MaxFiles")),
        ("MaxFiles 4".into(), 1, "Receipt".into()),
        ("MaxFiles 4".into(), 4, format!("{prefix}MaxFiles")),
        ("MaxFiles 5".into(), 4, "Note".into()),
        ("MaxRecursion 2".into(), 1, format!("{prefix}MaxRecursion")),
        ("MaxRecursion 2".into(), 4, "Note".into()),
    ] {
        let server = Server::new(stock, &format!("{options}\nAlertExceedsMax yes"), &rules[i])?;
        check(&server, doc, &name)?;
    }
    for doc in [doc.clone(), doc.replace('\n', "\r\n")] {
        let known = rules[2].clone() + &hash("Outer", doc.as_bytes())?;
        for extra in [
            NOTE.len() - 1,
            NOTE.len(),
            emitted.len() - 1,
            emitted.len(),
            emitted.len() + NOTE.len(),
        ] {
            let options = format!("MaxScanSize {}\nAlertExceedsMax yes", doc.len() + extra);
            let server = Server::new(stock, &options, &rules[4])?;
            if (NOTE.len()..emitted.len()).contains(&extra) {
                if stock {
                    let reply = server.scan(doc.as_bytes())?;
                    assert!(
                        reply == "stream: Fwd.Note.UNOFFICIAL FOUND\0"
                            || reply == "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0",
                        "{reply:?}"
                    );
                } else {
                    check(&server, &doc, "Incomplete")?;
                }
            } else {
                check(
                    &server,
                    &doc,
                    if extra == emitted.len() + NOTE.len() {
                        "Note"
                    } else {
                        "Heuristics.Limits.Exceeded.MaxScanSize"
                    },
                )?;
            }
            check(
                &Server::new(stock, &options, &known)?,
                &doc,
                if extra >= emitted.len() {
                    "Emitted"
                } else {
                    "Outer"
                },
            )?;
        }
    }
    // Both file count and recursion can exclude the note after size excluded the forward.
    for limit in ["MaxFiles 1", "MaxRecursion 1"] {
        let options = format!(
            "MaxScanSize {}\n{limit}\nAlertExceedsMax yes",
            doc.len() + NOTE.len()
        );
        check(
            &Server::new(stock, &options, &rules[4])?,
            doc,
            "Heuristics.Limits.Exceeded.MaxScanSize",
        )?;
    }
    // A direct contact still wins before the private recovery directory is opened.
    let with_contact = &samples.iter().find(|s| s.1).unwrap().0;
    let options = format!(
        "MaxScanSize {}\nAlertExceedsMax yes",
        with_contact.len() + CONTACT.len() + NOTE.len()
    );
    check(
        &Server::new(stock, &options, &(rules[3].clone() + &rules[4]))?,
        with_contact,
        "Contact",
    )?;
    Ok(())
}

#[test]
fn mixed_forward_note_winners() -> io::Result<()> {
    mixed_forward_note(false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_mixed_forward_note_winners() -> io::Result<()> {
    mixed_forward_note(true)
}

fn duplicate_forwards(stock: bool) -> io::Result<()> {
    let message = inner();
    let parts = ["office", "finance", "archive"].map(|name| (message.as_bytes(), "", name));
    let receipt = hash("Receipt", RECEIPT.as_bytes())?;
    let saved = hash("Forward", message.as_bytes())?;
    let contact = hash("Contact", CONTACT.as_bytes())?;
    for count in [2, 3] {
        let lf = String::from_utf8(multipart_forwards(&parts[..count], false)).unwrap();
        let with_contact = String::from_utf8(multipart_forwards(&parts[..count], true)).unwrap();
        for doc in [lf.clone(), lf.replace('\n', "\r\n")] {
            let outer = hash("Outer", doc.as_bytes())?;
            let child = receipt.clone() + &saved + &outer;
            check(&Server::new(stock, "", &child)?, &doc, "Receipt")?;
            check(
                &Server::new(stock, "", &(saved.clone() + &outer))?,
                &doc,
                "Forward",
            )?;
            check(&Server::new(stock, "", &outer)?, &doc, "Outer")?;
            // The forward contains the plain introduction and the decoded receipt.
            for (limits, hdb, expected) in [
                ("MaxRecursion 2".to_owned(), &child, "Forward"),
                ("MaxRecursion 3".into(), &child, "Receipt"),
                ("MaxFiles 3".into(), &child, "Forward"),
                ("MaxFiles 4".into(), &child, "Receipt"),
                (
                    format!("MaxScanSize {}", doc.len() + message.len() - 1),
                    &child,
                    "Outer",
                ),
                (
                    format!("MaxScanSize {}", doc.len() + message.len()),
                    &child,
                    "Forward",
                ),
                (
                    format!("MaxFiles {}", 3 * count),
                    &contact,
                    "Heuristics.Limits.Exceeded.MaxFiles",
                ),
                (
                    format!("MaxFiles {}", 3 * count + 1),
                    &contact,
                    if stock { "OK" } else { "Incomplete" },
                ),
            ] {
                check(
                    &Server::new(stock, &format!("{limits}\nAlertExceedsMax yes"), hdb)?,
                    &doc,
                    expected,
                )?;
            }
        }
        check(
            &Server::new(stock, "", &(receipt.clone() + &contact))?,
            &with_contact,
            "Contact",
        )?;
    }
    Ok(())
}

fn competing_deferred_receipts(stock: bool) -> io::Result<()> {
    let second_receipt =
        "South office: the monthly expense summary lists local travel and office supplies.\n"
            .repeat(3);
    let first = inner();
    let second = first.replace(&b64(RECEIPT.as_bytes()), &b64(second_receipt.as_bytes()));
    let db = hash("Receipt", RECEIPT.as_bytes())? + &hash("Expenses", second_receipt.as_bytes())?;
    for parts in [
        [
            (first.as_bytes(), "", "zulu"),
            (second.as_bytes(), "", "alpha"),
        ],
        [
            (second.as_bytes(), "", "alpha"),
            (first.as_bytes(), "", "zulu"),
        ],
    ] {
        let doc = multipart_forwards(&parts, false);
        let available = first.len() + "Attached receipt.\n".len() + RECEIPT.len();
        assert!(available < second.len());
        for restricted in [false, true] {
            let options = if restricted {
                format!("MaxScanSize {}\nAlertExceedsMax yes", doc.len() + available)
            } else {
                String::new()
            };
            let server = Server::new(stock, &options, &db)?;
            if stock {
                // Each scan creates a fresh directory with randomly named saved forwards.
                let reply = server.scan(&doc)?;
                let other = if restricted {
                    "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0"
                } else {
                    "stream: Fwd.Expenses.UNOFFICIAL FOUND\0"
                };
                assert!(
                    reply == "stream: Fwd.Receipt.UNOFFICIAL FOUND\0" || reply == other,
                    "{reply:?}"
                );
            } else {
                check(&server, std::str::from_utf8(&doc).unwrap(), "Incomplete")?;
            }
        }
    }
    Ok(())
}

#[test]
fn duplicate_forward_winners() -> io::Result<()> {
    duplicate_forwards(false)?;
    competing_deferred_receipts(false)?;
    // A third, different message can win before either of the first two saved files.
    let message = inner();
    let other = message.replace("Market receipt", "Office invoice");
    for members in [
        vec![
            (message.as_bytes(), "", "one"),
            (message.as_bytes(), "", "two"),
            (other.as_bytes(), "", "three"),
        ],
        vec![
            (message.as_bytes(), "", "one"),
            (message.as_bytes(), "7bit", "two"),
        ],
    ] {
        let doc = String::from_utf8(multipart_forwards(&members, false)).unwrap();
        check(
            &Server::new(false, "", &hash("Receipt", RECEIPT.as_bytes())?)?,
            &doc,
            "Incomplete",
        )?;
    }
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    let mut seen = 0;
    let pair = [
        (message.as_bytes(), "", "one"),
        (message.as_bytes(), "", "two"),
    ];
    scan(
        &multipart_forwards(&pair, false),
        &Options::default(),
        tmp.path(),
        |obj, _| {
            if obj.bytes == RECEIPT.as_bytes() {
                assert_eq!(
                    obj.parents.iter().map(|p| p.file_type).collect::<Vec<_>>(),
                    ["CL_TYPE_MAIL", "CL_TYPE_MAIL"]
                );
                assert!(obj.parents[1].name.is_none());
                seen += 1;
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(seen, 2);
    Ok(())
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_duplicate_forward_winners() -> io::Result<()> {
    duplicate_forwards(true)?;
    competing_deferred_receipts(true)?;
    let message = inner();
    let pair = [
        (message.as_bytes(), "", "one"),
        (message.as_bytes(), "", "two"),
    ];
    let doc = String::from_utf8(multipart_forwards(&pair, false)).unwrap();
    let marker: String = RECEIPT.bytes().map(|b| format!("{b:02x}")).collect();
    for (parent, winner) in [("CL_TYPE_MAIL", "Parent"), ("CL_TYPE_ZIP", "OK")] {
        let rule = format!(
            "Fwd.Parent;Engine:81-255,Target:0,Container:{parent},FileSize:{0}-{0};0;{marker}\n",
            RECEIPT.len()
        );
        check(
            &Server::with_rules(
                true,
                "",
                &hash("Miss", CONTACT.as_bytes())?,
                Some(("parent.ldb", &rule)),
            )?,
            &doc,
            winner,
        )?;
    }
    Ok(())
}

fn mbox_pair(first: &str, second: &str) -> String {
    format!(
        "From office@example.invalid Fri Nov 19 02:00:00 2026\n{first}\nFrom depot@example.invalid Fri Nov 19 02:01:00 2026\n{second}"
    )
}

fn mbox_orders(stock: bool) -> io::Result<()> {
    let a = format!("{HEAD}Content-Type: text/plain\n\n{RECEIPT}");
    let b = format!("{HEAD}Content-Type: text/plain\n\n{CONTACT}");
    let attachment = format!(
        "{HEAD}Content-Type: application/octet-stream; name=contact.vcf\nContent-Disposition: attachment; filename=contact.vcf\nContent-Transfer-Encoding: base64\n\n{}\n",
        b64(CONTACT.as_bytes())
    );
    // Stock retains the blank line before the following From separator.
    let ra =
        hash("Receipt", RECEIPT.as_bytes())? + &hash("Receipt", format!("{RECEIPT}\n").as_bytes())?;
    let rb =
        hash("Contact", CONTACT.as_bytes())? + &hash("Contact", format!("{CONTACT}\n").as_bytes())?;
    for (first, second, direct) in [
        (&a, &b, false),
        (&b, &a, false),
        (&a, &attachment, true),
        (&attachment, &a, true),
    ] {
        let lf = mbox_pair(first, second);
        for doc in [lf.clone(), lf.replace('\n', "\r\n")] {
            let outer = hash("Outer", doc.as_bytes())?;
            for (db, want) in [
                (ra.clone() + &outer, "Receipt"),
                (rb.clone() + &outer, "Contact"),
                (outer.clone(), "Outer"),
            ] {
                check(&Server::new(stock, "", &db)?, &doc, want)?;
            }
            let server = Server::new(stock, "", &(ra.clone() + &rb + &outer))?;
            if direct {
                check(&server, &doc, "Contact")?;
            } else if stock {
                for _ in 0..6 {
                    let reply = server.scan(doc.as_bytes())?;
                    assert!(
                        reply == "stream: Fwd.Receipt.UNOFFICIAL FOUND\0"
                            || reply == "stream: Fwd.Contact.UNOFFICIAL FOUND\0",
                        "{reply:?}"
                    );
                }
            } else {
                check(&server, &doc, "Incomplete")?;
            }
        }
    }
    let doc = mbox_pair(&a, &b);
    let rules = ra.clone() + &rb;
    for (opts, want) in [
        (
            format!("MaxFiles 1\nMaxScanSize {}", doc.len()),
            "Heuristics.Limits.Exceeded.MaxFiles",
        ),
        (
            format!("MaxRecursion 1\nMaxScanSize {}", doc.len()),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
        (
            "MaxRecursion 1".into(),
            "Heuristics.Limits.Exceeded.MaxRecursion",
        ),
        (
            format!("MaxScanSize {}", doc.len() + RECEIPT.len()),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
    ] {
        check(
            &Server::new(stock, &format!("{opts}\nAlertExceedsMax yes"), &rules)?,
            &doc,
            want,
        )?;
    }
    for opts in [
        "MaxFiles 2".to_owned(),
        format!("MaxScanSize {}", doc.len() + RECEIPT.len() + 1),
    ] {
        let s = Server::new(stock, &format!("{opts}\nAlertExceedsMax yes"), &rules)?;
        if stock {
            let r = s.scan(doc.as_bytes())?;
            assert!(
                r == "stream: Fwd.Receipt.UNOFFICIAL FOUND\0"
                    || r == "stream: Fwd.Contact.UNOFFICIAL FOUND\0"
                    || r == "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0"
            );
        } else {
            check(&s, &doc, "Incomplete")?;
        }
    }
    let shared =
        hash("Ledger", format!("{RECEIPT}\n").as_bytes())? + &hash("Ledger", CONTACT.as_bytes())?;
    check(&Server::new(stock, "", &shared)?, &doc, "Ledger")?;
    let with_markup = format!(
        "{HEAD}Content-Type: text/plain\n\nMail <desk@example.invalid> about café invoices.\n"
    );
    let body = "Mail <desk@example.invalid> about café invoices.\n";
    check(
        &Server::new(stock, "", &hash("Ledger", body.as_bytes())?)?,
        &mbox_pair(&a, &with_markup),
        "Ledger",
    )?;
    let cover = "Attached receipt.\n";
    let mixed = inner();
    for doc in [mbox_pair(&b, &mixed), mbox_pair(&mixed, &b)] {
        let cover_sig = hash("Cover", cover.as_bytes())?;
        check(
            &Server::new(stock, "", &(cover_sig + &ra + &rb))?,
            &doc,
            "Cover",
        )?;
        check(
            &Server::new(stock, "", &(ra.clone() + &rb))?,
            &doc,
            "Receipt",
        )?;
        check(&Server::new(stock, "", &rb)?, &doc, "Contact")?;
    }
    // A rejected direct attachment remains in the recovery directory beside the smaller letter.
    let pair = mbox_pair(&a, &attachment);
    let opts = format!(
        "MaxScanSize {}\nAlertExceedsMax yes",
        pair.len() + RECEIPT.len() + 1
    );
    let s = Server::new(stock, &opts, &ra)?;
    if stock {
        let reply = s.scan(pair.as_bytes())?;
        assert!(
            reply == "stream: Fwd.Receipt.UNOFFICIAL FOUND\0"
                || reply == "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0"
        );
    } else {
        check(&s, &pair, "Incomplete")?;
    }
    check(
        &Server::new(stock, &opts, &hash("Outer", pair.as_bytes())?)?,
        &pair,
        "Outer",
    )?;
    for (line, wire, expected) in [
        (997, true, "\n"),
        (998, true, "\n\n"),
        (998, false, "\n"),
        (999, false, "\n\n"),
    ] {
        let row = "Z".repeat(line);
        let note = format!("{HEAD}Content-Type: text/plain\n\n{row}\n");
        let m = mbox_pair(&a, &note);
        let m = if wire { m.replace('\n', "\r\n") } else { m };
        check(
            &Server::new(
                stock,
                "",
                &hash("Long", format!("{row}{expected}").as_bytes())?,
            )?,
            &m,
            "Long",
        )?;
    }
    let note = format!("{HEAD}Content-Type: text/plain\n\nNorth\n\n\nWednesday\n \t \nPaid\n");
    let doc = mbox_pair(&a, &note);
    check(
        &Server::new(stock, "", &hash("Copy", b"North\n\nWednesday\n \nPaid\n")?)?,
        &doc,
        "Copy",
    )?;
    let seven = a.replace(
        "Content-Type: text/plain\n",
        "Content-Type: text/plain\nContent-Transfer-Encoding: 7bit\n",
    );
    let doc = mbox_pair(&seven, &b);
    let s = Server::new(
        stock,
        "MaxFiles 3\nAlertExceedsMax yes",
        &hash("Miss", b"unlisted ledger")?,
    )?;
    check(
        &s,
        &doc,
        if stock {
            "Heuristics.Limits.Exceeded.MaxFiles"
        } else {
            "Incomplete"
        },
    )?;
    Ok(())
}
#[test]
fn mbox_winners() -> io::Result<()> {
    mbox_orders(false)
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_mbox_winners() -> io::Result<()> {
    mbox_orders(true)
}

fn longer_mbox(stock: bool) -> io::Result<()> {
    let plain = |s: &str| format!("{HEAD}Content-Type: text/plain\n\n{s}");
    let bin = |s: &str| {
        format!(
            "{HEAD}Content-Type: application/octet-stream; name=receipt.txt\nContent-Transfer-Encoding: base64\n\n{}\n",
            b64(s.as_bytes())
        )
    };
    let series = |parts: &[&String]| {
        parts
            .iter()
            .map(|s| format!("From desk@example.invalid Fri Nov 19 02:00:00 2026\n{s}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let first = plain(RECEIPT);
    let second = plain(CONTACT);
    let end = "Purchased train tickets for Friday.\n";
    let late = bin(end);
    let big = bin(&"Annual expense report, North Office. ".repeat(40));
    let receipts = hash("Receipt", format!("{RECEIPT}\n").as_bytes())?;
    let contact =
        hash("Contact", format!("{CONTACT}\n").as_bytes())? + &hash("Contact", CONTACT.as_bytes())?;
    let direct = hash("Tickets", end.as_bytes())?;
    for parts in [
        vec![&first, &second, &late],
        vec![&first, &second, &first, &second, &late],
    ] {
        let doc = series(&parts);
        let rules = receipts.clone() + &contact + &direct + &hash("Outer", doc.as_bytes())?;
        check(&Server::new(stock, "", &rules)?, &doc, "Tickets")?;
        check(
            &Server::new(stock, &format!("MaxFiles {}", parts.len()), &rules)?,
            &doc,
            "Tickets",
        )?;
        let s = Server::new(
            stock,
            &format!("MaxFiles {}\nAlertExceedsMax yes", parts.len() - 1),
            &direct,
        )?;
        check(&s, &doc, "Heuristics.Limits.Exceeded.MaxFiles")?;
    }
    let plain_end = plain(end);
    let doc = series(&[&first, &second, &first, &second, &plain_end]);
    check(&Server::new(stock, "", &direct)?, &doc, "Tickets")?;
    check(&Server::new(stock, "", &receipts)?, &doc, "Receipt")?;
    let h = hash("Outer", doc.as_bytes())?;
    check(&Server::new(stock, "", &h)?, &doc, "Outer")?;
    for parts in [[&big, &first, &second], [&first, &second, &big]] {
        let doc = series(&parts);
        let opts = format!(
            "MaxScanSize {}\nAlertExceedsMax yes",
            doc.len() + RECEIPT.len() + CONTACT.len() + 4
        );
        let s = Server::new(stock, &opts, &receipts)?;
        if stock {
            let reply = s.scan(doc.as_bytes())?;
            assert!(
                reply == "stream: Fwd.Receipt.UNOFFICIAL FOUND\0"
                    || reply == "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0",
                "{reply:?}"
            );
        } else {
            check(&s, &doc, "Incomplete")?;
        }
        check(
            &Server::new(stock, &opts, &direct)?,
            &doc,
            "Heuristics.Limits.Exceeded.MaxScanSize",
        )?;
        check(
            &Server::new(stock, &opts, &hash("Outer", doc.as_bytes())?)?,
            &doc,
            "Outer",
        )?;
    }
    Ok(())
}

#[test]
fn longer_mbox_winners() -> io::Result<()> {
    longer_mbox(false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_longer_mbox_winners() -> io::Result<()> {
    longer_mbox(true)
}

fn small_mail_and_views(stock: bool) -> io::Result<()> {
    let plain = |s: &str| format!("{HEAD}Content-Type: text/plain\n\n{s}");
    let a = "North office received more folders.\n".repeat(90);
    let b = "Bookkeeper approved the delivery.\n".repeat(70);
    let hdb = hash("B", b.as_bytes())? + &hash("B", format!("{b}\n").as_bytes())?;
    let only_view = "Unused:7:EOF-6:7a717a717a71\n";
    let ar = plain(&a);
    let br = plain(&b);
    let doc = mbox_pair(&ar, &br);
    let aggregate = doc.len() + a.len() + 1 + b.len();
    for option in [
        format!("MaxFileSize {}", doc.len()),
        "ScanHTML no\nMaxFiles 3".to_owned(),
        format!("ScanHTML no\nMaxScanSize {aggregate}"),
        "MaxScriptNormalize 16\nMaxFiles 3".into(),
        format!("MaxScriptNormalize 16\nMaxScanSize {aggregate}"),
    ] {
        for (rules, winner) in [(&hdb, "B"), (&hash("Outer", doc.as_bytes())?, "Outer")] {
            let s = Server::with_rules(
                stock,
                &format!("{option}\nAlertExceedsMax yes"),
                rules,
                Some(("views.ndb", only_view)),
            )?;
            check(&s, &doc, winner)?;
        }
    }
    for tiny in ["", "\n", "OK\n", "yes\n"] {
        let item = plain(tiny);
        for doc in [mbox_pair(&item, &br), mbox_pair(&br, &item)] {
            check(
                &Server::new(stock, "MaxFiles 2\nAlertExceedsMax yes", &hdb)?,
                &doc,
                "B",
            )?;
            check(
                &Server::new(stock, "", &hash("Outer", doc.as_bytes())?)?,
                &doc,
                "Outer",
            )?;
        }
        let doc = format!(
            "{}\nFrom desk@example.invalid Fri Nov 19 02:01:00 2026\n{br}",
            mbox_pair(&item, &item)
        );
        let s = Server::new(stock, "MaxFiles 2\nAlertExceedsMax yes", &hdb)?;
        check(
            &s,
            &doc,
            if tiny.trim().is_empty() {
                "B"
            } else {
                "Heuristics.Limits.Exceeded.MaxFiles"
            },
        )?;
    }
    Ok(())
}

#[test]
fn mbox_small_bodies_and_script_limits() -> io::Result<()> {
    small_mail_and_views(false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_mbox_small_bodies_and_script_limits() -> io::Result<()> {
    small_mail_and_views(true)
}

fn business_member(mime: &str, name: &str, encoding: &str, body: &str, mixed: bool) -> String {
    let typ = format!(
        "Content-Type: {mime}; name=\"{name}\"\nContent-Disposition: attachment; filename=\"{name}\"\n"
    );
    let cte = if encoding.is_empty() {
        String::new()
    } else {
        format!("Content-Transfer-Encoding: {encoding}\n")
    };
    if mixed {
        format!(
            "{HEAD}Content-Type: multipart/mixed; boundary=office\n\n--office\nContent-Type: text/plain\n\nAttached for the inventory.\n--office\n{typ}{cte}\n{body}--office--\n"
        )
    } else {
        format!("{HEAD}{typ}{cte}\n{body}")
    }
}

fn business_messages(stock: bool) -> io::Result<()> {
    const CSV: &[u8] = b"Month,Office,Count\nNovember,North,42\n";
    let items: &[(&str, &str, &[u8])] = &[
        (
            "application/pdf",
            "invoice.pdf",
            include_bytes!("fixtures/pdf/qpdf-object-stream.pdf"),
        ),
        (
            "image/png",
            "stamp.png",
            include_bytes!("fixtures/images/blue.png"),
        ),
        ("text/csv", "inventory.csv", CSV),
        (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "report.xlsx",
            include_bytes!("fixtures/ooxml/report.xlsx"),
        ),
    ];
    let first = format!("{HEAD}Content-Type: text/plain\n\n{RECEIPT}");
    let receipt = hash("Receipt", format!("{RECEIPT}\n").as_bytes())?;
    let cover = hash("Cover", b"Attached for the inventory.\n")?;
    for &(mime, name, data) in items {
        let file = hash("File", data)?;
        let encodings = if data == CSV {
            &["base64", "quoted-printable", "8bit", "binary", ""][..]
        } else {
            &["base64"][..]
        };
        for &enc in encodings {
            let wire = if enc == "base64" {
                mime_base64(data)
            } else {
                std::str::from_utf8(data).unwrap().to_owned()
            };
            for mixed in [false, true] {
                let member = business_member(mime, name, enc, &wire, mixed);
                let two = mbox_pair(&first, &member);
                let three =
                    format!("From desk@example.invalid Fri Nov 19 01:59:00 2026\n{first}\n{two}");
                let outer = hash("Outer", two.as_bytes())? + &hash("Outer", three.as_bytes())?;
                let all = Server::new(stock, "", &(file.clone() + &receipt + &outer))?;
                for doc in [&two, &three] {
                    if enc.is_empty() && !mixed {
                        // Stock saves unencoded standalone CSV beside the earlier receipt.
                        if stock {
                            let r = all.scan(doc.as_bytes())?;
                            assert!(
                                matches!(
                                    r.as_str(),
                                    "stream: Fwd.File.UNOFFICIAL FOUND\0"
                                        | "stream: Fwd.Receipt.UNOFFICIAL FOUND\0"
                                ),
                                "{r:?}"
                            );
                        } else {
                            check(&all, doc, "Incomplete")?;
                        }
                        check(&Server::new(stock, "", &file)?, doc, "File")?;
                    } else {
                        check(&all, doc, "File")?;
                    }
                }
                check(&Server::new(stock, "", &outer)?, &two, "Outer")?;
                if mixed {
                    check(
                        &Server::new(stock, "", &(cover.clone() + &file + &receipt + &outer))?,
                        &three,
                        "Cover",
                    )?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn business_attachment_mbox() -> io::Result<()> {
    business_messages(false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_business_attachment_mbox() -> io::Result<()> {
    business_messages(true)
}

fn saved_mailbox_spans(stock: bool) -> io::Result<()> {
    // Exercise borrowed LF, folded whitespace, CRLF, and replay beyond cached spans.
    let mut doc = String::new();
    let mut signatures = Vec::new();
    for i in 0..21 {
        let fold = i % 3 == 1;
        let crlf = i % 3 == 2;
        let body = if fold {
            format!("Office delivery {i}\n\t \nFiled.\n")
        } else if i == 15 || i == 17 {
            format!("Depot receipt {i}\nDelivered intact.\n")
        } else {
            format!("Office delivery {i}\nFiled.\n")
        };
        let saved = if fold {
            body.replace("\t ", " ")
        } else {
            body.clone()
        };
        let rendered = if crlf {
            body.replace('\n', "\r\n")
        } else {
            body
        };
        doc += &format!(
            "From stockroom@example.invalid Fri Nov 19 01:59:00 2026\n{HEAD}Content-Type: text/plain\n\n{rendered}"
        );
        let mut saved = saved;
        if i != 20 {
            doc += "\n";
            saved += "\n";
        }
        signatures.push(hash("Letter", saved.as_bytes())?);
    }
    let outer = hash("Outer", doc.as_bytes())?;
    for i in [0, 1, 2, 15, 16, 17, 20] {
        check(
            &Server::new(stock, "", &(signatures[i].clone() + &outer))?,
            &doc,
            "Letter",
        )?;
    }
    check(&Server::new(stock, "", &outer)?, &doc, "Outer")?;

    let server = Server::new(stock, "", &hash("Contact", CONTACT.as_bytes())?)?;
    let first_header = format!("{HEAD}Content-Type: text/plain\n\n");
    let second = format!(
        "{HEAD}Content-Type: text/plain\nContent-Transfer-Encoding: base64\n\n{}\n",
        b64(CONTACT.as_bytes())
    );
    let envelope = "From stockroom@example.invalid Fri Nov 19 02:00:00 2026\n";
    for at in 16382..=16389 {
        let body = "x".repeat(at - first_header.len() - 2);
        let doc = format!("{envelope}{first_header}{body}\n\n{envelope}{second}");
        check(&server, &doc, "Contact")?;
    }
    // A physical 999-byte row leaves its newline in an empty row before the separator.
    let body = "x".repeat(999);
    let doc = format!("{envelope}{first_header}{body}\n{envelope}{second}");
    check(&server, &doc, "Contact")?;
    let body = "Updates From accounting\nFrom Monday to Friday\nFiled.\n";
    check(
        &server,
        &mbox_pair(&(first_header + body), &second),
        "Contact",
    )
}

#[test]
fn large_saved_mailbox() -> io::Result<()> {
    saved_mailbox_spans(false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_large_saved_mailbox() -> io::Result<()> {
    saved_mailbox_spans(true)
}
