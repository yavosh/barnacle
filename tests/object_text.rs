//! Compare text, HTML, and mail object stages with the pinned Debian engine.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;

use client::{Daemon, stream_frame, unix_request};
use std::{fs, io, path::Path};

fn tnef(with_title: bool) -> Vec<u8> {
    let mut file = vec![0x78, 0x9f, 0x3e, 0x22, 3, 0];
    for (tag, value) in [
        (0x00018010u32, b"report.txt\0".as_slice()),
        (0x0006800f, b"First "),
        (0x0006800f, b"Letter\n"),
    ] {
        if !with_title && tag == 0x00018010 {
            continue;
        }
        file.push(2);
        file.extend(tag.to_le_bytes());
        file.extend((value.len() as u32).to_le_bytes());
        file.extend(value);
        file.extend(
            value
                .iter()
                .map(|&b| u16::from(b))
                .sum::<u16>()
                .to_le_bytes(),
        );
    }
    file
}

fn compare(executable: &Path, stock: bool) -> io::Result<()> {
    let root = tempfile::tempdir_in("/tmp")?;
    let db = root.path().join("db");
    fs::create_dir(&db)?;
    let rules = [
        ("Raw", 0, "LOUD MARK"),
        ("Scripted", 7, "loud mark"),
        ("Folded", 7, "case fold here"),
        ("ShortText", 7, "zzz"),
        ("Markup", 3, "<p>html label</p>"),
        ("Words", 3, "hello planet"),
        ("Decoded", 3, "badge&pin"),
        ("Unicode", 3, "résumé &#x03bb;"),
        ("JavaScript", 7, "var n000=23;var n001="),
        (
            "Function",
            7,
            "function n000(n001){var n002=n001;return n002;}say(\"hello\");",
        ),
        (
            "Property",
            7,
            "var n000=report.value;if(n000>1){n000=n000+2;}document.write(n000);",
        ),
        ("Hidden", 0, "HiddenCommentMarker"),
        ("MailBody", 0, "Barnacle Mail Fixture"),
        ("MailParent", 4, "EnvelopeMarker"),
        ("MailChild", 4, "ChildContextMarker"),
        ("FirstLetter", 7, "first letter"),
        ("NextLetter", 7, "second letter"),
        ("QP", 0, "bright violet"),
    ];
    let mut database = String::new();
    for (name, target, text) in rules {
        let hex: String = text.bytes().map(|b| format!("{b:02x}")).collect();
        database.push_str(&format!("Local.{name}:{target}:*:{hex}\n"));
    }
    let raw_utf16: String = "Utf16Raw"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .map(|b| format!("{b:02x}"))
        .collect();
    database.push_str(&format!(
        "Local.Utf16Raw:0:*:{raw_utf16}\nLocal.HtmlRaw:3:*:{raw_utf16}\n"
    ));
    fs::write(db.join("fixture.ndb"), database)?;
    let config = root.path().join("daemon.conf");
    let socket = root.path().join("sock");
    fs::write(
        &config,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\nSelfCheck 0\n",
            db.display(),
            socket.display()
        ),
    )?;
    let _daemon = Daemon::start(executable, &config, &socket)?;
    let mail = b"From: report@example.invalid\r\nSubject: EnvelopeMarker\r\nContent-Type: multipart/mixed; boundary=\"part\"\r\n\r\n--part\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"note.txt\"\r\nContent-Transfer-Encoding: base64\r\n\r\nQmFybmFjbGUgTWFpbCBGaXh0dXJlCg==\r\n--part--\r\n";
    let mut utf16 = vec![0xff, 0xfe];
    for c in "<html><p>HTML LaBeL</p></html>".encode_utf16() {
        utf16.extend(c.to_le_bytes());
    }
    let utf16_raw: Vec<_> = "<html><!--Utf16Raw--><p>report</p></html>"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let attachment = tnef(true);
    let untitled_attachment = tnef(false);
    let long_title = "monthly-summary\r\n  office-note ".repeat(800);
    let inline_note =
        format!("<html><img title='{long_title}' src='data:text/plain,First%20Letter'/></html>");
    let cases: &[(&[u8], Option<&str>)] = &[
        (inline_note.as_bytes(), Some("FirstLetter")),
        (&attachment, Some("FirstLetter")),
        (&untitled_attachment, Some("FirstLetter")),
        (b"From: report@example.invalid\nSubject: attachment\nContent-Type: application/ms-tnef; name=winmail.dat\nContent-Transfer-Encoding: base64\n\neJ8+IgMAAhCAAQALAAAAcmVwb3J0LnR4dAAqBAIPgAYABgAAAEZpcnN0ICgCAg+ABgAHAAAATGV0dGVyCnoC\n", Some("FirstLetter")),
        (b"begin 644 note.txt\n-1FER<W0@3&5T=&5R\"@``\n`\nend\n", Some("FirstLetter")),
        (b"<html><img src=\"data:application/octet-stream;base64,QmFybmFjbGUgTWFpbCBGaXh0dXJlCg==\"></html>", Some("MailBody")),
        (b"<html><img src='data:text/plain,First%20Letter'/><p>Office</p></html>", Some("FirstLetter")),
        (b"<html><img src=data:text/plain,First%20Letter/><p>Office</p></html>", Some("FirstLetter")),
        (b"<html><a href=\"data:text/plain,First%20Letter\">word</a></html>", Some("FirstLetter")),
        (b"<html><p>HTML LaBeL</p><img src=\"data:text/plain,First%20Letter\"></html>", Some("Markup")),
        (b"ordinary LOUD MARK document", Some("Raw")),
        (b"<?xml version=\"1.0\"?><report>LOUD MARK</report>", Some("Raw")),
        (b"<xar><toc><file><name>LOUD MARK</name></file></toc></xar>", Some("Raw")),
        (b"ZZZ       ", Some("ShortText")),
        ("ordinary CaSéE  FoLd\tHere".as_bytes(), Some("Folded")),
        (&utf16, Some("Markup")),
        (&utf16_raw, Some("Utf16Raw")),
        (b"ordinary CaSe\r\n   FoLd\tHere", Some("Folded")),
        (b"<HTML><P>HTML LaBeL</P></HTML>", Some("Markup")),
        (b"<html><p>HeLLo<b>PLANET</b></p></html>", Some("Words")),
        (b"<html><p>Badge&amp;Pin</p></html>", Some("Decoded")),
        ("<html><p>Résumé &lambda;</p></html>".as_bytes(), Some("Unicode")),
        (b"<html><!--HiddenCommentMarker--><p>just a note</p></html>", None),
        (b"<html><script>var Counter = 23; var Title = 'Hello';</script></html>", Some("JavaScript")),
        (b"<html><script>function Say(Word) { var Content = Word; return Content; } Say(\"Hello\");</script></html>", Some("Function")),
        (b"<html><script>var View = Report.Value; if(View > 1) { View = View + 2; } document.write(View);</script></html>", Some("Property")),
        (mail, Some("MailBody")),
        (b"From: report@example.invalid\nSubject: message\nContent-Type: message/rfc822\n\nFrom: source@example.invalid\nSubject: nested\nContent-Type: text/plain\n\nSecond Letter\n", Some("NextLetter")),
        (b"From: report@example.invalid\nSubject: alternatives\nContent-Type: multipart/alternative;\n boundary=\"abc\"\n\n--abc\nContent-Type: text/plain\n\nFirst Letter\n--abc\nContent-Type: text/html\n\n<html><p>HTML LaBeL</p></html>\n--abc--\n", Some("FirstLetter")),
        (b"From: letter@example.invalid\nSubject: EnvelopeMarker\nContent-Type: text/plain\n\nChildContextMarker\n", Some("MailParent")),
        (b"From: report@example.invalid\r\nSubject: EnvelopeMarker\r\nContent-Type: text/plain\r\n\r\nordinary text\r\n", Some("MailParent")),
        (b"From: report@example.invalid\r\nSubject: text\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nbright=20vi=\r\nolet\r\n", Some("QP")),
    ];
    for (i, &(sample, name)) in cases.iter().enumerate() {
        let expected = match name {
            Some(name) => format!("stream: Local.{name}.UNOFFICIAL FOUND\0"),
            None if stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        assert_eq!(
            unix_request(&socket, &stream_frame(sample)?)?,
            expected,
            "text fixture {i}"
        );
    }
    let mbox = b"From alpha@example.invalid Fri Nov 19 02:00:00 2026\nFrom: alpha@example.invalid\nSubject: one\nContent-Type: text/plain\n\nFirst Letter\n\nFrom beta@example.invalid Fri Nov 19 02:01:00 2026\nFrom: beta@example.invalid\nSubject: two\nContent-Type: text/plain\n\nSecond Letter\n";
    let reply = unix_request(&socket, &stream_frame(mbox)?)?;
    if stock {
        assert!(
            [
                "stream: Local.FirstLetter.UNOFFICIAL FOUND\0",
                "stream: Local.NextLetter.UNOFFICIAL FOUND\0"
            ]
            .contains(&reply.as_str())
        );
    } else {
        assert_eq!(
            reply,
            "stream: Incomplete scan: unsupported detection coverage. ERROR\0"
        );
    }
    Ok(())
}

#[test]
fn barnacle_normalized_objects_and_winners() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires Debian clamd 1.4.3+dfsg-1"]
fn stock_normalized_objects_and_winners() -> io::Result<()> {
    let pkg = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pkg.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}

fn compare_script_hash(executable: &Path, stock: bool) -> io::Result<()> {
    use md5::{Digest, Md5};
    let source = b"DocUMent     Key";
    let normalized = b"document key";
    for (relative, max, detect) in [
        (false, source.len(), false),
        (true, source.len(), true),
        (true, source.len() - 1, false),
        (true, 0, true),
    ] {
        let root = tempfile::tempdir_in("/tmp")?;
        let db = root.path().join("db");
        fs::create_dir(&db)?;
        fs::write(
            db.join("marker.hdb"),
            format!(
                "{}:{}:Local.NormalizedHash\n",
                Md5::digest(normalized)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                normalized.len()
            ),
        )?;
        let offset = if relative { "EOF-8" } else { "*" };
        fs::write(
            db.join("unused.ndb"),
            format!("Unused:7:{offset}:526f62696e\n"),
        )?;
        let config = root.path().join("config");
        let socket = root.path().join("socket");
        fs::write(
            &config,
            format!(
                "Foreground yes\nDisableCache yes\nLocalSocket {}\nDatabaseDirectory {}\nMaxScriptNormalize {max}\n",
                socket.display(),
                db.display()
            ),
        )?;
        let _daemon = Daemon::start(executable, &config, &socket)?;
        let result = unix_request(&socket, &stream_frame(source)?)?;
        let expected = if detect {
            "stream: Local.NormalizedHash.UNOFFICIAL FOUND\0"
        } else if stock {
            "stream: OK\0"
        } else {
            "stream: Incomplete scan: unsupported detection coverage. ERROR\0"
        };
        assert_eq!(
            result, expected,
            "relative {relative}, MaxScriptNormalize {max}"
        );
    }
    Ok(())
}

#[test]
fn normalized_hash_uses_script_offset_and_size_policy() -> io::Result<()> {
    compare_script_hash(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires Debian clamd 1.4.3+dfsg-1"]
fn stock_normalized_hash_policy() -> io::Result<()> {
    compare_script_hash(Path::new("/usr/sbin/clamd"), true)
}

fn compare_html_limits(executable: &Path, stock: bool) -> io::Result<()> {
    let source = b"<html><p>HELLO<b>Planet</b></p></html>";
    let len = source.len();
    for (html, no_tags, detect) in [
        (len, len, true),
        (len - 1, len, false),
        (len, len - 1, false),
        (0, 0, true),
    ] {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        fs::write(
            db.join("view.ndb"),
            "Local.View:3:*:68656c6c6f20706c616e6574\n",
        )?;
        let sock = dir.path().join("socket");
        let config = dir.path().join("config");
        fs::write(
            &config,
            format!(
                "Foreground yes\nDisableCache yes\nLocalSocket {}\nDatabaseDirectory {}\nMaxHTMLNormalize {html}\nMaxHTMLNoTags {no_tags}\n",
                sock.display(),
                db.display()
            ),
        )?;
        let _daemon = Daemon::start(executable, &config, &sock)?;
        let result = unix_request(&sock, &stream_frame(source)?)?;
        let expected = if detect {
            "stream: Local.View.UNOFFICIAL FOUND\0"
        } else if stock {
            "stream: OK\0"
        } else {
            "stream: Incomplete scan: unsupported detection coverage. ERROR\0"
        };
        assert_eq!(
            result, expected,
            "MaxHTMLNormalize {html}, MaxHTMLNoTags {no_tags}"
        );
    }
    Ok(())
}

#[test]
fn html_views_respect_input_size_limits() -> io::Result<()> {
    compare_html_limits(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires Debian clamd 1.4.3+dfsg-1"]
fn stock_html_size_limits() -> io::Result<()> {
    compare_html_limits(Path::new("/usr/sbin/clamd"), true)
}

fn long_script_hash(executable: &Path, stock: bool) -> io::Result<()> {
    use md5::{Digest, Md5};
    let mut paper = b" \tWAREHOUSE\r\n ".to_vec();
    paper.extend(b"Paper BOX-7. ".repeat(6000));
    paper.extend(b"\r\nPA\xc3\xa9PER   \tReCeiPt\r\n ");
    let mut normalized = b" warehouse ".to_vec();
    normalized.extend(b"paper box-7. ".repeat(6000));
    normalized.extend(b"paper receipt ");
    assert!(normalized.len() > 64 * 1024);
    let hd = |bytes: &[u8], name: &str| {
        format!(
            "{}:{}:Local.{name}\n",
            Md5::digest(bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            bytes.len()
        )
    };
    let len = paper.len();
    let total = len + normalized.len();
    let view = Some("Local.LargeView.UNOFFICIAL");
    let raw = Some("Local.RawPaper.UNOFFICIAL");
    let size_limit = Some("Heuristics.Limits.Exceeded.MaxScanSize");
    let file_limit = Some("Heuristics.Limits.Exceeded.MaxFiles");
    let depth_limit = Some("Heuristics.Limits.Exceeded.MaxRecursion");
    for (limit, scan, files, depth, outer, winner) in [
        (len, total, 0, 8, false, view),
        (len - 1, total, 0, 8, false, None),
        (0, total, 0, 8, false, view),
        (len, total, 0, 8, true, raw),
        (len, total - 1, 0, 8, false, size_limit),
        (len, total, 1, 8, false, file_limit),
        (len, total, 0, 1, false, depth_limit),
    ] {
        let root = tempfile::tempdir_in("/tmp")?;
        let db = root.path().join("db");
        fs::create_dir(&db)?;
        let mut rules = hd(&normalized, "LargeView");
        if outer {
            rules += &hd(&paper, "RawPaper")
        }
        fs::write(db.join("paper.hdb"), rules)?;
        fs::write(db.join("unused.ndb"), "Unused:7:EOF-8:526f62696e\n")?;
        let config = root.path().join("config");
        let socket = root.path().join("socket");
        fs::write(
            &config,
            format!(
                "Foreground yes\nDisableCache yes\nLocalSocket {}\nDatabaseDirectory {}\nMaxScriptNormalize {limit}\nMaxScanSize {scan}\nMaxFiles {files}\nMaxRecursion {depth}\nAlertExceedsMax yes\n",
                socket.display(),
                db.display()
            ),
        )?;
        let _daemon = Daemon::start(executable, &config, &socket)?;
        let reply = unix_request(&socket, &stream_frame(&paper)?)?;
        let expected = match winner {
            Some(name) => format!("stream: {name} FOUND\0"),
            None if stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        assert_eq!(
            reply, expected,
            "script {limit}, size {scan}, count {files}, depth {depth}, raw {outer}"
        );
    }
    Ok(())
}

#[test]
fn spilled_normalized_receipt_matches() -> io::Result<()> {
    long_script_hash(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_spilled_normalized_receipt_matches() -> io::Result<()> {
    long_script_hash(Path::new("/usr/sbin/clamd"), true)
}

#[test]
fn normalized_views_borrow_input_and_admit_scratch_by_output_size() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    let missing = tmp.path().join("unused-spool");
    let mut source = b"inventory receipt ".repeat(8192);
    let original = source.len();
    source.extend_from_slice(b"   \t\n");
    for mapped in [false, true] {
        let options = Options {
            map_normalized_script: mapped,
            ..Options::default()
        };
        let result = scan(
            &source,
            &options,
            &missing,
            |object, _| {
                if object.normalized {
                    assert_eq!(object.bytes, &source[..original]);
                    assert_eq!(object.bytes.as_ptr(), source.as_ptr());
                    assert_eq!(object.body_only, !mapped);
                    assert_eq!(object.parents.len(), usize::from(mapped));
                    return Ok(Verdict::Found("inventory".into()));
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert_eq!(result, Verdict::Found("inventory".into()));
    }
    source.make_ascii_uppercase();
    let mut raw_seen = false;
    let skipped = Options {
        scan_normalized_script: false,
        ..Options::default()
    };
    let result = scan(
        &source,
        &skipped,
        &missing,
        |object, _| {
            assert!(!object.normalized);
            raw_seen |= object.bytes == source;
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(result, Verdict::Miss);
    assert!(raw_seen);
    let total = (source.len() + original) as u64;
    for (max_scan_size, max_files, max_recursion, expected) in [
        (total - 1, 1, 1, "MaxScanSize"),
        (total, 1, 1, "MaxFiles"),
        (total, 2, 1, "MaxRecursion"),
        (0, 1, 1, "MaxFiles"),
    ] {
        let options = Options {
            max_scan_size,
            max_files,
            max_recursion,
            map_normalized_script: true,
            alert_exceeds_max: true,
            ..Options::default()
        };
        let result = scan(
            &source,
            &options,
            &missing,
            |object, _| {
                assert!(!object.normalized);
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert_eq!(
            result,
            Verdict::Found(format!("Heuristics.Limits.Exceeded.{expected}"))
        );
    }
    Ok(())
}

fn normalized_rule_eligibility(executable: &Path, stock: bool) -> io::Result<()> {
    let mut paper = b"Green Office trays. ".repeat(4600);
    paper.extend(b"Delivery LABEL");
    let normalized = paper.to_ascii_lowercase();
    let hdb = format!(
        "{}:{}:Local.Normalized\n",
        barnacle::hash_reader(normalized.as_slice())?.md5_hex(),
        normalized.len()
    );
    let root = tempfile::tempdir_in("/tmp")?;
    let db = root.path().join("db");
    fs::create_dir(&db)?;
    fs::write(db.join("paper.hdb"), hdb)?;
    fs::write(db.join("paper.ign2"), "Local.Ignored\n")?;
    let socket = root.path().join("socket");
    let config = root.path().join("config");
    fs::write(
        &config,
        format!(
            "Foreground yes\nDisableCache yes\nLocalSocket {}\nDatabaseDirectory {}\n",
            socket.display(),
            db.display()
        ),
    )?;
    for (rules, winner) in [
        (None, None),
        (
            Some("Local.Generic:0:*:64656c6976657279206c6162656c"),
            Some("Generic"),
        ),
        (
            Some("Local.Script:7:*:64656c6976657279206c6162656c"),
            Some("Script"),
        ),
        (Some("Local.Mail:4:*:64656c6976657279206c6162656c"), None),
        (Some("Local.Generic:0:EOF-6:616273656e74"), None),
        (
            Some("Local.Ignored:7:EOF-6:616273656e74\nLocal.Future:7:EOF-6:616273656e74:255"),
            None,
        ),
        (
            Some("Local.Relative:7:EOF-6:616273656e74"),
            Some("Normalized"),
        ),
    ] {
        if let Some(rules) = rules {
            fs::write(db.join("paper.ndb"), format!("{rules}\n"))?;
        }
        let _daemon = Daemon::start(executable, &config, &socket)?;
        let reply = unix_request(&socket, &stream_frame(&paper)?)?;
        let expected = match winner {
            Some(id) => format!("stream: Local.{id}.UNOFFICIAL FOUND\0"),
            None if stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        assert_eq!(reply, expected, "{rules:?}");
    }
    Ok(())
}

#[test]
fn active_rules_select_normalized_matches() -> io::Result<()> {
    normalized_rule_eligibility(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires the pinned Debian clamd"]
fn stock_active_rules_select_normalized_matches() -> io::Result<()> {
    normalized_rule_eligibility(Path::new("/usr/sbin/clamd"), true)
}
