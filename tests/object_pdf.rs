//! Compare the order and bytes of benign PDF objects with the pinned daemon.
#[path = "common/base64.rs"]
mod base64;
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/pdf_text.rs"]
mod pdf_text;
#[path = "common/pe.rs"]
mod pe;
#[path = "common/zip.rs"]
mod zip;

use daemon::{Daemon, stream_frame, unix_request};
use flate2::{Compression, write::ZlibEncoder};
use md5::{Digest, Md5};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const FIRST: &[u8] = b"ordinary first PDF document stream";
const SECOND: &[u8] = b"an ordinary second PDF attachment";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn deflate(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
    z.write_all(data)?;
    z.finish()
}

fn ascii85(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut padded = [0; 4];
        padded[..chunk.len()].copy_from_slice(chunk);
        let mut value = u32::from_be_bytes(padded);
        let mut digits = [0; 5];
        for digit in digits.iter_mut().rev() {
            *digit = b'!' + (value % 85) as u8;
            value /= 85;
        }
        out.extend_from_slice(&digits[..chunk.len() + 1]);
    }
    out.extend_from_slice(b"~>");
    out
}

fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut out = format!("<< /Length {} {dict} >>\nstream\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\nendstream");
    out
}

// Use a real indirect-object table, xref, trailer and byte offsets.
fn pdf(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"%PDF-1.5\n".to_vec();
    let mut offsets = vec![];
    for (i, object) in objects.iter().enumerate() {
        offsets.push(out.len());
        writeln!(out, "{} 0 obj", i + 1).unwrap();
        out.extend_from_slice(object);
        out.extend_from_slice(b"\nendobj\n");
    }
    let index = out.len();
    writeln!(out, "xref\n0 {}\n0000000000 65535 f ", objects.len() + 1).unwrap();
    for offset in offsets {
        writeln!(out, "{offset:010} 00000 n ").unwrap();
    }
    writeln!(
        out,
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{index}\n%%EOF",
        objects.len() + 1
    )
    .unwrap();
    out
}

fn document(catalog_note: &str, first: Vec<u8>, attachment: Vec<u8>) -> Vec<u8> {
    pdf(&[
        format!("<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(notes.txt) 5 0 R] >> >> /Note ({catalog_note}) >>").into_bytes(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 4 0 R >>".to_vec(),
        first,
        b"<< /Type /Filespec /F (notes.txt) /EF << /F 6 0 R >> >>".to_vec(),
        attachment,
    ])
}

fn xdp(chunks: &[&[u8]], padding: usize) -> Vec<u8> {
    let mut xml = format!(
        "<?xml version=\"1.0\"?>{}<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\"><pdf xmlns=\"http://ns.adobe.com/xdp/pdf/\"><document>",
        " ".repeat(padding)
    );
    for chunk in chunks {
        xml.push_str("<chunk>\n");
        xml.push_str(&base64::encode(chunk));
        xml.push_str("\n</chunk>");
    }
    xml.push_str("</document></pdf></xdp:xdp>");
    xml.into_bytes()
}

fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let root = tmp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let mut rules = String::new();
    let first_line = [FIRST, b"\n"].concat();
    let marked_pdf = document("OuterPdfMark", stream("", FIRST), stream("", SECOND));
    let marked_form = xdp(&[&marked_pdf], 10);
    let late_form = xdp(&[&marked_pdf], 1501);
    for (name, data) in [
        ("First", FIRST),
        ("Second", SECOND),
        ("FirstLine", first_line.as_slice()),
        ("Text", b"ordinary page text"),
        ("Form", &marked_form),
        ("LateForm", &late_form),
    ] {
        rules.push_str(&format!(
            "{}:{}:Pdf.{name}\n",
            hex(&Md5::digest(data)),
            data.len()
        ));
    }
    rules.push_str("6bcc4f3e0ad073a5dae0a109c80f328d:16384:Pdf.Blocks\n");
    rules.push_str("cea783782f854db573e33595bd1a254e:8196:Pdf.BlockSpaces\n");
    let full = b"abcghiz"
        .iter()
        .copied()
        .cycle()
        .take(16386)
        .collect::<Vec<_>>();
    rules.push_str(&format!(
        "{}:{}:Pdf.AllLetters\n",
        hex(&Md5::digest(&full)),
        full.len()
    ));
    fs::write(db.join("local.hdb"), rules)?;
    fs::write(
        db.join("local.ndb"),
        format!("Pdf.Outer:10:*:{}\n", hex(b"OuterPdfMark")),
    )?;
    let start = |profile: &str, options: &str| -> io::Result<_> {
        let conf = root.join(format!("{profile}.conf"));
        let socket = root.join(format!("{profile}.sock"));
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDisableCache yes\nSelfCheck 0\nDatabaseDirectory {}\nTemporaryDirectory {}\nLocalSocket {}\n{options}\n",
                db.display(),
                root.display(),
                socket.display()
            ),
        )?;
        Ok((Daemon::start(exe, &conf, &socket)?, socket))
    };
    let (daemon, socket) = start("base", "")?;
    let text = b"BT (ordinary page contents) Tj ET";
    let quiet = || stream("", text);
    let bare = document(
        "notes",
        stream("", FIRST),
        stream("/Type /EmbeddedFile", SECOND),
    );
    let flate = document(
        "notes",
        quiet(),
        stream(
            "/Type /EmbeddedFile /Filter /FlateDecode",
            &deflate(SECOND)?,
        ),
    );
    let mut pdf_resource = pe::benign_pe();
    pdf_resource.extend_from_slice(&flate);
    let mut late_pdf = b"Ordinary attachment collection\n".to_vec();
    late_pdf.resize(2048, b' ');
    late_pdf.extend_from_slice(&flate);
    let early_pdf = [b"\n".as_slice(), &flate].concat();
    let prefixed = |padding: usize, data: &[u8]| [vec![b' '; padding], data.to_vec()].concat();
    let ah = document(
        "notes",
        quiet(),
        stream(
            "/Type /EmbeddedFile /Filter /ASCIIHexDecode",
            format!("{}>", hex(SECOND)).as_bytes(),
        ),
    );
    let combined = document(
        "notes",
        quiet(),
        stream(
            "/Type /EmbeddedFile /Filter [/ASCIIHexDecode /FlateDecode]",
            format!("{}>", hex(&deflate(SECOND)?)).as_bytes(),
        ),
    );
    let flate_params = document(
        "notes",
        quiet(),
        stream(
            "/Type /EmbeddedFile /Filter /Fl /DecodeParms << /Predictor 1 >>",
            &deflate(SECOND)?,
        ),
    );
    let a85 = document(
        "notes",
        quiet(),
        stream(
            "/Type /EmbeddedFile /Filter /ASCII85Decode",
            &ascii85(SECOND),
        ),
    );
    let mut run = vec![(SECOND.len() - 1) as u8];
    run.extend_from_slice(SECOND);
    run.push(128);
    let run_length = document(
        "notes",
        quiet(),
        stream("/Type /EmbeddedFile /Filter /RunLengthDecode", &run),
    );
    let normalized = document(
        "notes",
        stream(
            "/Filter /FlateDecode",
            &deflate(b"BT\n[(Ordinary )(PAGE TEXT)] TJ\nET")?,
        ),
        stream("/Type /EmbeddedFile", SECOND),
    );
    let outer = document(
        "OuterPdfMark",
        stream("/Filter /FlateDecode", &deflate(FIRST)?),
        stream("/Type /EmbeddedFile", SECOND),
    );
    let mut truncated = flate.clone();
    truncated.truncate(truncated.len() - 20);
    let mut cut_stream = flate.clone();
    let endstream = flate.windows(9).rposition(|w| w == b"endstream").unwrap();
    cut_stream.truncate(endstream - 12);
    let mut truncated_chunk = xdp(&[&marked_pdf], 0);
    truncated_chunk.truncate(truncated_chunk.len() / 2);
    let cases = [
        (
            "PDF in resource section overlay",
            pdf_resource.clone(),
            None,
        ),
        ("PDF after a text preamble", late_pdf.clone(), None),
        ("PDF after a leading newline", early_pdf, Some("Second")),
        (
            "early PDF raw target",
            prefixed(80, &marked_pdf),
            Some("Outer"),
        ),
        (
            "PDF type ends at header boundary",
            prefixed(1017, &flate),
            Some("Second"),
        ),
        (
            "PDF type crosses header boundary",
            prefixed(1018, &flate),
            None,
        ),
        ("XDP child before form", marked_form.clone(), Some("Outer")),
        (
            "XDP raw form before late child",
            late_form,
            Some("LateForm"),
        ),
        ("XDP truncated attachment", truncated_chunk, None),
        ("XDP attached PDF", xdp(&[&flate], 0), Some("Second")),
        (
            "XDP first PDF wins",
            xdp(&[&marked_pdf, &flate], 0),
            Some("Outer"),
        ),
        (
            "XDP non-PDF chunk precedes document",
            xdp(&[b"ordinary text", &flate], 0),
            None,
        ),
        (
            "XDP beyond initial header",
            xdp(&[&marked_pdf], 1500),
            Some("Outer"),
        ),
        ("page then attachment", bare, Some("FirstLine")),
        ("compressed attachment", flate.clone(), Some("Second")),
        ("Flate parameters", flate_params, Some("Second")),
        ("ASCIIHex attachment", ah, Some("Second")),
        ("two filters", combined, Some("Second")),
        ("ASCII85 attachment", a85, Some("Second")),
        ("run length attachment", run_length, Some("Second")),
        (
            "physical page crosses two normalized output blocks",
            document("notes", stream("", &pdf_text::array(16386, b"")), quiet()),
            Some("Blocks"),
        ),
        (
            "whitespace restarts after flushing a full text block",
            document(
                "notes",
                stream("", &pdf_text::array(8191, b"   X   Y")),
                quiet(),
            ),
            Some("BlockSpaces"),
        ),
        ("normalized page text", normalized, Some("Text")),
        ("outer vs child", outer, Some("Outer")),
        (
            "ZIP containing PDF",
            zip::zip(&[("ordinary.pdf", &flate)], true, false, false)?,
            Some("Second"),
        ),
        ("missing final trailer", truncated, Some("Second")),
        ("incomplete attachment stream", cut_stream, None),
        (
            "clean",
            document("notes", quiet(), stream("/Type /EmbeddedFile", text)),
            None,
        ),
    ];
    for (label, bytes, name) in cases {
        let expected = match name {
            Some(name) => format!("stream: Pdf.{name}.UNOFFICIAL FOUND\0"),
            None if stock => "stream: OK\0".to_owned(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".to_owned(),
        };
        assert_eq!(
            unix_request(&socket, &stream_frame(&bytes)?)?,
            expected,
            "{label}"
        );
    }
    drop(daemon);
    let unmarked_form = xdp(&[&marked_pdf], 1500);
    let (service, socket) = start("no-archives", "ScanArchive no")?;
    for sample in [&pdf_resource, &late_pdf] {
        let expected = if stock {
            "stream: OK\0"
        } else {
            "stream: Incomplete scan: unsupported detection coverage. ERROR\0"
        };
        assert_eq!(unix_request(&socket, &stream_frame(sample)?)?, expected);
    }
    assert_eq!(
        unix_request(&socket, &stream_frame(&unmarked_form)?)?,
        "stream: Pdf.Outer.UNOFFICIAL FOUND\0"
    );
    drop(service);
    let larger = b"ordinary expanded document page.\n".repeat(256);
    let compressed = document(
        "notes",
        stream("/Filter /FlateDecode", &deflate(&larger)?),
        quiet(),
    );
    assert!(compressed.len() < 2048 && larger.len() > 2048);
    for (profile, options, sample, name) in [
        (
            "bytes",
            "MaxFileSize 2048\nAlertExceedsMax yes",
            &compressed,
            "Heuristics.Limits.Exceeded.MaxFileSize",
        ),
        (
            "depth",
            "MaxRecursion 1\nAlertExceedsMax yes",
            &flate,
            "Heuristics.Limits.Exceeded.MaxRecursion",
        ),
    ] {
        let (_service, socket) = start(profile, options)?;
        assert_eq!(
            unix_request(&socket, &stream_frame(sample)?)?,
            format!("stream: {name} FOUND\0"),
            "{profile}"
        );
    }
    for (name, content, normalized_len) in [
        ("array", b"BT\n[(School Summary)] TJ\nET".as_slice(), 14),
        ("short", b"BT\n[(Short)] TJ\nET", 5),
        ("single", b"BT\n(Next Page) Tj\nET", 0),
    ] {
        let page = pdf(&[
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 4 0 R >>".to_vec(),
            stream(
                "/Filter /ASCIIHexDecode",
                format!("{}>", hex(content)).as_bytes(),
            ),
        ]);
        for room in [1, 14] {
            let max = page.len() + content.len() + room;
            let options = format!("MaxFiles 2\nMaxScanSize {max}\nAlertExceedsMax yes");
            let (_service, socket) = start(&format!("page-{name}-{room}"), &options)?;
            let expected = if normalized_len > 5 {
                if room < normalized_len {
                    "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0"
                } else {
                    "stream: Heuristics.Limits.Exceeded.MaxFiles FOUND\0"
                }
            } else if stock {
                "stream: OK\0"
            } else {
                "stream: Incomplete scan: unsupported detection coverage. ERROR\0"
            };
            assert_eq!(
                unix_request(&socket, &stream_frame(&page)?)?,
                expected,
                "{name} {room}"
            );
        }
    }
    let (_service, socket) = start("disabled", "ScanPDF no")?;
    assert_eq!(
        unix_request(&socket, &stream_frame(&marked_form)?)?,
        "stream: Pdf.Form.UNOFFICIAL FOUND\0"
    );
    let reply = unix_request(&socket, &stream_frame(&flate)?)?;
    assert_eq!(
        reply,
        if stock {
            "stream: OK\0"
        } else {
            "stream: Incomplete scan: unsupported detection coverage. ERROR\0"
        }
    );
    Ok(())
}

#[test]
fn oversized_page_text_is_counted_before_spilling() -> io::Result<()> {
    use barnacle::objects::{Limit, Options, Verdict, scan};
    let temp = tempfile::tempdir()?;
    let missing = temp.path().join("missing");
    let source = pdf_text::array(135000, b"");
    let file = document(
        "notes",
        stream("", &source),
        stream("/Type /XObject /Subtype /Image", b"x"),
    );
    let options = Options {
        scan_html: false,
        max_scan_size: (file.len() + source.len() + 90000) as u64,
        alert_exceeds_max: true,
        ..Options::default()
    };
    for max_files in [0, 2] {
        let result = scan(
            &file,
            &Options {
                max_files,
                ..options.clone()
            },
            &missing,
            |_, _| Ok(Verdict::Miss),
            || Ok(()),
        )?;
        assert_eq!(result, Verdict::Found(Limit::MaxScanSize.signature()));
    }
    Ok(())
}

#[test]
fn barnacle_pdf_objects() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
fn xdp_parent_for_embedded_pdf() -> io::Result<()> {
    use barnacle::objects::{self, Options, Verdict};
    let dir = tempfile::tempdir()?;
    let pdf = document("parent check", stream("", FIRST), stream("", SECOND));
    for pad in [0, 1500] {
        let form = xdp(&[&pdf], pad);
        let result = objects::scan(
            &form,
            &Options::default(),
            dir.path(),
            |obj, _| {
                if obj.bytes == pdf {
                    assert_eq!(obj.layer.file_type, "CL_TYPE_PDF");
                    assert!(obj.layer.name.is_none());
                    assert_eq!(obj.parents.len(), 1);
                    assert_eq!(obj.parents[0].file_type, "CL_TYPE_XDP");
                    return Ok(Verdict::Found("Attached PDF".into()));
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert_eq!(result, Verdict::Found("Attached PDF".into()));
    }
    Ok(())
}

#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn stock_xdp_parent_for_embedded_pdf() -> io::Result<()> {
    let dir = tempfile::tempdir_in("/tmp")?;
    let db = dir.path().join("db");
    fs::create_dir(&db)?;
    fs::write(
        db.join("parent.ldb"),
        format!(
            "Pdf.InForm;Engine:81-255,Target:10,Container:CL_TYPE_XDP;0;{}\n",
            hex(b"parent check")
        ),
    )?;
    let conf = dir.path().join("clamd.conf");
    let sock = dir.path().join("sock");
    fs::write(
        &conf,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\n",
            db.display(),
            sock.display()
        ),
    )?;
    let _service = Daemon::start(Path::new("/usr/sbin/clamd"), &conf, &sock)?;
    let pdf = document("parent check", stream("", FIRST), stream("", SECOND));
    for pad in [0, 1500] {
        let form = xdp(&[&pdf], pad);
        assert_eq!(
            unix_request(&sock, &stream_frame(&form)?)?,
            "stream: Pdf.InForm.UNOFFICIAL FOUND\0"
        );
    }
    assert_eq!(unix_request(&sock, &stream_frame(&pdf)?)?, "stream: OK\0");
    Ok(())
}

#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn stock_pdf_objects() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}
