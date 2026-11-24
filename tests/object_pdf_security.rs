//! Compare qpdf standard-security attachments with pinned Debian clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;
use client::{Daemon, stream_frame, unix_request};
use std::{
    fs,
    io::{self, Read},
    path::Path,
};

const NOTE: &[u8] = b"Quarterly statement from accounting.";
const DISPATCH: &[u8] = b"Dispatch note for seven boxes of stationery.\n";
const INVENTORY_LABEL: &[u8] =
    b"<< /Type /EmbeddedFile /Description (Archive inventory label) >>\n";
const LARGE_PACKED: &[u8] = include_bytes!("fixtures/pdf/open/r6-packed-large-carrier.pdf");
const FILES: &[(&str, &[u8])] = &[
    ("plain", include_bytes!("fixtures/pdf/open/ordinary.pdf")),
    ("r4", include_bytes!("fixtures/pdf/open/r4.pdf")),
    ("r5", include_bytes!("fixtures/pdf/open/r5.pdf")),
    ("r6", include_bytes!("fixtures/pdf/open/r6.pdf")),
    ("r2-rc4", include_bytes!("fixtures/pdf/open/r2-rc4.pdf")),
    ("r3-rc4", include_bytes!("fixtures/pdf/open/r3-rc4.pdf")),
    ("r4-rc4", include_bytes!("fixtures/pdf/open/r4-rc4.pdf")),
    (
        "r4-clear-metadata",
        include_bytes!("fixtures/pdf/open/r4-clear-metadata.pdf"),
    ),
    (
        "r6-clear-metadata",
        include_bytes!("fixtures/pdf/open/r6-clear-metadata.pdf"),
    ),
    (
        "r6-flate-hex",
        include_bytes!("fixtures/pdf/open/r6-flate-hex.pdf"),
    ),
];

fn shipment_table() -> String {
    use std::fmt::Write;
    let mut text = String::from("Shipment,BoxCount,Receipt\n");
    let mut state = 1_285_u32;
    for row in 0..13_000 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        writeln!(text, "{row},{},{state:08X}", 1 + state % 100).unwrap();
    }
    text
}

fn hash(data: &[u8], name: &str) -> io::Result<String> {
    Ok(format!(
        "{}:{}:Pdf.{name}\n",
        barnacle::hash_reader(data)?.md5_hex(),
        data.len()
    ))
}

fn physical_stream<'a>(bytes: &'a [u8], object: &[u8]) -> &'a [u8] {
    let start = memchr::memmem::find(bytes, object).unwrap();
    let start = start + memchr::memmem::find(&bytes[start..], b"stream\n").unwrap() + 7;
    let end = start + memchr::memmem::find(&bytes[start..], b"endstream").unwrap();
    &bytes[start..end]
}

fn check_packed(
    check: impl Fn(&[u8], &str, &str, &str, &str) -> io::Result<()>,
    note: &str,
) -> io::Result<()> {
    const R6: &[u8] = include_bytes!("fixtures/pdf/open/r6-packed.pdf");
    for bytes in [
        include_bytes!("fixtures/pdf/open/r3-packed.pdf").as_slice(),
        include_bytes!("fixtures/pdf/open/r4-packed.pdf").as_slice(),
        include_bytes!("fixtures/pdf/open/r5-packed.pdf").as_slice(),
        R6,
        include_bytes!("fixtures/pdf/open/r6-restricted-packed.pdf").as_slice(),
    ] {
        check(bytes, note, "", "", "Note")?;
        for (short, want) in [(0, "Note"), (1, "Heuristics.Limits.Exceeded.MaxScanSize")] {
            check(
                bytes,
                note,
                "",
                &format!(
                    "MaxScanSize {}\nAlertExceedsMax yes",
                    bytes.len() + NOTE.len() - short
                ),
                want,
            )?;
        }
    }
    for limit in ["MaxFiles", "MaxRecursion"] {
        check(
            R6,
            note,
            "",
            &format!("{limit} 1\nAlertExceedsMax yes"),
            &format!("Heuristics.Limits.Exceeded.{limit}"),
        )?;
    }
    check(R6, note, "", "ScanPDF no", "Miss")?;

    let carrier = b"3 0 4 32 5 88 6 132\n\
        << /Title (Quarterly report) >>\n\
        << /EF << /F 7 0 R >> /F (notes.txt) /Type /Filespec >>\n\
        << /Count 1 /Kids [ 6 0 R ] /Type /Pages >>\n\
        << /Contents 8 0 R /MediaBox [ 0 0 100 100 ] /Parent 5 0 R /Resources << >> /Type /Page >>\n";
    let carrier_rule = hash(carrier, "Carrier")?;
    let competing = carrier_rule + note;
    check(R6, &competing, "", "", "Carrier")?;
    check(R6, &(competing + &hash(R6, "Outer")?), "", "", "Outer")?;

    let xref = physical_stream(R6, b"\n10 0 obj\n");
    let stored_xref = xref.strip_suffix(b"\n").unwrap();
    let mut predictor_rows = Vec::new();
    flate2::read::ZlibDecoder::new(stored_xref).read_to_end(&mut predictor_rows)?;
    assert_eq!(predictor_rows.len(), 55);
    let xref_rule = hash(&predictor_rows, "Xref")?;
    let packed_xref = hash(stored_xref, "CompressedXref")? + &hash(xref, "PhysicalXref")?;
    check(R6, &packed_xref, "", "", "Miss")?;
    check(R6, &(packed_xref + &xref_rule), "", "", "Xref")?;
    let page = hash(b"[(Quarterly REPORT)] TJ\n", "Page")?;
    check(R6, &(xref_rule + &page), "", "", "Page")?;

    let text = hash(b"quarterly report", "Text")?;
    check(R6, &text, "", "", "Miss")?;
    // Keep the encrypted bytes and cross-reference offsets intact.
    let mut compact = R6.to_vec();
    let spelling = b"/Type /ObjStm";
    let at = memchr::memmem::find(R6, spelling).unwrap();
    compact[at..at + spelling.len()].copy_from_slice(b"/Type/ObjStm ");
    check(&compact, &text, "", "", "Text")?;
    check(&compact, &(text + &page), "", "", "Page")?;

    let classic = include_bytes!("fixtures/pdf/open/r6-packed-classic.pdf");
    let member_rule = hash(INVENTORY_LABEL, "Member")?;
    let carrier = [b"10 0 ".as_slice(), INVENTORY_LABEL].concat();
    check(classic, &member_rule, "", "", "Member")?;
    check(
        classic,
        &(member_rule.clone() + &hash(&carrier, "ClassicCarrier")?),
        "",
        "",
        "ClassicCarrier",
    )?;
    check(
        classic,
        &member_rule,
        "",
        "MaxFiles 5\nAlertExceedsMax yes",
        "Heuristics.Limits.Exceeded.MaxFiles",
    )?;
    check(classic, &member_rule, "", "MaxFiles 6", "Member")?;

    for (space, expected) in [
        (141, "Member"),
        (140, "Heuristics.Limits.Exceeded.MaxScanSize"),
    ] {
        check(
            LARGE_PACKED,
            &member_rule,
            "",
            &format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                LARGE_PACKED.len() + space
            ),
            expected,
        )?;
    }

    let two = include_bytes!("fixtures/pdf/open/r6-two-packed.pdf");
    check(
        two,
        &(hash(DISPATCH, "Dispatch")? + note),
        "",
        "",
        "Dispatch",
    )?;
    check(two, note, "", "", "Note")?;

    let stored = include_bytes!("fixtures/pdf/open/r6-stored-packed.pdf");
    check(stored, note, "", "", "Miss")?;
    let carrier = physical_stream(stored, b"\n2 0 obj\n");
    let receipt = physical_stream(stored, b"\n7 0 obj\n");
    assert_eq!((carrier.len(), receipt.len()), (272, 64));
    let stored_receipt = hash(receipt, "StoredReceipt")?;
    check(stored, &stored_receipt, "", "", "StoredReceipt")?;
    check(
        stored,
        &(stored_receipt + &hash(carrier, "StoredCarrier")?),
        "",
        "",
        "StoredCarrier",
    )?;
    let xref = physical_stream(stored, b"\n10 0 obj\n");
    assert_eq!(xref.len(), 45);
    check(stored, &hash(xref, "StoredXref")?, "", "", "StoredXref")?;

    let r4_stored = include_bytes!("fixtures/pdf/open/r4-stored-packed.pdf");
    let receipt = physical_stream(r4_stored, b"\n9 0 obj\n");
    let page = physical_stream(r4_stored, b"\n8 0 obj\n");
    assert_eq!((receipt.len(), page.len()), (80, 96));
    check(
        r4_stored,
        &hash(receipt, "StoredReceipt")?,
        "",
        "",
        "StoredReceipt",
    )?;
    check(r4_stored, &hash(page, "StoredPage")?, "", "", "StoredPage")?;
    Ok(())
}

fn check(exe: &Path, stock: bool) -> io::Result<()> {
    let root = tempfile::tempdir_in("/tmp")?;
    let db = root.path().join("db");
    fs::create_dir(&db)?;
    let check = |bytes: &[u8],
                 rules: &str,
                 logical: &str,
                 extra: &str,
                 want: &str|
     -> io::Result<()> {
        fs::write(db.join("stock.hdb"), rules)?;
        if !logical.is_empty() {
            fs::write(db.join("context.ldb"), logical)?;
        }
        let config = root.path().join("conf");
        let sock = root.path().join("s");
        fs::write(
            &config,
            format!(
                "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n{extra}\n",
                db.display(),
                sock.display()
            ),
        )?;
        let daemon = Daemon::start(exe, &config, &sock)?;
        let reply = unix_request(&sock, &stream_frame(bytes)?)?;
        drop(daemon);
        if !logical.is_empty() {
            fs::remove_file(db.join("context.ldb"))?;
        }
        let expected = if want == "Miss" {
            if stock {
                "stream: OK\0".into()
            } else {
                "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into()
            }
        } else if want.starts_with("Heuristics.") {
            format!("stream: {want} FOUND\0")
        } else {
            format!("stream: Pdf.{want}.UNOFFICIAL FOUND\0")
        };
        assert_eq!(reply, expected, "{extra}, {want}, {} bytes", bytes.len());
        Ok(())
    };
    let note = hash(NOTE, "Note")?;
    check_packed(check, &note)?;
    let unrelated = hash(b"Unrelated stationery", "Other")?;
    let sig = NOTE.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let parent = format!("Pdf.Parent;Engine:81-255,Target:0,Container:CL_TYPE_PDF;0;{sig}\n");
    for &(_, bytes) in FILES {
        check(bytes, &note, "", "", "Note")?;
        check(
            bytes,
            &(note.clone() + &hash(bytes, "Outer")?),
            "",
            "",
            "Outer",
        )?;
        if stock {
            check(bytes, &unrelated, &parent, "", "Parent")?;
        }
        check(bytes, &note, "", "ScanPDF no", "Miss")?;
        check(
            bytes,
            &note,
            "",
            "MaxRecursion 1\nAlertExceedsMax yes",
            "Heuristics.Limits.Exceeded.MaxRecursion",
        )?;
        check(
            bytes,
            &note,
            "",
            "MaxFiles 1\nAlertExceedsMax yes",
            "Heuristics.Limits.Exceeded.MaxFiles",
        )?;
        check(
            bytes,
            &note,
            "",
            &format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                bytes.len() + NOTE.len()
            ),
            "Note",
        )?;
        check(
            bytes,
            &note,
            "",
            &format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                bytes.len() + NOTE.len() - 1
            ),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        )?;
    }
    let original = include_bytes!("fixtures/pdf/open/r6.pdf");
    let mut renamed = original.to_vec();
    for offset in memchr::memmem::find_iter(original, b"/StdCF") {
        renamed[offset..offset + 6].copy_from_slice(b"/AltCF");
    }
    check(&renamed, &note, "", "", "Note")?;
    let eff = include_bytes!("fixtures/pdf/open/r6-explicit-eff.pdf");
    let receipt = hash(
        b"November warehouse delivery receipt, six notebooks.\n",
        "Receipt",
    )?;
    check(eff, &receipt, "", "", "Receipt")?;
    check(eff, &(receipt + &hash(eff, "Outer")?), "", "", "Outer")?;
    let stored_mime = include_bytes!("fixtures/pdf/open/r6-stored-mime.pdf");
    let physical = physical_stream(stored_mime, b"\n5 0 obj\n");
    let declared = physical.strip_suffix(b"\n").unwrap();
    assert_eq!((physical.len(), declared.len()), (81, 80));
    let declared_rule = hash(declared, "DeclaredLength")?;
    check(stored_mime, &declared_rule, "", "", "Miss")?;
    check(
        stored_mime,
        &(declared_rule + &hash(physical, "PhysicalStream")?),
        "",
        "",
        "PhysicalStream",
    )?;
    let explicit = include_bytes!("fixtures/pdf/open/r6-identity.pdf");
    let with_eol = [NOTE, b"\n"].concat();
    let identity = hash(&with_eol, "Identity")?;
    check(explicit, &note, "", "", "Miss")?;
    check(explicit, &(identity.clone() + &note), "", "", "Identity")?;
    for (adjustment, expected) in [
        (0, "Identity"),
        (1, "Heuristics.Limits.Exceeded.MaxScanSize"),
    ] {
        check(
            explicit,
            &identity,
            "",
            &format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                explicit.len() + with_eol.len() - adjustment
            ),
            expected,
        )?;
    }
    check(
        explicit,
        &identity,
        "",
        &format!(
            "MaxScanSize {}\nMaxRecursion 1\nAlertExceedsMax yes",
            explicit.len() + 1
        ),
        "Heuristics.Limits.Exceeded.MaxScanSize",
    )?;
    let named = include_bytes!("fixtures/pdf/open/r6-explicit-name.pdf");
    let physical = physical_stream(named, b"\n7 0 obj\n");
    let page = physical.strip_suffix(b"\n").unwrap();
    assert_eq!((physical.len(), page.len()), (97, 96));
    let with_eol = hash(physical, "PageWithEol")?;
    check(named, &with_eol, "", "", "Miss")?;
    check(
        named,
        &(with_eol + &hash(page, "PageBytes")?),
        "",
        "",
        "PageBytes",
    )?;
    let two = include_bytes!("fixtures/pdf/open/two.pdf");
    check(
        two,
        &(note.clone() + &hash(DISPATCH, "Dispatch")?),
        "",
        "",
        "Dispatch",
    )?;
    check(two, &note, "", "", "Note")?;
    let stored = include_bytes!("fixtures/pdf/open/stored.pdf");
    let at = memchr::memmem::find(stored, b"stream\n").unwrap() + 7;
    let cipher = &stored[at..at + 64];
    let stored_rule = hash(cipher, "Stored")?;
    check(stored, &note, "", "", "Miss")?;
    check(stored, &(stored_rule.clone() + &note), "", "", "Stored")?;
    check(
        stored,
        &stored_rule,
        "",
        &format!("MaxScanSize {}\nAlertExceedsMax yes", stored.len() + 64),
        "Stored",
    )?;
    check(
        stored,
        &stored_rule,
        "",
        &format!("MaxScanSize {}\nAlertExceedsMax yes", stored.len() + 63),
        "Heuristics.Limits.Exceeded.MaxScanSize",
    )?;
    let manifest = include_bytes!("fixtures/pdf/open/manifest.pdf");
    let table = b"shipment,quantity\n1024,12\n1025,16\n";
    let start = memchr::memmem::find(manifest, b"stream\n").unwrap() + 7;
    let size = memchr::memmem::find(&manifest[start..], b"endstream").unwrap() / 16 * 16;
    let cipher_rule = hash(&manifest[start..start + size], "ManifestCipher")?;
    check(manifest, &hash(table, "Table")?, "", "", "Miss")?;
    check(
        manifest,
        &(hash(table, "Table")? + &cipher_rule),
        "",
        "",
        "ManifestCipher",
    )?;
    let mime = include_bytes!("fixtures/pdf/open/mime.pdf");
    check(mime, &note, "", "", "Note")?;
    check(mime, &(hash(mime, "Outer")? + &note), "", "", "Outer")?;
    let shipments = include_bytes!("fixtures/pdf/open/shipments.pdf");
    let table = shipment_table();
    let rows = hash(table.as_bytes(), "Shipments")?;
    check(shipments, &rows, "", "", "Shipments")?;
    check(
        shipments,
        &(rows.clone() + &hash(shipments, "Outer")?),
        "",
        "",
        "Outer",
    )?;
    check(
        shipments,
        &rows,
        "",
        &format!(
            "MaxScanSize {}\nAlertExceedsMax yes",
            shipments.len() + table.len()
        ),
        "Shipments",
    )?;
    check(
        shipments,
        &rows,
        "",
        &format!(
            "MaxScanSize {}\nAlertExceedsMax yes",
            shipments.len() + table.len() - 1
        ),
        "Heuristics.Limits.Exceeded.MaxScanSize",
    )?;
    check(
        shipments,
        &rows,
        "",
        "MaxFiles 1\nAlertExceedsMax yes",
        "Heuristics.Limits.Exceeded.MaxFiles",
    )?;
    let restricted = include_bytes!("fixtures/pdf/open/restricted.pdf");
    check(restricted, &note, "", "", "Note")?;
    check(
        restricted,
        &(note.clone() + &hash(restricted, "Outer")?),
        "",
        "",
        "Outer",
    )?;
    for (adjustment, expected) in [(0, "Note"), (1, "Heuristics.Limits.Exceeded.MaxScanSize")] {
        check(
            restricted,
            &note,
            "",
            &format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                restricted.len() + NOTE.len() - adjustment
            ),
            expected,
        )?;
    }
    // Stock flags an attachment only when its type precedes the filter list.
    // LZW alone is not dumped, so the later spelling hides the attachment.
    check(
        include_bytes!("fixtures/pdf/open/lzw.pdf"),
        &note,
        "",
        "",
        "Note",
    )?;
    check(
        include_bytes!("fixtures/pdf/open/lzw-late.pdf"),
        &note,
        "",
        "",
        "Miss",
    )?;
    // Only the final filter output counts against the scan budget.
    let hex_lzw = include_bytes!("fixtures/pdf/open/hex-lzw.pdf");
    for (short, want) in [(0, "Note"), (1, "Heuristics.Limits.Exceeded.MaxScanSize")] {
        check(
            hex_lzw,
            &note,
            "",
            &format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                hex_lzw.len() + NOTE.len() - short
            ),
            want,
        )?;
    }
    // Encrypted LZW chains decode from the decrypted stream. A DCT image keeps its ciphertext.
    for bytes in [
        include_bytes!("fixtures/pdf/open/r3-hex-lzw.pdf").as_slice(),
        include_bytes!("fixtures/pdf/open/r4-hex-lzw.pdf"),
        include_bytes!("fixtures/pdf/open/r6-hex-lzw.pdf"),
    ] {
        check(bytes, &note, "", "", "Note")?;
        for (short, want) in [(0, "Note"), (1, "Heuristics.Limits.Exceeded.MaxScanSize")] {
            check(
                bytes,
                &note,
                "",
                &format!(
                    "MaxScanSize {}\nAlertExceedsMax yes",
                    bytes.len() + NOTE.len() - short
                ),
                want,
            )?;
        }
        let image = physical_stream(bytes, b"\n7 0 obj\n");
        let image = hash(image.strip_suffix(b"\n").unwrap_or(image), "Image")?;
        check(bytes, &image, "", "", "Image")?;
    }
    let lzw_only = include_bytes!("fixtures/pdf/open/r6-lzw.pdf");
    check(lzw_only, &note, "", "", "Miss")?;
    let image = physical_stream(lzw_only, b"\n7 0 obj\n");
    let image = hash(image.strip_suffix(b"\n").unwrap_or(image), "Image")?;
    check(lzw_only, &image, "", "", "Image")?;

    let locked = include_bytes!("fixtures/pdf/open/locked.pdf");
    check(locked, &note, "", "", "Miss")?;
    check(locked, &(note + &hash(locked, "Outer")?), "", "", "Outer")?;
    // Flate fails on each locked stream, so stock scans its ciphertext in physical order.
    let receipt = hash(physical_stream(locked, b"\n5 0 obj\n"), "LockedReceipt")?;
    let page = hash(physical_stream(locked, b"\n7 0 obj\n"), "LockedPage")?;
    check(locked, &(page.clone() + &receipt), "", "", "LockedReceipt")?;
    let limit = |name: &str, value: usize| format!("{name} {value}\nAlertExceedsMax yes");
    let exceeded = |name: &str| format!("Heuristics.Limits.Exceeded.{name}");
    for (rules, files, scan_bytes, want) in [
        (&receipt, 2, 64, "LockedReceipt"),
        (&page, 3, 128, "LockedPage"),
    ] {
        check(locked, rules, "", &limit("MaxFiles", files), want)?;
        check(
            locked,
            rules,
            "",
            &limit("MaxFiles", files - 1),
            &exceeded("MaxFiles"),
        )?;
        let size = locked.len() + scan_bytes;
        check(locked, rules, "", &limit("MaxScanSize", size), want)?;
        check(
            locked,
            rules,
            "",
            &limit("MaxScanSize", size - 1),
            &exceeded("MaxScanSize"),
        )?;
    }
    check(
        locked,
        &page,
        "",
        &limit("MaxRecursion", 1),
        &exceeded("MaxRecursion"),
    )?;
    check(locked, &page, "", &limit("MaxRecursion", 2), "LockedPage")?;
    Ok(())
}
#[test]
fn openable_pdf_streams() -> io::Result<()> {
    check(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}
#[test]
fn decrypted_attachment_metadata() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    for &(_, bytes) in FILES {
        let mut count = 0;
        scan(
            bytes,
            &Options::default(),
            tmp.path(),
            |object, _| {
                if object.bytes == NOTE && !object.normalized {
                    assert_eq!(
                        object.parents.last().map(|p| p.file_type),
                        Some("CL_TYPE_PDF")
                    );
                    assert_eq!(object.layer.file_type, "CL_TYPE_TEXT_ASCII");
                    assert!(object.layer.name.is_none());
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
fn stock_openable_pdf_streams() -> io::Result<()> {
    check(Path::new("/usr/sbin/clamd"), true)
}

#[test]
fn denied_large_attachment_counts_without_creating_scratch() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("missing");
    let bytes = include_bytes!("fixtures/pdf/open/shipments.pdf");
    let denied = Options {
        max_files: 1,
        alert_exceeds_max: true,
        ..Options::default()
    };
    let result = scan(
        bytes,
        &denied,
        &missing,
        |_, _| Ok(Verdict::Miss),
        || Ok(()),
    )?;
    assert_eq!(
        result,
        Verdict::Found("Heuristics.Limits.Exceeded.MaxFiles".into())
    );
    let denied_size = Options {
        max_scan_size: (bytes.len() + shipment_table().len() - 1) as u64,
        alert_exceeds_max: true,
        ..Options::default()
    };
    let result = scan(
        bytes,
        &denied_size,
        &missing,
        |_, _| Ok(Verdict::Miss),
        || Ok(()),
    )?;
    assert_eq!(
        result,
        Verdict::Found("Heuristics.Limits.Exceeded.MaxScanSize".into())
    );
    let error = scan(
        bytes,
        &Options::default(),
        &missing,
        |_, _| Ok(Verdict::Miss),
        || Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    Ok(())
}

#[test]
fn excluded_packed_carrier_keeps_eligible_member_without_scratch() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("missing");
    for (space, expected) in [
        (141, "InventoryLabel"),
        (140, "Heuristics.Limits.Exceeded.MaxScanSize"),
    ] {
        let options = Options {
            max_scan_size: (LARGE_PACKED.len() + space) as u64,
            alert_exceeds_max: true,
            ..Options::default()
        };
        let result = scan(
            LARGE_PACKED,
            &options,
            &missing,
            |object, _| {
                if object.bytes == INVENTORY_LABEL && !object.normalized {
                    assert_eq!(
                        object.parents.last().map(|p| p.file_type),
                        Some("CL_TYPE_PDF")
                    );
                    return Ok(Verdict::Found("InventoryLabel".into()));
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert_eq!(result, Verdict::Found(expected.into()));
    }
    assert!(!missing.exists());
    Ok(())
}
