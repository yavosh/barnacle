//! Compare harmless bytecode programs against pinned clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/pe.rs"]
mod pe;
#[path = "common/pe_icons.rs"]
mod pe_icons;
#[path = "bytecode_reference/scalar.rs"]
mod scalar;
#[path = "common/zip.rs"]
mod zip;

use daemon::{Daemon, stream_frame, unix_request};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const MARKER: &[u8] = b"CLAMAV-TEST-STRING-NOT-EICAR";
const CBC: &str = "harmless.cbc";
const LDB: &str = "receipt.ldb";
const FOUND: &str = "stream: BC.Clamav-Unit-Test-Signature FOUND\0";
const LDB_FOUND: &str = "stream: Receipt.Plain.UNOFFICIAL FOUND\0";
const STOCK_MISS: &str = "stream: OK\0";
const PARTIAL_MISS: &str = "stream: Incomplete scan: unsupported detection coverage. ERROR\0";

fn start(dir: &Path, executable: &Path, options: &str) -> io::Result<(Daemon, PathBuf)> {
    let config = dir.join("clamd.conf");
    let socket = dir.join("sock");
    fs::write(
        &config,
        format!(
            "Foreground yes\nSelfCheck 0\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n{options}",
            dir.join("db").display(),
            socket.display()
        ),
    )?;
    Ok((Daemon::start(executable, &config, &socket)?, socket))
}

fn fixture() -> io::Result<Vec<u8>> {
    let fixture = std::env::var_os("BARNACLE_CBC_FIXTURE")
        .ok_or_else(|| io::Error::other("set BARNACLE_CBC_FIXTURE to the pinned upstream CBC"))?;
    let fixture = fs::read(fixture)?;
    let digest: String = Sha256::digest(&fixture)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        digest,
        "36d282680ef43be4eb5fc1aec95b6d262460c3a5ffb2563a280a35dbe64bc8b3"
    );
    Ok(fixture)
}

fn compare(executable: &Path, fixture: &[u8], miss: &str) -> io::Result<()> {
    for (options, expected) in [
        ("", miss),
        ("BytecodeUnsigned no\n", miss),
        ("BytecodeUnsigned yes\nBytecodeMode Auto\n", FOUND),
        (
            "BytecodeUnsigned yes\nBytecodeMode ForceInterpreter\n",
            FOUND,
        ),
        ("Bytecode no\nBytecodeUnsigned yes\n", miss),
    ] {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join(CBC), fixture)?;
        let (_daemon, socket) = start(dir.path(), executable, options)?;
        assert_eq!(
            unix_request(&socket, &stream_frame(MARKER)?)?,
            expected,
            "{options}"
        );
        let prefixed = [b" ".as_slice(), MARKER].concat();
        assert_eq!(
            unix_request(&socket, &stream_frame(&prefixed)?)?,
            miss,
            "{options}"
        );
    }

    let marker: String = MARKER.iter().map(|byte| format!("{byte:02x}")).collect();
    let ordinary = format!("Receipt.Plain;Target:0;0;0:{marker}\n");
    for paths in [[CBC, LDB], [LDB, CBC]] {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        for path in paths {
            let bytes = if path == CBC {
                fixture
            } else {
                ordinary.as_bytes()
            };
            fs::write(db.join(path), bytes)?;
        }
        let first = fs::read_dir(db)?.next().unwrap()?.file_name();
        let expected = if first == CBC { FOUND } else { LDB_FOUND };
        let (_daemon, socket) = start(dir.path(), executable, "BytecodeUnsigned yes\n")?;
        assert_eq!(unix_request(&socket, &stream_frame(MARKER)?)?, expected);
    }
    Ok(())
}

#[test]
fn unsigned_bytecode_requires_explicit_enablement() -> io::Result<()> {
    let dir = tempfile::tempdir_in("/tmp")?;
    let db = dir.path().join("db");
    fs::create_dir(&db)?;
    fs::write(db.join(CBC), b"not a bytecode database\n")?;
    let exe = Path::new(env!("CARGO_BIN_EXE_barnacle"));
    {
        let (_daemon, socket) = start(dir.path(), exe, "")?;
        assert_eq!(unix_request(&socket, &stream_frame(MARKER)?)?, PARTIAL_MISS);
    }
    fs::remove_file(dir.path().join("sock"))?;
    let failed = start(dir.path(), exe, "BytecodeUnsigned yes\n")
        .err()
        .unwrap();
    assert!(failed.to_string().contains(CBC), "{failed}");
    Ok(())
}

#[test]
#[ignore = "set BARNACLE_CBC_FIXTURE to the pinned upstream fixture"]
fn barnacle_logical_bytecode() -> io::Result<()> {
    let executable = Path::new(env!("CARGO_BIN_EXE_barnacle"));
    let fixture = fixture()?;
    compare(executable, &fixture, PARTIAL_MISS)?;
    let fixture = std::str::from_utf8(&fixture).map_err(io::Error::other)?;
    let dir = tempfile::tempdir_in("/tmp")?;
    let db = dir.path().join("db");
    fs::create_dir(&db)?;
    fs::write(
        db.join(CBC),
        fixture.replacen("Target:0;", "Target:0,HandlerType:CL_TYPE_ZIP;", 1),
    )?;
    let failure = start(dir.path(), executable, "BytecodeUnsigned yes\n")
        .err()
        .unwrap();
    assert!(failure.to_string().contains("unsupported handler"));
    Ok(())
}

#[test]
#[ignore = "requires pinned Debian clamd and BARNACLE_CBC_FIXTURE"]
fn stock_logical_bytecode() -> io::Result<()> {
    verify_stock()?;
    compare(Path::new("/usr/sbin/clamd"), &fixture()?, STOCK_MISS)
}

fn verify_stock() -> io::Result<()> {
    let package = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(package.stdout, b"1.4.3+dfsg-1");
    Ok(())
}

fn run_program(
    executable: &Path,
    program: &str,
    options: &str,
    cases: &[(&[u8], bool)],
    miss: &str,
) -> io::Result<()> {
    let dir = tempfile::tempdir_in("/tmp")?;
    let db = dir.path().join("db");
    fs::create_dir(&db)?;
    fs::write(db.join(CBC), program)?;
    let (_daemon, socket) = start(dir.path(), executable, options)?;
    let found = format!("stream: {} FOUND\0", scalar::NAME);
    for (case, &(input, detects)) in cases.iter().enumerate() {
        let reply = unix_request(&socket, &stream_frame(input)?)?;
        assert_eq!(reply, if detects { &found } else { miss }, "case {case}");
    }
    Ok(())
}

fn compare_vm(executable: &Path, miss: &str) -> io::Result<()> {
    let options = "BytecodeUnsigned yes\nBytecodeMode ForceInterpreter\n";
    run_program(
        executable,
        &scalar::first_match(),
        options,
        &[
            (b"xxreceiptYzzreceiptX", true),
            (b"xxreceiptXzzreceiptY", false),
            (b"xxreceipt", false),
            (b"xxreceiptY with draft", false),
            (b"no trigger", false),
        ],
        miss,
    )?;
    let files = [
        (4_093, true),
        (4_094, false),
        (4_096, true),
        (4_102, true),
        (4_103, false),
    ]
    .map(|(position, detects)| {
        let mut input = vec![b' '; 4_110];
        input[..7].copy_from_slice(b"receipt");
        input[position..position + 3].copy_from_slice(b"ABC");
        (input, detects)
    });
    run_program(
        executable,
        &scalar::find(),
        options,
        &files
            .each_ref()
            .map(|(input, detects)| (input.as_slice(), *detects)),
        miss,
    )?;
    run_program(
        executable,
        &scalar::scalar_widths(),
        options,
        &[(b"receipt", true)],
        miss,
    )?;
    let options = format!("{options}BytecodeTimeout 1\n");
    run_program(
        executable,
        &scalar::counted_loop(8),
        &options,
        &[(b"receipt", true)],
        miss,
    )?;
    run_program(
        executable,
        &scalar::counted_loop(3_000_000),
        &options,
        &[(b"receipt", false)],
        miss,
    )
}

#[test]
fn barnacle_scalar_bytecode() -> io::Result<()> {
    compare_vm(Path::new(env!("CARGO_BIN_EXE_barnacle")), PARTIAL_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_scalar_bytecode() -> io::Result<()> {
    verify_stock()?;
    compare_vm(Path::new("/usr/sbin/clamd"), STOCK_MISS)
}

fn compare_read_cursor(executable: &Path, miss: &str) -> io::Result<()> {
    let options = "BytecodeUnsigned yes\nBytecodeMode ForceInterpreter\n";
    let zip = zip::zip(
        &[("first.txt", b"receiptAX"), ("second.txt", b"receiptAB")],
        true,
        false,
        false,
    )?;
    run_program(
        executable,
        &scalar::read_word(),
        options,
        &[
            (b"receiptAB tail", true),
            (b"receiptAX tail", false),
            (b"receiptA", false),
            (b"receipt", false),
            (b"receiptAB", true),
            (&zip, true),
        ],
        miss,
    )?;
    run_program(
        executable,
        &scalar::direct_read(),
        options,
        &[
            (b"receiptQ", true),
            (b"receiptX", false),
            (b"receipt", false),
        ],
        miss,
    )?;
    run_program(
        executable,
        &scalar::scan_metadata(),
        options,
        &[
            (b"receipt receipt padded!!", true),
            (b"receipt receipt padded!", false),
            (b"receipt form            ", false),
        ],
        miss,
    )?;
    for mapped in [false, true] {
        run_program(
            executable,
            &scalar::normalized_script(mapped),
            options,
            &[(b"RECEIPT    PADDED", true), (b"RECEIPT    DRAFT", false)],
            miss,
        )?;
    }
    run_program(
        executable,
        &scalar::cursor_search(),
        options,
        &[
            (b"receiptABC!", true),
            (b"ABCreceipt!!!", false),
            (b"receiptXABC", false),
            (b"receipt!ABC?", true),
        ],
        miss,
    )
}

#[test]
fn barnacle_bytecode_frame_and_cursor() -> io::Result<()> {
    compare_read_cursor(Path::new(env!("CARGO_BIN_EXE_barnacle")), PARTIAL_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_bytecode_frame_and_cursor() -> io::Result<()> {
    verify_stock()?;
    compare_read_cursor(Path::new("/usr/sbin/clamd"), STOCK_MISS)
}

fn compare_host_calls_and_helpers(executable: &Path, miss: &str) -> io::Result<()> {
    let options = "BytecodeUnsigned yes\nBytecodeMode ForceInterpreter\n";
    run_program(
        executable,
        &scalar::numeric_read(10, 42, 27),
        options,
        &[
            (b"receipt------------------42................", true),
            (b"receipt------------------43................", false),
        ],
        miss,
    )?;
    run_program(
        executable,
        &scalar::numeric_read(16, 42, 19),
        options,
        &[(b"receipt--------0x2A................", true)],
        miss,
    )?;
    run_program(
        executable,
        &scalar::numeric_read(10, u32::MAX, 7),
        options,
        &[
            (b"receipt..............42", true),
            (b"receipt................", false),
        ],
        miss,
    )?;
    for debug in [false, true] {
        let options = format!("{options}Debug {}\n", if debug { "yes" } else { "no" });
        run_program(
            executable,
            &scalar::diagnostics(debug),
            &options,
            &[(b"receipt diagnostic", true)],
            miss,
        )?;
    }
    run_program(
        executable,
        &scalar::direct_calls(),
        options,
        &[
            (b"receiptQ", true),
            (b"receiptX", false),
            (b"receipt", false),
        ],
        miss,
    )
}

#[test]
fn barnacle_bytecode_host_calls_and_helpers() -> io::Result<()> {
    compare_host_calls_and_helpers(Path::new(env!("CARGO_BIN_EXE_barnacle")), PARTIAL_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_bytecode_host_calls_and_helpers() -> io::Result<()> {
    verify_stock()?;
    compare_host_calls_and_helpers(Path::new("/usr/sbin/clamd"), STOCK_MISS)
}

fn compare_memory_and_pe_queries(executable: &Path, miss: &str) -> io::Result<()> {
    let options = "BytecodeUnsigned yes\nBytecodeMode ForceInterpreter\n";
    run_program(
        executable,
        &scalar::heap_search(),
        options,
        &[
            (b"receiptOKAY", true),
            (b"receiptOOPS", false),
            (b"receiptOA", false),
        ],
        miss,
    )?;

    let mut image = pe::benign_pe();
    image[544..551].copy_from_slice(b"receipt");
    let mut other = image.clone();
    other[544..551].copy_from_slice(b"product");
    let mut larger_section = image.clone();
    larger_section[384..388].copy_from_slice(&4097u32.to_le_bytes());
    larger_section[208..212].copy_from_slice(&12288u32.to_le_bytes());
    let mut nonzero_entry = image.clone();
    nonzero_entry[168..172].copy_from_slice(&0x1040u32.to_le_bytes());
    for target in [0, 1] {
        run_program(
            executable,
            &scalar::pe_metadata(target),
            options,
            &[
                (&image, true),
                (&other, false),
                (&larger_section, false),
                (&nonzero_entry, false),
            ],
            miss,
        )?;
    }
    Ok(())
}

#[test]
fn barnacle_bytecode_memory_and_pe_queries() -> io::Result<()> {
    compare_memory_and_pe_queries(Path::new(env!("CARGO_BIN_EXE_barnacle")), PARTIAL_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_bytecode_memory_and_pe_queries() -> io::Result<()> {
    verify_stock()?;
    compare_memory_and_pe_queries(Path::new("/usr/sbin/clamd"), STOCK_MISS)
}

const PDF_ATTACHMENT: &[u8] = b"Receipt for ordinary office stationery";

fn receipt_pdf(escaped_name: bool) -> (Vec<u8>, usize, usize) {
    let mut pdf = b"%PDF-1.5\n".to_vec();
    let mut offsets = [0; 3];
    let mut starts = [0; 3];
    for index in 0..3 {
        offsets[index] = pdf.len();
        write!(pdf, "{} 0 obj", index + 1).unwrap();
        starts[index] = pdf.len();
        match index {
            0 => {
                let key = if escaped_name { "Ty#70e" } else { "Type" };
                write!(pdf, "\n<< /{key} /Catalog /Pages 2 0 R >>").unwrap();
            }
            1 => pdf.extend_from_slice(b"\n<< /Type /Pages /Count 0 /Kids [] >>"),
            _ => {
                write!(
                    pdf,
                    "\n<< /Type /EmbeddedFile /Length {} >>\nstream\n",
                    PDF_ATTACHMENT.len()
                )
                .unwrap();
                pdf.extend_from_slice(PDF_ATTACHMENT);
                pdf.extend_from_slice(b"\nendstream");
            }
        }
        pdf.extend_from_slice(b"\nendobj\n");
    }
    let xref = pdf.len();
    pdf.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
    for offset in offsets {
        writeln!(pdf, "{offset:010} 00000 n ").unwrap();
    }
    write!(
        pdf,
        "trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    )
    .unwrap();
    (pdf, starts[0], starts[1] - starts[0] - 4)
}

fn compare_pdf_hooks(executable: &Path, miss: &str) -> io::Result<()> {
    let options = "BytecodeUnsigned yes\nBytecodeMode ForceInterpreter\n";
    let (receipt, first, size) = receipt_pdf(false);
    let (escaped, end_first, end_size) = receipt_pdf(true);
    let prefix = b" \n";
    let prefixed = [prefix, receipt.as_slice()].concat();
    for (phase, flags, offset, len, first_byte, doc) in [
        (4, 0, None, 0, b'%', receipt.as_slice()),
        (1, 0, Some(first), size, b'%', receipt.as_slice()),
        (
            1,
            2,
            Some(prefix.len() + first),
            size,
            b' ',
            prefixed.as_slice(),
        ),
        (2, 0, Some(first), 0, b'R', receipt.as_slice()),
        (
            3,
            1 << 11,
            Some(end_first),
            end_size,
            b'%',
            escaped.as_slice(),
        ),
    ] {
        let hook = scalar::pdf_hook(scalar::PdfProbe {
            phase,
            flags,
            first_offset: offset,
            first_size: len,
            first_byte,
            stop_pdf: false,
        });
        let control = if phase == 3 {
            &receipt
        } else {
            b"Ordinary plain text receipt".as_slice()
        };
        run_program(
            executable,
            &hook,
            options,
            &[(doc, true), (control, false)],
            miss,
        )
        .map_err(|error| io::Error::new(error.kind(), format!("phase {phase}: {error}")))?;
    }

    let stop_hook = scalar::pdf_hook(scalar::PdfProbe {
        phase: 1,
        flags: 0,
        first_offset: Some(first),
        first_size: size,
        first_byte: b'%',
        stop_pdf: true,
    });
    let post_hook = scalar::pdf_hook(scalar::PdfProbe {
        phase: 2,
        flags: 0,
        first_offset: Some(first),
        first_size: 0,
        first_byte: b'R',
        stop_pdf: false,
    });
    let trailing_line = [PDF_ATTACHMENT, b"\n"].concat();
    let rules: String = [PDF_ATTACHMENT, trailing_line.as_slice()]
        .iter()
        .map(|input| {
            let md5: String = md5::Md5::digest(input)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            format!("{md5}:{}:Pdf.HookReceipt\n", input.len())
        })
        .collect();
    let child = "stream: Pdf.HookReceipt.UNOFFICIAL FOUND\0";
    for (hook, settings, expected) in [
        (&stop_hook, options, miss),
        (&stop_hook, "BytecodeUnsigned no\n", child),
        (&stop_hook, "Bytecode no\nBytecodeUnsigned yes\n", child),
        (&post_hook, options, child),
    ] {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join(CBC), hook)?;
        fs::write(db.join("receipt.hdb"), &rules)?;
        let (_daemon, socket) = start(dir.path(), executable, settings)?;
        assert_eq!(
            unix_request(&socket, &stream_frame(&receipt)?)?,
            expected,
            "{settings}"
        );
    }
    Ok(())
}

#[test]
fn barnacle_pdf_hook_execution() -> io::Result<()> {
    compare_pdf_hooks(Path::new(env!("CARGO_BIN_EXE_barnacle")), PARTIAL_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_pdf_hook_execution() -> io::Result<()> {
    verify_stock()?;
    compare_pdf_hooks(Path::new("/usr/sbin/clamd"), STOCK_MISS)
}

fn compare_matchicon(executable: &Path, miss: &str) -> io::Result<()> {
    use pe_icons::{Drawing::*, image};
    let with_entry = |drawings: &[pe_icons::Drawing]| {
        let mut image = image(drawings, true);
        image[168..172].copy_from_slice(&0x1020u32.to_le_bytes());
        image
    };
    let doc = with_entry(&[Document]);
    let diamond = with_entry(&[Diamond]);
    let both = with_entry(&[Document, Diamond]);
    let mixed = with_entry(&[Diamond, ExtendedHeader]);
    let zero_entry = image(&[Document, Diamond], true);
    let groups = format!(
        "Document:Paper:Office:{}\nDrawing:Art:Shapes:{}\n",
        pe_icons::DOCUMENT,
        pe_icons::DIAMOND
    );
    let found = format!("stream: {} FOUND\0", scalar::NAME);
    let run = |program: String, cases: &[(&[u8], &str)]| -> io::Result<()> {
        let root = tempfile::tempdir_in("/tmp")?;
        let db = root.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join(CBC), program)?;
        fs::write(db.join("drawings.idb"), &groups)?;
        let (_daemon, socket) = start(
            root.path(),
            executable,
            "BytecodeUnsigned yes\nBytecodeMode ForceInterpreter\n",
        )?;
        for (index, &(input, matched)) in cases.iter().enumerate() {
            assert_eq!(
                unix_request(&socket, &stream_frame(input)?)?,
                matched,
                "case {index}"
            );
        }
        Ok(())
    };
    let extended = with_entry(&[ExtendedHeader]);
    let incomplete = if miss == PARTIAL_MISS {
        "stream: unverified PE icon DIB header or compression. ERROR\0"
    } else {
        miss
    };
    run(
        scalar::match_icon(1, Some("Paper"), b"Shapes\0memo", 0),
        &[
            (&both, &found),
            (&doc, &found),
            (&diamond, miss),
            (&zero_entry, miss),
            (&extended, incomplete),
        ],
    )?;
    run(
        scalar::match_icon(1, None, b"*", 0),
        &[
            (&doc, &found),
            (&diamond, &found),
            (&mixed, &found),
            (&zero_entry, miss),
        ],
    )?;
    run(
        scalar::match_icon(1, None, b"Unknown", u32::MAX),
        &[(&doc, miss), (&zero_entry, &found)],
    )?;
    run(
        scalar::match_icon(1, None, &[b'Q'; 127], 0),
        &[(&doc, &found)],
    )?;
    run(
        scalar::match_icon(1, None, &[b'Q'; 128], u32::MAX),
        &[(&doc, &found)],
    )?;
    run(
        scalar::match_icon(0, None, b"Unknown", 0),
        &[(&doc, &found), (&zero_entry, miss)],
    )?;

    Ok(())
}

#[test]
fn barnacle_matchicon_execution() -> io::Result<()> {
    compare_matchicon(Path::new(env!("CARGO_BIN_EXE_barnacle")), PARTIAL_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_matchicon_execution() -> io::Result<()> {
    verify_stock()?;
    compare_matchicon(Path::new("/usr/sbin/clamd"), STOCK_MISS)
}

fn compare_pe_all_hooks(executable: &Path, miss: &str) -> io::Result<()> {
    let options = "BytecodeUnsigned yes\nBytecodeMode ForceInterpreter\n";
    let mut marked = pe::benign_pe();
    marked[168..172].copy_from_slice(&0x1020u32.to_le_bytes());
    marked[544..552].copy_from_slice(b"receiptY");
    let mut other_entry = marked.clone();
    other_entry[168..172].copy_from_slice(&0x1030u32.to_le_bytes());
    let mut prefilter_only = marked.clone();
    prefilter_only[551] = b'N';
    let mut hook_only = marked.clone();
    hook_only[544] = b'R';
    let mut pe64 = marked.clone();
    pe64.copy_within(376..416, 392);
    pe64[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
    pe64[148..150].copy_from_slice(&240u16.to_le_bytes());
    pe64[152..154].copy_from_slice(&0x20bu16.to_le_bytes());
    pe64[260..264].copy_from_slice(&16u32.to_le_bytes());

    let overlay_note = b"Ordinary installer overlay receipt";
    let mut overlay = marked.clone();
    overlay.resize(1536, 0);
    overlay[134..136].copy_from_slice(&2u16.to_le_bytes());
    overlay[208..212].copy_from_slice(&12288u32.to_le_bytes());
    overlay.copy_within(376..416, 416);
    overlay[416..424].copy_from_slice(b".notes\0\0");
    overlay[428..432].copy_from_slice(&8192u32.to_le_bytes());
    overlay[436..440].copy_from_slice(&1024u32.to_le_bytes());
    overlay.extend_from_slice(b"notes.txt\0docs\0v1\0");
    write!(overlay, "{}\0", overlay_note.len())?;
    overlay.extend_from_slice(overlay_note);
    overlay.extend_from_slice(&[0; 4]);

    let nested = zip::zip(&[("receipt.exe", &marked)], true, false, false)?;
    let siblings = zip::zip(
        &[("first.exe", &prefilter_only), ("second.exe", &hook_only)],
        true,
        false,
        false,
    )?;
    let program = scalar::pe_all_hook();
    run_program(
        executable,
        &program,
        options,
        &[
            (&marked, true),
            (&other_entry, false),
            (&prefilter_only, false),
            (&hook_only, false),
            (&pe64, false),
            (&overlay, true),
            (&nested, true),
            (&siblings, false),
        ],
        miss,
    )?;
    for options in ["BytecodeUnsigned no\n", "BytecodeUnsigned yes\nScanPE no\n"] {
        run_program(executable, &program, options, &[(&marked, false)], miss)?;
    }

    let root = tempfile::tempdir_in("/tmp")?;
    let db = root.path().join("db");
    fs::create_dir(&db)?;
    fs::write(db.join(CBC), &program)?;
    let mut rules = String::new();
    for (input, name) in [
        (marked.as_slice(), "Pe.RawReceipt"),
        (overlay_note.as_slice(), "Pe.OverlayReceipt"),
    ] {
        let hash = barnacle::hash_reader(input)?;
        rules.push_str(&format!("{}:{}:{name}\n", hash.md5_hex(), input.len()));
    }
    fs::write(db.join("receipt.hdb"), rules)?;
    let (_daemon, socket) = start(root.path(), executable, options)?;
    assert_eq!(
        unix_request(&socket, &stream_frame(&marked)?)?,
        "stream: Pe.RawReceipt.UNOFFICIAL FOUND\0"
    );
    assert_eq!(
        unix_request(&socket, &stream_frame(&overlay)?)?,
        "stream: Pe.OverlayReceipt.UNOFFICIAL FOUND\0"
    );
    Ok(())
}

#[test]
fn barnacle_pe_all_hook_execution() -> io::Result<()> {
    compare_pe_all_hooks(Path::new(env!("CARGO_BIN_EXE_barnacle")), PARTIAL_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_pe_all_hook_execution() -> io::Result<()> {
    verify_stock()?;
    compare_pe_all_hooks(Path::new("/usr/sbin/clamd"), STOCK_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd and BARNACLE_CVD_DIR"]
fn stock_and_barnacle_run_verified_pdf_modules() -> io::Result<()> {
    use barnacle::PINNED_FLEVEL;
    use barnacle::bytecode::{PINNED_ARCHIVE, PdfHookContext, PdfHookResult, PdfPhase, Program};
    use std::time::Duration;

    verify_stock()?;
    let snapshot = std::env::var_os("BARNACLE_CVD_DIR")
        .ok_or_else(|| io::Error::other("set BARNACLE_CVD_DIR to the verified snapshot"))?;
    let (archive_name, size, digest) = PINNED_ARCHIVE;
    let mut archive = Vec::new();
    fs::File::open(Path::new(&snapshot).join(archive_name))?
        .take(size + 1)
        .read_to_end(&mut archive)?;
    let actual: String = Sha256::digest(&archive)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(archive.len() as u64, size);
    assert_eq!(actual, digest);

    let (ordinary, _, _) = receipt_pdf(false);
    let before_discovery = PdfHookContext {
        phase: PdfPhase::Pre,
        flags: Some(0),
        objects: Some(&[]),
        start: 0,
        size: ordinary.len(),
    };
    let mut modules = Vec::new();
    let mut tar = tar::Archive::new(GzDecoder::new(&archive[512..]));
    for entry in tar.entries()? {
        let mut entry = entry?;
        if entry.path()?.extension().and_then(|s| s.to_str()) != Some("cbc") {
            continue;
        }
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;
        if let Ok(Some(program)) = Program::compile(&contents, u64::from(PINNED_FLEVEL))
            && program.is_pdf_hook()
        {
            let mut entered = false;
            let outcome = program.run_pdf(
                &ordinary,
                before_discovery,
                false,
                Duration::from_secs(10),
                || {
                    entered = true;
                    Ok(())
                },
            )?;
            assert!(entered && matches!(outcome, PdfHookResult::Continue));
            modules.push(contents);
        }
    }
    assert_eq!(modules.len(), 2);

    let (escaped, _, _) = receipt_pdf(true);
    let prefixed = [b" \n".as_slice(), &ordinary].concat();
    let stock = Path::new("/usr/sbin/clamd");
    let barnacle = Path::new(env!("CARGO_BIN_EXE_barnacle"));
    for (label, executable, signed, miss) in [
        ("stock archive", stock, true, STOCK_MISS),
        ("stock local PDF modules", stock, false, STOCK_MISS),
        ("Barnacle local PDF modules", barnacle, false, PARTIAL_MISS),
    ] {
        let root = tempfile::tempdir_in("/tmp")?;
        let db = root.path().join("db");
        fs::create_dir(&db)?;
        if signed {
            fs::write(db.join(archive_name), &archive)?;
        } else {
            for (index, contents) in modules.iter().enumerate() {
                fs::write(db.join(format!("module-{index}.cbc")), contents)?;
            }
        }
        let unsigned = if signed { "no" } else { "yes" };
        let options = format!("BytecodeUnsigned {unsigned}\nBytecodeMode ForceInterpreter\n");
        let (_daemon, socket) = start(root.path(), executable, &options)?;
        for (case, bytes, expected) in [
            ("ordinary PDF", ordinary.as_slice(), miss),
            ("prefixed PDF", prefixed.as_slice(), miss),
            ("plain text", b"ordinary office stationery".as_slice(), miss),
            (
                "escaped common name",
                escaped.as_slice(),
                "stream: Heuristics.PDF.ObfuscatedNameObject FOUND\0",
            ),
        ] {
            let reply = unix_request(&socket, &stream_frame(bytes)?)?;
            assert!(reply == expected, "{label}: unexpected verdict for {case}");
        }
    }
    Ok(())
}
