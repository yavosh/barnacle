use super::{
    PARTIAL_MISS, STOCK_MISS, pe, scalar, start, stream_frame, unix_request, verify_stock,
};
use scalar::WriteFinish::{Abort, Report, Result as Returns};
use std::{fs, io, path::Path};

#[test]
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[ignore = "requires pinned Debian clamd and BARNACLE_CVD_DIR"]
fn stock_signed_receipt_selection() -> io::Result<()> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;

    verify_stock()?;
    let snapshot = std::env::var_os("BARNACLE_CVD_DIR")
        .ok_or_else(|| io::Error::other("set BARNACLE_CVD_DIR to the verified snapshot"))?;
    let verified = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")?;
    let archives = [
        barnacle::bytecode::PINNED_ARCHIVE,
        (
            "main.cvd",
            89_072_577,
            "0b2182d229f46981ec8f535382222f7c9dfdd656b250ad47988b910a8d302365",
        ),
        (
            "daily.cvd",
            23_450_852,
            "423f7774182bfbc82b50c7796c68a93f8b1817ef7ebbc88d7def444bc2c8f35b",
        ),
    ];
    for (name, length, digest) in archives {
        let mut input = fs::File::open(Path::new(&snapshot).join(name))?.take(length + 1);
        let mut output = fs::File::create_new(verified.path().join(name))?;
        let mut hash = Sha256::new();
        let mut size = 0;
        let mut block = [0; 64 * 1024];
        loop {
            let count = input.read(&mut block)?;
            if count == 0 {
                break;
            }
            output.write_all(&block[..count])?;
            hash.update(&block[..count]);
            size += count as u64;
        }
        assert_eq!(size, length);
        let actual: String = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(actual, digest);
    }
    for (label, bytes, pe_all, executed) in [
        ("inactive PE32", pe::benign_pe(), 1, 0),
        (
            "ledger PE32",
            include_bytes!("../fixtures/upx/ledger.exe").to_vec(),
            1,
            1,
        ),
        (
            "packed ledger",
            include_bytes!("../fixtures/upx/ledger-nrv2b.exe").to_vec(),
            2,
            1,
        ),
    ] {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")?;
        let db = root.path().join("db");
        fs::create_dir(&db)?;
        for (name, _, _) in archives {
            std::os::unix::fs::symlink(verified.path().join(name), db.join(name))?;
        }
        let (daemon, socket) = start(
            root.path(),
            Path::new("/usr/sbin/clamd"),
            "Debug yes\nBytecode yes\nBytecodeUnsigned no\nBytecodeMode ForceInterpreter\nScanPE yes\n",
        )?;
        let log = root.path().join("clamd.log");
        let scan_start = fs::metadata(&log)?.len() as usize;
        assert_eq!(
            unix_request(&socket, &stream_frame(&bytes)?)?,
            STOCK_MISS,
            "{label}"
        );
        drop(daemon);
        let log = fs::read_to_string(log)?;
        let scan = &log[scan_start..];
        assert_eq!(
            scan.matches("Bytecode executing hook id 259 (2 hooks)")
                .count(),
            pe_all,
            "{label}"
        );
        assert_eq!(
            scan.matches("Bytecode executing hook id 257 (6 hooks)")
                .count(),
            1,
            "{label}"
        );
        assert_eq!(
            scan.matches("Bytecode: executing bytecode ").count(),
            executed,
            "{label}"
        );
        assert_eq!(
            scan.matches("Bytecode: executed 1 bytecodes for this hook")
                .count(),
            executed,
            "{label}"
        );
        assert_eq!(
            scan.matches("after executing 3291 opcodes").count(),
            executed,
            "{label}"
        );
        assert_eq!(
            scan.matches("previous tempfile had 0 bytes").count(),
            executed,
            "{label}"
        );
        assert_eq!(
            scan.matches("Bytecode 26 returned 0").count(),
            executed,
            "{label}"
        );
        assert!(!scan.contains("failed to run:"), "{label}");
    }
    Ok(())
}

fn compare(executable: &Path, miss: &str) -> io::Result<()> {
    let trigger = "Local.Receipt.Unpack.{};Target:1;0;544:72656365697074";
    let always = "Local.Receipt.Unpack";
    let name = format!("stream: {} FOUND\0", scalar::NAME);
    let child = "stream: Receipt.Child.UNOFFICIAL FOUND\0";
    let limit = "stream: Heuristics.Limits.Exceeded.MaxFiles FOUND\0";
    let size_limit = "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0";
    let mut marked = pe::benign_pe();
    marked[544..551].copy_from_slice(b"receipt");
    let plain = pe::benign_pe();
    let run = |late: String,
               early: Option<String>,
               child_hash: bool,
               options: &str,
               cases: &[(&[u8], &str)]|
     -> io::Result<()> {
        let root = tempfile::tempdir_in("/tmp")?;
        let db = root.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join("late.cbc"), late)?;
        if let Some(early) = early {
            fs::write(db.join("early.cbc"), early)?;
        }
        let note = if child_hash {
            scalar::EXTRACTED_NOTE
        } else {
            b"unrelated plain receipt"
        };
        fs::write(
            db.join("child.hdb"),
            format!(
                "{}:{}:Receipt.Child\n",
                barnacle::hash_reader(note)?.md5_hex(),
                note.len()
            ),
        )?;
        let options = format!("BytecodeUnsigned yes\nBytecodeMode ForceInterpreter\n{options}");
        let (_daemon, socket) = start(root.path(), executable, &options)?;
        for &(bytes, expected) in cases {
            assert_eq!(
                unix_request(&socket, &stream_frame(bytes)?)?,
                expected,
                "{options}"
            );
        }
        Ok(())
    };
    let emit = |title, result| scalar::output_probe(257, title, result);
    run(
        emit(trigger, Report),
        None,
        false,
        "",
        &[(&marked, &name), (&plain, miss)],
    )?;
    run(
        emit(always, Report),
        None,
        false,
        "",
        &[(&plain, &name), (b"plain receipt", miss)],
    )?;
    run(
        emit(always, Report),
        None,
        false,
        "ScanPE no\n",
        &[(&plain, miss)],
    )?;
    run(
        emit(always, Report),
        None,
        false,
        "Bytecode no\n",
        &[(&plain, miss)],
    )?;
    run(
        emit(always, Report),
        Some(scalar::pe_all_break()),
        false,
        "",
        &[(&marked, miss), (&plain, &name)],
    )?;

    for ret in [Returns(0), Returns(1), Returns(0xcea5e), Abort, Report] {
        run(emit(trigger, ret), None, true, "", &[(&marked, child)])?;
    }
    for (opts, expected) in [
        ("MaxFiles 2\n", limit),
        ("MaxFiles 3\n", child),
        ("MaxScanSize 1083\n", size_limit),
        ("MaxScanSize 1084\n", child),
    ] {
        run(
            emit(trigger, Returns(0)),
            None,
            true,
            &(opts.to_owned() + "AlertExceedsMax yes\n"),
            &[(&marked, expected)],
        )?;
    }

    // A successful native unpack returns even when the unpacked child has no matching rule.
    let packed = include_bytes!("../fixtures/upx/ledger-nrv2b.exe");
    let mut control = plain;
    control.resize(packed.len(), 0);
    let size = packed.len();
    let same_size = format!(
        "Local.Receipt.Packed.{{}};Engine:150-255,Target:1,FileSize:{size}-{size};0;0:4d5a"
    );
    run(
        emit(&same_size, Report),
        None,
        false,
        "",
        &[(packed, miss), (&control, &name)],
    )?;
    Ok(())
}

#[test]
fn barnacle_pe_unpacker() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), PARTIAL_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_pe_unpacker() -> io::Result<()> {
    verify_stock()?;
    compare(Path::new("/usr/sbin/clamd"), STOCK_MISS)
}

fn compare_extract_new(executable: &Path, miss: &str) -> io::Result<()> {
    let first = b"first ledger note".as_slice();
    let tail = b"second ledger note".as_slice();
    let mut parent = pe::benign_pe();
    parent[544..551].copy_from_slice(b"receipt");
    let first_hit = "stream: Local.First.UNOFFICIAL FOUND\0";
    let second_hit = "stream: Local.Second.UNOFFICIAL FOUND\0";
    let cases = [
        (
            b"".as_slice(),
            b"".as_slice(),
            false,
            0,
            "",
            false,
            false,
            miss,
        ),
        (first, tail, false, 0, "", false, true, second_hit),
        (first, tail, false, 1, "", true, false, first_hit),
        (first, tail, true, 0, "", true, false, first_hit),
        (first, tail, true, 1, "", false, true, second_hit),
        (first, tail, false, 0, "", false, false, miss),
        (
            b"x".as_slice(),
            b"".as_slice(),
            false,
            0,
            "MaxRecursion 1\n",
            false,
            false,
            miss,
        ),
        (
            first,
            tail,
            false,
            24,
            "MaxScanSize 1041\nMaxFiles 2\n",
            false,
            false,
            "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0",
        ),
        (
            first,
            tail,
            false,
            23,
            "MaxRecursion 1\n",
            false,
            false,
            "stream: Heuristics.Limits.Exceeded.MaxRecursion FOUND\0",
        ),
        (
            first,
            tail,
            false,
            24,
            "MaxScanSize 1041\n",
            false,
            false,
            "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0",
        ),
        (
            first,
            tail,
            false,
            25,
            "MaxFiles 2\n",
            false,
            false,
            "stream: Heuristics.Limits.Exceeded.MaxFiles FOUND\0",
        ),
        (
            first,
            tail,
            false,
            0,
            "MaxFiles 4\n",
            false,
            true,
            "stream: Heuristics.Limits.Exceeded.MaxFiles FOUND\0",
        ),
        (
            first,
            tail,
            false,
            0,
            "MaxFiles 5\n",
            false,
            true,
            second_hit,
        ),
        (
            first,
            tail,
            false,
            0,
            "MaxScanSize 1093\n",
            false,
            true,
            "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0",
        ),
        (
            first,
            tail,
            false,
            0,
            "MaxScanSize 1094\n",
            false,
            true,
            second_hit,
        ),
    ];
    for (head, end, flush_end, expected_status, limits, detect_first, detect_tail, expected) in
        cases
    {
        let root = tempfile::tempdir_in("/tmp")?;
        let db = root.path().join("db");
        fs::create_dir(&db)?;
        fs::write(
            db.join("extract.cbc"),
            scalar::extract_segments(head, end, flush_end, expected_status),
        )?;
        let joined = [first, tail].concat();
        let mut hashes = String::new();
        for (bytes, name, enabled) in [
            (joined.as_slice(), "Joined", true),
            (first, "First", detect_first),
            (tail, "Second", detect_tail),
        ] {
            if enabled {
                use std::fmt::Write;
                writeln!(
                    hashes,
                    "{}:{}:Local.{name}",
                    barnacle::hash_reader(bytes)?.md5_hex(),
                    bytes.len()
                )
                .unwrap();
            }
        }
        fs::write(db.join("notes.hdb"), hashes)?;
        let options = format!(
            "Debug yes\nBytecodeUnsigned yes\nBytecodeMode ForceInterpreter\nAlertExceedsMax yes\n{limits}"
        );
        let (daemon, socket) = start(root.path(), executable, &options)?;
        assert_eq!(
            unix_request(&socket, &stream_frame(&parent)?)?,
            expected,
            "{options}"
        );
        drop(daemon);
        let log = fs::read_to_string(root.path().join("clamd.log"))?;
        assert!(
            log.lines().any(|line| line.starts_with("871035284")),
            "extract_new status {expected_status}, {options}"
        );
    }
    Ok(())
}

#[test]
fn barnacle_extract_new() -> io::Result<()> {
    compare_extract_new(Path::new(env!("CARGO_BIN_EXE_barnacle")), PARTIAL_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_extract_new() -> io::Result<()> {
    verify_stock()?;
    compare_extract_new(Path::new("/usr/sbin/clamd"), STOCK_MISS)
}

#[test]
fn explicit_child_survives_later_incomplete_scans() -> io::Result<()> {
    use barnacle::{
        bytecode::Program,
        objects::{self, Options, PeHooks, Verdict},
    };
    let first = b"first ledger note";
    let tail = b"second ledger note";
    let directory = tempfile::tempdir()?;
    for flush_tail in [false, true] {
        let program = scalar::extract_segments(first, tail, flush_tail, 0);
        let unpackers = [(None, Program::compile(program.as_bytes(), 213)?.unwrap())];
        let hooks = PeHooks {
            programs: &[],
            unpackers: &unpackers,
            debug: false,
            timeout: std::time::Duration::from_secs(10),
        };
        let run = |detect_first, interrupted| {
            objects::scan_with_hooks(
                &pe::benign_pe(),
                &Options::default(),
                directory.path(),
                None,
                Some(hooks),
                |object, _| {
                    Ok(if object.bytes == first && detect_first {
                        Verdict::Found("Receipt.First".to_owned())
                    } else if object.bytes == tail {
                        if interrupted {
                            return Err(io::ErrorKind::Interrupted.into());
                        }
                        Verdict::Incomplete
                    } else {
                        Verdict::Miss
                    })
                },
                || Ok(()),
            )
        };
        assert_eq!(
            run(true, false)?,
            Verdict::Found("Receipt.First".to_owned())
        );
        assert_eq!(
            run(true, true).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        if flush_tail {
            assert_eq!(
                run(false, false).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        } else {
            assert_eq!(run(false, false)?, Verdict::Incomplete);
        }
    }
    Ok(())
}
