//! Compare benign, compiled AutoIt resources with pinned stock clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/pe.rs"]
mod pe;
#[path = "common/zip.rs"]
mod zip;

use barnacle::objects::{self, Options, Verdict};
use daemon::{Daemon, stream_frame, unix_request};
use std::{fmt::Write, fs, io, path::Path};

const GUIDE: &[u8] = include_bytes!("fixtures/autoit/guide.a3x");
const HEADER_LEN: usize = 40;
const GUIDE_LEDGER_OFFSET: usize = 835;
const QUANTITIES: &[u8] = include_bytes!("fixtures/autoit/quantities.a3x");
const LEGACY_NOTICE: &[u8] = include_bytes!("fixtures/autoit/notice-ea05.a3x");
const LEGACY_NOTICE_PAYLOAD_OFFSET: usize = 111;
const LEGACY_PACKED: &[u8] = include_bytes!("fixtures/autoit/ledger-ea05.a3x");
const LEGACY_LEDGER_OFFSET: usize = 174;
const NOTICE: &[u8] = b"Inventory terminal reference sheet, revision six.\n";
const QUANTITY_SCRIPT: &[u8] = concat!(
    "LOCAL $CARTONS = 0x0000002a \n",
    "LOCAL $SERIAL = 0x0000000100000001 \n",
    "LOCAL $RATE = 1.25 \n",
    "CONSOLEWRITE ( $CARTONS & \" / \" & $SERIAL & \" @ \" & $RATE & @CRLF ) \n",
    "FILEINSTALL ( \"notice.txt\" , @TEMPDIR & \"\\notice.txt\" ) \n",
)
.as_bytes();
const SCRIPT: &[u8] = concat!(
    "FILEINSTALL ( \"notice.txt\" , @TEMPDIR & \"\\notice.txt\" ) \n",
    "FILEINSTALL ( \"ledger.txt\" , @TEMPDIR & \"\\ledger.txt\" ) \n",
    "CONSOLEWRITE ( \"Inventory guide prepared.\" & @CRLF ) \n",
)
.as_bytes();

fn ledger() -> Vec<u8> {
    let mut data = String::new();
    for row in 0..4096 {
        writeln!(data, "Shelf {row:04} holds quarterly material.").expect("write to string");
    }
    data.into_bytes()
}

fn rule(name: &str, bytes: &[u8]) -> io::Result<String> {
    Ok(format!(
        "{}:{}:AutoItFixture.{name}\n",
        barnacle::hash_reader(bytes)?.md5_hex(),
        bytes.len()
    ))
}

fn check(
    executable: &Path,
    input: &[u8],
    rules: &str,
    options: &str,
    expected: &str,
) -> io::Result<()> {
    let root = tempfile::tempdir_in("/tmp")?;
    let db = root.path().join("db");
    fs::create_dir(&db)?;
    fs::write(db.join("local.hdb"), rules)?;
    let socket = root.path().join("sock");
    let config = root.path().join("clamd.conf");
    fs::write(
        &config,
        format!(
            "Foreground yes\nTemporaryDirectory {}\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\nAlertExceedsMax yes\n{options}\n",
            root.path().display(),
            db.display(),
            socket.display(),
        ),
    )?;
    let _daemon = Daemon::start(executable, &config, &socket)?;
    let reply = unix_request(&socket, &stream_frame(input)?)?;
    assert_eq!(reply, format!("stream: {expected}\0"), "{options}");
    Ok(())
}

fn compare(executable: &Path) -> io::Result<()> {
    let ledger_bytes = ledger();
    let script = rule("Script", SCRIPT)?;
    let notice = rule("Notice", NOTICE)?;
    let ledger = rule("Ledger", &ledger_bytes)?;
    let outer = rule("Container", GUIDE)?;
    let resources = notice.clone() + &ledger;
    let all = script.clone() + &resources + &outer;
    let exact_script = GUIDE.len() + 311;
    let exact_notice = GUIDE.len() + NOTICE.len();
    let exact_ledger = GUIDE.len() + SCRIPT.len() + NOTICE.len() + ledger_bytes.len();
    for (rules, options, expected) in [
        (&all, String::new(), "AutoItFixture.Script.UNOFFICIAL FOUND"),
        (
            &resources,
            String::new(),
            "AutoItFixture.Notice.UNOFFICIAL FOUND",
        ),
        (
            &ledger,
            String::new(),
            "AutoItFixture.Ledger.UNOFFICIAL FOUND",
        ),
        (
            &outer,
            String::new(),
            "AutoItFixture.Container.UNOFFICIAL FOUND",
        ),
        (
            &all,
            "ScanArchive no".into(),
            "AutoItFixture.Container.UNOFFICIAL FOUND",
        ),
        (
            &notice,
            "MaxFiles 2".into(),
            "Heuristics.Limits.Exceeded.MaxFiles FOUND",
        ),
        (
            &notice,
            "MaxFiles 3".into(),
            "AutoItFixture.Notice.UNOFFICIAL FOUND",
        ),
        (
            &all,
            "MaxRecursion 1".into(),
            "Heuristics.Limits.Exceeded.MaxRecursion FOUND",
        ),
        (
            &script,
            format!("MaxScanSize {exact_script}"),
            "AutoItFixture.Script.UNOFFICIAL FOUND",
        ),
        (
            &script,
            format!("MaxScanSize {}", exact_script - 1),
            "Heuristics.Limits.Exceeded.MaxScanSize FOUND",
        ),
        (
            &notice,
            format!("MaxScanSize {exact_notice}"),
            "AutoItFixture.Notice.UNOFFICIAL FOUND",
        ),
        (
            &notice,
            format!("MaxScanSize {}", exact_notice - 1),
            "Heuristics.Limits.Exceeded.MaxScanSize FOUND",
        ),
        (
            &ledger,
            format!("MaxScanSize {exact_ledger}"),
            "AutoItFixture.Ledger.UNOFFICIAL FOUND",
        ),
        (
            &ledger,
            format!("MaxScanSize {}", exact_ledger - 1),
            "Heuristics.Limits.Exceeded.MaxScanSize FOUND",
        ),
        (
            &ledger,
            format!("MaxFileSize {}", GUIDE.len()),
            "Heuristics.Limits.Exceeded.MaxFileSize FOUND",
        ),
    ] {
        check(executable, GUIDE, rules, &options, expected)?;
    }
    check(
        executable,
        &GUIDE[..GUIDE.len() - 1024],
        &notice,
        "",
        "AutoItFixture.Notice.UNOFFICIAL FOUND",
    )?;
    check(
        executable,
        QUANTITIES,
        &(rule("QuantityScript", QUANTITY_SCRIPT)? + &notice),
        "",
        "AutoItFixture.QuantityScript.UNOFFICIAL FOUND",
    )?;
    check(
        executable,
        QUANTITIES,
        &notice,
        "",
        "AutoItFixture.Notice.UNOFFICIAL FOUND",
    )?;
    let mut pe = pe::benign_pe();
    pe.extend_from_slice(GUIDE);
    let pe_hash = rule("Executable", &pe)?;
    let archive = zip::zip(&[("guide.exe", &pe)], true, false, false)?;
    let exact_suffix = pe.len() + GUIDE.len();
    for (bytes, rules, options, expected) in [
        (
            pe.as_slice(),
            all.clone() + &pe_hash,
            String::new(),
            "AutoItFixture.Executable.UNOFFICIAL FOUND",
        ),
        (
            pe.as_slice(),
            notice.clone() + &outer,
            "ScanPE no".into(),
            "AutoItFixture.Notice.UNOFFICIAL FOUND",
        ),
        (
            pe.as_slice(),
            notice.clone(),
            format!("MaxScanSize {exact_suffix}"),
            "AutoItFixture.Notice.UNOFFICIAL FOUND",
        ),
        (
            pe.as_slice(),
            notice.clone(),
            format!("MaxScanSize {}", exact_suffix - 1),
            "Heuristics.Limits.Exceeded.MaxScanSize FOUND",
        ),
        (
            archive.as_slice(),
            notice + &rule("Zip", &archive)?,
            String::new(),
            "AutoItFixture.Notice.UNOFFICIAL FOUND",
        ),
    ] {
        check(executable, bytes, &rules, &options, expected)?;
    }
    Ok(())
}

fn compare_legacy(executable: &Path) -> io::Result<()> {
    let notice = rule("Notice", NOTICE)?;
    let outer = rule("Container", LEGACY_NOTICE)?;
    let both = notice.clone() + &outer;
    let short = format!("MaxScanSize {}", LEGACY_NOTICE.len() + NOTICE.len() - 1);
    let exact = format!("MaxScanSize {}", LEGACY_NOTICE.len() + NOTICE.len());
    for (rules, options, expected) in [
        (&both, "", "AutoItFixture.Notice.UNOFFICIAL FOUND"),
        (&both, "ScanPE no", "AutoItFixture.Notice.UNOFFICIAL FOUND"),
        (
            &both,
            "ScanArchive no",
            "AutoItFixture.Container.UNOFFICIAL FOUND",
        ),
        (
            &notice,
            "MaxFiles 1",
            "Heuristics.Limits.Exceeded.MaxFiles FOUND",
        ),
        (
            &both,
            "MaxFiles 1",
            "AutoItFixture.Container.UNOFFICIAL FOUND",
        ),
        (&both, "MaxFiles 2", "AutoItFixture.Notice.UNOFFICIAL FOUND"),
        (
            &notice,
            "MaxRecursion 1",
            "Heuristics.Limits.Exceeded.MaxRecursion FOUND",
        ),
        (
            &both,
            "MaxRecursion 1",
            "AutoItFixture.Container.UNOFFICIAL FOUND",
        ),
        (
            &both,
            "MaxRecursion 2",
            "AutoItFixture.Notice.UNOFFICIAL FOUND",
        ),
        (
            &notice,
            short.as_str(),
            "Heuristics.Limits.Exceeded.MaxScanSize FOUND",
        ),
        (
            &both,
            short.as_str(),
            "AutoItFixture.Container.UNOFFICIAL FOUND",
        ),
        (
            &both,
            exact.as_str(),
            "AutoItFixture.Notice.UNOFFICIAL FOUND",
        ),
        (&outer, "", "AutoItFixture.Container.UNOFFICIAL FOUND"),
    ] {
        check(executable, LEGACY_NOTICE, rules, options, expected)?;
    }
    for end in [32, 75] {
        let interrupted = &LEGACY_NOTICE[..end];
        check(
            executable,
            interrupted,
            &rule("Container", interrupted)?,
            "",
            "AutoItFixture.Container.UNOFFICIAL FOUND",
        )?;
    }
    let short_timestamps = &LEGACY_NOTICE[..LEGACY_NOTICE_PAYLOAD_OFFSET - 8];
    check(
        executable,
        short_timestamps,
        &notice,
        &format!("MaxScanSize {}", short_timestamps.len() + NOTICE.len() - 1),
        "Heuristics.Limits.Exceeded.MaxScanSize FOUND",
    )?;
    let ledger_bytes = ledger();
    let ledger = rule("Ledger", &ledger_bytes)?;
    let both = notice.clone() + &ledger + &rule("Container", LEGACY_PACKED)?;
    let exact_ledger = LEGACY_PACKED.len() + NOTICE.len() + ledger_bytes.len();
    let truncated = &LEGACY_PACKED[..LEGACY_PACKED.len() - 1024];
    let truncated_outer = rule("Container", truncated)?;
    for (bytes, rules, options, expected) in [
        (
            LEGACY_PACKED,
            &both,
            String::new(),
            "AutoItFixture.Notice.UNOFFICIAL FOUND",
        ),
        (
            LEGACY_PACKED,
            &ledger,
            "MaxFiles 3".into(),
            "AutoItFixture.Ledger.UNOFFICIAL FOUND",
        ),
        (
            LEGACY_PACKED,
            &ledger,
            format!("MaxScanSize {exact_ledger}"),
            "AutoItFixture.Ledger.UNOFFICIAL FOUND",
        ),
        (
            LEGACY_PACKED,
            &ledger,
            format!("MaxScanSize {}", exact_ledger - 1),
            "Heuristics.Limits.Exceeded.MaxScanSize FOUND",
        ),
        (
            truncated,
            &notice,
            String::new(),
            "AutoItFixture.Notice.UNOFFICIAL FOUND",
        ),
        (
            truncated,
            &truncated_outer,
            String::new(),
            "AutoItFixture.Container.UNOFFICIAL FOUND",
        ),
    ] {
        check(executable, bytes, rules, &options, expected)?;
    }
    let mut pe = pe::benign_pe();
    pe.extend_from_slice(LEGACY_PACKED);
    let pe_hash = rule("Executable", &pe)?;
    check(
        executable,
        &pe,
        &(pe_hash + &notice),
        "",
        "AutoItFixture.Executable.UNOFFICIAL FOUND",
    )?;
    check(
        executable,
        &pe,
        &notice,
        "ScanPE no",
        "AutoItFixture.Notice.UNOFFICIAL FOUND",
    )?;
    let archive = zip::zip(&[("guide.a3x", LEGACY_PACKED)], true, false, false)?;
    check(
        executable,
        &archive,
        &(rule("Zip", &archive)? + &notice),
        "",
        "AutoItFixture.Notice.UNOFFICIAL FOUND",
    )?;
    Ok(())
}

#[test]
fn legacy_resources() -> io::Result<()> {
    compare_legacy(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
#[ignore = "requires the pinned Debian clamd"]
fn stock_legacy_resources() -> io::Result<()> {
    compare_legacy(Path::new("/usr/sbin/clamd"))
}

#[test]
fn autoit_resources() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
#[ignore = "requires the pinned Debian clamd"]
fn stock_autoit_resources() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"))
}

#[test]
fn recursion_denied_resources_do_not_need_scratch() -> io::Result<()> {
    // Keep the archive header and move the compressed ledger to the first record.
    let scratch = tempfile::tempdir()?;
    for (input, offset) in [
        (GUIDE, GUIDE_LEDGER_OFFSET),
        (LEGACY_PACKED, LEGACY_LEDGER_OFFSET),
    ] {
        let ledger_first = [&input[..HEADER_LEN], &input[offset..]].concat();
        let result = objects::scan(
            &ledger_first,
            &Options {
                max_recursion: 1,
                alert_exceeds_max: true,
                ..Options::default()
            },
            &scratch.path().join("absent"),
            |_, _| Ok(Verdict::Miss),
            || Ok(()),
        )?;
        assert_eq!(
            result,
            Verdict::Found("Heuristics.Limits.Exceeded.MaxRecursion".into())
        );
    }
    Ok(())
}

#[test]
fn resource_copy_propagates_interrupted_scan() -> io::Result<()> {
    let ledger_first = [&GUIDE[..HEADER_LEN], &GUIDE[GUIDE_LEDGER_OFFSET..]].concat();
    let scratch = tempfile::tempdir()?;
    let mut checks = 0;
    let error = objects::scan(
        &ledger_first,
        &Options::default(),
        scratch.path(),
        |_, _| Ok(Verdict::Miss),
        || {
            checks += 1;
            if checks == 10 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "fixture interrupted",
                ));
            }
            Ok(())
        },
    )
    .expect_err("propagate the interruption during compressed resource decoding");
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(error.to_string(), "fixture interrupted");
    assert_eq!(checks, 10);
    Ok(())
}

#[test]
fn recovered_resources_keep_autoit_context() -> io::Result<()> {
    let scratch = tempfile::tempdir()?;
    let mut recovered = Vec::new();
    let ledger = ledger();
    let result = objects::scan(
        GUIDE,
        &Options::default(),
        scratch.path(),
        |object, _| {
            if object.normalized {
                return Ok(Verdict::Miss);
            }
            for (name, bytes) in [
                ("script", SCRIPT),
                ("notice", NOTICE),
                ("ledger", ledger.as_slice()),
            ] {
                if object.bytes == bytes {
                    assert_eq!(object.parents.len(), 1);
                    assert_eq!(object.parents[0].file_type, "CL_TYPE_AUTOIT");
                    assert!(object.layer.name.is_none());
                    recovered.push(name);
                }
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(result, Verdict::Miss);
    assert_eq!(recovered, ["script", "notice", "ledger"]);
    Ok(())
}
