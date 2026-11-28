use super::{
    PARTIAL_MISS, STOCK_MISS, pe, scalar, start, stream_frame, unix_request, verify_stock,
};
use scalar::WriteFinish::{Abort, Report, Result as Returns};
use std::{fs, io, path::Path};

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
