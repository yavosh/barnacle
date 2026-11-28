//! Compare harmless logical bytecode programs against pinned clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "bytecode_reference/scalar.rs"]
mod scalar;
#[path = "common/zip.rs"]
mod zip;

use daemon::{Daemon, stream_frame, unix_request};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
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
    for title in [
        "Target:0,HandlerType:CL_TYPE_ZIP;",
        "Target:1,IconGroup1:Receipt;",
    ] {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join(CBC), fixture.replacen("Target:0;", title, 1))?;
        let failure = start(dir.path(), executable, "BytecodeUnsigned yes\n")
            .err()
            .unwrap();
        assert!(
            failure
                .to_string()
                .contains("requires handler or icon evaluation")
        );
    }
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
