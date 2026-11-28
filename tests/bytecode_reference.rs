//! Compare one harmless logical bytecode trigger against pinned clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;

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
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), &fixture()?, STOCK_MISS)
}
