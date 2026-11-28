use super::{STOCK_MISS, start, stream_frame, unix_request, verify_stock};
use barnacle::body::{LogicalIndex, LogicalObject, ObjectContext};
use barnacle::bytecode::{PINNED_ARCHIVE, visit_verified_members};
use barnacle::{IgnoreSet, PINNED_FLEVEL};
use std::{
    fs,
    io::{self, Read},
    path::Path,
    time::Duration,
};

const EICAR: &[u8; 68] = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

#[test]
#[ignore = "requires pinned Debian clamd and BARNACLE_CVD_DIR"]
fn verified_eicar_logical_rule() -> io::Result<()> {
    verify_stock()?;
    let snapshot = std::env::var_os("BARNACLE_CVD_DIR")
        .ok_or_else(|| io::Error::other("set BARNACLE_CVD_DIR to the verified snapshot"))?;
    let mut archive = Vec::new();
    fs::File::open(Path::new(&snapshot).join(PINNED_ARCHIVE.0))?
        .take(PINNED_ARCHIVE.1 + 1)
        .read_to_end(&mut archive)?;
    let source = Path::new("6327695.cbc");
    let mut module = None;
    visit_verified_members(&archive[..], |path, bytes| {
        if path == source {
            assert!(module.replace(bytes.to_vec()).is_none());
        }
        Ok(())
    })?;
    let module = module.expect("verified EICAR member");
    let index = LogicalIndex::load_with_bytecode(
        &[(source, true)],
        PINNED_FLEVEL,
        &IgnoreSet::default(),
        Duration::from_secs(60),
        |path| {
            assert_eq!(path, source);
            Ok(module.as_slice())
        },
    )?;
    assert_eq!(index.rule_count(), 1);

    let mut altered = EICAR.to_vec();
    altered[0] = b'Z';
    let mut cap = EICAR.to_vec();
    cap.resize(128, b' ');
    let cases = [
        ("canonical", EICAR.to_vec(), true),
        ("first byte changed", altered, false),
        ("truncated", EICAR[..67].to_vec(), false),
        (
            "allowed suffix",
            [EICAR.as_slice(), b" \t\n\r\x1a"].concat(),
            true,
        ),
        (
            "non-whitespace suffix",
            [EICAR.as_slice(), b"x"].concat(),
            false,
        ),
        ("128 bytes", cap.clone(), true),
        ("129 bytes", [cap.as_slice(), b" "].concat(), false),
    ];
    for (label, bytes, hit) in &cases {
        let found = index.first_match_checked(
            bytes,
            &ObjectContext::raw(bytes),
            LogicalObject {
                file_size: bytes.len(),
                parents: &[],
                recursion_level: 0,
                unmapped_script: false,
                script_source: None,
            },
            || Ok(()),
        )?;
        assert_eq!(found, hit.then_some("Eicar-Signature"), "Barnacle {label}");
    }
    for enabled in [true, false] {
        let root = tempfile::tempdir_in("/tmp")?;
        let db = root.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join(PINNED_ARCHIVE.0), &archive)?;
        let flag = if enabled { "yes" } else { "no" };
        let options =
            format!("Bytecode {flag}\nBytecodeUnsigned no\nBytecodeMode ForceInterpreter\n");
        let (_daemon, socket) = start(root.path(), Path::new("/usr/sbin/clamd"), &options)?;
        for (label, bytes, hit) in &cases {
            let reply = unix_request(&socket, &stream_frame(bytes)?)?;
            let expected = if enabled && *hit {
                "stream: Eicar-Signature FOUND\0"
            } else {
                STOCK_MISS
            };
            assert_eq!(reply, expected, "stock Bytecode {flag}: {label}");
        }
    }
    Ok(())
}
