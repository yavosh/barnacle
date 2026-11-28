//! Compare icon-group logical signatures against pinned stock clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;
#[path = "common/pe.rs"]
mod pe;
#[path = "common/pe_icons.rs"]
mod pe_icons;

use client::{Daemon, stream_frame, unix_request};
use pe_icons::{Drawing, image};
use std::{fs, io, path::Path};

use pe_icons::{DIAMOND, DOCUMENT};

fn compare(executable: &Path, stock: bool) -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let db = temp.path().join("db");
    fs::create_dir(&db)?;
    let sock = temp.path().join("socket");
    let conf = temp.path().join("clamd.conf");
    let run = |idb: &str, rules: &str, options: &str, cases: &[(&[u8], Option<&str>)]| {
        fs::write(db.join("icons.idb"), idb)?;
        fs::write(db.join("icons.ldb"), rules)?;
        fs::write(
            &conf,
            format!(
                "Foreground yes\nSelfCheck 0\nLocalSocket {}\nDatabaseDirectory {}\n{options}",
                sock.display(),
                db.display()
            ),
        )?;
        let _daemon = Daemon::start(executable, &conf, &sock)?;
        for &(bytes, winner) in cases {
            let expected = match winner {
                Some(name) => format!("stream: {name}.UNOFFICIAL FOUND\0"),
                None if stock => "stream: OK\0".into(),
                None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
            };
            assert_eq!(
                unix_request(&sock, &stream_frame(bytes)?)?,
                expected,
                "{rules:?}, {options:?}, {} bytes",
                bytes.len()
            );
        }
        io::Result::Ok(())
    };
    let rule =
        |attrs: &str, body: &str| format!("Local.Icon;Engine:81-255,Target:1,{attrs};0;{body}\n");
    let ordinary = "Local.Ordinary;Target:1;0;4d5a\n";
    let groups = format!("Document:Paper:Office:{DOCUMENT}\nDrawing:Art:Shapes:{DIAMOND}\n");
    let doc = image(&[Drawing::Document], true);
    let diamond = image(&[Drawing::Diamond], true);
    let both = image(&[Drawing::Document, Drawing::Diamond], true);
    let ungrouped = image(&[Drawing::Document], false);
    let plain = pe::benign_pe();
    let extended = image(&[Drawing::ExtendedHeader], true);
    let mixed = image(&[Drawing::Document, Drawing::ExtendedHeader], true);
    let icon = Some("Local.Icon");
    let fallback = Some("Local.Ordinary");
    let uncached = "DisableCache yes\n";

    for attrs in [
        "IconGroup1:Paper",
        "IconGroup2:Office",
        "IconGroup1:Paper,IconGroup2:Office",
    ] {
        run(
            &groups,
            &rule(attrs, "4d5a"),
            uncached,
            &[
                (&doc, icon),
                (&both, icon),
                (&diamond, None),
                (&ungrouped, None),
                (&plain, None),
            ],
        )?;
    }
    // Both groups must be satisfied by one database row, even for identical icon metrics.
    let split = format!("Document:Paper:Other:{DOCUMENT}\nDuplicate:Other:Office:{DOCUMENT}\n");
    run(
        &split,
        &rule("IconGroup1:Paper,IconGroup2:Office", "4d5a"),
        uncached,
        &[(&doc, None)],
    )?;
    run(
        &groups,
        &rule("IconGroup1:Paper,IconGroup2:Shapes", "4d5a"),
        uncached,
        &[(&both, None)],
    )?;

    let first = rule("IconGroup1:Paper", "4d5a");
    run(
        &groups,
        &(first.clone() + ordinary),
        uncached,
        &[(&doc, icon), (&diamond, fallback)],
    )?;
    run(
        &groups,
        &(ordinary.to_owned() + &first),
        uncached,
        &[(&doc, fallback), (&extended, fallback)],
    )?;
    run(&groups, &first, uncached, &[(&mixed, icon)])?;
    run(
        &groups,
        &(rule("IconGroup1:Paper", "deadbeef") + ordinary),
        uncached,
        &[(&doc, fallback)],
    )?;
    run(
        &groups,
        &first,
        "DisableCache yes\nScanPE no\n",
        &[(&doc, icon)],
    )?;

    let second = rule("IconGroup2:Shapes", "4d5a");
    for (limit, expected) in [(0, None), (1, None), (2, icon)] {
        run(
            &groups,
            &second,
            &format!("DisableCache yes\nMaxIconsPE {limit}\n"),
            &[(&both, expected), (&diamond, icon)],
        )?;
    }
    // A cached hint rescans as graphics before checking its icon. Without a map digest,
    // stock checks the hint's icon and then continues to the next eligible rule.
    let child = "Local.Child;Engine:81-255,Target:5,Container:CL_TYPE_MSEXE;0;4d5a\n";
    let hint = rule(
        "HandlerType:CL_TYPE_GRAPHICS,Container:CL_TYPE_ANY,IconGroup2:Shapes",
        "4d5a",
    );
    let chain = hint + child + ordinary;
    run(
        &groups,
        &chain,
        "DisableCache no\n",
        &[(&doc, Some("Local.Child"))],
    )?;
    run(
        &groups,
        &chain,
        uncached,
        &[(&doc, fallback), (&diamond, icon)],
    )?;
    Ok(())
}

#[test]
fn logical_pe_icons() -> io::Result<()> {
    let exe = std::env::var_os("BARNACLE_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_barnacle").into());
    compare(Path::new(&exe), false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_logical_pe_icons() -> io::Result<()> {
    let exe =
        std::env::var_os("BARNACLE_REFERENCE_CLAMD").unwrap_or_else(|| "/usr/sbin/clamd".into());
    compare(Path::new(&exe), true)
}
