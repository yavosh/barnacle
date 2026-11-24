//! Compare independently authored Office package members and normalized stylesheet winners.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;

use std::{fs, io, path::Path};

const PACKAGES: [&[u8]; 4] = [
    include_bytes!("fixtures/ooxml/report.docx"),
    include_bytes!("fixtures/ooxml/report.pptx"),
    include_bytes!("fixtures/ooxml/report.xlsx"),
    include_bytes!("fixtures/ooxml/report.odt"),
];
const OUTER: [&str; 4] = ["WordOuter", "SlideOuter", "SheetOuter", "OdtOuter"];
const PART: [&str; 4] = ["WordXml", "SlideXml", "SheetXml", "OdtContent"];
const PART_RULES: &str = "6f8e0cdd2d9acee8886fe702cf9d6a81:2666:Office.WordXml\n\
7a96fd2466d74ee0c38efce77a99865e:1698:Office.SlideXml\n\
1c614885aaa8b0a9b2d1e53a8b3a7faf:599:Office.SheetXml\n\
db535591f0cb46f6d35d5ad7e514a19a:2968:Office.OdtContent\n";
const IMAGE: &str = "b8bde3e503a52c3239ab107b1ff268b6:4556:Office.Image\n";
// Stock clamd's normalized xl/styles.xml. The original XML contains 867 bytes.
const STYLE: &str = "0a40ed6b0ea24f8929625d19592243fa:879:Office.Styles\n";

fn compare(exe: &Path) -> io::Result<()> {
    let mut outer_rules = String::new();
    for (package, name) in PACKAGES.into_iter().zip(OUTER) {
        let digest = barnacle::hash_reader(package)?.md5_hex();
        outer_rules.push_str(&format!("{digest}:{}:Office.{name}\n", package.len()));
    }
    for (label, rules, options, winners) in [
        ("outer", vec![], "", OUTER),
        ("image before outer", vec![IMAGE], "", ["Image"; 4]),
        ("XML before image", vec![IMAGE, PART_RULES], "", PART),
        (
            "styles before sheet",
            vec![IMAGE, PART_RULES, STYLE],
            "",
            ["WordXml", "SlideXml", "Styles", "OdtContent"],
        ),
        (
            "HTML disabled",
            vec![IMAGE, PART_RULES, STYLE],
            "ScanHTML no",
            PART,
        ),
        (
            "archives disabled",
            vec![IMAGE, PART_RULES, STYLE],
            "ScanArchive no",
            OUTER,
        ),
    ] {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join("local.hdb"), outer_rules.clone() + &rules.concat())?;
        let cfg = dir.path().join("clamd.conf");
        let sock = dir.path().join("clamd.sock");
        fs::write(
            &cfg,
            format!(
                "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n{options}\n",
                db.display(),
                sock.display()
            ),
        )?;
        let _service = daemon::Daemon::start(exe, &cfg, &sock)?;
        for ((package, kind), winner) in PACKAGES.into_iter().zip(OUTER).zip(winners) {
            assert_eq!(
                daemon::unix_request(&sock, &daemon::stream_frame(package)?)?,
                format!("stream: Office.{winner}.UNOFFICIAL FOUND\0"),
                "{label}, {kind}",
            );
        }
    }
    Ok(())
}

#[test]
fn authored_office_packages() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_authored_office_packages() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"))
}
