//! Compare Unicode HTML artifacts retained by the pinned clamd with local hash rules.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;
use std::{fs, io, path::Path};

const PAGE: &str = "<html><p>café — κόσμος 東🌍</p><b>Report</b></html>";
const LE_MARKUP: &[u8] =
    b"<html><p>caf\xe9 \x14 \xea\xfc\xf3\xec\xef\xf2 \xe1\xbc\xfd</p><b>report</b></html>";
const LE_TEXT: &[u8] = b" caf\0 \xea\xfc\xfc\xec\xef\xef\xe1\xbc\xbcreport ";
const BE_MARKUP: &[u8] = b"\xfe\xff<html><p>caf\xe9 \x14 \x03\xba\x03\xcc\x03\xc3\x03\xbc\x03\xbf\x03\xc2 gq\xd8<\xdf</p><b>report</b></html>";
const BE_TEXT: &[u8] = b"\xfe\xfe caf\0 \0\0\0\0\0\0gq\0 report ";

fn encode(text: &str, little: bool, bom: bool) -> Vec<u8> {
    let mut result = Vec::new();
    if bom {
        result.extend(if little { [0xff, 0xfe] } else { [0xfe, 0xff] });
    }
    for unit in text.encode_utf16() {
        result.extend(if little {
            unit.to_le_bytes()
        } else {
            unit.to_be_bytes()
        });
    }
    result
}

fn hash(name: &str, bytes: &[u8]) -> io::Result<String> {
    let digest = barnacle::hash_reader(bytes)?.md5_hex();
    Ok(format!("{digest}:{}:Html.{name}\n", bytes.len()))
}

fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let root = temp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let little = encode(PAGE, true, true);
    let bare = encode(PAGE, true, false);
    let big = encode(PAGE, false, true);
    let little_markup = [&[0xdf], LE_MARKUP].concat();
    let little_text = [&[0], LE_TEXT].concat();
    let hashes = |text_only: bool| -> io::Result<String> {
        let mut rules =
            hash("LeText", &little_text)? + &hash("BareText", LE_TEXT)? + &hash("BeText", BE_TEXT)?;
        if !text_only {
            rules += &hash("LeMarkup", &little_markup)?;
            rules += &hash("BareMarkup", LE_MARKUP)?;
            rules += &hash("BeMarkup", BE_MARKUP)?;
        }
        Ok(rules)
    };
    let zipped = zip::zip(&[("report.html", &little)], true, false, false)?;
    let long_page = format!(
        "<html><body>{}</body></html>",
        "<p>Résumé Αθήνα 東京. Café sur l'île. </p>".repeat(2500)
    );
    let large_be = encode(&long_page, false, true);
    let short_limit = format!("MaxHTMLNormalize {}", little.len() / 2 - 1);
    let exact_limit = format!("MaxHTMLNormalize {}", little.len() / 2);
    let big_limit = format!("MaxHTMLNormalize {}", big.len() - 1);
    let one_short = format!(
        "MaxFiles 1\nMaxScanSize {}\nAlertExceedsMax yes",
        large_be.len() + 117520
    );
    let exact = format!(
        "MaxRecursion 1\nMaxScanSize {}\nAlertExceedsMax yes",
        large_be.len() + 117521
    );
    let enough = little.len() + little_markup.len();
    let short_budget = format!("MaxScanSize {}\nAlertExceedsMax yes", enough - 1);
    let exact_budget = format!("MaxScanSize {enough}\nAlertExceedsMax yes");
    let tags_limit = format!("MaxHTMLNoTags {}", little.len() / 2 - 1);
    for (id, config, only_text, cases) in [
        (
            "markup",
            "",
            false,
            vec![
                (&large_be, "LargeMarkup"),
                (&little, "LeMarkup"),
                (&bare, "BareMarkup"),
                (&big, "BeMarkup"),
                (&zipped, "LeMarkup"),
            ],
        ),
        (
            "text",
            "",
            true,
            vec![
                (&little, "LeText"),
                (&bare, "BareText"),
                (&big, "BeText"),
                (&large_be, "LargeText"),
            ],
        ),
        (
            "short",
            &short_limit,
            false,
            vec![(&little, ""), (&bare, "BareMarkup")],
        ),
        (
            "exact",
            &exact_limit,
            false,
            vec![(&little, "LeMarkup"), (&big, "")],
        ),
        ("big", &big_limit, false, vec![(&big, "")]),
        (
            "short-before-files",
            &one_short,
            false,
            vec![(&large_be, "Heuristics.Limits.Exceeded.MaxScanSize")],
        ),
        (
            "exact-before-depth",
            &exact,
            false,
            vec![(&large_be, "Heuristics.Limits.Exceeded.MaxRecursion")],
        ),
        (
            "no-tags",
            &tags_limit,
            true,
            vec![(&little, ""), (&bare, "BareText")],
        ),
        (
            "budget",
            &short_budget,
            false,
            vec![(&little, "Heuristics.Limits.Exceeded.MaxScanSize")],
        ),
        (
            "budget-exact",
            &exact_budget,
            false,
            vec![(&little, "LeMarkup")],
        ),
        ("off", "ScanHTML no", false, vec![(&little, ""), (&big, "")]),
        (
            "files",
            "MaxFiles 2\nAlertExceedsMax yes",
            false,
            vec![(&little, "LeMarkup")],
        ),
        (
            "depth",
            "MaxRecursion 2\nAlertExceedsMax yes",
            false,
            vec![
                (&little, "Heuristics.Limits.Exceeded.MaxRecursion"),
                (&big, "BeMarkup"),
            ],
        ),
    ] {
        let mut rules = hashes(only_text)?;
        rules += "aea455320bee44f8605f78752f757950:85016:Html.LargeText\n";
        if !only_text {
            rules += "63255a85a194df801a7b615507e7a094:117521:Html.LargeMarkup\n";
        }
        fs::write(db.join("pages.hdb"), rules)?;
        let cfg = root.join(format!("{id}.conf"));
        let sock = root.join(format!("{id}.sock"));
        fs::write(
            &cfg,
            format!(
                "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n{config}\n",
                db.display(),
                sock.display()
            ),
        )?;
        let _service = daemon::Daemon::start(exe, &cfg, &sock)?;
        for (data, name) in cases {
            let want = if name.starts_with("Heuristics.") {
                format!("stream: {name} FOUND\0")
            } else if !name.is_empty() {
                format!("stream: Html.{name}.UNOFFICIAL FOUND\0")
            } else if stock {
                "stream: OK\0".into()
            } else {
                "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into()
            };
            assert_eq!(
                daemon::unix_request(&sock, &daemon::stream_frame(data)?)?,
                want,
                "{id} {name}"
            );
        }
    }
    Ok(())
}

#[test]
fn unicode_html_views() -> io::Result<()> {
    use barnacle::objects::{self, Options, Verdict};
    let tmp = tempfile::tempdir()?;
    for (little, mark, kind, markup, text) in [
        (
            true,
            true,
            "CL_TYPE_HTML_UTF16",
            [&[0xdf], LE_MARKUP].concat(),
            [&[0], LE_TEXT].concat(),
        ),
        (
            true,
            false,
            "CL_TYPE_HTML_UTF16",
            LE_MARKUP.to_vec(),
            LE_TEXT.to_vec(),
        ),
        (
            false,
            true,
            "CL_TYPE_HTML",
            BE_MARKUP.to_vec(),
            BE_TEXT.to_vec(),
        ),
    ] {
        let page = encode(PAGE, little, mark);
        let archive = zip::zip(&[("report.html", &page)], true, false, false)?;
        let mut seen = Vec::new();
        objects::scan(
            &archive,
            &Options::default(),
            tmp.path(),
            |obj, _| {
                if let Some(name @ (b"nocomment.html" | b"notags.html")) = obj.layer.name.as_deref()
                {
                    assert_eq!(
                        obj.parents
                            .iter()
                            .map(|layer| layer.file_type)
                            .collect::<Vec<_>>(),
                        ["CL_TYPE_ZIP", kind]
                    );
                    seen.push((name.to_vec(), obj.bytes.to_vec()));
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert_eq!(
            seen,
            [
                (b"nocomment.html".to_vec(), markup),
                (b"notags.html".to_vec(), text)
            ],
            "little={little}, BOM={mark}"
        );
    }
    Ok(())
}

#[test]
fn excluded_html_views_only_count_bytes() -> io::Result<()> {
    use barnacle::objects::{self, Limit, Options, Verdict};
    let root = tempfile::tempdir()?;
    let unavailable = root.path().join("missing");
    let page = format!("<html><p>{}</p></html>", "School report. ".repeat(8_000));
    for (room, limit) in [(page.len(), Limit::MaxFiles), (1, Limit::MaxScanSize)] {
        let options = Options {
            max_files: 1,
            max_scan_size: (page.len() + room) as u64,
            alert_exceeds_max: true,
            ..Options::default()
        };
        let verdict = objects::scan(
            page.as_bytes(),
            &options,
            &unavailable,
            |_, _| Ok(Verdict::Miss),
            || Ok(()),
        )?;
        assert_eq!(verdict, Verdict::Found(limit.signature()));
    }
    Ok(())
}

#[test]
fn unicode_html_winners() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_unicode_html_winners() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"), true)
}
