//! Exact hashes of both HTML views, observed with Debian clamd 1.4.3.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;
use std::{fs, io, path::Path};

struct Case {
    id: String,
    page: String,
    markup: String,
    text: String,
}

fn digest(bytes: &[u8]) -> io::Result<String> {
    Ok(format!(
        "{}:{}",
        barnacle::hash_reader(bytes)?.md5_hex(),
        bytes.len()
    ))
}

fn cases() -> io::Result<Vec<Case>> {
    let mut cases = Vec::new();
    for (id, page, markup, text) in [
        (
            "multiline-image-url",
            "<html><img src='Desk\nMap'/><a href='/West\tGate' />Office</html>",
            b"<html><img src=\"desk map\"/><a href=\"/west\tgate\" />office</html>".as_slice(),
            b" Desk Map\" /West Gate office ".as_slice(),
        ),
        (
            "quoted-data-delimiter",
            "<html><img alt='data:text/plain,Notice' src='Map'/><img src='Data:text/plain,Office' />Monthly</html>",
            br#"<html><img alt="data"src="map" /><img src="data:text/plain,office" />monthly</html>"#.as_slice(),
            b" Data:text/plain,Office monthly ".as_slice(),
        ),
        (
            "unquoted-data-delimiter",
            "<html><img src=data:text/plain,Desk/><a href='/Map'>Route</a><img src=data:text/plain,Hall />West</html>",
            b"<html><img src=data<a href=\"/map\">route</a><img src=data/>west</html>".as_slice(),
            b" route west ".as_slice(),
        ),
        (
            "tab-and-line-break",
            "<html><img alt='Red\tBlue\nGreen'/><a href='/Red\tBlue\nGreen'>Report</a></html>",
            b"<html><img alt=\"red\tblue green'/><a href=\"/red\tblue green'>report</a></html>".as_slice(),
            b" /Red Blu report ".as_slice(),
        ),
        (
            "carriage-return",
            "<html><img alt='North\rRoad\tEast'/><a href='/North\rRoad\tEast'>Report</a></html>",
            b"<html><img alt=\"northroad\teast\"/><a href=\"/northroad\teast\">report</a></html>".as_slice(),
            b" /NorthRoad East report ".as_slice(),
        ),
        (
            "multiline-title",
            "<html><img alt='Paris\r\n  Lyon'/><a href='/Paris\r\n  Lyon'>Report</a></html>",
            b"<html><img alt=\"paris lyon\"/><a href=\"/paris lyon\">report</a></html>".as_slice(),
            b" /Paris Lyon report ".as_slice(),
        ),
        (
            "inline-text",
            "<html><img alt='data:text/plain,Inventory'/><a href='/data:text/plain,Inventory'>Report</a></html>",
            br#"<html><img alt="data"/><a href="/data:text/plain,inventory">report</a></html>"#.as_slice(),
            b" /data:text/plain,Inventory report ".as_slice(),
        ),
        (
            "tag-endings",
            "<?sheet value?><?sheet value ?><?sheet val=a?><?sheet val='a'?><?sheet flag other?><table><input disabled/><input disabled /><input disabled='x'/><item name=value/><item name=value /><br/><br />Inventory</table>",
            br#"<?sheet value?><?sheet value ?><?sheet val=a?><?sheet val="a" ?><?sheet flag other?><table><input disabled/><input disabled /><input disabled="x" /><item name=value/><item name=value /><br/><br />inventory</table>"#.as_slice(),
            b" inventory ".as_slice(),
        ),
        (
            "spaced-attribute-endings",
            r#"<html><img alt='Two words'/><img alt='Deux mots ici'/><img alt="Deux mots ici" /><img alt='A&#32;B'/><?paper alt='Print this'?><?paper alt='Print this' ?>Report</html>"#,
            br#"<html><img alt="two words"/><img alt="deux mots ici'/><img alt="deux mots ici" /><img alt="a b" /><?paper alt="print this"?><?paper alt="print this" ?>report</html>"#.as_slice(),
            b" report ".as_slice(),
        ),
        (
            "office-paths",
            r#"<?xml version="1.0"?><table><row path='xl/workbook.xml' format='Word.Document' alt='HWPML report'/>Documents</table>"#,
            br#"<?xml version="1.0" ?><table><row path="xl/workbook.xml" format="word.document" alt="hwpml report"/>documents</table>"#.as_slice(),
            b" documents ".as_slice(),
        ),
        (
            "press",
            "<html><p>Research & Development & Publications.</p></html>",
            b"<html><p>research & development & publications.</p></html>".as_slice(),
            b" research development publications. ".as_slice(),
        ),
        (
            "names",
            "<html><p>Résumé &amp; Caf&eacute; &copy; 2026</p></html>",
            b"<html><p>r\xc3\xa9sum\xc3\xa9 & caf\xe9 \xa9 2026</p></html>",
            b" r\xc3\xc3sum\xc3\xc3 caf 2026 ",
        ),
        (
            "map",
            "<html><a href=\"/map?lat=1&lon=2\">Find room A&B</a></html>",
            b"<html><a href=\"/map?lat=1&lon=2\">find room a&b</a></html>",
            b" /map?lat=1&lon=2 find room a ",
        ),
        (
            "companies",
            "<html><p>AT&T and R&D. Stars &amp; Planets. One &amp two.</p></html>",
            b"<html><p>at&t and r&d. stars & planets. one &amp two.</p></html>",
            b" at and r . stars planets. one two. ",
        ),
        (
            "tools",
            "<html><p>5 &lt; 8 and 7 &gt; 3. Tool A&B; sales.</p></html>",
            b"<html><p>5 < 8 and 7 > 3. tool a&b; sales.</p></html>",
            b" 5 8 and 7 3. tool a sales. ",
        ),
        (
            "music",
            "<html><p>Dots &hellip; Euro &euro; Music &#9834; and Paris &#233;.</p></html>",
            b"<html><p>dots &#x2026; euro &#x20ac; music &#x266a; and paris \xe9.</p></html>",
            b" dots euro music and paris . ",
        ),
        (
            "query",
            "<html><a title='Arts &amp; Crafts' href='/A?First=Paris&Region_ID=North&amp;Owner=Us#Map'>Visitor Info</a></html>",
            b"<html><a title=\"arts & crafts' href=\"/a?first=paris&region_id=north&owner=us#map\">visitor info</a></html>",
            b" /A?First=Paris&region_id=North&Owner=Us#Map visitor info ",
        ),
        (
            "picture",
            "<html><img src=/Photo?Title=&eacute;&Fee=&euro;&Note=&#9834;><p>Gallery &COPY; 2026</p></html>",
            b"<html><img src=/photo?title=\xe9&fee=&#x20ac;&note=&#x266a;><p>gallery &copy; 2026</p></html>",
            b" /Photo?Title=\xe9&fee=&#x20ac;&note=j gallery 2026 ",
        ),
        (
            "absent",
            "<html><p>Upper &AMP; units &angst; &ohm; &epsi; &epsiv; &phiv; &lang;3&rang;. Empty &; and &NotEqualTilde;.</p></html>",
            b"<html><p>upper &amp; units &#x212b; &#x2126; &#x03f5; &#x03b5; &#x03c6; &#x2329;3&#x232a;. empty &; and &notequaltilde;.</p></html>",
            b" upper units 3 . empty and . ",
        ),
        (
            "department",
            "<html><a href=\"/Dept/First Second   Third&amp;Four\">News &amp; Events</a></html>",
            b"<html><a href=\"/dept/first second third&amp;four\">news & events</a></html>",
            b" /Dept/First Secon news events ",
        ),
        (
            "station",
            "<html><img src='/city?near=東京　駅' alt='Arts &amp; Crafts'><p>New gallery</p></html>",
            "<html><img src=\"/city?near=東京　\" alt=\"駅arts & crafts'><p>new gallery</p></html>".as_bytes(),
            " /city?near=東京　 new gallery ".as_bytes(),
        ),
        (
            "edition",
            "<html><p><p title=\"Part 1 &amp; Résumé\">Paris</p></p></html>",
            "<html><p><p title=\"part 1 &amp; résumé\">paris</p></p></html>".as_bytes(),
            b" paris ",
        ),
        (
            "later",
            "<html><a href=\"é\">R</a><img src=\"PHOTO\"></html>",
            "<html><a href=\"\">r</a><img src=\"éphoto\"></html>".as_bytes(),
            " r éPHOTO ".as_bytes(),
        ),
        (
            "international",
            "<html><a href=\"/résumé?x=é&B=é.\">Room</a></html>",
            "<html><a href=\"/résumé?x=&bé=é.\">room</a></html>".as_bytes(),
            " /résumé?x=&bé=é. room ".as_bytes(),
        ),
        (
            "tokyo",
            "<html><a href=\"/Résumé?Tokyo=東京\">Room</a></html>",
            "<html><a href=\"/résumé?tokyo=東\">room</a></html>".as_bytes(),
            " /Résumé?Tokyo=東 room ".as_bytes(),
        ),
        (
            "capture",
            "<html><a href='A&b=2 Test ABC'>Registration</a></html>",
            b"<html><a href=\"a&b=2 test abc'>registration</a></html>",
            b" A&b=2 Tes registration ",
        ),
    ] {
        cases.push(Case {
            id: id.into(),
            page: page.into(),
            markup: digest(markup)?,
            text: digest(text)?,
        });
    }

    // Pin both complete artifacts independently of the values in the runtime table.
    let mut directory = String::from("<html><p>Directory:");
    for (i, row) in include_str!("../src/objects/text/html/entities.txt")
        .lines()
        .enumerate()
    {
        directory.push_str(&format!(
            "[{i}]&{};",
            row.split_ascii_whitespace().next().unwrap()
        ));
    }
    directory.push_str("</p></html>");
    cases.push(Case {
        id: "directory".into(),
        page: directory,
        markup: "7d530a7201abfd0b875258b7d2b4afe8:7637".into(),
        text: "8416fec5b806d1c62c332691d1b5bf4a:3873".into(),
    });
    for n in [1021, 1022, 1023, 1024, 1025] {
        let letters = "U".repeat(n);
        let page = format!("<html><a href=\"{letters}&Z=Paris\">Room {n}</a></html>");
        let markup = page.to_ascii_lowercase();
        let url = format!("{letters}&z=Paris");
        let text = format!(" {} room {n} ", &url[..1022]);
        cases.push(Case {
            id: format!("url{n}"),
            page,
            markup: digest(markup.as_bytes())?,
            text: digest(text.as_bytes())?,
        });
        let page = format!("<html><p>A&{letters}BC; end {n}</p></html>");
        let markup = page.to_ascii_lowercase();
        let token = format!("{letters}BC");
        let retained = if token.len() <= 1024 {
            String::new()
        } else {
            format!("{}; ", token[1024..].to_ascii_lowercase())
        };
        let text = format!(" a {retained}end {n} ");
        cases.push(Case {
            id: format!("token{n}"),
            page,
            markup: digest(markup.as_bytes())?,
            text: digest(text.as_bytes())?,
        });
    }
    for len in [8191, 8192, 8193] {
        let value = format!("/{}\nGate", "R".repeat(len - 6));
        let page = format!("<html><a href=\"{value}\">Ticket {len}</a></html>");
        let markup = page.to_ascii_lowercase().replace('\n', " ");
        let text = format!(" {} ticket {len} ", &value[..1022]);
        cases.push(Case {
            id: format!("route{len}"),
            page,
            markup: digest(markup.as_bytes())?,
            text: digest(text.as_bytes())?,
        });
    }
    let split = "\r".repeat(19_000);
    for (id, reference, markup, text) in [
        (
            "splitNamed",
            format!("&am{split}p;"),
            "a4a409f48dbc4a5f275e0de1369a7485:61",
            "25cad57f9ff192dda55e37889079a3b5:21",
        ),
        (
            "splitNumeric",
            format!("&#x3{split}bb;"),
            "ac69038ba2a628b7069c151396806164:68",
            "32db0989391cab2e0c66ab50e8e5dba6:21",
        ),
    ] {
        cases.push(Case {
            id: id.into(),
            page: format!(
                "<html><a href=\"Account {reference}Due\" title='Office'>Review</a></html>"
            ),
            markup: markup.into(),
            text: text.into(),
        });
    }
    // This placement drops one space at the start of a reference input block.
    let path_list = "list-a list-b\r\n data-section ".repeat(1000);
    cases.push(Case {
        id: "blockSpace".into(),
        page: format!("<html><a href=\"{path_list}\" title='Office'>Review</a></html>"),
        markup: "68977dfa4b8a228fa0c9b5f962a4e49b:27048".into(),
        text: "318a09841e6c1e33b122bff4dc00f721:21".into(),
    });
    // Pinned stock hashes for a multiline ledger style list and its visible label.
    let classes = "section-Accounts\r\n  item-current\titem-review &amp; status-Due ".repeat(800);
    cases.push(Case {
        id: "ledger".into(),
        page: format!(
            "<html><table class=\"{classes}\" id='Ledger'><tr><td>Ledger</td></tr></table></html>"
        ),
        markup: "2f7b99ed342313b014dc1dcba1a6b345:47273".into(),
        text: "0c44d736017dd92c086648dae6a58ae5:8".into(),
    });
    Ok(cases)
}

fn compare(exe: &Path) -> io::Result<()> {
    let root = tempfile::tempdir_in("/tmp")?;
    let db = root.path().join("db");
    fs::create_dir(&db)?;
    let cases = cases()?;
    let ledger = cases.iter().find(|case| case.id == "ledger").unwrap();
    let archive = zip::zip(
        &[("ledger.html", ledger.page.as_bytes())],
        true,
        false,
        false,
    )?;
    for markup in [true, false] {
        let mut rules = format!(
            "{}:Page.Zip\n{}:Page.Original\n",
            digest(&archive)?,
            digest(ledger.page.as_bytes())?
        );
        for case in &cases {
            rules.push_str(&format!("{}:Page.{}.Text\n", case.text, case.id));
            if markup {
                rules.push_str(&format!("{}:Page.{}.Markup\n", case.markup, case.id));
            }
        }
        fs::write(db.join("pages.hdb"), rules)?;
        let config = root.path().join("config");
        let socket = root.path().join("sock");
        fs::write(
            &config,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\n",
                db.display(),
                socket.display()
            ),
        )?;
        let _service = daemon::Daemon::start(exe, &config, &socket)?;
        for case in &cases {
            let response =
                daemon::unix_request(&socket, &daemon::stream_frame(case.page.as_bytes())?)?;
            let kind = if markup { "Markup" } else { "Text" };
            assert_eq!(
                response,
                format!("stream: Page.{}.{kind}.UNOFFICIAL FOUND\0", case.id),
                "{}",
                case.page
            );
        }
        let response = daemon::unix_request(&socket, &daemon::stream_frame(&archive)?)?;
        let kind = if markup { "Markup" } else { "Text" };
        assert_eq!(
            response,
            format!("stream: Page.ledger.{kind}.UNOFFICIAL FOUND\0")
        );
    }
    Ok(())
}

#[test]
fn html_entities() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_html_entities() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"))
}

#[test]
fn large_inline_attribute_checks_cancel_before_submitting_views() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let page = format!(
        "<html><img src='data:text/plain,{}'/></html>",
        "A".repeat(512 * 1024)
    );
    let long_title = format!(
        "<html><img title='{}'/></html>",
        "Monthly\r\n  notice ".repeat(32 * 1024)
    );
    let dir = tempfile::tempdir()?;
    for page in [&page, &long_title] {
        let mut checks = 0;
        let mut seen = false;
        let result = scan(
            page.as_bytes(),
            &Options::default(),
            dir.path(),
            |_, _| {
                seen = true;
                Ok(Verdict::Miss)
            },
            || {
                checks += 1;
                if checks == 24 {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert!(!seen);
    }
    Ok(())
}

#[test]
fn excluded_long_attribute_does_not_create_scratch_files() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let page = format!(
        "<html><p class='{}'>Office</p></html>",
        "list-a list-b\r\n data-section ".repeat(5000)
    );
    let dir = tempfile::tempdir()?;
    let absent = dir.path().join("absent");
    let options = Options {
        max_files: 1,
        alert_exceeds_max: true,
        ..Options::default()
    };
    let verdict = scan(
        page.as_bytes(),
        &options,
        &absent,
        |_, _| Ok(Verdict::Miss),
        || Ok(()),
    )?;
    assert_eq!(
        verdict,
        Verdict::Found("Heuristics.Limits.Exceeded.MaxFiles".into())
    );
    Ok(())
}
