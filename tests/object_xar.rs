//! Compare benign XAR heap members, XML and limits against the pinned daemon.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;
use daemon::{Daemon, stream_frame, unix_request};
use flate2::{Compression, write::ZlibEncoder};
use md5::{Digest, Md5};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const FIRST: &[u8] = b"an ordinary guide stored in the XAR heap";
const SECOND: &[u8] = b"ordinary notes in the second XAR member";
fn deflate(d: &[u8]) -> io::Result<Vec<u8>> {
    let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
    z.write_all(d)?;
    z.finish()
}
fn build(toc: &str, heap: &[u8]) -> io::Result<Vec<u8>> {
    let z = deflate(toc.as_bytes())?;
    let mut out = b"xar!\0\x1c\0\x01".to_vec();
    out.extend((z.len() as u64).to_be_bytes());
    out.extend((toc.len() as u64).to_be_bytes());
    out.extend([0; 4]);
    out.extend(z);
    out.extend(heap);
    Ok(out)
}
fn extent(tag: &str, offset: usize, len: usize, size: usize, codec: &str) -> String {
    format!(
        "<{tag}><length>{len}</length><offset>{offset}</offset><size>{size}</size><encoding style=\"{codec}\"/></{tag}>"
    )
}
fn toc(subdocs: &str, properties: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xar>\n{subdocs}\n<toc><file id=\"1\"><name>notes.txt</name><type>file</type>{properties}</file></toc>\n</xar>\n"
    )
}
fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let root = tmp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let plain = "application/octet-stream";
    let zlib = "application/x-gzip";
    let note = extent("data", 0, FIRST.len(), FIRST.len(), plain);
    let compressed = deflate(SECOND)?;
    let z = extent("data", 0, compressed.len(), SECOND.len(), zlib);
    let short_heap = [FIRST, SECOND].concat();
    let later = extent("data", FIRST.len(), SECOND.len(), SECOND.len(), plain);
    let ea = extent("ea", 0, FIRST.len(), FIRST.len(), plain);
    let doc = "<meta>ordinary subdocument</meta>";
    let packed_toc = toc("", &z);
    let packed = build(&packed_toc, &compressed)?;
    let hash_toc = toc("", &format!("<note>whole table marker</note>{note}"));
    let hash_outer = build(
        &toc("", &format!("<note>whole XAR marker</note>{note}")),
        FIRST,
    )?;
    let mut bz = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    bz.write_all(SECOND)?;
    let bz = bz.finish()?;
    let sub = toc(
        &format!("<subdoc subdoc_name=\"extra\">{doc}</subdoc>"),
        &note,
    );
    let options = lzma_rust2::LzmaOptions {
        dict_size: 8192,
        ..Default::default()
    };
    let mut lz =
        lzma_rust2::LzmaWriter::new_use_header(Vec::new(), &options, Some(SECOND.len() as u64))?;
    lz.write_all(SECOND)?;
    let lz = lz.finish()?;
    let mut xz = lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1))?;
    xz.write_all(SECOND)?;
    let xz = xz.finish()?;
    let canonical = "<metadata id=\"x\"><empty/></metadata>";
    let mut rules = String::new();
    for (name, data) in [
        ("First", FIRST),
        ("Second", SECOND),
        ("Toc", hash_toc.as_bytes()),
        ("Outer", &hash_outer),
        ("Subdoc", doc.as_bytes()),
        ("BzipWrapper", &bz),
        ("Canonical", canonical.as_bytes()),
    ] {
        let digest: String = Md5::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        rules.push_str(&format!("{digest}:{}:Xar.{name}\n", data.len()));
    }
    fs::write(db.join("local.hdb"), rules)?;
    let start = |id: &str, opts: &str| -> io::Result<_> {
        let conf = root.join(format!("{id}.conf"));
        let socket = root.join(format!("{id}.sock"));
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nTemporaryDirectory {}\nLocalSocket {}\n{opts}\n",
                db.display(),
                root.display(),
                socket.display()
            ),
        )?;
        Ok((Daemon::start(exe, &conf, &socket)?, socket))
    };
    let check = |socket: &Path, label: &str, bytes: &[u8], name: Option<&str>| -> io::Result<()> {
        let expected = match name {
            Some(s) if s.starts_with("Heuristics.") => format!("stream: {s} FOUND\0"),
            Some(s) => format!("stream: Xar.{s}.UNOFFICIAL FOUND\0"),
            None if stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        let actual = unix_request(socket, &stream_frame(bytes)?)?;
        assert_eq!(actual, expected, "{label}");
        Ok(())
    };
    let (daemon, sock) = start("default", "")?;
    let checked = note.replace("</data>","<archived-checksum style=\"md5\">00000000000000000000000000000000</archived-checksum></data>");
    let separated = toc("<subdoc>harmless notes</subdoc>", &note);
    let canonical_subdoc = toc(
        "<subdoc><metadata id='x'><empty></empty></metadata></subdoc>",
        &note,
    );
    let bad_member = [b"ordinary invalid compressed data".as_slice(), FIRST].concat();
    let bad_len = bad_member.len() - FIRST.len();
    let mixed = toc(
        "",
        &format!(
            "{}{}",
            extent("data", 0, bad_len, 48, zlib),
            extent("data", bad_len, FIRST.len(), FIRST.len(), plain)
        ),
    );
    let mut long_toc = toc("", &note);
    long_toc = long_toc.replace(
        "<file id",
        &format!("<!--{}--><file id", "ordinary text ".repeat(100)),
    );
    let over_catalog = build(&long_toc, FIRST)?;
    let larger = b"ordinary long document section ".repeat(200);
    let zlarge = deflate(&larger)?;
    let over_member = build(
        &toc("", &extent("data", 0, zlarge.len(), larger.len(), zlib)),
        &zlarge,
    )?;
    let valid_toc = toc(
        "",
        &format!(
            "<checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum>{}",
            extent("data", 20, FIRST.len(), FIRST.len(), plain)
        ),
    );
    let mut valid = build(&valid_toc, &[])?;
    valid[24..28].copy_from_slice(&1u32.to_be_bytes());
    let sum = sha1::Sha1::digest(&valid[28..]);
    valid.extend_from_slice(&sum);
    valid.extend_from_slice(FIRST);
    let nested_zip = zip::zip(&[("plain.xar", &packed)], true, false, false)?;
    let heap = |bytes: &[u8], size, codec| {
        build(
            &toc("", &extent("data", 0, bytes.len(), size, codec)),
            bytes,
        )
    };
    let cases = [
        ("checksummed archive", valid, Some("First")),
        (
            "damaged member before good extent",
            build(&mixed, &bad_member)?,
            Some("First"),
        ),
        ("stored", build(&toc("", &note), FIRST)?, Some("First")),
        ("deflated", packed.clone(), Some("Second")),
        ("whole table wins", build(&hash_toc, FIRST)?, Some("Toc")),
        ("child beats outer", hash_outer.clone(), Some("First")),
        ("subdoc first", build(&sub, FIRST)?, Some("Subdoc")),
        (
            "subdoc serialization",
            build(&canonical_subdoc, FIRST)?,
            Some("Canonical"),
        ),
        (
            "subdoc preceding heap",
            build(&separated, FIRST)?,
            Some("First"),
        ),
        (
            "adjacent subdoc and toc",
            build(
                &separated.replace("</subdoc>\n<toc>", "</subdoc><toc>"),
                FIRST,
            )?,
            None,
        ),
        (
            "EA before data",
            build(&toc("", &format!("{ea}{later}")), &short_heap)?,
            Some("First"),
        ),
        (
            "table order vs offset",
            build(&toc("", &format!("{later}{note}")), &short_heap)?,
            Some("Second"),
        ),
        (
            "wrong checksum",
            build(&toc("", &checked), FIRST)?,
            Some("First"),
        ),
        (
            "bzip wrapper",
            heap(&bz, SECOND.len(), "application/x-bzip2")?,
            Some("Second"),
        ),
        (
            "XZ wrapper",
            heap(&xz, SECOND.len(), "application/x-xz")?,
            Some("Second"),
        ),
        (
            "LZMA direct decode",
            heap(&lz, SECOND.len(), "application/x-lzma")?,
            Some("Second"),
        ),
        (
            "unknown encoding",
            heap(FIRST, FIRST.len(), "text/plain")?,
            Some("First"),
        ),
        (
            "truncated heap",
            build(
                &toc(
                    "",
                    &extent("data", FIRST.len(), SECOND.len() + 20, SECOND.len(), plain),
                ),
                &short_heap,
            )?,
            Some("Second"),
        ),
        ("ZIP containing XAR", nested_zip, Some("Second")),
        ("short header", b"xar!ordinary".to_vec(), None),
        ("truncated TOC", packed[..40].to_vec(), None),
        (
            "truncated XML",
            build(&packed_toc[..packed_toc.len() - 12], &compressed)?,
            Some("Second"),
        ),
    ];
    for (label, file, expected) in cases {
        check(&sock, label, &file, expected)?;
    }
    drop(daemon);
    for (id, config, bytes, name) in [
        (
            "disabled",
            "ScanArchive no".to_string(),
            &hash_outer,
            Some("Outer"),
        ),
        (
            "depth",
            "MaxRecursion 1\nAlertExceedsMax yes".into(),
            &packed,
            Some("Heuristics.Limits.Exceeded.MaxRecursion"),
        ),
        (
            "count",
            "MaxFiles 2\nAlertExceedsMax yes".into(),
            &packed,
            Some("Heuristics.Limits.Exceeded.MaxFiles"),
        ),
        (
            "byte",
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                packed.len() + packed_toc.len() + 7
            ),
            &packed,
            Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        ),
        (
            "catalog-size",
            "MaxFileSize 512\nAlertExceedsMax yes".into(),
            &over_catalog,
            Some("Heuristics.Limits.Exceeded.MaxFileSize"),
        ),
        (
            "catalog-no-alert",
            "MaxFileSize 512\nAlertExceedsMax no".into(),
            &over_catalog,
            None,
        ),
        (
            "expanded-size",
            "MaxFileSize 512\nAlertExceedsMax yes".into(),
            &over_member,
            Some("Heuristics.Limits.Exceeded.MaxFileSize"),
        ),
    ] {
        let (_service, sock) = start(id, &config)?;
        check(&sock, id, bytes, name)?;
    }
    Ok(())
}
#[test]
fn barnacle_xar_objects() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}
#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn stock_xar_objects() -> io::Result<()> {
    let pkg = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pkg.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}

#[test]
fn catalog_and_extent_receive_fresh_unnamed_contexts() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    let catalog = toc(
        "",
        &extent(
            "data",
            0,
            FIRST.len(),
            FIRST.len(),
            "application/octet-stream",
        ),
    );
    let xar = build(&catalog, FIRST)?;
    let archive = zip::zip(&[("ordinary.xar", &xar)], true, false, false)?;
    let mut objects = Vec::new();
    scan(
        &archive,
        &Options::default(),
        tmp.path(),
        |object, _| {
            if !object.normalized && (object.bytes == catalog.as_bytes() || object.bytes == FIRST) {
                assert_eq!(
                    object
                        .parents
                        .iter()
                        .map(|e| e.file_type)
                        .collect::<Vec<_>>(),
                    ["CL_TYPE_ZIP", "CL_TYPE_XAR"]
                );
                assert_eq!(
                    object.parents[1].name.as_deref(),
                    Some(b"ordinary.xar".as_slice())
                );
                assert!(object.layer.name.is_none());
                objects.push(object.bytes == FIRST);
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(objects, [false, true]);
    Ok(())
}

fn namespace_cases(stock: bool) -> io::Result<()> {
    let archive = include_bytes!("fixtures/xar/inventory.xar");
    let descriptions = include_bytes!("fixtures/xar/descriptions.xar");
    let described = "\n  <inv:catalog xmlns:inv=\"urn:warehouse:inventory\">\n   <inv:part inv:aisle=\"A&#9;7\" description=\"Folders &amp; clips, 6 &gt; 4, &quot;blue&quot; Café\" id=\"R-17\"/>\n  </inv:catalog>\n ";
    let receipt = b"Ordinary inventory receipt for 42 paper folders.\n";
    let rendered = b"\n  <inv:catalog xmlns:u=\"urn:warehouse:units\" xmlns:inv=\"urn:warehouse:inventory\">\n   <inv:part id=\"P-042\" u:unit=\"box\">Paper folders</inv:part>\n  </inv:catalog>\n ";
    let mut cases = Vec::new();
    let mut interrupted = Vec::new();
    let member = extent(
        "data",
        0,
        receipt.len(),
        receipt.len(),
        "application/octet-stream",
    );
    let escaped = "<Item note='A &amp; B'>";
    let canonical = "<Item note=\"A &amp; B\">";
    for (source, output) in [
        ("Café 📦", "Café 📦"),
        ("<Café étiquette='a'/>", "<Café étiquette=\"a\"/>"),
        (
            "<m:Pièce xmlns:m='urn:café'/>",
            "<m:Pièce xmlns:m=\"urn:café\"/>",
        ),
        ("<![CDATA[Café 📦]]>", "<![CDATA[Café 📦]]>"),
        ("<!--Café 📦-->", "<!--Café 📦-->"),
        ("<?réserve Café 📦?>", "<?réserve Café 📦?>"),
        (
            "Caf&#233; &#x1F4E6; &lt; &#62; &amp; &apos; &quot; &#9;&#10;&#13;",
            "Café 📦 &lt; &gt; &amp; ' \" \t\n&#13;",
        ),
    ] {
        let doc = format!("<subdoc>{escaped}{source}</Item></subdoc>");
        let xml = toc(&doc, &member);
        let rendered = format!("{canonical}{output}</Item>");
        for declared in ["", " encoding=\"UTF-8\"", " encoding=\"US-ASCII\""] {
            let catalog = xml.replace(" encoding=\"UTF-8\"", declared);
            let archive = build(&catalog, receipt)?;
            if declared.contains("US-ASCII") && !source.is_ascii() {
                interrupted.push((archive, "Archive", "Archive"));
            } else {
                cases.push((archive, rendered.clone()));
            }
        }
    }
    let encoded_count = cases.len();
    let office = format!("{escaped}Office</Item>");
    let complete = format!("<subdoc>{office}</subdoc>");
    let prefix = format!("{canonical}Office</Item>");
    for (source, sub_winner, heap_winner) in [
        (
            format!("<subdoc>{office}<!--Café--></subdoc>"),
            "Archive",
            "Archive",
        ),
        (format!("{complete}\n<!--Café-->"), "Subdocument", "Archive"),
        (complete.clone(), "Subdocument", "Receipt"),
    ] {
        let mut catalog = toc(&source, &member).replace("UTF-8", "US-ASCII");
        if source == complete {
            catalog = catalog.replace("</toc>", "</toc><!--Café-->");
        }
        interrupted.push((build(&catalog, receipt)?, sub_winner, heap_winner));
    }
    for (root, sub, markup, expected) in [
        (
            " xmlns:inv='urn:inventory' xmlns:u='urn:unit'",
            "",
            "<Quantity inv:note='A &amp; B'><inv:Box label='&quot;A > B&quot;'/></Quantity>",
            "<Quantity xmlns:inv=\"urn:inventory\" inv:note=\"A &amp; B\"><inv:Box label=\"&quot;A &gt; B&quot;\"/></Quantity>",
        ),
        (
            "",
            "",
            "<Item note='Paper &amp; clips &lt;five&gt; &quot;blue&quot; &apos;two&apos; and \"two\" > three'/>",
            "<Item note=\"Paper &amp; clips &lt;five&gt; &quot;blue&quot; 'two' and &quot;two&quot; &gt; three\"/>",
        ),
        (
            "",
            "",
            "<Item note='  Warehouse\tlabels\r\nlocated\rhere\n  next shelf  '/>",
            "<Item note=\"  Warehouse labels located here   next shelf  \"/>",
        ),
        (
            "",
            "",
            "<Item note='Tabs&#9;/&#x9; returns&#13;/&#xD; lines&#10;/&#xA; space&#32;/&#x20;'/>",
            "<Item note=\"Tabs&#9;/&#9; returns&#13;/&#13; lines&#10;/&#10; space / \"/>",
        ),
        (
            "",
            "",
            "<Item note='&#38;&#x26;&#60;&#x3e;&#34;&#39;&#xE9;&#x1F4E6; café'/>",
            "<Item note=\"&amp;&amp;&lt;&gt;&quot;'&#xE9;&#x1F4E6; caf&#xE9;\"/>",
        ),
        (
            "",
            "",
            "<u:Part xmlns:u='urn:unit'/>",
            "<u:Part xmlns:u=\"urn:unit\"/>",
        ),
        (
            " xmlns:u='urn:unit'",
            "",
            "<Box><Count u:qty='2'/></Box>",
            "<Box xmlns:u=\"urn:unit\"><Count u:qty=\"2\"/></Box>",
        ),
        (
            "",
            " xmlns:u='urn:one'",
            "<Item u:qty='2'/> <u:Box/>",
            "<Item xmlns:u=\"urn:one\" u:qty=\"2\"/> <u:Box xmlns:u=\"urn:one\"/>",
        ),
        (
            " xmlns:u='urn:unused'",
            "",
            "<Item serial='12'/>",
            "<Item serial=\"12\"/>",
        ),
        (
            "",
            "",
            "<Item serial='12' xmlns:u='urn:u' u:qty='2' xmlns:c='urn:c' c:key='box'/>",
            "<Item xmlns:u=\"urn:u\" xmlns:c=\"urn:c\" serial=\"12\" u:qty=\"2\" c:key=\"box\"/>",
        ),
        (
            " xmlns:e='urn:e' xmlns:f='urn:f'",
            "",
            "<e:Item first='1' xmlns:u='urn:u' f:measure='2'><u:Note/></e:Item>",
            "<e:Item xmlns:u=\"urn:u\" xmlns:e=\"urn:e\" xmlns:f=\"urn:f\" first=\"1\" f:measure=\"2\"><u:Note/></e:Item>",
        ),
        (
            " xmlns:u='urn:one'",
            "",
            "<Item><u:Box xmlns:u='urn:two'/><u:Label/></Item>",
            "<Item xmlns:u=\"urn:one\"><u:Box xmlns:u=\"urn:two\"/><u:Label/></Item>",
        ),
        (
            " xmlns='urn:one'",
            "",
            "<Item><Box xmlns=''><Label/></Box></Item>",
            "<Item xmlns=\"urn:one\"><Box xmlns=\"\"><Label/></Box></Item>",
        ),
        (
            " xmlns='urn:one' xmlns:u='urn:two'",
            "",
            "<u:Item><Box/></u:Item>",
            "<u:Item xmlns:u=\"urn:two\" xmlns=\"urn:one\"><Box/></u:Item>",
        ),
        (
            "",
            "",
            "<Item xml:lang='en'>Paper</Item>",
            "<Item xml:lang=\"en\">Paper</Item>",
        ),
        (
            " xmlns:s='urn:stock'",
            "",
            "<s:Item><?stockroom  slots='12' ?><!-- Shelf A\r\nShelf B --><![CDATA[Blue & <Green>]]></s:Item>",
            "<s:Item xmlns:s=\"urn:stock\"><?stockroom slots='12' ?><!-- Shelf A\nShelf B --><![CDATA[Blue & <Green>]]></s:Item>",
        ),
        (
            "",
            "",
            "<!-- shelf B --><Item><![CDATA[shelf]]><![CDATA[]]><![CDATA[ number]]>2</Item><?next?>",
            "<!-- shelf B --><Item><![CDATA[shelf number]]>2</Item><?next?>",
        ),
        (
            "",
            "",
            "<Item><![CDATA[labels ]]]><![CDATA[]> next]]></Item>",
            "<Item><![CDATA[labels ]]]]><![CDATA[> next]]></Item>",
        ),
        (
            "",
            "",
            "<Item><![CDATA[]]><?data\rbox\r\nbag\rcart?><?done  ?></Item>",
            "<Item><![CDATA[]]><?data box\nbag\ncart?><?done ?></Item>",
        ),
        (
            "",
            "",
            "<Item><?office:notes  shelf = 'B' ?>Folders</Item>",
            "<Item><?office:notes shelf = 'B' ?>Folders</Item>",
        ),
    ] {
        let catalog = format!(
            "<?xml version=\"1.0\"?>\n<xar{root}>\n<subdoc{sub}>{markup}</subdoc>\n<toc><file><name>receipt</name><type>file</type>{}</file></toc>\n</xar>",
            extent(
                "data",
                0,
                receipt.len(),
                receipt.len(),
                "application/octet-stream"
            )
        );
        cases.push((build(&catalog, receipt)?, expected.to_owned()));
    }
    for (declaration, output) in [("UTF-8", "é📦"), ("US-ASCII", "é📦")] {
        let xml = toc("<subdoc><Label value='&#233;&#x1F4E6;'/></subdoc>", "")
            .replace("UTF-8", declaration);
        cases.push((build(&xml, &[])?, format!("<Label value=\"{output}\"/>")));
    }
    let archive_with = |parents: &str, subdocs: &str| {
        build(
            &format!(
                "<?xml version=\"1.0\"?>\n<xar{parents}>\n{subdocs}\n<toc><file>{}</file></toc>\n</xar>",
                extent(
                    "data",
                    0,
                    receipt.len(),
                    receipt.len(),
                    "application/octet-stream"
                )
            ),
            receipt,
        )
    };
    // Keep a UTF-8 character before a CRLF split across output blocks.
    let label = format!("{}é", "a".repeat(65533));
    let source = format!(
        "<Item><!--{label}\r\nbox--><?s {label}\r\nqty?><![CDATA[{label}\r\nnote]]></Item>"
    );
    let expected =
        format!("<Item><!--{label}\nbox--><?s {label}\nqty?><![CDATA[{label}\r\nnote]]></Item>");
    cases.push((
        archive_with("", &format!("<subdoc>{source}</subdoc>"))?,
        expected,
    ));
    for (outer, documents, expected) in [
        // One sibling shadows the outer binding. The next sibling must recover it.
        (
            " xmlns:p='urn:outer'",
            "<subdoc><One xmlns:p='urn:one'><p:Child/></One> <p:Two/></subdoc>",
            "<One xmlns:p=\"urn:one\"><p:Child/></One> <p:Two xmlns:p=\"urn:outer\"/>",
        ),
        // An empty default declaration lasts only until the closing tag.
        (
            " xmlns='urn:outer'",
            "<subdoc><One xmlns=''><Child/></One> <Two/></subdoc>",
            "<One xmlns=\"\"><Child/></One> <Two xmlns=\"urn:outer\"/>",
        ),
        // Locally declared bindings survive even if unused. Ancestor bindings do not.
        (
            " xmlns:p='urn:unused'",
            "<subdoc><One id='7' xmlns:u='urn:local'><Two/></One></subdoc>",
            "<One xmlns:u=\"urn:local\" id=\"7\"><Two/></One>",
        ),
        // Removing the first subdocument's scope must reveal the enclosing binding.
        (
            " xmlns:p='urn:outer'",
            "<subdoc xmlns:p='urn:first'><p:One/></subdoc>\n<subdoc><p:Two/></subdoc>",
            "<p:Two xmlns:p=\"urn:outer\"/>",
        ),
        // A default namespace never applies to an attribute without a prefix.
        (
            " xmlns='urn:a' xmlns:p='urn:a'",
            "<subdoc><Box id='1' p:id='2'/></subdoc>",
            "<Box xmlns=\"urn:a\" xmlns:p=\"urn:a\" id=\"1\" p:id=\"2\"/>",
        ),
    ] {
        cases.push((archive_with(outer, documents)?, expected.into()));
    }
    let mut over_bounds = Vec::new();
    for count in [256, 257] {
        // Split declarations across levels to exercise the live-binding limit independently.
        let declarations = |range: std::ops::Range<usize>| {
            range
                .map(|i| format!(" xmlns:p{i}='urn:scope:{i}'"))
                .collect::<String>()
        };
        let outer = declarations(0..128);
        let last = count - 1;
        let documents = format!(
            "<subdoc{}><p0:Box><p{last}:Item/></p0:Box></subdoc>",
            declarations(128..count)
        );
        let rendering = format!(
            "<p0:Box xmlns:p0=\"urn:scope:0\" xmlns:p{last}=\"urn:scope:{last}\"><p{last}:Item/></p0:Box>"
        );
        let binding_case = (archive_with(&outer, &documents)?, rendering);
        let attrs = (0..count)
            .map(|n| format!(" n{n}=\"1\""))
            .collect::<String>();
        let rendering = format!("<Box{attrs}/>");
        let attribute_case = (
            archive_with("", &format!("<subdoc>{rendering}</subdoc>"))?,
            rendering,
        );
        if count == 256 {
            cases.extend([binding_case, attribute_case]);
        } else {
            over_bounds.extend([binding_case, attribute_case]);
        }
    }
    let tmp = tempfile::tempdir_in("/tmp")?;
    let root = tmp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let rule = |name: &str, b: &[u8]| {
        let md5 = Md5::digest(b)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("{md5}:{}:Xar.{name}\n", b.len())
    };
    let receipt_rule = rule("Receipt", receipt);
    let (expanded_xml, expanded_rendering) = expanding_description();
    let expanded = build(&expanded_xml, &[])?;
    let expanded_rule = rule("Expanded", expanded_rendering.as_bytes());
    let expanded_total = expanded.len() + expanded_xml.len() + expanded_rendering.len();
    let mut archive_rule = rule("Archive", archive) + &rule("Archive", descriptions);
    for (bytes, ..) in &interrupted {
        archive_rule += &rule("Archive", bytes);
    }
    let subdoc = rule("Subdocument", rendered)
        + &rule("Subdocument", described.as_bytes())
        + &rule("Subdocument", prefix.as_bytes());
    let mut all = subdoc.clone() + &receipt_rule + &archive_rule;
    for (_, artifact) in cases.iter().chain(&over_bounds) {
        all += &rule("Subdocument", artifact.as_bytes())
    }
    let toc_size = u64::from_be_bytes(archive[16..24].try_into().unwrap());
    let mut decoded = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::ZlibDecoder::new(&archive[28..]),
        &mut decoded,
    )?;
    for (label, options, rules, want) in [
        (
            "expanded-exact",
            format!("MaxScanSize {expanded_total}"),
            expanded_rule.clone(),
            "Expanded",
        ),
        (
            "expanded-below",
            format!(
                "MaxScanSize {}\nMaxFiles 2\nAlertExceedsMax yes",
                expanded_total - 1
            ),
            expanded_rule,
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
        ("competing", "".to_string(), all.clone(), "Subdocument"),
        (
            "heap",
            "".to_string(),
            receipt_rule.clone() + &archive_rule,
            "Receipt",
        ),
        ("outer", "".to_string(), archive_rule.clone(), "Archive"),
        (
            "toc",
            "".to_string(),
            all.clone() + &rule("Toc", &decoded),
            "Toc",
        ),
        ("disabled", "ScanArchive no".into(), all.clone(), "Archive"),
        (
            "size-exact",
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                archive.len() as u64 + toc_size + rendered.len() as u64
            ),
            subdoc.clone(),
            "Subdocument",
        ),
        (
            "size-below",
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                archive.len() as u64 + toc_size + rendered.len() as u64 - 1
            ),
            subdoc.clone(),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
        (
            "count-and-size",
            format!(
                "MaxFiles 2\nMaxScanSize {}\nAlertExceedsMax yes",
                archive.len() as u64 + toc_size + rendered.len() as u64 - 1
            ),
            subdoc.clone(),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
        (
            "count",
            "MaxFiles 2\nAlertExceedsMax yes".into(),
            subdoc.clone(),
            "Heuristics.Limits.Exceeded.MaxFiles",
        ),
    ] {
        fs::write(db.join("note.hdb"), rules)?;
        let conf = root.join(format!("{label}.conf"));
        let socket = root.join(format!("{label}.sock"));
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\nTemporaryDirectory {}\n{options}\n",
                db.display(),
                socket.display(),
                root.display()
            ),
        )?;
        let exe = if stock {
            "/usr/sbin/clamd"
        } else {
            env!("CARGO_BIN_EXE_barnacle")
        };
        let _service = Daemon::start(Path::new(exe), &conf, &socket)?;
        let reply = |b: &[u8]| unix_request(&socket, &stream_frame(b)?);
        let expected = if want.starts_with("Heuristics.") {
            format!("stream: {want} FOUND\0")
        } else {
            format!("stream: Xar.{want}.UNOFFICIAL FOUND\0")
        };
        if label.starts_with("expanded-") {
            assert_eq!(reply(&expanded)?, expected, "{label}");
            continue;
        }
        assert_eq!(reply(archive)?, expected, "{label}");
        if matches!(label, "competing" | "heap" | "outer" | "disabled") {
            assert_eq!(reply(descriptions)?, expected, "Apple inventory: {label}");
        }
        if label == "heap" {
            for (bytes, rendered) in &cases[..encoded_count] {
                assert_eq!(reply(bytes)?, expected, "heap after {rendered}");
            }
        }
        if matches!(label, "competing" | "heap" | "outer") {
            for (i, (bytes, sub, heap)) in interrupted.iter().enumerate() {
                let winner = match label {
                    "competing" => sub,
                    "heap" => heap,
                    _ => &"Archive",
                };
                assert_eq!(
                    reply(bytes)?,
                    format!("stream: Xar.{winner}.UNOFFICIAL FOUND\0"),
                    "interrupted ASCII: {label} {i}"
                );
            }
        }
        if label == "competing" {
            for (bytes, artifact) in &cases {
                assert_eq!(reply(bytes)?, expected, "{artifact}")
            }
            for (bytes, artifact) in &over_bounds {
                let want = if stock {
                    expected.as_str()
                } else {
                    "stream: Incomplete scan: unsupported detection coverage. ERROR\0"
                };
                assert_eq!(
                    reply(bytes)?,
                    want,
                    "over supported XAR namespace limit, {artifact}"
                );
            }
        }
    }
    Ok(())
}
#[test]
fn inventory_namespaces() -> io::Result<()> {
    namespace_cases(false)
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_inventory_namespaces() -> io::Result<()> {
    namespace_cases(true)
}

#[test]
fn subdocument_scratch_follows_admission() -> io::Result<()> {
    let uri = format!("urn:{}", "ordinary-stationery-".repeat(50));
    let siblings = "<u:Box/>".repeat(128);
    let rendered = format!("<u:Box xmlns:u=\"{uri}\"/>").repeat(128);
    let xml = toc(&format!("<subdoc xmlns:u='{uri}'>{siblings}</subdoc>"), "");
    for (xml, rendered) in [(xml, rendered), expanding_description()] {
        check_subdocument_scratch(&xml, &rendered)?;
    }
    Ok(())
}

fn expanding_description() -> (String, String) {
    let source = format!("<Item note='{}'/>", "\"".repeat(16_384));
    let rendered = format!("<Item note=\"{}\"/>", "&quot;".repeat(16_384));
    (toc(&format!("<subdoc>{source}</subdoc>"), ""), rendered)
}

fn check_subdocument_scratch(xml: &str, rendered: &str) -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    assert!(rendered.len() > 64 * 1024);
    assert!(xml.len() < 64 * 1024);
    let archive = build(xml, &[])?;
    let tmp = tempfile::tempdir()?;
    let missing = tmp.path().join("missing");
    for (options, path, expected) in [
        (Options::default(), tmp.path(), true),
        (
            Options {
                max_files: 2,
                ..Options::default()
            },
            missing.as_path(),
            false,
        ),
        (
            Options {
                max_file_size: 32 * 1024,
                ..Options::default()
            },
            missing.as_path(),
            false,
        ),
    ] {
        let mut found = false;
        scan(
            &archive,
            &options,
            path,
            |object, _| {
                if object.bytes == rendered.as_bytes() {
                    found = true;
                    Ok(Verdict::Found("subdoc".into()))
                } else {
                    Ok(Verdict::Miss)
                }
            },
            || Ok(()),
        )?;
        assert_eq!(found, expected);
    }
    Ok(())
}

#[test]
fn unsupported_namespace_forms_keep_an_uncertain_member_ahead_of_the_heap() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    for markup in [
        "<u:Part/>",
        "<Part note='&undeclared;'/>",
        "<Part note='unfinished &amp'/>",
        "<Part note='&#0;'/>",
        "<a:Part xmlns:a='urn:a&amp;b'/>",
        "<Item xmlns:a='urn:u' xmlns:b='urn:u' a:id='1' b:id='2'/>",
    ] {
        let archive = build(
            &toc(
                &format!("<subdoc>{markup}</subdoc>"),
                &extent(
                    "data",
                    0,
                    FIRST.len(),
                    FIRST.len(),
                    "application/octet-stream",
                ),
            ),
            FIRST,
        )?;
        let result = scan(
            &archive,
            &Options::default(),
            tmp.path(),
            |object, _| {
                Ok(if object.bytes == FIRST {
                    Verdict::Found("heap".into())
                } else {
                    Verdict::Miss
                })
            },
            || Ok(()),
        )?;
        assert_eq!(result, Verdict::Incomplete, "{markup}");
    }
    Ok(())
}

#[test]
fn canonical_subdocument_borrows_the_catalog_and_a_late_change_keeps_the_prefix() -> io::Result<()>
{
    use barnacle::objects::{Options, Verdict, scan};
    let note = "Issued paper folders. ".repeat(5000);
    let tmp = tempfile::tempdir()?;
    for (element, borrowed) in [("<Leaf id=\"1\"/>", true), ("<Leaf id='1'></Leaf>", false)] {
        let source = format!("<List><Note>{note}</Note>{element}</List>");
        let expected = format!("<List><Note>{note}</Note><Leaf id=\"1\"/></List>");
        let catalog = toc(&format!("<subdoc>{source}</subdoc>"), "");
        let archive = build(&catalog, &[])?;
        let mut owner = None;
        let result = scan(
            &archive,
            &Options::default(),
            tmp.path(),
            |object, _| {
                if object.bytes == catalog.as_bytes() {
                    let at = object.bytes.as_ptr() as usize;
                    owner = Some(at..at + object.bytes.len());
                } else if object.bytes == expected.as_bytes() {
                    let at = object.bytes.as_ptr() as usize;
                    assert_eq!(owner.as_ref().unwrap().contains(&at), borrowed);
                    return Ok(Verdict::Found("inventory".into()));
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert_eq!(result, Verdict::Found("inventory".into()));
    }
    Ok(())
}
