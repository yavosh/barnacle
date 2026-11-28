//! Compare local logical signatures with pinned Debian clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;
#[path = "common/pe.rs"]
mod pe;
#[path = "common/zip.rs"]
mod zip;

use client::{Daemon, stream_frame, unix_request};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

const ANY: &str = "Engine:81-255,Target:0";
const CREDIT: &str = "637265646974";
const DEBIT: &str = "6465626974";
const LEDGER: &str = "6c6564676572";
const NOTE: &[u8] = b"ordinary credit ledger note";

fn logical(name: &str, target: &str, expression: &str, children: &str) -> String {
    format!("Logic.{name};{target};{expression};{children}\n")
}

fn compare(executable: &Path, stock: bool) -> io::Result<()> {
    let temporary = tempfile::tempdir_in("/tmp")?;
    let db = temporary.path().join("db");
    let socket = temporary.path().join("socket");
    let config = temporary.path().join("clamd.conf");
    fs::create_dir(&db)?;
    let scan = |rules: &str,
                body: &str,
                hashes: &str,
                cases: &[(&[u8], Option<&str>)],
                options: &str| {
        fs::write(
            &config,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\nSelfCheck 0\n{options}",
                db.display(),
                socket.display()
            ),
        )?;
        fs::write(db.join("local.ldb"), rules)?;
        if !body.is_empty() {
            fs::write(db.join("local.ndb"), body)?;
        }
        if !hashes.is_empty() {
            fs::write(db.join("local.hdb"), hashes)?;
        }
        let daemon = Daemon::start(executable, &config, &socket)?;
        for &(bytes, winner) in cases {
            let expected = match winner {
                Some(name) => format!("stream: Logic.{name}.UNOFFICIAL FOUND\0"),
                None if stock || bytes.len() <= 5 => "stream: OK\0".into(),
                None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
            };
            assert_eq!(
                unix_request(&socket, &stream_frame(bytes)?)?,
                expected,
                "{rules:?} on {} bytes",
                bytes.len()
            );
        }
        drop(daemon);
        if !body.is_empty() {
            fs::remove_file(db.join("local.ndb"))?;
        }
        if !hashes.is_empty() {
            fs::remove_file(db.join("local.hdb"))?;
        }
        io::Result::Ok(())
    };

    let run = |rules: &str, body: &str, hashes: &str, cases: &[(&[u8], Option<&str>)]| {
        scan(rules, body, hashes, cases, "")
    };

    let notes = format!("{CREDIT};{DEBIT};{LEDGER}");
    run(
        &(logical("Right", ANY, "0&1|2", &notes) + &logical("Grouped", ANY, "(0&1|2)", &notes)),
        "",
        "",
        &[
            (b"ordinary ledger note", Some("Grouped")),
            (NOTE, Some("Right")),
            (b"ordinary receipt note", None),
        ],
    )?;
    run(
        &logical(
            "Occurrences",
            ANY,
            "(0|1)=2,2",
            &format!("{CREDIT};{DEBIT}"),
        ),
        "",
        "",
        &[
            (b"credit then debit", Some("Occurrences")),
            (b"credit then credit", None),
            (b"credit debit debit", None),
        ],
    )?;
    run(
        &logical("Duplicate", ANY, "(0|1)=2,2", &format!("{CREDIT};{CREDIT}")),
        "",
        "",
        &[(NOTE, Some("Duplicate")), (b"credit then credit", None)],
    )?;
    run(
        &logical("Overlap", ANY, "0=2", "61616161"),
        "",
        "",
        &[(b"note aaaaa note", Some("Overlap")), (b"aaaaa", None)],
    )?;
    run(
        &logical("Absent", ANY, "(0&1)=0", &format!("{CREDIT};{DEBIT}")),
        "",
        "",
        &[
            (NOTE, Some("Absent")),
            (b"ordinary receipt note", Some("Absent")),
            (b"credit then debit", None),
        ],
    )?;

    let by_offset = logical(
        "Offset",
        &format!("{ANY},FileSize:{0}-{0}", NOTE.len()),
        "0",
        &format!("9:{CREDIT}"),
    );
    run(
        &by_offset,
        "",
        "",
        &[
            (NOTE, Some("Offset")),
            (b"extraordinary credit ledger note", None),
        ],
    )?;

    let nested = zip::zip(&[("receipt.txt", NOTE)], true, false, false)?;
    assert!(!nested.windows(6).any(|bytes| bytes == b"credit"));
    run(
        &logical("Root", &format!("{ANY},Container:CL_TYPE_ANY"), "0", CREDIT),
        "",
        "",
        &[(NOTE, Some("Root")), (&nested, None)],
    )?;

    run(
        &logical(
            "InZip",
            &format!("{ANY},Container:CL_TYPE_ZIP"),
            "0",
            CREDIT,
        ),
        "",
        "",
        &[(NOTE, None), (&nested, Some("InZip"))],
    )?;
    let basic = logical("Logical", ANY, "0", CREDIT);
    let html = b"<html><body>ordinary CREDIT ledger note</body></html>";
    run(
        &basic,
        "",
        "",
        &[(NOTE, Some("Logical")), (html, Some("Logical"))],
    )?;

    // The unmapped script pass uses the source size and skips generic relative offsets.
    let upper = b"LEDGER  CREDIT";
    run(
        &logical("GenericEof", ANY, "0", &format!("EOF-6:{CREDIT}")),
        "",
        "",
        &[(upper, None)],
    )?;
    run(
        &logical(
            "SourceSize",
            &format!("{ANY},FileSize:14-14"),
            "0",
            &format!("7:{CREDIT}"),
        ),
        "",
        "",
        &[(upper, Some("SourceSize"))],
    )?;
    let ascii = "Engine:81-255,Target:7";
    run(
        &logical(
            "Mapped",
            &format!("{ascii},FileSize:13-13,Container:CL_TYPE_ANY"),
            "0",
            &format!("EOF-6:{CREDIT}"),
        ),
        "",
        "",
        &[(upper, Some("Mapped"))],
    )?;

    let zero = logical(
        "OriginalZero",
        &format!("{ascii},FileSize:14-14"),
        "0=0",
        CREDIT,
    );
    let space = b"LEDGER  credit";
    run(&zero, "", "", &[(space, None)])?;
    let map_trigger = logical("MapTrigger", ascii, "0", "EOF-6:7a7a7a7a");
    run(
        &(zero + &map_trigger),
        "",
        "",
        &[(space, Some("OriginalZero"))],
    )?;

    let hashes = format!(
        "{}:{}:Logic.Hash\n",
        barnacle::hash_reader(NOTE)?.md5_hex(),
        NOTE.len()
    );
    run(&basic, "", &hashes, &[(NOTE, Some("Hash"))])?;
    run(
        &basic,
        &format!("Logic.Body:0:*:{CREDIT}\n"),
        &hashes,
        &[(NOTE, Some("Body"))],
    )?;
    let mut executable = pe::benign_pe();
    executable[600..606].copy_from_slice(b"credit");
    run(
        &(basic + &logical("Typed", "Engine:81-255,Target:1", "0", CREDIT)),
        "",
        "",
        &[(&executable, Some("Typed"))],
    )?;
    let mut at_entry = executable.clone();
    at_entry[168..172].copy_from_slice(&0x1040u32.to_le_bytes());
    let mut no_layout = executable.clone();
    no_layout[128..132].fill(0);
    for (name, condition, zero, mapped) in [
        (
            "OneSection",
            "NumberOfSections:1-1",
            Some("OneSection"),
            Some("OneSection"),
        ),
        ("TwoSections", "NumberOfSections:2-2", None, None),
        ("ZeroEntry", "EntryPoint:0-0", Some("ZeroEntry"), None),
        (
            "EntryOffset",
            "EntryPoint:576-576",
            None,
            Some("EntryOffset"),
        ),
        ("EntryAddress", "EntryPoint:4160-4160", None, None),
        (
            "Layout",
            "EntryPoint:576-576,NumberOfSections:1-1",
            None,
            Some("Layout"),
        ),
    ] {
        run(
            &logical(
                name,
                &format!("Engine:51-255,Target:1,{condition}"),
                "0",
                CREDIT,
            ),
            "",
            "",
            &[
                (&executable, zero),
                (&at_entry, mapped),
                (&no_layout, None),
                (NOTE, None),
            ],
        )?;
    }
    modifiers(|rules, cases| scan(rules, "", "", cases, RAW_OPTIONS))?;
    if !stock {
        // Pinned clamd's LDB tokenizer rejects this valid PCRE child before PCRE sees it.
        scan(
            &logical(
                "RegexBackslash",
                ANY,
                "1&2",
                &format!(r"{LEDGER};0/credit\\/;{DEBIT}"),
            ),
            "",
            "",
            &[
                (&binary(b"ledger credit\\ debit"), Some("RegexBackslash")),
                (&binary(b"ledger credit debit"), None),
                (&binary(b"ledger credit\\"), None),
            ],
            RAW_OPTIONS,
        )?;
    }
    pcre(|rules, cases, options| scan(rules, "", "", cases, options))
}

const RAW_OPTIONS: &str = "ScanHTML no\nScanMail no\n";

fn binary(content: &[u8]) -> Vec<u8> {
    [
        b"\xff\0\x81\x02\xfd\x04\x80\x06".as_slice(),
        content,
        b"\xfe\0\x83\x03\xfc\x05\x82\x07",
    ]
    .concat()
}

fn modifiers(run: impl Fn(&str, &[(&[u8], Option<&str>)]) -> io::Result<()>) -> io::Result<()> {
    fn wide(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    let ascii = binary(b"credit");
    let uppercase = binary(b"CREDIT");
    let utf16 = binary(&wide("credit"));
    let utf16_uppercase = binary(&wide("CREDIT"));
    let both = binary(&[b"credit ".as_slice(), &wide("credit")].concat());

    for (flags, ascii_winner, uppercase_winner, wide_winner, wide_upper_winner) in [
        ("a", Some("Modifier"), None, None, None),
        ("i", Some("Modifier"), Some("Modifier"), None, None),
        ("w", None, None, Some("Modifier"), None),
        ("wa", Some("Modifier"), None, Some("Modifier"), None),
        ("wii", None, None, Some("Modifier"), Some("Modifier")),
    ] {
        run(
            &logical("Modifier", ANY, "0", &format!("{CREDIT}::{flags}")),
            &[
                (&ascii, ascii_winner),
                (&uppercase, uppercase_winner),
                (&utf16, wide_winner),
                (&utf16_uppercase, wide_upper_winner),
            ],
        )?;
    }
    run(
        &logical("Count", ANY, "0=2", &format!("{CREDIT}::wa")),
        &[(&ascii, None), (&utf16, None), (&both, Some("Count"))],
    )?;
    run(
        &logical("Word", ANY, "0", &format!("{CREDIT}::waf")),
        &[
            (&binary(b"_credit_"), Some("Word")),
            (&binary(b"1credit2"), None),
            (&binary(&wide("_credit_")), Some("Word")),
            (&binary(&wide("xcredity")), None),
        ],
    )?;
    run(
        &logical("Offset", ANY, "0", &format!("9:{CREDIT}::w")),
        &[
            (
                &binary(&[b"x".as_slice(), &wide("credit")].concat()),
                Some("Offset"),
            ),
            (&utf16, None),
        ],
    )?;
    run(
        &logical("End", ANY, "0", &format!("EOF-20:{CREDIT}::w")),
        &[(&utf16, Some("End")), (&ascii, None)],
    )?;

    let raw_gap = binary(&[wide("cre").as_slice(), b"X", &wide("it")].concat());
    let code_unit_gap = binary(&wide("creXit"));
    run(
        &logical("Gap", ANY, "0", "637265{1}6974::w"),
        &[(&raw_gap, Some("Gap")), (&code_unit_gap, None)],
    )?;
    run(
        &logical("WideWildcard", ANY, "0", "637265??6974::w"),
        &[(&raw_gap, None), (&code_unit_gap, Some("WideWildcard"))],
    )?;
    run(
        &logical("Nibble", ANY, "0", "6372656?6974::iw"),
        &[(&utf16, Some("Nibble")), (&utf16_uppercase, None)],
    )?;
    run(
        &logical("NoEngine", "Target:0", "0", &format!("{CREDIT}::i")),
        &[(&uppercase, Some("NoEngine"))],
    )?;
    let matching_both_widths = binary(b"a\0\0\0 b\0\0\0");
    run(
        &logical("OneStart", ANY, "0=1", "6100::wa"),
        &[(&matching_both_widths, Some("OneStart"))],
    )?;
    run(
        &logical("TwoCompletions", ANY, "0=2", "6100*6200::wa"),
        &[(&matching_both_widths, Some("TwoCompletions"))],
    )?;
    run(
        &logical("Multipart", ANY, "0", "48454144*5441494c::f"),
        &[
            (&binary(b"xHEAD  HEAD TAIL ."), Some("Multipart")),
            (&binary(b"xHEAD TAIL ."), None),
        ],
    )?;
    run(
        &(logical("LeftFirst", ANY, "0", &format!("(20|7820){CREDIT}::f"))
            + &logical("LeftSecond", ANY, "0", &format!("(7820|20){CREDIT}::f"))
            + &logical("Right", ANY, "0", &format!("{CREDIT}(20|2078)::f"))),
        &[
            (&binary(b"x credit"), Some("LeftSecond")),
            (&binary(b"credit x "), Some("Right")),
        ],
    )?;
    run(
        &(logical("BracketCore", ANY, "0", "10:61[1]626364[1]65::f")
            + &logical("BracketStart", ANY, "0", "8:61[1]626364[1]65::f")),
        &[(&binary(b"aXbcdYe"), Some("BracketStart"))],
    )?;
    run(
        &logical("RepeatedModifiers", ANY, "0", &format!("{CREDIT}::i::w")),
        &[
            (&binary(b" credit "), Some("RepeatedModifiers")),
            (&binary(b" CREDIT "), None),
            (&binary(&wide("credit")), None),
        ],
    )?;
    let mut window_edge = binary(&vec![b' '; 131_073]);
    window_edge[131_068..131_073].copy_from_slice(b"noteQ");
    run(
        &logical("WindowEnd", ANY, "0", "6e6f7465::f"),
        &[(&window_edge, Some("WindowEnd"))],
    )?;
    let mut overlap = binary(&vec![b'.'; 131_088]);
    let word = wide("credit");
    overlap[131_061..131_061 + word.len()].copy_from_slice(&word);
    let mut punctuation = overlap.clone();
    punctuation[131_059..131_061].copy_from_slice(b".\0");
    let mut letter = overlap.clone();
    letter[131_059..131_061].copy_from_slice(b"x\0");
    run(
        &logical("WideWindow", ANY, "0", &format!("{CREDIT}::wf")),
        &[
            (&overlap, Some("WideWindow")),
            (&punctuation, Some("WideWindow")),
            (&letter, None),
        ],
    )
}

fn pcre(run: impl Fn(&str, &[(&[u8], Option<&str>)], &str) -> io::Result<()>) -> io::Result<()> {
    let chained = logical(
        "RegexChain",
        ANY,
        "2",
        &format!(r"{LEDGER};0/(?<=--)([A-Z]{{2}})-\1/i;1/credit/"),
    );
    run(
        &chained,
        &[
            (&binary(b"ledger --AB-ab credit"), Some("RegexChain")),
            (&binary(b"ledger --AB-cd credit"), None),
            (&binary(b"ledger AB-ab credit"), None),
            (&binary(b"debit --AB-ab credit"), None),
        ],
        RAW_OPTIONS,
    )?;
    run(
        &logical("RegexZero", ANY, "1", &format!("{LEDGER};0=0/credit/")),
        &[
            (&binary(b"ordinary credit"), Some("RegexZero")),
            (&binary(b"ledger credit"), None),
        ],
        RAW_OPTIONS,
    )?;
    for (name, offset, winner) in [
        ("RegexTextOffset", "7", Some("RegexTextOffset")),
        ("RegexTextEnd", "EOF-6", Some("RegexTextEnd")),
        ("RegexUnnormalizedOffset", "8", None),
    ] {
        run(
            &logical(name, ANY, "1", &format!("{LEDGER};{offset}:0/credit/")),
            &[(b"LEDGER  CREDIT", winner)],
            "",
        )?;
    }
    run(
        &logical("RegexUtf", ANY, "1", &format!("{LEDGER};0/(*UTF)credit/")),
        &[
            (b"ledger credit", Some("RegexUtf")),
            (&binary(b"ledger credit"), None),
        ],
        RAW_OPTIONS,
    )?;
    run(
        &logical(
            "RegexEarlierTrigger",
            ANY,
            "2",
            &format!("{LEDGER};{DEBIT};0/credit/"),
        ),
        &[
            (&binary(b"ledger credit"), Some("RegexEarlierTrigger")),
            (&binary(b"debit credit"), None),
        ],
        RAW_OPTIONS,
    )?;
    run(
        &logical(
            "RegexSemicolon",
            ANY,
            "1&2",
            &format!("{LEDGER};0/credit;note/;{DEBIT}"),
        ),
        &[
            (&binary(b"ledger credit;note debit"), Some("RegexSemicolon")),
            (&binary(b"ledger credit note debit"), None),
        ],
        RAW_OPTIONS,
    )?;
    run(
        &logical(
            "RegexEscapedSlash",
            ANY,
            "1&2",
            &format!(r"{LEDGER};0/credit\/note;paid/;{DEBIT}"),
        ),
        &[
            (
                &binary(b"ledger credit/note;paid debit"),
                Some("RegexEscapedSlash"),
            ),
            (&binary(b"ledger credit/note;paid"), None),
        ],
        RAW_OPTIONS,
    )?;
    let note = b"LEDGER  CREDIT";
    let archive = zip::zip(&[("receipt.txt", note)], true, false, false)?;
    run(
        &logical(
            "RegexZip",
            &format!("{ANY},Container:CL_TYPE_ZIP"),
            "1",
            &format!("{LEDGER};EOF-6:0/credit/"),
        ),
        &[(note, None), (&archive, Some("RegexZip"))],
        "",
    )?;
    let adjacent = binary(b"creditcredit ledger");
    let separated = binary(b"credit credit ledger");
    let shifted = binary(b"-credit ledger");
    for (name, field, cases) in [
        (
            "RegexExact",
            "8:0/^credit/",
            [(&adjacent, Some("RegexExact")), (&shifted, None)],
        ),
        (
            "RegexShift",
            "8,1:0/credit/",
            [
                (&adjacent, Some("RegexShift")),
                (&shifted, Some("RegexShift")),
            ],
        ),
        (
            "RegexSpan",
            "8,6:0/credit/e",
            [(&adjacent, Some("RegexSpan")), (&shifted, None)],
        ),
    ] {
        let cases = cases.map(|(bytes, winner)| (bytes.as_slice(), winner));
        run(
            &logical(name, ANY, "1", &format!("{LEDGER};{field}")),
            &cases,
            RAW_OPTIONS,
        )?;
    }
    for (name, flags, separated_winner) in [
        ("RegexGlobal", "g", None),
        ("RegexRolling", "gr", Some("RegexRolling")),
    ] {
        run(
            &logical(name, ANY, "1=2", &format!("{LEDGER};8:0/credit/{flags}")),
            &[(&adjacent, Some(name)), (&separated, separated_winner)],
            RAW_OPTIONS,
        )?;
    }
    run(
        &logical("RegexCap", ANY, "1", &format!("{LEDGER};8,6:0/credit/e")),
        &[
            (&adjacent, Some("RegexCap")),
            (&binary(b"creditcredit ledger."), None),
        ],
        &format!("{RAW_OPTIONS}PCREMaxFileSize {}\n", adjacent.len()),
    )?;
    Ok(())
}

#[test]
fn local_logical_signatures() -> io::Result<()> {
    compare(&barnacle_binary(), false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_logical_signatures() -> io::Result<()> {
    compare(&reference_clamd(), true)
}

fn barnacle_binary() -> PathBuf {
    std::env::var_os("BARNACLE_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_barnacle").into())
        .into()
}

fn reference_clamd() -> PathBuf {
    std::env::var_os("BARNACLE_REFERENCE_CLAMD")
        .unwrap_or_else(|| "/usr/sbin/clamd".into())
        .into()
}

fn compare_handlers(executable: &Path, stock: bool) -> io::Result<()> {
    let temporary = tempfile::tempdir_in("/tmp")?;
    let db = temporary.path().join("db");
    let socket = temporary.path().join("socket");
    let config = temporary.path().join("clamd.conf");
    fs::create_dir(&db)?;
    let run = |rules: &str, options: &str, bytes: &[u8], winner: Option<&str>| {
        fs::write(db.join("local.ldb"), rules)?;
        fs::write(
            &config,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nSelfCheck 0\n{options}",
                db.display(),
                socket.display()
            ),
        )?;
        let _daemon = Daemon::start(executable, &config, &socket)?;
        let expected = match winner {
            Some(name) if name.starts_with("Heuristics.") => format!("stream: {name} FOUND\0"),
            Some(name) => format!("stream: Logic.{name}.UNOFFICIAL FOUND\0"),
            None if stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        assert_eq!(
            unix_request(&socket, &stream_frame(bytes)?)?,
            expected,
            "{rules:?} with {options:?} on {} bytes",
            bytes.len()
        );
        io::Result::Ok(())
    };
    let hint = |kind: &str, root: bool| {
        let scope = if root { ",Container:CL_TYPE_ANY" } else { "" };
        logical(
            "Hint",
            &format!("Engine:51-255,Target:0,HandlerType:CL_TYPE_{kind}{scope}"),
            "0",
            CREDIT,
        )
    };
    let ordinary = logical("Ordinary", ANY, "0", CREDIT);
    for (kind, target, parser_off) in [
        ("PDF", 10, "ScanPDF no\n"),
        ("GRAPHICS", 5, "ScanImage no\n"),
    ] {
        let typed = logical(
            "Typed",
            &format!("Engine:51-255,Target:{target},Container:CL_TYPE_TEXT_ASCII"),
            "0",
            CREDIT,
        );
        let rules = typed.clone() + &hint(kind, true) + &ordinary;
        run(&rules, "", NOTE, Some("Typed"))?;
        run(&rules, "DisableCache yes\n", NOTE, Some("Hint"))?;
        run(&rules, parser_off, NOTE, Some("Typed"))?;
        run(
            &(typed.clone() + &ordinary + &hint(kind, true)),
            "",
            NOTE,
            Some("Ordinary"),
        )?;
        let bounded = typed + &hint(kind, true);
        run(&bounded, "MaxRecursion 1\nScanHTML no\n", NOTE, None)?;
        run(&bounded, "MaxRecursion 1\n", NOTE, Some("Hint"))?;
    }
    run(&hint("GRAPHICS", true), "ScanHTML no\n", NOTE, None)?;
    run(&hint("GRAPHICS", false), "", NOTE, Some("Hint"))?;
    let binary = b"\0\x01\0\x02 ordinary credit ledger\x01";
    let binary_hint = hint("GRAPHICS", true);
    run(&binary_hint, "", binary, Some("Hint"))?;
    let other = logical("Other", "Engine:51-255,Target:14", "0", CREDIT);
    run(&(binary_hint + &other), "", binary, Some("Other"))?;
    let first = hint("GRAPHICS", true);
    let second = first.replacen("Logic.Hint", "Logic.Second", 1);
    run(&(first.clone() + &second), "", NOTE, Some("Second"))?;
    let blocked = first + &second + &ordinary;
    for (limit, value) in [
        ("MaxRecursion", 1),
        ("MaxFiles", 1),
        ("MaxScanSize", NOTE.len()),
    ] {
        run(
            &blocked,
            &format!("{limit} {value}\nScanHTML no\n"),
            NOTE,
            None,
        )?;
        run(
            &blocked,
            &format!("{limit} {value}\nScanHTML no\nAlertExceedsMax yes\n"),
            NOTE,
            Some(&format!("Heuristics.Limits.Exceeded.{limit}")),
        )?;
    }
    run(
        &blocked,
        "MaxRecursion 1\nAlertExceedsMax yes\n",
        NOTE,
        Some("Hint"),
    )?;

    let source = b"ordinary credit RECEIPTLEDGER note";
    let script = logical(
        "Normalized",
        "Engine:51-255,Target:7,Container:CL_TYPE_TEXT_ASCII",
        "0",
        "726563656970746c6564676572",
    );
    let script_rules = hint("SCRIPT", true) + &script;
    run(&script_rules, "ScanHTML no\n", source, Some("Normalized"))?;
    run(
        &script_rules,
        "ScanHTML no\nDisableCache yes\n",
        source,
        Some("Hint"),
    )?;

    let archive = zip::zip(&[("credit.txt", b"receipt ledger")], true, false, false)?;
    let member = logical(
        "Member",
        "Engine:51-255,Target:0,Intermediates:CL_TYPE_ZIP>CL_TYPE_ZIP",
        "0",
        LEDGER,
    );
    let zip_rules = hint("ZIP", true) + &member;
    run(&zip_rules, "", &archive, Some("Member"))?;
    run(&zip_rules, "ScanArchive no\n", &archive, None)?;

    let aliases = b"[aliases]\nreport=credit ledger\n";
    let typed = logical(
        "AliasParent",
        "Engine:51-255,Target:5,Container:CL_TYPE_POSIX_TAR",
        "0",
        CREDIT,
    );
    let alias_rules = hint("GRAPHICS", true) + &typed;
    run(&alias_rules, "", aliases, Some("AliasParent"))?;
    run(
        &alias_rules,
        "ScanArchive no\n",
        aliases,
        Some("AliasParent"),
    )?;
    run(&alias_rules, "DisableCache yes\n", aliases, Some("Hint"))?;
    let mut long_aliases = aliases.to_vec();
    long_aliases.extend(b"; invoice report settings\n".repeat(40));
    run(&alias_rules, "", &long_aliases, Some("AliasParent"))?;
    Ok(())
}

#[test]
fn local_logical_handlers() -> io::Result<()> {
    compare_handlers(&barnacle_binary(), false)
}

#[test]
#[ignore = "requires pinned clamd 1.4.3"]
fn stock_logical_handlers() -> io::Result<()> {
    compare_handlers(&reference_clamd(), true)
}
