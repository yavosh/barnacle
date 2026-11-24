//! Exercise read-only, synthetic partition tables using local whole-object signatures.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "object_partition/fixtures.rs"]
mod fixtures;
use daemon::{Daemon, stream_frame, unix_request};
use fixtures::{FIRST, S, SECOND, apm, extended, gpt, mbr, note};
use std::{
    fs,
    io::{self, Read},
    path::Path,
};
fn authored(gz: &[u8]) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(gz).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let dir = temp.path();
    let db = dir.join("db");
    fs::create_dir(&db)?;
    let m = mbr(&[(0x83, 8, 1), (0x83, 4, 1)]);
    let mut boot = m.clone();
    boot[0] = 2;
    let mut m_outer = m.clone();
    m_outer[0] = 3;
    let gt = [(8, "First"), (4, "Second")];
    let g = gpt(S, &gt, &gt);
    let mut g_outer = g.clone();
    g_outer[0] = 7;
    let a = apm();
    let mut a_outer = a.clone();
    a_outer[10] = 9;
    let first = note(FIRST, S);
    let second = note(SECOND, S);
    let first2 = note(FIRST, 2048);
    let first4 = note(FIRST, 4096);
    let mut g4_outer = gpt(4096, &gt, &gt);
    g4_outer[0] = 8;
    let mut rows = String::new();
    for (key, data) in [
        ("First", &first[..]),
        ("Apm2k", &first2),
        ("Second", &second),
        ("Boot", &boot[..S]),
        ("OuterM", &m_outer),
        ("OuterG", &g_outer),
        ("OuterA", &a_outer),
        ("LargeSector", &first4),
        ("Outer4", &g4_outer),
        ("Authored", b"Ordinary UDF text from the second member"),
    ] {
        rows.push_str(&format!(
            "{}:{}:Part.{key}\n",
            barnacle::hash_reader(data)?.md5_hex(),
            data.len()
        ));
    }
    fs::write(db.join("test.hdb"), rows)?;
    let mut backup = g.clone();
    backup[S + 16] ^= 1;
    let mut broken = backup.clone();
    broken[31 * S + 16] ^= 1;
    let mut ext = extended();
    ext[S * 8] = b'X';
    let mut trunc = m.clone();
    trunc.pop();
    let mut invalid = m.clone();
    invalid[446] = 13;
    let mut old_a = a.clone();
    old_a[2..4].copy_from_slice(&2048u16.to_be_bytes());
    old_a[4..8].copy_from_slice(&4u32.to_be_bytes());
    let mut long_a = a.clone();
    long_a[2 * S + 12..2 * S + 16].copy_from_slice(&4u32.to_be_bytes());
    let mut intersect_a = a.clone();
    intersect_a[3 * S + 8..3 * S + 12].copy_from_slice(&8u32.to_be_bytes());
    let inter = |wins: [&'static str; 3]| {
        let same = [(8, "One"), (8, "Two")];
        vec![
            ("mbr", mbr(&[(0x83, 8, 1), (0x83, 8, 1)]), Some(wins[0])),
            ("gpt", gpt(S, &same, &same), Some(wins[1])),
            ("apm", intersect_a.clone(), Some(wins[2])),
        ]
    };
    let discs = |wins: [Option<&'static str>; 3]| {
        vec![
            ("mbr", m.clone(), wins[0]),
            ("gpt", g.clone(), wins[1]),
            ("apm", a.clone(), wins[2]),
        ]
    };
    let size = Some("Heuristics.Limits.Exceeded.MaxScanSize");
    let first = Some("First");
    let regular = vec![
        ("MBR", m.clone(), first),
        ("boot", boot.clone(), Some("Boot")),
        ("standalone boot", boot[..S].to_vec(), Some("Boot")),
        ("outer MBR", m_outer, Some("OuterM")),
        ("truncated MBR", trunc, None),
        ("invalid MBR status", invalid, None),
        ("extended MBR", extended(), first),
        ("second logical partition", ext, Some("Second")),
        ("GPT", g.clone(), first),
        ("outer GPT", g_outer, first),
        ("backup GPT", backup, first),
        (
            "differing backup",
            gpt(S, &[(10, "No")], &[(4, "Second")]),
            Some("Second"),
        ),
        ("both GPT headers invalid", broken, None),
        ("4 KiB GPT", gpt(4096, &gt, &gt), Some("LargeSector")),
        ("4 KiB GPT outer", g4_outer, Some("Outer4")),
        ("APM", a.clone(), first),
        ("outer APM", a_outer, first),
        ("legacy 2048 APM", old_a, first),
        ("native 2048 APM", fixtures::native_apm_2048(), None),
        (
            "hdiutil MBR",
            authored(include_bytes!("fixtures/partition/MBRSPUD.cdr.gz"))?,
            Some("Authored"),
        ),
        (
            "hdiutil GPT",
            authored(include_bytes!("fixtures/partition/GPTSPUD.cdr.gz"))?,
            Some("Authored"),
        ),
        (
            "hdiutil APM",
            authored(include_bytes!("fixtures/partition/SPUD.cdr.gz"))?,
            Some("Authored"),
        ),
    ];
    let empty = [(0, ""), (8, "First")];
    let mut profiles = vec![
        ("regular", "", regular),
        ("off", "ScanArchive no", discs([None; 3])),
        (
            "parts",
            "MaxPartitions 1\nAlertExceedsMax yes",
            vec![
                (
                    "empty MBR first slot",
                    mbr(&[(0, 0, 0), (0x83, 8, 1)]),
                    None,
                ),
                ("empty GPT first slot", gpt(S, &empty, &empty), None),
                ("APM map counts", a.clone(), None),
            ],
        ),
        (
            "zero",
            "MaxPartitions 0\nAlertExceedsMax yes",
            discs([None; 3]),
        ),
        (
            "depth",
            "MaxRecursion 1\nAlertExceedsMax yes",
            discs([Some("Heuristics.Limits.Exceeded.MaxRecursion"); 3]),
        ),
        (
            "count",
            "MaxFiles 2\nAlertExceedsMax yes",
            discs([Some("Heuristics.Limits.Exceeded.MaxFiles"), first, first]),
        ),
        (
            "budget",
            "MaxScanSize 8704\nAlertExceedsMax yes",
            vec![
                ("mbr", m, size),
                ("apm", a, first),
                ("oversize before small", long_a, size),
            ],
        ),
    ];
    if stock {
        profiles.extend([
            (
                "inter",
                "AlertPartitionIntersection yes",
                inter(["First"; 3]),
            ),
            (
                "interfirst",
                "AlertPartitionIntersection yes\nHeuristicScanPrecedence yes",
                inter([
                    "Heuristics.MBRPartitionnIntersect",
                    "Heuristics.GPTPartitionIntersection",
                    "Heuristics.APMPartitionIntersection",
                ]),
            ),
            (
                "interno",
                "AlertPartitionIntersection yes\nHeuristicAlerts no",
                inter(["First"; 3]),
            ),
        ]);
    }
    for (id, opts, cases) in profiles {
        let sock = dir.join(format!("{id}.sock"));
        let conf = dir.join(format!("{id}.conf"));
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\nSelfCheck 0\n{opts}\n",
                db.display(),
                sock.display()
            ),
        )?;
        let _daemon = Daemon::start(exe, &conf, &sock)?;
        for (label, bytes, name) in cases {
            let reply = unix_request(&sock, &stream_frame(&bytes)?)?;
            let expected = match name {
                Some(heuristic) if heuristic.starts_with("Heuristics.") => {
                    format!("stream: {heuristic} FOUND\0")
                }
                Some(name) => format!("stream: Part.{name}.UNOFFICIAL FOUND\0"),
                None if stock => "stream: OK\0".to_owned(),
                None => {
                    "stream: Incomplete scan: unsupported detection coverage. ERROR\0".to_owned()
                }
            };
            assert_eq!(reply, expected, "{id} {label}");
        }
    }
    Ok(())
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_partition_tables() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}

#[test]
fn barnacle_partition_tables() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[path = "common/zip.rs"]
mod zip;

type ParentCase = (Vec<u8>, &'static str, Option<&'static [u8]>);

fn parent_cases() -> [ParentCase; 3] {
    let g = [(8, "First"), (4, "Second")];
    [
        (mbr(&[(0x83, 8, 1)]), "CL_TYPE_MBR", None),
        (gpt(S, &g, &g), "CL_TYPE_GPT", Some(b"First")),
        (apm(), "CL_TYPE_APM", Some(b"First")),
    ]
}

#[test]
fn nested_partitions_keep_their_names_and_parent_types() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    let first = note(FIRST, S);
    for (disc, kind, name) in parent_cases() {
        let zip = zip::zip(&[("ordinary.img", &disc)], true, false, false)?;
        let mut found = 0;
        scan(
            &zip,
            &Options::default(),
            tmp.path(),
            |object, _| {
                if !object.normalized && object.bytes == first {
                    let parents: Vec<_> = object.parents.iter().map(|p| p.file_type).collect();
                    assert_eq!(parents, ["CL_TYPE_ZIP", kind]);
                    assert_eq!(object.layer.file_type, "CL_TYPE_PART_ANY");
                    assert_eq!(object.layer.name.as_deref(), name);
                    found += 1;
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        // The protective MBR marker repeats the initial GPT partition scan.
        assert_eq!(found, if kind == "CL_TYPE_GPT" { 2 } else { 1 }, "{kind}");
    }
    Ok(())
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_partition_parent_constraints() -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let dir = tmp.path();
    let db = dir.join("db");
    fs::create_dir(&db)?;
    let hex: String = FIRST.iter().map(|b| format!("{b:02x}")).collect();
    let mut rules = String::new();
    for (_, kind, _) in parent_cases() {
        rules.push_str(&format!(
            "{kind};Engine:81-255,Target:0,Container:{kind},FileSize:512-512;0;{hex}\n"
        ));
    }
    fs::write(db.join("parents.ldb"), rules)?;
    let conf = dir.join("test.conf");
    let sock = dir.join("sock");
    fs::write(
        &conf,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\n",
            db.display(),
            sock.display()
        ),
    )?;
    let _service = Daemon::start(Path::new("/usr/sbin/clamd"), &conf, &sock)?;
    for (disc, kind, _) in parent_cases() {
        let zip = zip::zip(&[("ordinary.img", &disc)], true, false, false)?;
        assert_eq!(
            unix_request(&sock, &stream_frame(&zip)?)?,
            format!("stream: {kind}.UNOFFICIAL FOUND\0")
        );
    }
    assert_eq!(
        unix_request(&sock, &stream_frame(&note(FIRST, S))?)?,
        "stream: OK\0"
    );
    Ok(())
}
