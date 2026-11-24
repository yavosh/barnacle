//! Stock clamd and Barnacle scan inert Mach-O object data. No fixture runs as code.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;
use daemon::{Daemon, stream_frame, unix_request};
use std::{
    fs,
    io::{self, Read},
    path::Path,
};
const ARM: u32 = 0x0100_000c;
const X86: u32 = 0x0100_0007;
const NOTE: &[u8] = b"Harmless data assigned to a universal file slice.";
fn authored(gz: &[u8]) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(gz).read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn fat(parts: &[(u32, &[u8])]) -> Vec<u8> {
    let mut data = vec![0; 8 + 20 * parts.len()];
    data[..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
    data[4..8].copy_from_slice(&(parts.len() as u32).to_be_bytes());
    for (i, (cpu, slice)) in parts.iter().enumerate() {
        let offset = data.len() as u32;
        let start = 8 + 20 * i;
        for (j, n) in [
            *cpu,
            if *cpu == X86 { 3 } else { 0 },
            offset,
            slice.len() as u32,
            0,
        ]
        .iter()
        .enumerate()
        {
            data[start + j * 4..start + j * 4 + 4].copy_from_slice(&n.to_be_bytes());
        }
        data.extend_from_slice(slice);
    }
    data
}
fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let dir = tmp.path();
    let db = dir.join("db");
    fs::create_dir(&db)?;
    let x = authored(include_bytes!("fixtures/macho/x86_64.o.gz"))?;
    let arm = authored(include_bytes!("fixtures/macho/arm64.o.gz"))?;
    let apple = authored(include_bytes!("fixtures/macho/ordinary.o.gz"))?;
    let wide = authored(include_bytes!("fixtures/macho/wide.o.gz"))?;
    let both = fat(&[(X86, &x), (ARM, &arm)]);
    let mut outer = both.clone();
    outer[27] = 1;
    let mut reverse = both.clone();
    let (start, end) = reverse.split_at_mut(28);
    start[8..28].swap_with_slice(&mut end[..20]);
    let text = fat(&[(X86, NOTE)]);
    let mut past = both.clone();
    past[16..20].copy_from_slice(&(both.len() as u32 + 128).to_be_bytes());
    let mut truncated = both.clone();
    truncated.truncate(15);
    let mut alternate = both.clone();
    for header in alternate[..48].as_chunks_mut::<4>().0 {
        header.reverse();
    }
    let many = |n: usize| {
        let mut parts = vec![(X86, b"ordinary".as_slice()); n];
        if let Some(last) = parts.last_mut() {
            *last = (ARM, NOTE);
        }
        fat(&parts)
    };
    let large = vec![1; 4096];
    let before_small = fat(&[(X86, &large), (ARM, NOTE)]);
    let scan_size = format!(
        "MaxScanSize {}\nAlertExceedsMax yes",
        before_small.len() + NOTE.len()
    );
    let quiet = scan_size.replace("yes", "no");
    let zip = zip::zip(
        &[("notes.universal", &fat(&[(X86, NOTE)]))],
        true,
        false,
        false,
    )?;
    // Java classes and universal Mach-O files share their first four bytes.
    let class = include_bytes!("fixtures/java/Note.class.bin");
    let mut java11 = class.to_vec();
    java11[7] = 55;
    let mut java21 = class.to_vec();
    java21[7] = 65;
    let mut rules = String::new();
    for (id, bytes) in [
        ("X86", x.as_slice()),
        ("Arm", &arm),
        ("Outer", &outer),
        ("Note", NOTE),
        ("JavaHash", &java11),
        ("Java21Hash", &java21),
    ] {
        rules.push_str(&format!(
            "{}:{}:Mach.{id}\n",
            barnacle::hash_reader(bytes)?.md5_hex(),
            bytes.len()
        ));
    }
    fs::write(db.join("test.hdb"), rules)?;
    fs::write(
        db.join("java.ndb"),
        "Mach.JavaBody:12:0:cafebabe0000003d\nMach.Java21Body:12:0:cafebabe00000041\n",
    )?;
    let jar = zip::zip(&[("Note.class", class)], true, false, false)?;
    let hash_jar = zip::zip(&[("Note.class", &java11)], true, false, false)?;
    let mut zero = text.clone();
    zero[20..24].fill(0);
    let mut clipped = text.clone();
    clipped[20..24].copy_from_slice(&4096u32.to_be_bytes());
    let mut early = both.clone();
    early[16..20].copy_from_slice(&8u32.to_be_bytes());
    let first = Some("X86");
    for (name, config, cases) in [
        (
            "ordinary",
            "",
            vec![
                ("Java 17 interface", class.to_vec(), Some("JavaBody")),
                ("Java 17 JAR", jar, Some("JavaBody")),
                ("Java 11 interface", java11, Some("JavaHash")),
                ("Java 11 JAR", hash_jar, Some("JavaHash")),
                ("Java 21 is generic on stock", java21, Some("Java21Hash")),
                ("direct x86", x.clone(), first),
                ("direct arm", arm.clone(), Some("Arm")),
                ("lipo original", apple, first),
                ("fat64 lipo", wide, None),
                ("fat vs. slice", outer, first),
                ("reversed descriptor", reverse, Some("Arm")),
                ("plain slice", text, Some("Note")),
                ("nested ZIP", zip, Some("Note")),
                ("zero-length extent", zero, Some("Note")),
                ("clipped extent", clipped, Some("Note")),
                ("empty", many(0), None),
                ("31 slices", many(31), Some("Note")),
                ("32 slices", many(32), None),
                ("reversed endian", alternate, None),
                ("short header", truncated, None),
                ("first extent past eof", past, Some("Arm")),
                ("first extent before descriptor end", early, None),
            ],
        ),
        (
            "elf",
            "ScanELF no",
            vec![("fat", both.clone(), first), ("thin", x.clone(), first)],
        ),
        (
            "archive",
            "ScanArchive no",
            vec![("fat", both.clone(), first)],
        ),
        (
            "maxfiles",
            "MaxFiles 1\nAlertExceedsMax yes",
            vec![
                (
                    "fat",
                    both.clone(),
                    Some("Heuristics.Limits.Exceeded.MaxFiles"),
                ),
                ("thin", x, first),
            ],
        ),
        (
            "recursion",
            "MaxRecursion 1\nAlertExceedsMax yes",
            vec![("fat", both, Some("Heuristics.Limits.Exceeded.MaxRecursion"))],
        ),
        (
            "budget",
            &scan_size,
            vec![(
                "large then small",
                before_small.clone(),
                Some("Heuristics.Limits.Exceeded.MaxScanSize"),
            )],
        ),
        (
            "quiet",
            &quiet,
            vec![("large then small", before_small, None)],
        ),
    ] {
        let conf = dir.join(format!("{name}.conf"));
        let sock = dir.join(format!("{name}.sock"));
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nSelfCheck 0\nDisableCache yes\n{config}\n",
                db.display(),
                sock.display()
            ),
        )?;
        let _service = Daemon::start(exe, &conf, &sock)?;
        for (label, bytes, expected) in cases {
            let reply = unix_request(&sock, &stream_frame(&bytes)?)?;
            let expected = match expected {
                Some(d) if d.starts_with("Heuristics.") => format!("stream: {d} FOUND\0"),
                Some(d) => format!("stream: Mach.{d}.UNOFFICIAL FOUND\0"),
                None if stock => "stream: OK\0".to_owned(),
                None => {
                    "stream: Incomplete scan: unsupported detection coverage. ERROR\0".to_owned()
                }
            };
            assert_eq!(reply, expected, "{name} {label}");
        }
    }
    Ok(())
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_universal_files() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}

fn elf_controls(executable: &Path) -> io::Result<()> {
    let dir = tempfile::tempdir_in("/tmp")?;
    let db = dir.path().join("db");
    fs::create_dir(&db)?;
    let elf = authored(include_bytes!("fixtures/macho/elf.o.gz"))?;
    let marker = b"A data-only ELF section";
    let mut hashed = elf.clone();
    let pos = hashed
        .windows(marker.len())
        .position(|s| s == marker)
        .unwrap();
    hashed[pos] = b'Z';
    fs::write(
        db.join("whole.hdb"),
        format!(
            "{}:{}:Mach.ElfHash\n",
            barnacle::hash_reader(&hashed[..])?.md5_hex(),
            hashed.len()
        ),
    )?;
    let hex: String = marker.iter().map(|b| format!("{b:02x}")).collect();
    fs::write(
        db.join("section.ndb"),
        format!("Mach.ElfSection:6:S3+0:{hex}\n"),
    )?;
    for setting in ["yes", "no"] {
        let config = dir.path().join(format!("{setting}.conf"));
        let sock = dir.path().join(format!("{setting}.sock"));
        fs::write(
            &config,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nSelfCheck 0\nDisableCache yes\nScanELF {setting}\n",
                db.display(),
                sock.display()
            ),
        )?;
        let _service = Daemon::start(executable, &config, &sock)?;
        for (name, data) in [("ElfHash", &hashed), ("ElfSection", &elf)] {
            let result = unix_request(&sock, &stream_frame(data)?)?;
            assert_eq!(
                result,
                format!("stream: Mach.{name}.UNOFFICIAL FOUND\0"),
                "{setting} {name}"
            );
        }
    }
    Ok(())
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_elf_policy() -> io::Result<()> {
    elf_controls(Path::new("/usr/sbin/clamd"))
}
#[test]
fn barnacle_universal_files() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}
#[test]
fn barnacle_elf_policy() -> io::Result<()> {
    elf_controls(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
fn nested_universal_slice_contexts() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let dir = tempfile::tempdir()?;
    let arm = authored(include_bytes!("fixtures/macho/arm64.o.gz"))?;
    let universal = fat(&[(ARM, &arm), (X86, NOTE)]);
    let zip = zip::zip(&[("notes.universal", &universal)], true, false, false)?;
    let mut found = Vec::new();
    scan(
        &zip,
        &Options::default(),
        dir.path(),
        |object, _| {
            if !object.normalized && (object.bytes == arm || object.bytes == NOTE) {
                let chain: Vec<_> = object.parents.iter().map(|p| p.file_type).collect();
                assert_eq!(chain, ["CL_TYPE_ZIP", "CL_TYPE_MACHO_UNIBIN"]);
                assert!(object.layer.name.is_none());
                found.push(object.layer.file_type);
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(found, ["CL_TYPE_MACHO", "CL_TYPE_TEXT_ASCII"]);
    Ok(())
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_universal_parent() -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let root = tmp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let hex: String = NOTE.iter().map(|b| format!("{b:02x}")).collect();
    fs::write(
        db.join("parents.ldb"),
        format!("Mach.Parent;Engine:81-255,Target:0,Container:CL_TYPE_MACHO_UNIBIN;0;{hex}\n"),
    )?;
    let conf = root.join("parent.conf");
    let sock = root.join("sock");
    fs::write(
        &conf,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nSelfCheck 0\nDisableCache yes\n",
            db.display(),
            sock.display()
        ),
    )?;
    let _daemon = Daemon::start(Path::new("/usr/sbin/clamd"), &conf, &sock)?;
    let bytes = zip::zip(
        &[("notes.universal", &fat(&[(ARM, NOTE)]))],
        true,
        false,
        false,
    )?;
    assert_eq!(
        unix_request(&sock, &stream_frame(&bytes)?)?,
        "stream: Mach.Parent.UNOFFICIAL FOUND\0"
    );
    assert_eq!(unix_request(&sock, &stream_frame(NOTE)?)?, "stream: OK\0");
    Ok(())
}
