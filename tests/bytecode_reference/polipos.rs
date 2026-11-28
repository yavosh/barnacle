use super::{
    CBC, PARTIAL_MISS, STOCK_MISS, parite, pe, scalar, start, stream_frame, unix_request,
    verify_stock,
};
use std::{fs, io, path::Path};

const FOUND: &str = "stream: Heuristics.W32.Polipos.A FOUND\0";
const TARGET_RVA: u32 = 0x8000;

fn word(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

// The entry point only returns. The source records are in a read-only data section.
// Stock requires executable flags on the target. Nothing in the entry section references it.
fn ledger(source_size: usize, target_size: usize) -> Vec<u8> {
    let mut image = pe::benign_pe();
    image.resize(1024 + source_size + target_size, 0);
    image[512..].fill(0);
    image[134] = 3;
    word(&mut image, 168, 0x6000);
    word(&mut image, 208, 0x14000);
    word(&mut image, 224, 0x80000);
    word(&mut image, 384, source_size as u32);
    word(&mut image, 392, source_size as u32);
    for (i, (name, vsz, rva, size, raw, flags)) in [
        (
            b".entry\0\0".as_slice(),
            512,
            0x6000,
            512,
            512 + source_size,
            0x60000020,
        ),
        (
            b".ledger\0".as_slice(),
            49152,
            TARGET_RVA,
            target_size,
            1024 + source_size,
            0xe0000060,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let h = 416 + i * 40;
        image[h..h + 8].copy_from_slice(name);
        for (offset, value) in [
            (8, vsz),
            (12, rva),
            (16, size as u32),
            (20, raw as u32),
            (36, flags),
        ] {
            word(&mut image, h + offset, value);
        }
    }
    image[512 + source_size] = 0xc3;
    image[544..551].copy_from_slice(b"receipt");
    image
}

fn reference(image: &mut [u8], from: usize, target: usize) {
    image[512 + from] = 0xe8;
    word(
        image,
        513 + from,
        TARGET_RVA + target as u32 - (0x1000 + from as u32 + 5),
    );
}

fn receipt() -> Vec<u8> {
    let mut image = ledger(512, 512);
    reference(&mut image, 64, 32);
    image[1568..1572].copy_from_slice(&[0x55, 0x8b, 0xec, 0x60]);
    image
}

fn many_targets(accepted: usize) -> Vec<u8> {
    let source_size = 16384;
    let mut image = ledger(source_size, 2048);
    for i in 0..1281 {
        reference(&mut image, 64 + 8 * i, i);
    }
    let at = 1024 + source_size + accepted;
    image[at..at + 4].copy_from_slice(&[0x55, 0x8b, 0xec, 0x60]);
    image
}

fn thirteen_sections(missing: bool) -> Vec<u8> {
    let mut image = receipt();
    image.resize(2560, 0);
    image.copy_within(512..2048, 1024);
    image[512..1024].fill(0);
    image[134] = 13;
    word(&mut image, 212, 1024);
    for (i, raw) in [1024, 1536, 2048].into_iter().enumerate() {
        word(&mut image, 396 + 40 * i, raw);
    }
    for i in 3..13 {
        let h = 376 + 40 * i;
        word(&mut image, h + 12, 0x14000 + i as u32 * 0x1000);
        if missing {
            word(&mut image, h + 16, 512);
            word(&mut image, h + 20, 0x10000);
        }
    }
    image
}

fn compare(executable: &Path, miss: &str) -> io::Result<()> {
    let positive = receipt();
    let change = |at, value| {
        let mut image = positive.clone();
        word(&mut image, at, value);
        image
    };
    let mut misplaced = positive.clone();
    misplaced[576..581].fill(0);
    reference(&mut misplaced, 507, 32);
    let mut target_edge = positive.clone();
    reference(&mut target_edge, 64, 503);
    target_edge[2039..2043].copy_from_slice(&positive[1568..1572]);
    let mut short_target = target_edge.clone();
    reference(&mut short_target, 64, 504);
    short_target[2040..2044].copy_from_slice(&positive[1568..1572]);
    let mut outside_first = positive.clone();
    outside_first.copy_within(376..496, 416);
    outside_first[134] = 4;
    word(&mut outside_first, 396, 0x10000);
    let mut virtual_first = outside_first.clone();
    word(&mut virtual_first, 392, 0);
    let mut later_candidate = positive.clone();
    later_candidate.resize(2560, 0);
    later_candidate.copy_within(456..496, 496);
    later_candidate[134] = 4;
    word(&mut later_candidate, 508, 0x14000);
    word(&mut later_candidate, 516, 2048);
    let mut later_missing = later_candidate.clone();
    word(&mut later_missing, 516, 0x10000);
    let mut variant_two = positive.clone();
    variant_two[1568..1575].copy_from_slice(&[0x55, 0x8b, 0xec, 0x83, 0xec, 0, 0x60]);
    let mut variant_three = positive.clone();
    variant_three[1568..1577].copy_from_slice(&[0x55, 0x8b, 0xec, 0x81, 0xec, 0, 0, 0, 0]);
    let mut both = positive.clone();
    both.resize(1536 + 4096, 0);
    word(&mut both, 168, TARGET_RVA);
    word(&mut both, 472, 4096);
    both[1536] = 0xc3;
    both[1664..1703].copy_from_slice(&parite::receipt(128)[640..679]);
    let mut raw = positive.clone();
    raw[624..630].copy_from_slice(b"rawtag");
    let mut idle = positive.clone();
    idle[544] = b'R';
    let raw_name = "stream: Receipt.Raw.UNOFFICIAL FOUND\0";
    let parite_name = "stream: Heuristics.W32.Parite.B FOUND\0";
    let mut repeated = many_targets(1280);
    reference(&mut repeated, 64 + 8 * 1279, 0);
    let cases = [
        ("positive", positive.clone(), FOUND),
        ("second target form", variant_two, FOUND),
        ("third target form", variant_three, FOUND),
        ("unmapped reference", change(577, 0x100000), miss),
        ("ordinary data", change(1568, 0), miss),
        ("machine", change(132, 0x0003_8664), miss),
        ("DLL", change(148, 0x2002_00e0), miss),
        ("subsystem", change(220, 1), miss),
        ("stack", change(224, 0x7ffff), miss),
        ("virtual size", change(464, 24000), miss),
        ("section flags", change(492, 0xc0000040), miss),
        ("last source position excluded", misplaced, miss),
        ("last full target", target_edge, FOUND),
        ("target clipped", short_target, miss),
        ("missing first section removed", outside_first, FOUND),
        ("virtual first section retained", virtual_first, miss),
        ("last candidate wins", later_candidate, miss),
        ("missing candidate removed", later_missing, FOUND),
        ("thirteen retained sections", thirteen_sections(false), miss),
        (
            "ten of thirteen sections missing",
            thirteen_sections(true),
            FOUND,
        ),
        ("last accepted target", many_targets(1279), FOUND),
        ("target beyond cap", many_targets(1280), miss),
        ("repeated target counts once", repeated, FOUND),
        ("earlier raw", raw.clone(), raw_name),
        ("Parite competition", both.clone(), FOUND),
    ];
    for (options, subset) in [
        (
            "",
            cases
                .iter()
                .map(|(label, b, w)| (*label, b.as_slice(), *w))
                .collect::<Vec<_>>(),
        ),
        (
            "HeuristicAlerts no\n",
            vec![("alerts off", positive.as_slice(), miss)],
        ),
        ("ScanPE no\n", vec![("PE off", &positive, miss)]),
        (
            "HeuristicScanPrecedence yes\n",
            vec![
                ("earlier raw", &raw, raw_name),
                ("immediate", &positive, FOUND),
                ("Parite competition", &both, parite_name),
            ],
        ),
        (
            "BytecodeUnsigned yes\nBytecodeMode ForceInterpreter\n",
            vec![("hook break", &positive, miss), ("idle hook", &idle, FOUND)],
        ),
    ] {
        let root = tempfile::tempdir_in("/tmp")?;
        let db = root.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join("raw.ndb"), "Receipt.Raw:1:624:726177746167\n")?;
        if options.contains("BytecodeUnsigned") {
            fs::write(db.join(CBC), scalar::pe_all_break())?;
        }
        let (_daemon, socket) = start(root.path(), executable, options)?;
        for (label, data, expected) in subset {
            let reply = unix_request(&socket, &stream_frame(data)?)?;
            // Pinned stock may choose either deferred heuristic.
            if options.is_empty()
                && miss == STOCK_MISS
                && label == "Parite competition"
                && reply == parite_name
            {
                continue;
            }
            assert_eq!(reply, expected, "{options} {label}");
        }
    }
    Ok(())
}

#[test]
fn barnacle_polipos() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), PARTIAL_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_polipos() -> io::Result<()> {
    verify_stock()?;
    compare(Path::new("/usr/sbin/clamd"), STOCK_MISS)
}
