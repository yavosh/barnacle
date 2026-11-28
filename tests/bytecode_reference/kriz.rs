use super::{
    CBC, PARTIAL_MISS, STOCK_MISS, magistr, parite, pe, scalar, start, stream_frame, unix_request,
    verify_stock,
};
use std::{fs, io, path::Path};

// Only a read-only data section. Its entry immediately returns. The unreachable marker
// has a zero XOR mask and no payload. These bytes are only submitted to scanners.
fn receipt(entry_offset: usize, skip: u8) -> Vec<u8> {
    let mut image = pe::benign_pe();
    image.resize(512 + 4096, 0);
    image[512..].fill(0);
    for offset in [160, 384, 392] {
        image[offset..offset + 4].copy_from_slice(&4096u32.to_le_bytes());
    }
    image[168..172].copy_from_slice(&(4096 + entry_offset as u32).to_le_bytes());
    let entry = &mut image[512 + entry_offset..];
    entry[..8].copy_from_slice(&[0xc3, 0x9c, 0x60, 0xe8, skip, 0, 0, 0]);
    let at = 8 + usize::from(skip);
    entry[at..at + 17].copy_from_slice(&[
        0x58, 0xb9, 0xd2, 0x0f, 0, 0, 0x80, 0xb0, b'n', b'o', b't', b'e', 0, 0x48, 0x49, 0x75, 0xf8,
    ]);
    image
}

fn compare(executable: &Path, miss: &str) -> io::Result<()> {
    let found = "stream: Heuristics.W32.Kriz FOUND\0";
    let mut positive = receipt(0, 0);
    positive[544..551].copy_from_slice(b"receipt");
    let mut dll = positive.clone();
    dll[151] |= 0x20;
    let mut pe64 = positive.clone();
    pe64.copy_within(376..416, 392);
    pe64[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
    pe64[148..150].copy_from_slice(&240u16.to_le_bytes());
    pe64[152..154].copy_from_slice(&0x20bu16.to_le_bytes());
    pe64[260..264].copy_from_slice(&16u32.to_le_bytes());
    let mut wrong_register = positive.clone();
    wrong_register[533] = 0x49;
    let mut outside_loop = positive.clone();
    outside_loop[536] = 0xf9;
    let mut lower_loop_edge = positive.clone();
    lower_loop_edge[536] = 0xf5;
    let mut before_loop = positive.clone();
    before_loop[536] = 0xf4;
    let mut with_noise = positive.clone();
    let padding = [0x81, 0, 0, 0, 0, 0, 0xba, 0, 0, 0, 0, 0x4a, 0x3e];
    with_noise.copy_within(526..537, 526 + padding.len());
    with_noise[526..526 + padding.len()].copy_from_slice(&padding);
    let mut counter_clobber = with_noise.clone();
    counter_clobber[532] = 0xb9;
    let mut misplaced = positive.clone();
    misplaced[134] = 2;
    misplaced.copy_within(376..416, 416);
    misplaced[428..432].copy_from_slice(&8192u32.to_le_bytes());
    misplaced[436..440].copy_from_slice(&4608u32.to_le_bytes());
    let missing_tail = misplaced.clone();
    misplaced.resize(4608 + 512, 0);
    let mut raw = positive.clone();
    raw[896..902].copy_from_slice(b"rawtag");
    let mut both = positive.clone();
    both[640..679].copy_from_slice(&parite::receipt(128)[640..679]);
    let mut with_magistr = magistr::receipt(0x61ec, 0x6400, 0x612c, 64);
    with_magistr[168..172].copy_from_slice(&8192u32.to_le_bytes());
    with_magistr[1024..1049].copy_from_slice(&positive[512..537]);
    let inside_extent = receipt(46, 0);
    let outside_extent = receipt(47, 0);
    let inside_window = receipt(0, 171);
    let outside_window = receipt(0, 172);
    for (options, cases) in [
        (
            "",
            vec![
                ("data receipt", positive.as_slice(), found),
                ("DLL", &dll, found),
                ("PE32+", &pe64, miss),
                (
                    "last section ends at the required extent",
                    &inside_extent,
                    found,
                ),
                ("last section is one byte short", &outside_extent, miss),
                (
                    "last seven bytes of the entry window",
                    &inside_window,
                    found,
                ),
                ("entry window exhausted", &outside_window, miss),
                ("different register", &wrong_register, miss),
                ("outside signed loop range", &outside_loop, miss),
                ("lower signed loop edge", &lower_loop_edge, found),
                ("before signed loop range", &before_loop, miss),
                ("unrelated register and prefix", &with_noise, found),
                ("modified counter register", &counter_clobber, miss),
                ("earlier section", &misplaced, miss),
                ("missing trailing section", &missing_tail, found),
                (
                    "raw signature",
                    &raw,
                    "stream: Receipt.Raw.UNOFFICIAL FOUND\0",
                ),
            ],
        ),
        ("HeuristicAlerts no\n", vec![("off", &positive, miss)]),
        ("ScanPE no\n", vec![("PE off", &positive, miss)]),
        (
            "HeuristicScanPrecedence yes\n",
            vec![
                (
                    "Parite first",
                    &both,
                    "stream: Heuristics.W32.Parite.B FOUND\0",
                ),
                ("Kriz before Magistr", &with_magistr, found),
            ],
        ),
        (
            "BytecodeUnsigned yes\nBytecodeMode ForceInterpreter\n",
            vec![("PE_ALL break", &positive, miss)],
        ),
    ] {
        let root = tempfile::tempdir_in("/tmp")?;
        let db = root.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join("raw.ndb"), "Receipt.Raw:1:896:726177746167\n")?;
        if options.contains("BytecodeUnsigned") {
            fs::write(db.join(CBC), scalar::pe_all_break())?;
        }
        let (_daemon, socket) = start(root.path(), executable, options)?;
        for (label, bytes, expected) in cases {
            assert_eq!(
                unix_request(&socket, &stream_frame(bytes)?)?,
                expected,
                "{options} {label}"
            );
        }
    }
    Ok(())
}

#[test]
fn barnacle_kriz() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), PARTIAL_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_kriz() -> io::Result<()> {
    verify_stock()?;
    compare(Path::new("/usr/sbin/clamd"), STOCK_MISS)
}
