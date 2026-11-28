use super::{
    CBC, PARTIAL_MISS, STOCK_MISS, parite, pe, scalar, start, stream_frame, unix_request,
    verify_stock,
};
use std::{fs, io, path::Path};

// Two data sections, no executable section, zero entry RVA. The last section contains one numeric record.
pub(super) fn receipt(virtual_size: u32, disk_size: u32, tag: u32, tag_offset: usize) -> Vec<u8> {
    let mut image = pe::benign_pe();
    image[512..].fill(0);
    image.resize(1024 + disk_size as usize, 0);
    image[134] = 2;
    image[208..212].copy_from_slice(&0xc000u32.to_le_bytes());
    image.copy_within(376..416, 416);
    image[416..424].copy_from_slice(b".notes\0\0");
    for (offset, value) in [
        (424, virtual_size),
        (428, 8192),
        (432, disk_size),
        (436, 1024),
        (452, 0xc0000040),
    ] {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    image[544..551].copy_from_slice(b"receipt");
    let start = 1024 + tag_offset;
    image[start] = 232;
    image[start + 1..start + 5].copy_from_slice(&tag.to_le_bytes());
    image
}

fn compare(executable: &Path, miss: &str) -> io::Result<()> {
    let a_name = "stream: Heuristics.W32.Magistr.A FOUND\0";
    let b_name = "stream: Heuristics.W32.Magistr.B FOUND\0";
    let raw_name = "stream: Receipt.Raw.UNOFFICIAL FOUND\0";
    let parite_name = "stream: Heuristics.W32.Parite.B FOUND\0";
    let a = receipt(0x61ec, 0x6400, 0x612c, 64);
    let b = receipt(0x70ed, 0x7200, 0x7204, 64);
    let mut both = a.clone();
    both[168..172].copy_from_slice(&8192u32.to_le_bytes());
    both[1152..1191].copy_from_slice(&parite::receipt(128)[640..679]);
    let mut dll = a.clone();
    dll[151] |= 0x20;
    let mut read_only = b.clone();
    read_only[455] &= 0x7f;
    let mut unaligned = a[..a.len() - 128].to_vec();
    unaligned[436..440].copy_from_slice(&1027u32.to_le_bytes());
    let mut single = a.clone();
    single[134] = 1;
    single.copy_within(416..456, 376);
    let mut missing = a.clone();
    missing[134] = 3;
    missing.copy_within(416..456, 456);
    missing[476..480].copy_from_slice(&65536u32.to_le_bytes());
    let mut virtual_last = missing.clone();
    virtual_last[472..476].fill(0);
    let mut raw = a.clone();
    raw[624..630].copy_from_slice(b"rawtag");
    let mut idle = b.clone();
    idle[544] = b'R';
    let a_edge = receipt(0x61ec, 0x9000, 0x612c, 0x2000 + 4086);
    let a_outside = receipt(0x61ec, 0x9000, 0x612c, 0x2000 + 4087);
    let b_edge = receipt(0x70ed, 0x9000, 0x7204, 0x1000);
    let b_outside = receipt(0x70ed, 0x9000, 0x7204, 0x1000 - 1);
    let wrong_tag = receipt(0x61ec, 0x6400, 0x7204, 64);
    let small_disk = receipt(0x61ec, 0x6000, 0x612c, 64);
    let small_virtual = receipt(0x6fed, 0x7200, 0x7204, 64);
    for (options, cases) in [
        (
            "",
            vec![
                ("A", a.as_slice(), a_name),
                ("B", &b, b_name),
                ("clipped raw size", &a[..a.len() - 128], a_name),
                ("unaligned clipped data", &unaligned, a_name),
                ("A at search end", &a_edge, a_name),
                ("A beyond search", &a_outside, miss),
                ("B at search start", &b_edge, b_name),
                ("B before search", &b_outside, miss),
                ("missing last section", &missing, a_name),
                ("virtual last section", &virtual_last, miss),
                ("read only", &read_only, miss),
                ("DLL", &dll, miss),
                ("single section", &single, miss),
                ("small physical", &small_disk, miss),
                ("small virtual", &small_virtual, miss),
                ("wrong tag", &wrong_tag, miss),
                ("raw priority", &raw, raw_name),
                ("Parite competition", &both, a_name),
            ],
        ),
        ("HeuristicAlerts no\n", vec![("A", &a, miss)]),
        ("ScanPE no\n", vec![("B", &b, miss)]),
        (
            "HeuristicScanPrecedence yes\n",
            vec![
                ("raw priority", &raw, raw_name),
                ("Parite competition", &both, parite_name),
            ],
        ),
        (
            "BytecodeUnsigned yes\nBytecodeMode ForceInterpreter\n",
            vec![("hook stops", &a, miss), ("hook idle", &idle, b_name)],
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
        for (label, input, winner) in cases {
            let reply = unix_request(&socket, &stream_frame(input)?)?;
            // Stock may report either name when both heuristics are deferred.
            if miss == STOCK_MISS
                && options.is_empty()
                && label == "Parite competition"
                && reply == parite_name
            {
                continue;
            }
            assert_eq!(reply, winner, "{options} {label}");
        }
    }
    Ok(())
}

#[test]
fn barnacle_magistr() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), PARTIAL_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_magistr() -> io::Result<()> {
    verify_stock()?;
    compare(Path::new("/usr/sbin/clamd"), STOCK_MISS)
}
