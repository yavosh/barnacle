use super::{
    CBC, PARTIAL_MISS, STOCK_MISS, pe, scalar, start, stream_frame, unix_request, verify_stock,
};
use std::{fs, io, path::Path};

// One read-only .data section containing numbers and labels. The fixture has no executable section.
pub(super) fn receipt(label_offset: usize) -> Vec<u8> {
    let mut bytes = pe::benign_pe();
    bytes.resize(512 + 4096, 0);
    bytes[512..].fill(0);
    // Data size, entry RVA, and the virtual and raw sizes of the data section.
    for offset in [160, 168, 384, 392] {
        bytes[offset..offset + 4].copy_from_slice(&4096u32.to_le_bytes());
    }
    bytes[544..551].copy_from_slice(b"receipt");
    let mut start = 512 + label_offset;
    bytes[start..start + 15].copy_from_slice(b"GetProcAddress\0");
    start += 15;
    for delta in [0x505a4f, 0xffffb, 0xb8] {
        let value = u32::from_le_bytes(*b"note");
        bytes[start..start + 4].copy_from_slice(&value.to_le_bytes());
        bytes[start + 4..start + 8].copy_from_slice(&(value ^ delta).to_le_bytes());
        start += 8;
    }
    bytes
}

fn compare(executable: &Path, miss: &str) -> io::Result<()> {
    let found = "stream: Heuristics.W32.Parite.B FOUND\0";
    let raw = "stream: Receipt.Raw.UNOFFICIAL FOUND\0";
    let positive = receipt(128);
    let mut first_label = positive.clone();
    first_label[575..590].copy_from_slice(b"GetProcAddress\0");
    let mut dll = positive.clone();
    dll[151] |= 0x20;
    let mut inner_entry = positive.clone();
    inner_entry[168..172].copy_from_slice(&4097u32.to_le_bytes());
    let mut missing_section = positive.clone();
    missing_section[134] = 2;
    missing_section.copy_within(376..416, 416);
    missing_section[428..432].copy_from_slice(&0x2000u32.to_le_bytes());
    missing_section[436..440].copy_from_slice(&0x2000u32.to_le_bytes());
    let mut virtual_section = missing_section.clone();
    virtual_section[432..436].fill(0);
    let mut bad_pair = positive.clone();
    bad_pair[676] ^= 1;
    let mut competing = positive.clone();
    competing[624..630].copy_from_slice(b"rawtag");
    let mut untriggered = positive.clone();
    untriggered[544] = b'R';
    let ordinary = pe::benign_pe();
    let boundary = receipt(4025);
    let outside = receipt(4026);
    for (options, cases) in [
        (
            "",
            vec![
                ("receipt", positive.as_slice(), found),
                ("ordinary", &ordinary, miss),
                ("short entry window", &positive[..positive.len() - 1], miss),
                ("edge label", &boundary, found),
                ("outside label window", &outside, miss),
                ("wrong pair", &bad_pair, miss),
                ("first label", &first_label, miss),
                ("DLL", &dll, miss),
                ("interior entry", &inner_entry, miss),
                ("missing trailing section", &missing_section, found),
                ("virtual trailing section", &virtual_section, miss),
                ("raw match", &competing, raw),
            ],
        ),
        ("ScanPE no\n", vec![("receipt", &positive, miss)]),
        ("HeuristicAlerts no\n", vec![("receipt", &positive, miss)]),
        (
            "HeuristicScanPrecedence yes\n",
            vec![("raw before heuristic", &competing, raw)],
        ),
        (
            "BytecodeUnsigned yes\nBytecodeMode ForceInterpreter\n",
            vec![
                ("hook breaks", &positive, miss),
                ("hook idle", &untriggered, found),
            ],
        ),
    ] {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join("raw.ndb"), "Receipt.Raw:1:624:726177746167\n")?;
        if options.contains("BytecodeUnsigned") {
            fs::write(db.join(CBC), scalar::pe_all_break())?;
        }
        let (_daemon, socket) = start(dir.path(), executable, options)?;
        for (label, input, expected) in cases {
            assert_eq!(
                unix_request(&socket, &stream_frame(input)?)?,
                expected,
                "{options} {label}"
            );
        }
    }
    Ok(())
}

#[test]
fn barnacle_parite() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), PARTIAL_MISS)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_parite() -> io::Result<()> {
    verify_stock()?;
    compare(Path::new("/usr/sbin/clamd"), STOCK_MISS)
}
