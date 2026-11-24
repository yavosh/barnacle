//! Compare extracted children with harmless whole-file signatures in both daemons.
#[path = "common/cabinet.rs"]
mod cabinet;
#[path = "common/chm.rs"]
mod chm;
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;
#[path = "common/legacy.rs"]
mod legacy;
#[path = "common/sis.rs"]
mod sis;
#[path = "common/zip.rs"]
mod zip;

use client::{Daemon, stream_frame, unix_request};
use flate2::{Compression, write::GzEncoder};
use md5::{Digest, Md5};
use sevenz_rust2::{
    ArchiveEntry, ArchiveWriter, EncoderConfiguration, SourceReader,
    encoder_options::{LzmaOptions, PpmdOptions},
};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const FIRST: &[u8] = b"ordinary first archive marker";
const SECOND: &[u8] = b"ordinary second archive marker";

fn gzip(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

fn solid_archive(entries: &[(&str, &[u8])], method: EncoderConfiguration) -> io::Result<Vec<u8>> {
    let mut writer = ArchiveWriter::new(io::Cursor::new(Vec::new())).map_err(io::Error::other)?;
    writer.set_content_methods(vec![method]);
    writer
        .push_archive_entries(
            entries
                .iter()
                .map(|(name, _)| ArchiveEntry::new_file(name))
                .collect(),
            entries
                .iter()
                .map(|(_, data)| SourceReader::new(*data))
                .collect(),
        )
        .map_err(io::Error::other)?;
    Ok(writer.finish()?.into_inner())
}

fn bzip(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

fn szdd(data: &[u8]) -> Vec<u8> {
    let mut out = b"SZDD\x88\xf0\x27\x33A\0".to_vec();
    out.extend((data.len() as u32).to_le_bytes());
    for group in data.chunks(8) {
        out.push(255);
        out.extend(group);
    }
    out
}

fn alz(method: u8) -> io::Result<Vec<u8>> {
    let mut out = b"ALZ\x01\0\0\0\0".to_vec();
    for data in [FIRST, SECOND] {
        let packed = match method {
            0 => data.to_vec(),
            1 => bzip(data)?,
            _ => {
                let mut encoder =
                    flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(data)?;
                encoder.finish()?
            }
        };
        out.extend(b"BLZ\x01\x05\0\x20\0\0\0\0\x20\0");
        out.extend([method, 0]);
        let mut crc = flate2::Crc::new();
        crc.update(data);
        out.extend(crc.sum().to_le_bytes());
        out.extend((packed.len() as u16).to_le_bytes());
        out.extend((data.len() as u16).to_le_bytes());
        out.extend(b"notes");
        out.extend(packed);
    }
    out.extend(b"CLZ\x01\0\0\0\0\0\0\0\0CLZ\x02");
    Ok(out)
}

fn egg(method: u8, comment: bool) -> io::Result<Vec<u8>> {
    const END: u32 = 0x08e28222;
    fn field(out: &mut Vec<u8>, kind: u32, value: &[u8]) {
        out.extend(kind.to_le_bytes());
        out.push(0);
        out.extend((value.len() as u16).to_le_bytes());
        out.extend(value);
    }
    let mut out = b"EGGA\0\x01\x01\0\0\0\0\0\0\0".to_vec();
    out.extend(END.to_le_bytes());
    for (i, data) in [if comment { SECOND } else { FIRST }, SECOND]
        .into_iter()
        .enumerate()
    {
        out.extend(0x0a8590e3u32.to_le_bytes());
        out.extend((i as u32).to_le_bytes());
        out.extend((data.len() as u64).to_le_bytes());
        field(&mut out, 0x0a8591ac, b"notes");
        out.extend(END.to_le_bytes());
        for piece in data.chunks(16) {
            let packed = match method {
                0 => piece.to_vec(),
                1 => {
                    let mut encoder =
                        flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
                    encoder.write_all(piece)?;
                    encoder.finish()?
                }
                _ => bzip(piece)?,
            };
            out.extend(0x02b50c13u32.to_le_bytes());
            out.extend([method, 0]);
            out.extend((piece.len() as u32).to_le_bytes());
            out.extend((packed.len() as u32).to_le_bytes());
            let mut crc = flate2::Crc::new();
            crc.update(piece);
            out.extend(crc.sum().to_le_bytes());
            out.extend(END.to_le_bytes());
            out.extend(packed);
        }
    }
    if comment {
        field(&mut out, 0x04c63672, FIRST);
    }
    out.extend(END.to_le_bytes());
    Ok(out)
}

fn lha(compressed: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for data in [FIRST, SECOND] {
        let packed = if compressed {
            legacy::huffman_literals(data, 4)
        } else {
            data.to_vec()
        };
        let mut header = if compressed { b"-lh5-" } else { b"-lh0-" }.to_vec();
        header.extend((packed.len() as u32).to_le_bytes());
        header.extend((data.len() as u32).to_le_bytes());
        header.extend([0; 4]);
        header.extend(b"\x20\0\x05notes");
        let mut crc = delharc::crc::Crc16::default();
        crc.digest(data);
        header.extend(crc.sum16().to_le_bytes());
        out.push(header.len() as u8);
        out.push(header.iter().copied().fold(0u8, u8::wrapping_add));
        out.extend(header);
        out.extend(packed);
    }
    out.push(0);
    out
}

fn binhex(data: &[u8], resource: &[u8]) -> Vec<u8> {
    fn append_crc(target: &mut Vec<u8>, bytes: &[u8]) {
        let mut crc = 0u16;
        for &byte in bytes {
            crc ^= u16::from(byte) << 8;
            for _ in 0..8 {
                crc = (crc << 1) ^ if crc & 0x8000 != 0 { 0x1021 } else { 0 };
            }
        }
        target.extend(bytes);
        target.extend(crc.to_be_bytes());
    }
    let mut head = b"\x05notes\0TEXTTEST\0\0".to_vec();
    head.extend((data.len() as u32).to_be_bytes());
    head.extend((resource.len() as u32).to_be_bytes());
    let mut plain = Vec::new();
    for chunk in [&head[..], data, resource] {
        append_crc(&mut plain, chunk);
    }
    let mut packed = Vec::new();
    for run in plain.chunk_by(|a, b| a == b) {
        for chunk in run.chunks(255) {
            packed.push(chunk[0]);
            if chunk[0] == 0x90 {
                packed.push(0);
            }
            if chunk.len() > 1 {
                packed.extend([0x90, chunk.len() as u8]);
            }
        }
    }
    let alphabet = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[\x60abcdefhijklmpqr";
    let mut out = b"(This file must be converted with BinHex 4.0)\r\n\r\n:".to_vec();
    let mut bits = 0u16;
    let mut count = 0;
    for byte in packed {
        bits = (bits << 8) | u16::from(byte);
        count += 8;
        while count >= 6 {
            count -= 6;
            out.push(alphabet[usize::from((bits >> count) & 63)]);
        }
    }
    if count != 0 {
        out.push(alphabet[usize::from((bits << (6 - count)) & 63)]);
    }
    out.extend(b":\r\n");
    out
}

fn stored_rar(data: &[u8]) -> Vec<u8> {
    fn add_block(out: &mut Vec<u8>, kind: u8, flags: u16, fields: &[u8]) {
        let mut head = vec![kind];
        head.extend(flags.to_le_bytes());
        head.extend(((7 + fields.len()) as u16).to_le_bytes());
        head.extend(fields);
        let mut crc = flate2::Crc::new();
        crc.update(&head);
        out.extend((crc.sum() as u16).to_le_bytes());
        out.extend(head);
    }
    let mut out = b"Rar!\x1a\x07\0".to_vec();
    add_block(&mut out, 0x73, 0, &[0; 6]);
    let mut file = (data.len() as u32).to_le_bytes().repeat(2);
    file.push(3);
    let mut crc = flate2::Crc::new();
    crc.update(data);
    file.extend(crc.sum().to_le_bytes());
    file.extend([0; 4]);
    file.extend([20, 0x30, 5, 0]);
    file.extend(0o100644u32.to_le_bytes());
    file.extend(b"notes");
    add_block(&mut out, 0x74, 0x8000, &file);
    out.extend(data);
    add_block(&mut out, 0x7b, 0x4000, &[]);
    out
}

fn tar(old: bool) -> io::Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, payload) in [("first.txt", FIRST), ("second.txt", SECOND)] {
        let mut header = if old {
            tar::Header::new_old()
        } else {
            tar::Header::new_ustar()
        };
        header.set_mode(0o644);
        header.set_size(payload.len() as u64);
        builder.append_data(&mut header, name, payload)?;
    }
    let mut data = builder.into_inner()?;
    if old {
        let checksum = data[148..156]
            .iter()
            .copied()
            .take_while(|&b| (b'0'..=b'7').contains(&b))
            .fold(0u32, |n, b| n * 8 + u32::from(b - b'0'));
        let field = format!("{checksum:06o}\0X");
        data[148..156].copy_from_slice(field.as_bytes());
    }
    Ok(data)
}

fn cpio(style: &str) -> Vec<u8> {
    let mut archive = Vec::new();
    for (name, payload) in [("first", FIRST), ("second", SECOND), ("TRAILER!!!", &[])] {
        let namesize = name.len() + 1;
        let size = payload.len();
        let alignment = match style {
            "newc" | "crc" => {
                archive.extend(if style == "crc" { b"070702" } else { b"070701" });
                let sum = if style == "crc" {
                    payload.iter().map(|&b| usize::from(b)).sum()
                } else {
                    0
                };
                for field in [1, 0o100644, 0, 0, 1, 0, size, 0, 0, 0, 0, namesize, sum] {
                    write!(archive, "{field:08x}").unwrap();
                }
                4
            }
            "odc" => {
                write!(archive, "07070700000000000110064400000000000000000100000000000000000{namesize:06o}{size:011o}").unwrap();
                1
            }
            "le" | "be" => {
                for word in [
                    0x71c7,
                    0,
                    1,
                    0o100644,
                    0,
                    0,
                    1,
                    0,
                    0,
                    0,
                    namesize as u16,
                    0,
                    size as u16,
                ] {
                    archive.extend(if style == "le" {
                        word.to_le_bytes()
                    } else {
                        word.to_be_bytes()
                    });
                }
                2
            }
            _ => unreachable!(),
        };
        archive.extend(name.bytes());
        archive.push(0);
        archive.resize(archive.len().next_multiple_of(alignment), 0);
        archive.extend(payload);
        archive.resize(archive.len().next_multiple_of(alignment), 0);
    }
    archive
}

fn compare(exe: &Path) -> io::Result<()> {
    let dir = tempfile::tempdir_in("/tmp")?;
    let db = dir.path().join("db");
    fs::create_dir(&db)?;
    let mut rules = String::new();
    let joined = [FIRST, FIRST].concat();
    let page = vec![b'a'; 8192];
    for (name, data) in [
        ("First", FIRST),
        ("Second", SECOND),
        ("Joined", &joined),
        ("Clipped", &page),
    ] {
        let digest: String = Md5::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        rules.push_str(&format!("{digest}:{}:Archive.{name}\n", data.len()));
    }
    fs::write(db.join("markers.hdb"), rules)?;
    let config = dir.path().join("clamd.conf");
    let socket = dir.path().join("clamd.sock");
    fs::write(
        &config,
        format!(
            "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nTemporaryDirectory {}\nSelfCheck 0\nDisableCache yes\nMaxFileSize 8200\n",
            socket.display(),
            db.display(),
            dir.path().display()
        ),
    )?;
    let _daemon = Daemon::start(exe, &config, &socket)?;
    let entries = [("first", FIRST), ("second", SECOND)];
    let mut gzip_members = gzip(&FIRST[..7])?;
    gzip_members.extend(gzip(&FIRST[7..])?);
    let mut bzip_members = bzip(FIRST)?;
    bzip_members.extend(bzip(SECOND)?);
    let xz = include_bytes!("fixtures/archive-child.xz");
    let mut short_gzip = gzip(FIRST)?;
    short_gzip.truncate(short_gzip.len() - 4);
    let mut local_zip = zip::zip(&entries, true, false, false)?;
    let start_directory = local_zip.len() - 22;
    let offset = u32::from_le_bytes(
        local_zip[start_directory + 16..start_directory + 20]
            .try_into()
            .unwrap(),
    );
    local_zip.truncate(offset as usize);
    let model = || PpmdOptions::from_order_memory_size(6, 64 << 20).into();
    let nested_model = solid_archive(
        &[("report", FIRST)],
        PpmdOptions::from_order_memory_size(6, 96 << 20).into(),
    )?;
    let mut cases = vec![
        ("gzip", gzip(FIRST)?),
        ("concatenated gzip", gzip_members),
        ("bzip2", bzip(FIRST)?),
        ("two bzip2 members", bzip_members),
        ("XZ", xz.to_vec()),
        (
            "7z LZMA",
            solid_archive(&[("report", FIRST)], LzmaOptions::from_level(0).into())?,
        ),
        (
            "solid PPMd nested winner before a later member",
            solid_archive(&[("first", &nested_model), ("later", SECOND)], model())?,
        ),
        ("SZDD", szdd(FIRST)),
        (
            "7z",
            legacy::sevenzip(
                false,
                &[
                    ("notes", b"ordinary unmarked archive entry"),
                    ("report", FIRST),
                ],
            )?,
        ),
        (
            "solid 7z",
            legacy::sevenzip(
                true,
                &[
                    ("notes", b"ordinary unmarked archive entry"),
                    ("report", FIRST),
                ],
            )?,
        ),
        (
            "solid 7z competing matches",
            legacy::sevenzip(true, &entries)?,
        ),
        (
            "solid 7z nested winner before a later member",
            legacy::sevenzip(true, &[("nested", &gzip(FIRST)?), ("later", SECOND)])?,
        ),
        ("stored ALZ", alz(0)?),
        ("bzip2 ALZ", alz(1)?),
        ("deflated ALZ", alz(2)?),
        ("stored EGG blocks", egg(0, false)?),
        ("deflated EGG blocks", egg(1, false)?),
        ("bzip2 EGG blocks", egg(2, false)?),
        ("EGG comment before members", egg(0, true)?),
        ("stored ARJ", legacy::arj(0, &[FIRST, SECOND])),
        ("Symbian SIS stored", sis::package(&[FIRST, SECOND], false)?),
        (
            "Symbian SIS language variants",
            sis::package(&[b"a different language", FIRST], true)?,
        ),
        ("CHM uncompressed section", chm::chm(FIRST, SECOND, false)),
        ("ARJ method 1", legacy::arj(1, &[FIRST, SECOND])),
        ("ARJ method 2", legacy::arj(2, &[FIRST, SECOND])),
        ("ARJ method 3", legacy::arj(3, &[FIRST, SECOND])),
        ("ARJ method 4", legacy::arj(4, &[FIRST, SECOND])),
        ("stored LHA", lha(false)),
        ("LH5 archive", lha(true)),
        ("BinHex data fork", binhex(FIRST, SECOND)),
        ("BinHex resource fork", binhex(b"ordinary text", FIRST)),
        ("truncated gzip trailer", short_gzip),
        ("stored ZIP", zip::zip(&entries, false, false, false)?),
        (
            "bzip2 ZIP",
            zip::zip_with_method(&entries, 12, true, false)?,
        ),
        (
            "deflated ZIP with reversed directory",
            zip::zip(&entries, true, false, true)?,
        ),
        (
            "ZIP data descriptors",
            zip::zip(&entries, true, true, false)?,
        ),
        ("TAR", tar(false)?),
        ("old TAR with a terminated checksum", tar(true)?),
        ("gzip of TAR", gzip(&tar(false)?)?),
        (
            "ZIP of gzip",
            zip::zip(&[("inner.gz", &gzip(FIRST)?)], true, true, false)?,
        ),
    ];
    for style in ["newc", "crc", "odc", "be", "le"] {
        cases.push((style, cpio(style)));
    }
    for (label, method) in [("stored CAB", 0), ("MSZIP CAB", 1), ("LZX CAB", 3)] {
        let mut dictionary = b"ordinary archive marker in the dictionary".to_vec();
        if method == 1 {
            dictionary.resize(32768, b' ');
            dictionary[32768 - FIRST.len()..].copy_from_slice(FIRST);
        }
        cases.push((label, cabinet::cabinet(&dictionary, FIRST, method)?));
    }
    for (label, data) in cases {
        assert_eq!(
            unix_request(&socket, &stream_frame(&data)?)?,
            "stream: Archive.First.UNOFFICIAL FOUND\0",
            "{label}"
        );
    }
    for method in [8, 12] {
        let data = zip::zip_with_method(&[("notes", &vec![b'a'; 8201])], method, false, false)?;
        assert_eq!(
            unix_request(&socket, &stream_frame(&data)?)?,
            "stream: Archive.Clipped.UNOFFICIAL FOUND\0",
            "ZIP method {method}, clipped at 8200"
        );
    }
    assert_eq!(
        unix_request(&socket, &stream_frame(&xz.repeat(2))?)?,
        "stream: Archive.Joined.UNOFFICIAL FOUND\0",
        "two XZ streams"
    );
    // The fixture uses one LZMA2 filter. A larger valid dictionary preserves
    // its output, and the second stream requires a larger admission charge.
    let mut larger_window = xz.to_vec();
    larger_window[18] = 30;
    let mut checksum = flate2::Crc::new();
    checksum.update(&larger_window[12..28]);
    larger_window[28..32].copy_from_slice(&checksum.sum().to_le_bytes());
    let joined = [xz.as_slice(), &larger_window].concat();
    assert_eq!(
        unix_request(&socket, &stream_frame(&joined)?)?,
        "stream: Archive.Joined.UNOFFICIAL FOUND\0",
        "two XZ streams with increasing dictionaries"
    );
    let expected = if exe == Path::new("/usr/sbin/clamd") {
        "stream: OK\0"
    } else {
        "stream: Incomplete scan: unsupported detection coverage. ERROR\0"
    };
    assert_eq!(
        unix_request(&socket, &stream_frame(&stored_rar(FIRST))?)?,
        expected,
        "the pinned Debian clamd has no optional UnRAR module"
    );
    assert_eq!(
        unix_request(&socket, &stream_frame(&sis::v9(FIRST))?)?,
        expected,
        "ordinary Symbian SIS v9 with a stored data unit"
    );
    assert_eq!(
        unix_request(&socket, &stream_frame(&local_zip)?)?,
        expected,
        "ZIP with local headers only"
    );
    assert_eq!(
        unix_request(&socket, &stream_frame(&xz[..xz.len() - 4])?)?,
        expected,
        "truncated XZ trailer"
    );
    drop(_daemon);
    let config = dir.path().join("chm.conf");
    let socket = dir.path().join("chm.sock");
    fs::write(
        &config,
        format!(
            "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nTemporaryDirectory {}\nSelfCheck 0\nDisableCache yes\n",
            socket.display(),
            db.display(),
            dir.path().display()
        ),
    )?;
    let _chm_daemon = Daemon::start(exe, &config, &socket)?;
    assert_eq!(
        unix_request(&socket, &stream_frame(&chm::chm(FIRST, SECOND, true))?)?,
        "stream: Archive.First.UNOFFICIAL FOUND\0",
        "CHM member crossing an LZX reset"
    );
    drop(_chm_daemon);
    let socket = dir.path().join("deadline.sock");
    let config = dir.path().join("deadline.conf");
    fs::write(
        &config,
        format!(
            "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nTemporaryDirectory {}\nSelfCheck 0\nDisableCache yes\nMaxScanTime 1\nAlertExceedsMax yes\n",
            socket.display(),
            db.display(),
            dir.path().display()
        ),
    )?;
    let report = b"Ordinary monthly filing notes.\n".repeat(512 * 1024);
    let entries = [("report", report.as_slice()), ("later", SECOND)];
    let _deadline_daemon = Daemon::start(exe, &config, &socket)?;
    for archive in [
        legacy::sevenzip(true, &entries)?,
        solid_archive(&entries, model())?,
    ] {
        assert_eq!(
            unix_request(&socket, &stream_frame(&archive)?)?,
            "stream: Heuristics.Limits.Exceeded.MaxScanTime FOUND\0",
            "deadline during solid 7z before a later match"
        );
    }
    Ok(())
}

#[test]
fn nested_archive_children() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
#[ignore = "requires Debian clamd 1.4.3+dfsg-1"]
fn stock_archive_children() -> io::Result<()> {
    let package = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(package.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"))
}
