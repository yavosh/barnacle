//! Compare image fuzzy logical signatures with the pinned Debian daemon.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;
#[path = "common/zip.rs"]
mod zip;

use client::{Daemon, stream_frame, unix_request};
use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
use std::{
    fs,
    io::{self, Cursor},
    path::Path,
};

const HASH: &str = "e3f302e2c0e7ec51";

fn mosaic(width: u32, height: u32) -> DynamicImage {
    let colors = [
        [27, 42, 49],
        [212, 83, 43],
        [223, 213, 176],
        [92, 173, 117],
        [45, 89, 172],
        [236, 172, 39],
    ];
    DynamicImage::ImageRgb8(RgbImage::from_fn(width, height, |x, y| {
        let region =
            (x / 7 + 2 * (y / 9) + u32::from(x * x + 2 * y * y < width * height) + x * y / 193) % 6;
        Rgb(colors[region as usize])
    }))
}

fn encode(image: &DynamicImage, format: ImageFormat) -> io::Result<Vec<u8>> {
    let mut bytes = Cursor::new(Vec::new());
    image
        .write_to(&mut bytes, format)
        .map_err(io::Error::other)?;
    Ok(bytes.into_inner())
}

fn compare(executable: &Path, stock: bool) -> io::Result<()> {
    let temporary = tempfile::tempdir_in("/tmp")?;
    let db = temporary.path().join("db");
    let socket = temporary.path().join("socket");
    let config = temporary.path().join("clamd.conf");
    fs::create_dir(&db)?;
    let run = |target: &str,
               expression: &str,
               children: &str,
               options: &str,
               cases: &[(&[u8], bool)]| {
        fs::write(
            &config,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\nSelfCheck 0\n{options}",
                db.display(),
                socket.display()
            ),
        )?;
        let record =
            format!("Logical.Image;Engine:150-255,Target:{target};{expression};{children}\n");
        fs::write(db.join("local.ldb"), &record)?;
        let _daemon = Daemon::start(executable, &config, &socket)?;
        for &(bytes, found) in cases {
            let expected = match (stock, found) {
                (_, true) => "stream: Logical.Image.UNOFFICIAL FOUND\0",
                (true, false) => "stream: OK\0",
                (false, false) => {
                    "stream: Incomplete scan: unsupported detection coverage. ERROR\0"
                }
            };
            assert_eq!(
                unix_request(&socket, &stream_frame(bytes)?)?,
                expected,
                "{record:?} on {} bytes",
                bytes.len()
            );
        }
        io::Result::Ok(())
    };

    let mosaic = mosaic(47, 61);
    let png = encode(&mosaic, ImageFormat::Png)?;
    let jpg = encode(&mosaic, ImageFormat::Jpeg)?;
    let gif = encode(&mosaic, ImageFormat::Gif)?;
    let tiff = encode(&mosaic, ImageFormat::Tiff)?;
    let bmp = encode(&mosaic, ImageFormat::Bmp)?;
    let bmp_rgba = encode(
        &DynamicImage::ImageRgba8(mosaic.to_rgba8()),
        ImageFormat::Bmp,
    )?;
    let gray_bmp = encode(&DynamicImage::new_rgb8(32, 32), ImageFormat::Bmp)?;
    let gray = encode(&DynamicImage::new_luma8(32, 32), ImageFormat::Png)?;
    let rule = format!("fuzzy_img#{HASH}#0");
    run(
        "0",
        "0",
        &rule,
        "",
        &[
            (&png, true),
            (&jpg, true),
            (&gif, true),
            (&tiff, true),
            (&bmp, true),
            (&bmp_rgba, true),
            (&gray_bmp, false),
            (&gray, false),
        ],
    )?;
    run(
        "5",
        "0&1",
        &format!("{rule};{rule}"),
        "",
        &[(&png, true), (&bmp, true)],
    )?;
    run(
        "0",
        "1",
        &format!(r"{rule};0/\x89PNG/"),
        "",
        &[(&png, true), (&jpg, false)],
    )?;
    run(
        "0",
        "0",
        &rule,
        "ScanImageFuzzyHash no\n",
        &[(&png, false), (&bmp, false)],
    )?;
    run(
        "0",
        "0",
        &rule,
        "ScanImage no\n",
        &[(&png, false), (&bmp, false)],
    )?;
    let archive = zip::zip(&[("tile.png", &png)], true, false, false)?;
    let bmp_archive = zip::zip(&[("tile.bmp", &bmp)], true, false, false)?;
    run(
        "0,Container:CL_TYPE_ZIP",
        "0",
        &rule,
        "",
        &[
            (&png, false),
            (&archive, true),
            (&bmp, false),
            (&bmp_archive, true),
        ],
    )?;
    run(
        "0",
        "0=0",
        &rule,
        "",
        &[
            (&png, false),
            (&gray, true),
            (b"ordinary ledger receipt", true),
        ],
    )?;

    let large_png = encode(&DynamicImage::new_luma8(140_000, 1), ImageFormat::Png)?;
    let header = "Logical.Header;Target:5;0;0:89504e470d0a1a0a\n";
    let fuzzy = format!("Logical.Fuzzy;Engine:150-255,Target:5;0;{rule}\n");
    let restricted =
        format!("Logical.ZipImage;Engine:150-255,Target:5,Container:CL_TYPE_ZIP;0;{rule}\n");
    let mixed = format!("Logical.Mixed;Engine:150-255,Target:5;0|1;0:89504e470d0a1a0a;{rule}\n");
    let mixed_regex = format!(
        "Logical.MixedRegex;Engine:150-255,Target:5;0|2;0:89504e470d0a1a0a;{rule};1/office/\n"
    );
    let impossible = format!("Logical.RequireBoth;Engine:150-255,Target:5;0&1;0:41424344;{rule}\n");
    for (records, winner) in [
        (format!("{restricted}{header}"), "Header"),
        (format!("{header}{fuzzy}"), "Header"),
        (mixed, "Mixed"),
        (mixed_regex, "MixedRegex"),
        (format!("{impossible}{header}"), "Header"),
    ] {
        fs::write(db.join("local.ldb"), &records)?;
        let _daemon = Daemon::start(executable, &config, &socket)?;
        assert_eq!(
            unix_request(&socket, &stream_frame(&large_png)?)?,
            format!("stream: Logical.{winner}.UNOFFICIAL FOUND\0"),
            "{records}"
        );
    }
    if !stock {
        let generic_header = header.replace("Target:5", "Target:0");
        fs::write(db.join("local.ldb"), format!("{generic_header}{fuzzy}"))?;
        let _daemon = Daemon::start(executable, &config, &socket)?;
        assert_eq!(
            unix_request(&socket, &stream_frame(&large_png)?)?,
            "stream: image fuzzy hash exceeds the decoded image budget. ERROR\0"
        );
    }

    fs::write(
        db.join("local.ldb"),
        format!("Logical.Image;Engine:150-255,Target:0;0;fuzzy_img#{HASH}#1\n"),
    )?;
    assert!(Daemon::start(executable, &config, &socket).is_err());
    Ok(())
}

#[test]
fn local_image_fuzzy() -> io::Result<()> {
    let executable = std::env::var_os("BARNACLE_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_barnacle").into());
    compare(Path::new(&executable), false)
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_image_fuzzy() -> io::Result<()> {
    let executable =
        std::env::var_os("BARNACLE_REFERENCE_CLAMD").unwrap_or_else(|| "/usr/sbin/clamd".into());
    compare(Path::new(&executable), true)
}
