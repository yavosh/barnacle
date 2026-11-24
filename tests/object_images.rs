//! Check image file types, raw body winners, and whole-file hashes on benign pixels.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;

use std::{fs, io, path::Path};

fn pixels() -> Vec<(&'static str, Vec<u8>)> {
    let mut bmp = vec![0u8; 58];
    bmp[..2].copy_from_slice(b"BM");
    bmp[2..6].copy_from_slice(&58u32.to_le_bytes());
    bmp[10] = 54;
    bmp[14] = 40;
    bmp[18] = 1;
    bmp[22] = 1;
    bmp[26] = 1;
    bmp[28] = 24;
    let gif =
        b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;"
            .to_vec();
    vec![
        ("Bmp", bmp),
        ("Gif", gif),
        ("Png", include_bytes!("fixtures/images/blue.png").to_vec()),
        ("Jpeg", include_bytes!("fixtures/images/blue.jpg").to_vec()),
        ("Tiff", include_bytes!("fixtures/images/blue.tiff").to_vec()),
    ]
}

// One frame of unsigned 8-bit mono PCM, followed by RIFF's alignment byte.
fn wave(big_endian: bool) -> Vec<u8> {
    let word = |n: u16| {
        if big_endian {
            n.to_be_bytes()
        } else {
            n.to_le_bytes()
        }
    };
    let long = |n: u32| {
        if big_endian {
            n.to_be_bytes()
        } else {
            n.to_le_bytes()
        }
    };
    let mut bytes = if big_endian { b"RIFX" } else { b"RIFF" }.to_vec();
    bytes.extend(long(38));
    bytes.extend(b"WAVEfmt ");
    bytes.extend(long(16));
    bytes.extend(word(1));
    bytes.extend(word(1));
    bytes.extend(long(8000));
    bytes.extend(long(8000));
    bytes.extend(word(1));
    bytes.extend(word(8));
    bytes.extend(b"data");
    bytes.extend(long(1));
    bytes.extend([128, 0]);
    bytes
}

fn compare(exe: &Path) -> io::Result<()> {
    for rules in [false, true] {
        let tmp = tempfile::tempdir_in("/tmp")?;
        let db = tmp.path().join("db");
        fs::create_dir(&db)?;
        let images = pixels();
        let waves = [("Riff", wave(false)), ("Rifx", wave(true))];
        let omitted: &[&[u8]] = &[
            b"ID3\x04\0\0\0\0\0\0",
            b"OggS ordinary media",
            b"SQLite format 3\0notes",
            b".RMF ordinary media",
        ];
        let mut hashes = String::new();
        let mut bodies = String::new();
        for (name, image) in &images {
            let hash = barnacle::hash_reader(image.as_slice())?.md5_hex();
            hashes += &format!("{hash}:{}:Pixel.{name}\n", image.len());
            let marker: String = image[..6].iter().map(|b| format!("{b:02x}")).collect();
            bodies += &format!("Body.{name}:5:0:{marker}\n");
        }
        for data in omitted {
            hashes += &format!(
                "{}:{}:Media.Skipped\n",
                barnacle::hash_reader(*data)?.md5_hex(),
                data.len()
            );
        }
        for (name, data) in &waves {
            let hash = barnacle::hash_reader(data.as_slice())?.md5_hex();
            hashes += &format!("{hash}:{}:Wave.{name}\n", data.len());
        }
        bodies += "Body.Wave:0:8:57415645666d7420\n";
        fs::write(db.join("pixels.hdb"), hashes)?;
        if rules {
            fs::write(db.join("pixels.ndb"), bodies)?;
        }
        let sock = tmp.path().join("sock");
        let conf = tmp.path().join("clamd.conf");
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n",
                db.display(),
                sock.display()
            ),
        )?;
        let _clamd = daemon::Daemon::start(exe, &conf, &sock)?;
        for data in omitted {
            assert_eq!(
                daemon::unix_request(&sock, &daemon::stream_frame(data)?)?,
                "stream: OK\0"
            );
        }
        let members = zip::zip(
            &[("music.tag", omitted[0]), ("pixel.gif", &images[1].1)],
            true,
            false,
            false,
        )?;
        let winner = if rules { "Body" } else { "Pixel" };
        assert_eq!(
            daemon::unix_request(&sock, &daemon::stream_frame(&members)?)?,
            format!("stream: {winner}.Gif.UNOFFICIAL FOUND\0")
        );
        for (name, image) in images {
            let response = daemon::unix_request(&sock, &daemon::stream_frame(&image)?)?;
            assert_eq!(
                response,
                format!("stream: {winner}.{name}.UNOFFICIAL FOUND\0")
            );
        }
        for (name, data) in &waves {
            let expected = if rules {
                "Body.Wave".into()
            } else {
                format!("Wave.{name}")
            };
            let nested = zip::zip(&[("audio.wav", data)], true, false, false)?;
            for input in [data.as_slice(), nested.as_slice()] {
                assert_eq!(
                    daemon::unix_request(&sock, &daemon::stream_frame(input)?)?,
                    format!("stream: {expected}.UNOFFICIAL FOUND\0"),
                );
            }
        }
    }
    Ok(())
}

#[test]
fn image_winners() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
fn zip_member_types() -> io::Result<()> {
    use barnacle::body::Target;
    use barnacle::objects::{self, Options, Verdict};

    let tmp = tempfile::tempdir()?;
    let audio = wave(true);
    let java = include_bytes!("fixtures/java/Note.class.bin");
    for (name, data, kind, target) in [
        (
            "audio.wav",
            audio.as_slice(),
            "CL_TYPE_RIFF",
            Target::Generic,
        ),
        ("Note.class", java.as_slice(), "CL_TYPE_JAVA", Target::Java),
    ] {
        let archive = zip::zip(&[(name, data)], true, false, false)?;
        let result = objects::scan(
            &archive,
            &Options::default(),
            tmp.path(),
            |object, _| {
                if object.bytes != data {
                    return Ok(Verdict::Miss);
                }
                assert_eq!(object.context.target(), target);
                assert_eq!(object.layer.file_type, kind);
                assert_eq!(object.layer.name.as_deref(), Some(name.as_bytes()));
                assert_eq!(object.parents.len(), 1);
                assert_eq!(object.parents[0].file_type, "CL_TYPE_ZIP");
                Ok(Verdict::Found(name.into()))
            },
            || Ok(()),
        )?;
        assert_eq!(result, Verdict::Found(name.into()));
    }
    Ok(())
}

#[test]
#[ignore = "requires the pinned Debian clamd"]
fn stock_image_winners() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"))
}
