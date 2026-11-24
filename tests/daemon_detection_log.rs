//! Compare detection logs and wire replies across clamd scan transports.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;

use client::{Daemon, exchange, stream_frame, unix_request};
use flate2::{Compression, write::GzEncoder};
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
use std::fs::{self, File};
use std::io::{self, IoSlice, Read, Write};
use std::mem::MaybeUninit;
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

fn detection_log(exe: &Path, extended: bool, input: &[u8]) -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let root = tmp.path().canonicalize()?;
    let config = root.join("clamd.conf");
    let socket = root.join("socket");
    let log = root.join("detection.log");
    let db = root.join("db");
    let path = root.join("sample");
    let md5 = "e80b5017098950fc58aad83c8c14978e";
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let addr = listener.local_addr()?;
    drop(listener);
    fs::create_dir(&db)?;
    fs::write(db.join("test.hdb"), format!("{md5}:6:Test\n"))?;
    fs::write(&path, input)?;
    fs::write(
        &config,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nLogFile {}\nTCPAddr 127.0.0.1\nTCPSocket {}\nExtendedDetectionInfo {}\n",
            db.display(),
            socket.display(),
            log.display(),
            addr.port(),
            if extended { "yes" } else { "no" }
        ),
    )?;
    let _daemon = Daemon::start(exe, &config, &socket)?;
    let wire = "Test.UNOFFICIAL FOUND\0";
    let request = format!("zSCAN {}\0", path.display());
    assert_eq!(
        unix_request(&socket, request.as_bytes())?,
        format!("{}: {wire}", path.display())
    );

    let stream = stream_frame(input)?;
    assert_eq!(unix_request(&socket, &stream)?, format!("stream: {wire}"));
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    let peer_port = tcp.local_addr()?.port();
    assert_eq!(exchange(tcp, &stream)?, format!("stream: {wire}"));

    let mut conn = UnixStream::connect(&socket)?;
    conn.set_read_timeout(Some(Duration::from_secs(5)))?;
    conn.write_all(b"zFILDES\0")?;
    let file = File::open(&path)?;
    let fds = [file.as_fd()];
    let mut storage = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut storage);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(&fds)));
    assert_eq!(
        sendmsg(
            &conn,
            &[IoSlice::new(&[0])],
            &mut ancillary,
            SendFlags::empty()
        )?,
        1
    );
    let mut fd_reply = String::new();
    conn.read_to_string(&mut fd_reply)?;
    let fd = fd_reply
        .strip_prefix("fd[")
        .unwrap()
        .strip_suffix(&format!("]: {wire}"))
        .unwrap();
    assert!(fd.parse::<u32>().is_ok());

    let expected = if extended {
        let digest = barnacle::hash_reader(input)?.md5_hex();
        format!("Test.UNOFFICIAL({digest}:{}) FOUND", input.len())
    } else {
        "Test.UNOFFICIAL FOUND".into()
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = fs::read_to_string(&log)?;
        let detections: Vec<_> = text
            .lines()
            .filter(|line| line.ends_with(" FOUND"))
            .collect();
        if detections.len() >= 4 {
            assert_eq!(detections.len(), 4);
            let path_line = format!("{}: {expected}", path.display());
            assert_eq!(
                detections
                    .iter()
                    .filter(|l| l.ends_with(&path_line))
                    .count(),
                2,
                "{text}"
            );
            assert!(
                detections
                    .iter()
                    .any(|l| l.ends_with(&format!("instream(local): {expected}"))),
                "{text}"
            );
            assert!(
                detections
                    .iter()
                    .any(|l| l.ends_with(&format!("instream(127.0.0.1@{peer_port}): {expected}"))),
                "{text}"
            );
            break;
        }
        assert!(Instant::now() < deadline, "{text}");
        std::thread::sleep(Duration::from_millis(30));
    }
    Ok(())
}

#[test]
fn extended_detection_info_controls_only_log_details() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
#[ignore = "requires pinned Debian clamd 1.4.3"]
fn stock_extended_detection_info_controls_only_log_details() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"))
}

fn compare(exe: &Path) -> io::Result<()> {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    gzip.write_all(b"abcdef")?;
    let compressed = gzip.finish()?;
    for input in [b"abcdef".as_slice(), compressed.as_slice()] {
        detection_log(exe, false, input)?;
        detection_log(exe, true, input)?;
    }
    Ok(())
}
