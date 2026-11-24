//! Measure concurrent archive traversal in a fresh Linux cgroup per invocation.
#[path = "compat_oracle/daemon.rs"]
mod daemon;
use barnacle::objects::{self, Options, Verdict};
use lzma_rust2::{XzOptions, XzWriter};
use md5::{Digest, Md5};
use sevenz_rust2::{
    ArchiveEntry, ArchiveWriter, EncoderConfiguration, SourceReader,
    encoder_options::{Lzma2Options, PpmdOptions},
};
use std::{
    env, fs,
    io::{self, Cursor, Write},
    path::Path,
    sync::{Arc, Barrier},
    time::Instant,
};
const MIB: usize = 1 << 20;
const MARKER: &[u8] = b"Reference archive workspace measurement.\0\x02\x03";

fn seven(parts: &[(&str, &[u8])], method: EncoderConfiguration) -> io::Result<Vec<u8>> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).map_err(io::Error::other)?;
    writer.set_content_methods(vec![method]);
    writer
        .push_archive_entries(
            parts
                .iter()
                .map(|(name, _)| ArchiveEntry::new_file(name))
                .collect(),
            parts.iter().map(|(_, b)| SourceReader::new(*b)).collect(),
        )
        .map_err(io::Error::other)?;
    Ok(writer.finish()?.into_inner())
}
fn lzma2_method() -> EncoderConfiguration {
    let mut options = Lzma2Options::from_level(0);
    options.set_dictionary_size((16 * MIB) as u32);
    options.into()
}
fn prepare(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut data = MARKER.to_vec();
    data.resize(16 * MIB, b'q');
    let mut ledger = MARKER.to_vec();
    for number in 0..32_768 {
        writeln!(
            ledger,
            "Order {number:05}: item {}, quantity {}, zone {}.",
            number * 19 % 8009,
            number * 13 % 127,
            number * 7 % 43
        )?;
    }
    let database = dir.join("db");
    fs::create_dir_all(&database)?;
    let mut rule = fs::File::create(database.join("reference.hdb"))?;
    for bytes in [MARKER, data.as_slice(), ledger.as_slice()] {
        for byte in Md5::digest(bytes) {
            write!(rule, "{byte:02x}")?;
        }
        writeln!(rule, ":{}:Workspace.Reference", bytes.len())?;
    }
    for (name, bytes) in [("tiny", MARKER), ("data", &data[..])] {
        let mut options = XzOptions::with_preset(0);
        options.lzma_options.dict_size = (64 * MIB) as u32;
        let mut writer = XzWriter::new(fs::File::create(dir.join(format!("{name}.xz")))?, options)?;
        writer.write_all(bytes)?;
        writer.finish()?;
        fs::write(
            dir.join(format!("{name}.7z")),
            seven(&[("reference", bytes)], lzma2_method())?,
        )?;
    }
    let mut child = MARKER.to_vec();
    let mut cover = vec![0; 8 * MIB];
    cover[..14].copy_from_slice(b"Note\0\x01\x02\x03\x04\x05body");
    let names: Vec<_> = (1..=9).map(|number| format!("report-{number}")).collect();
    let mut entries: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), cover.as_slice()))
        .collect();
    entries.push(("reference", MARKER));
    fs::write(dir.join("batches.7z"), seven(&entries, lzma2_method())?)?;
    for depth in 1..=8 {
        child = seven(
            &[
                ("cover", &cover),
                ("child", &child),
                ("next", b"Other harmless filing notes."),
            ],
            lzma2_method(),
        )?;
        if [1, 4, 8].contains(&depth) {
            fs::write(dir.join(format!("nested{depth}.7z")), &child)?;
        }
    }
    let mut child = MARKER.to_vec();
    fs::write(
        dir.join("model64.7z"),
        seven(
            &[("notes", &data)],
            PpmdOptions::from_order_memory_size(6, 64 * MIB as u32).into(),
        )?,
    )?;
    fs::write(
        dir.join("ledger64.7z"),
        seven(
            &[("ledger", &ledger)],
            PpmdOptions::from_order_memory_size(6, 64 * MIB as u32).into(),
        )?,
    )?;
    for depth in 1..=8 {
        child = seven(
            &[("child", &child)],
            PpmdOptions::from_order_memory_size(6, 16 * MIB as u32).into(),
        )?;
        if [1, 4, 8].contains(&depth) {
            fs::write(dir.join(format!("ppmd{depth}.7z")), &child)?;
        }
    }
    Ok(())
}
fn run(
    path: &Path,
    worker_count: usize,
    executable: Option<&Path>,
    samples: usize,
) -> io::Result<()> {
    let input = Arc::new(fs::read(path)?);
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("clamd.sock");
    let pid_file = directory.path().join("clamd.pid");
    let mut process = "self".to_owned();
    let _daemon = if let Some(executable) = executable {
        let config = directory.path().join("clamd.conf");
        let database = fs::canonicalize(path.with_file_name("db"))?;
        fs::write(
            &config,
            format!(
                "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nTemporaryDirectory {}\nPidFile {}\nSelfCheck 0\nDisableCache yes\nMaxThreads {}\n",
                socket.display(),
                database.display(),
                directory.path().display(),
                pid_file.display(),
                worker_count
            ),
        )?;
        let daemon = daemon::Daemon::start(executable, &config, &socket)?;
        process = fs::read_to_string(pid_file)?.trim().to_owned();
        Some(daemon)
    } else {
        None
    };
    let frame = executable
        .map(|_| daemon::stream_frame(&input))
        .transpose()?
        .map(Arc::new);
    let barrier = Arc::new(Barrier::new(worker_count));
    let timer = Instant::now();
    let mut workers = Vec::new();
    for _ in 0..worker_count {
        let input = Arc::clone(&input);
        let frame = frame.clone();
        let socket = socket.clone();
        let start = Arc::clone(&barrier);
        workers.push(std::thread::spawn(
            move || -> io::Result<Vec<std::time::Duration>> {
                start.wait();
                if let Some(frame) = frame {
                    let mut timings = Vec::new();
                    for _ in 0..samples {
                        let request = Instant::now();
                        let reply = daemon::unix_request(&socket, &frame)?;
                        if reply != "stream: Workspace.Reference.UNOFFICIAL FOUND\0" {
                            return Err(io::Error::other(format!(
                                "unexpected daemon reply {reply:?}"
                            )));
                        }
                        timings.push(request.elapsed());
                    }
                    return Ok(timings);
                }
                let request = Instant::now();
                let verdict = objects::scan(
                    &input,
                    &Options::default(),
                    Path::new("/tmp"),
                    |obj, _| {
                        Ok(if obj.bytes.starts_with(MARKER) {
                            Verdict::Found("reference".into())
                        } else {
                            Verdict::Miss
                        })
                    },
                    || Ok(()),
                )?;
                if verdict != Verdict::Found("reference".into()) {
                    return Err(io::Error::other(format!(
                        "unexpected scan verdict {verdict:?}"
                    )));
                }
                Ok(vec![request.elapsed()])
            },
        ));
    }
    let mut requests = Vec::with_capacity(worker_count);
    for worker in workers {
        requests.extend(
            worker
                .join()
                .map_err(|_| io::Error::other("scan worker panicked"))??,
        );
    }
    let elapsed = timer.elapsed();
    requests.sort_unstable();
    let p95 = requests[(95 * requests.len()).div_ceil(100) - 1];
    let status = fs::read_to_string(format!("/proc/{process}/status"))?;
    let hwm = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .ok_or_else(|| io::Error::other("VmHWM missing from /proc/self/status"))?;
    let cgroup_peak = fs::read_to_string("/sys/fs/cgroup/memory.peak")?;
    println!(
        "{} workers={} elapsed_ms={} {} cgroup_peak_bytes={} requests_s={:.2} p95_us={}",
        path.display(),
        worker_count,
        elapsed.as_millis(),
        hwm,
        cgroup_peak.trim(),
        requests.len() as f64 / elapsed.as_secs_f64(),
        p95.as_micros()
    );
    Ok(())
}
fn main() -> io::Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    match args.as_slice() {
        [command, directory] if command == "prepare" => prepare(Path::new(directory)),
        [command, file, count, rest @ ..] if command == "run" && rest.len() <= 2 => {
            let count = count
                .parse::<std::num::NonZeroUsize>()
                .map_err(|_| io::Error::other("workers must be a positive integer"))?;
            let samples = rest
                .get(1)
                .map(|n| n.parse::<std::num::NonZeroUsize>())
                .transpose()
                .map_err(|_| io::Error::other("requests per client must be a positive integer"))?;
            run(
                Path::new(file),
                count.get(),
                rest.first().map(Path::new),
                samples.map_or(1, |n| n.get()),
            )
        }
        _ => Err(io::Error::other(
            "usage: archive_workspace prepare DIRECTORY | run FILE WORKERS [DAEMON [REQUESTS_PER_CLIENT]]",
        )),
    }
}
