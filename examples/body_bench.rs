//! Replay a deterministic INSTREAM corpus against one daemon in a fresh benchmark guest.
use flate2::{Compression, write::GzEncoder};
use lzma_rust2::{XzOptions, XzWriter};
use std::fs;
use std::io::{self, Read, Seek, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const MARKER: &[u8] = b"Barnacle benign body benchmark marker";
const GROUP: &str = "/sys/fs/cgroup/scanner";
const TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, PartialEq)]
enum Corpus {
    Raw,
    Gzip,
    Xz,
}

fn corpus(format: Corpus) -> io::Result<Vec<Vec<u8>>> {
    let mut state = 0x38d63d4ff6e7b31du64;
    (0..128)
        .map(|i| {
            let size = [4096, 16384, 65536, 262144][i % 4];
            let mut data = vec![0xa5; size];
            for bytes in data[1024..].chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                bytes.copy_from_slice(&state.to_le_bytes()[..bytes.len()]);
            }
            data[size - MARKER.len()..].copy_from_slice(MARKER);
            for _ in 0..=i % 2 {
                data = match format {
                    Corpus::Raw => break,
                    Corpus::Gzip => {
                        let mut archive = GzEncoder::new(Vec::new(), Compression::default());
                        archive.write_all(&data)?;
                        archive.finish()?
                    }
                    Corpus::Xz => {
                        let mut archive = XzWriter::new(Vec::new(), XzOptions::with_preset(5))?;
                        archive.write_all(&data)?;
                        archive.finish()?
                    }
                };
            }
            Ok(data)
        })
        .collect()
}

fn request(socket: &str, payload: Option<&[u8]>) -> io::Result<()> {
    let mut conn = UnixStream::connect(socket)?;
    conn.set_read_timeout(Some(TIMEOUT))?;
    conn.set_write_timeout(Some(TIMEOUT))?;
    let expected = if let Some(bytes) = payload {
        conn.write_all(b"zINSTREAM\0")?;
        for chunk in bytes.chunks(64 * 1024) {
            conn.write_all(&(chunk.len() as u32).to_be_bytes())?;
            conn.write_all(chunk)?;
        }
        conn.write_all(&[0; 4])?;
        "stream: Barnacle.Body.Benchmark.UNOFFICIAL FOUND\0"
    } else {
        conn.write_all(b"zPING\0")?;
        "PONG\0"
    };
    let mut response = String::new();
    conn.take(1024).read_to_string(&mut response)?;
    if response != expected {
        return Err(io::Error::other(format!(
            "expected {expected:?}, received {response:?}"
        )));
    }
    Ok(())
}

fn memory(stage: &str) -> io::Result<()> {
    let group = Path::new(GROUP);
    let stats = fs::read_to_string(group.join("memory.stat"))?;
    let field = |name: &str| -> io::Result<&str> {
        stats
            .lines()
            .filter_map(|line| line.split_once(' '))
            .find(|(key, _)| *key == name)
            .map(|(_, val)| val)
            .ok_or_else(|| io::Error::other("missing memory.stat field"))
    };
    println!(
        "body_memory stage={} current={} peak={} anon={} file={}",
        stage,
        fs::read_to_string(group.join("memory.current"))?.trim(),
        fs::read_to_string(group.join("memory.peak"))?.trim(),
        field("anon")?,
        field("file")?
    );
    Ok(())
}

fn replay(
    socket: &str,
    data: &[Vec<u8>],
    concurrency: usize,
    count: usize,
    stage: &str,
) -> io::Result<()> {
    let next = AtomicUsize::new(0);
    let start = Instant::now();
    let mut timings = thread::scope(|scope| {
        let workers: Vec<_> = (0..concurrency)
            .map(|_| {
                scope.spawn(|| {
                    let mut latencies = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= count {
                            break;
                        }
                        let began = Instant::now();
                        request(socket, Some(&data[i % data.len()]))?;
                        latencies.push(began.elapsed());
                    }
                    Ok::<_, io::Error>(latencies)
                })
            })
            .collect();
        let mut timings = Vec::new();
        for worker in workers {
            timings.extend(
                worker
                    .join()
                    .map_err(|_| io::Error::other("client thread failed"))??,
            );
        }
        Ok::<_, io::Error>(timings)
    })?;
    let elapsed = start.elapsed();
    timings.sort_unstable();
    let bytes: usize = data.iter().cycle().take(count).map(Vec::len).sum();
    println!(
        "body_pass stage={stage} requests={count} bytes={bytes} elapsed_ns={} requests_s={:.2} mib_s={:.2} p95_us={:.1}",
        elapsed.as_nanos(),
        count as f64 / elapsed.as_secs_f64(),
        bytes as f64 / (1024. * 1024.) / elapsed.as_secs_f64(),
        timings[(count * 95).div_ceil(100) - 1].as_secs_f64() * 1e6
    );
    memory(stage)
}

struct Service(Child);
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn allocated_bytes(path: &Path) -> io::Result<u64> {
    let fs = rustix::fs::statvfs(path)?;
    Ok((fs.f_blocks - fs.f_bfree) * fs.f_frsize)
}

fn pressure(socket: &str, data: &[Vec<u8>], clients: usize, temp: &Path) -> io::Result<()> {
    let baseline = allocated_bytes(temp)?;
    let mut peak = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(Path::new(GROUP).join("memory.peak"))?;
    // Linux resets this counter for subsequent reads through the same file descriptor.
    peak.write_all(b"reset")?;
    let finished = AtomicBool::new(false);
    let scratch_delta = thread::scope(|scope| -> io::Result<u64> {
        let sampler = scope.spawn(|| -> io::Result<u64> {
            let mut highest = baseline;
            while !finished.load(Ordering::Acquire) {
                highest = highest.max(allocated_bytes(temp)?);
                thread::sleep(Duration::from_millis(1));
            }
            Ok(highest - baseline)
        });
        let result = replay(socket, data, clients, data.len(), "pressure");
        finished.store(true, Ordering::Release);
        let sampled = sampler
            .join()
            .map_err(|_| io::Error::other("sampler failed"))??;
        result?;
        Ok(sampled)
    })?;
    peak.rewind()?;
    let mut value = String::new();
    peak.read_to_string(&mut value)?;
    println!(
        "object_pressure scan_peak={} scratch_delta={scratch_delta}",
        value.trim()
    );
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "rule" {
        let hex: String = MARKER.iter().map(|b| format!("{b:02x}")).collect();
        println!("Barnacle.Body.Benchmark:0:*:{hex}");
        return Ok(());
    }
    let (format, args) = match args.split_last() {
        Some((arg, rest)) if arg == "gzip" => (Corpus::Gzip, rest),
        Some((arg, rest)) if arg == "xz" => (Corpus::Xz, rest),
        _ => (Corpus::Raw, args.as_slice()),
    };
    let [_, exe, config, socket, clients] = args else {
        return Err(io::Error::other(
            "usage: body_bench rule | DAEMON CONFIG SOCKET CLIENTS [gzip|xz]",
        ));
    };
    let clients: usize = clients.parse().map_err(io::Error::other)?;
    if !(1..=4).contains(&clients) {
        return Err(io::Error::other("expected 1 through 4 clients"));
    }
    if Path::new(socket).exists()
        || !fs::read_to_string(Path::new(GROUP).join("cgroup.procs"))?
            .trim()
            .is_empty()
    {
        return Err(io::Error::other(
            "expected an empty scanner cgroup and unused socket",
        ));
    }
    let data = corpus(format)?;
    let began = Instant::now();
    let mut child = Service(
        Command::new("/bin/sh")
            .args([
                "-ec",
                r#"echo $$ > "$1/cgroup.procs"; exec "$2" --config-file "$3""#,
                "body_bench",
                GROUP,
                exe,
                config,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    loop {
        match request(socket, None) {
            Ok(()) => break,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) => {}
            Err(e) => return Err(e),
        }
        if child.0.try_wait()?.is_some() || began.elapsed() >= TIMEOUT {
            return Err(io::Error::other("daemon failed to become ready"));
        }
        thread::sleep(Duration::from_millis(5));
    }
    println!("body_ready elapsed_ns={}", began.elapsed().as_nanos());
    memory("ready")?;
    replay(socket, &data, clients, data.len(), "cold")?;
    replay(socket, &data, clients, data.len() * 4, "warm")?;
    if format != Corpus::Raw {
        let conf = fs::read_to_string(config)?;
        let temp = conf
            .lines()
            .find_map(|line| line.strip_prefix("TemporaryDirectory "))
            .ok_or_else(|| {
                io::Error::other("nested benchmark requires an explicit TemporaryDirectory")
            })?;
        pressure(socket, &data, clients, Path::new(temp.trim()))?;
    }
    Ok(())
}
