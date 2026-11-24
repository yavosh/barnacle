use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::net::TcpStream;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::{ffi::OsStrExt, fs::FileExt, net::UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::net::{self, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags};

use super::State;
use super::engine::{Detection, ScanResult};

mod jobs;
mod order;
mod paths;
use jobs::Jobs;
use std::sync::Mutex;

const COMMANDS: &str = "SCAN QUIT RELOAD PING CONTSCAN VERSIONCOMMANDS VERSION END SHUTDOWN MULTISCAN FILDES STATS IDSESSION INSTREAM DETSTATSCLEAR DETSTATS ALLMATCHSCAN";
const INCOMPLETE: &str = "Incomplete scan: unsupported detection coverage. ERROR";
const HEADER_LIMIT: usize = 8192;

pub(super) enum Connection {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl AsFd for Connection {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Unix(s) => s.as_fd(),
            Self::Tcp(s) => s.as_fd(),
        }
    }
}

impl Connection {
    fn finish_input(&self) -> io::Result<()> {
        net::shutdown(self, net::Shutdown::Write)?;
        // Closing a socket with unread data can reset the peer after the error
        // response. Discard only bytes already queued, with a fixed work budget.
        let mut scratch = [0; 8192];
        let mut left = 65536;
        while left > 0 {
            let limit = left.min(scratch.len());
            match net::recv(self, &mut scratch[..limit], RecvFlags::DONTWAIT) {
                Ok((_, 0)) | Err(rustix::io::Errno::AGAIN) => break,
                Ok((_, n)) => left -= n,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn read_timeout(&self, timeout: Duration) -> io::Result<()> {
        let timeout = (!timeout.is_zero()).then_some(timeout);
        match self {
            Self::Unix(s) => s.set_read_timeout(timeout),
            Self::Tcp(s) => s.set_read_timeout(timeout),
        }
    }
}

impl Read for &Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Connection::Unix(s) => (&*s).read(buf),
            Connection::Tcp(s) => (&*s).read(buf),
        }
    }
}

impl Write for &Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Connection::Unix(s) => (&*s).write(buf),
            Connection::Tcp(s) => (&*s).write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Deadline(Option<Instant>);

impl Deadline {
    fn new(timeout: Duration) -> Self {
        Self(
            (!timeout.is_zero())
                .then(|| Instant::now().checked_add(timeout))
                .flatten(),
        )
    }

    fn apply(&self, conn: &Connection) -> io::Result<()> {
        let remaining = match self.0 {
            None => Duration::ZERO,
            Some(end) => end
                .checked_duration_since(Instant::now())
                .filter(|time| !time.is_zero())
                .ok_or(io::ErrorKind::TimedOut)?,
        };
        conn.read_timeout(remaining)
    }
}

struct Frame {
    command: Vec<u8>,
    term: u8,
    legacy: bool,
}

fn frame(conn: &Connection, timeout: Duration) -> io::Result<Option<Frame>> {
    let mut command = Vec::new();
    let deadline = Deadline::new(timeout);
    let mut term = b'\n';
    let mut legacy = false;
    let mut scratch = [0; HEADER_LIMIT];
    loop {
        deadline.apply(conn)?;
        // Leave the following FILDES marker and any SCM_RIGHTS in the socket.
        let (_, n) = net::recv(conn, &mut scratch[..], RecvFlags::PEEK)?;
        if n == 0 {
            return if command.is_empty() {
                Ok(None)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
        if command.is_empty() {
            term = if scratch[0] == b'z' { 0 } else { b'\n' };
            legacy = !matches!(scratch[0], b'z' | b'n');
        }
        let delimiter = scratch[..n].iter().position(|&b| b == term);
        let used = delimiter.map_or(n, |at| at + 1);
        if command.len() + used > HEADER_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Command too long",
            ));
        }
        (&*conn).read_exact(&mut scratch[..used])?;
        command.extend_from_slice(&scratch[..delimiter.unwrap_or(used)]);
        if delimiter.is_some() || legacy {
            if term == b'\n' && command.last() == Some(&b'\r') {
                command.pop();
            }
            if !legacy {
                command.remove(0);
            }
            return Ok(Some(Frame {
                command,
                term,
                legacy,
            }));
        }
    }
}

#[derive(Clone, Copy)]
struct Reply<'a> {
    state: &'a State,
    output: &'a Mutex<()>,
    conn: &'a Connection,
    id: Option<u64>,
    term: u8,
}

impl Reply<'_> {
    fn line(&self, path: Option<&OsStr>, status: &str) -> io::Result<()> {
        self.line_and_log(path, status, path, status)
    }

    fn line_and_log(
        &self,
        path: Option<&OsStr>,
        status: &str,
        log_path: Option<&OsStr>,
        log_status: &str,
    ) -> io::Result<()> {
        let mut bytes = Vec::new();
        if let Some(id) = self.id {
            write!(bytes, "{id}: ")?;
        }
        if let Some(path) = path {
            bytes.extend_from_slice(path.as_bytes());
            bytes.extend_from_slice(b": ");
        }
        bytes.extend_from_slice(status.as_bytes());
        bytes.push(self.term);
        if let Some(path) = log_path
            && (status.ends_with("FOUND")
                || status.ends_with("ERROR")
                || self.state.config.log_clean)
        {
            self.state.log(&format!(
                "{}: {}",
                path.to_string_lossy().escape_debug(),
                log_status.escape_debug()
            ));
        }
        let _guard = self.output.lock().unwrap();
        (&*self.conn).write_all(&bytes)
    }

    fn scan(&self, generation: &super::Generation, input: impl Read) -> io::Result<ScanResult> {
        let mut checked: Option<Instant> = None;
        generation.scan_checked(input, || {
            if self.state.stopping() {
                return Err(io::ErrorKind::ConnectionAborted.into());
            }
            if checked.is_none_or(|last| last.elapsed() >= Duration::from_millis(100)) {
                check_connection(self.conn)?;
                checked = Some(Instant::now());
            }
            Ok(())
        })
    }

    fn result(&self, label: &OsStr, result: io::Result<ScanResult>) -> io::Result<bool> {
        self.named_result(label, label, result)
    }

    fn stream_result(&self, result: io::Result<ScanResult>) -> io::Result<bool> {
        let peer = match self.conn {
            Connection::Tcp(stream) => match stream.peer_addr() {
                Ok(std::net::SocketAddr::V4(addr)) => {
                    format!("instream({}@{})", addr.ip(), addr.port())
                }
                _ => "instream(local)".into(),
            },
            Connection::Unix(_) => "instream(local)".into(),
        };
        self.named_result(OsStr::new("stream"), OsStr::new(&peer), result)
    }

    fn named_result(
        &self,
        label: &OsStr,
        log_label: &OsStr,
        result: io::Result<ScanResult>,
    ) -> io::Result<bool> {
        let detected = matches!(result, Ok(ScanResult::Found(_)));
        let mut details = None;
        let status = match result {
            Ok(ScanResult::Found(Detection { name, hashes })) => {
                if self.state.config.extended_detection_info
                    && let Some(hashes) = hashes
                {
                    details = Some(format!(
                        "{name}({}:{}) FOUND",
                        hashes.md5_hex(),
                        hashes.size
                    ));
                }
                format!("{name} FOUND")
            }
            Ok(ScanResult::Skipped) => "OK".to_owned(),
            Ok(ScanResult::Incomplete) => INCOMPLETE.to_owned(),
            Err(error) => format!("{error}. ERROR"),
        };
        self.line_and_log(
            Some(label),
            &status,
            Some(log_label),
            details.as_deref().unwrap_or(&status),
        )?;
        Ok(detected)
    }
}

fn descriptor_path(file: &File) -> Option<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
    }
    #[cfg(target_vendor = "apple")]
    {
        rustix::fs::getpath(file)
            .ok()
            .map(|s| Path::new(OsStr::from_bytes(s.as_bytes())).to_owned())
    }
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    {
        let _ = file;
        None
    }
}

fn check_connection(conn: &Connection) -> io::Result<()> {
    use nix::poll::{PollFd, PollFlags, poll};
    let mut fd = [PollFd::new(conn.as_fd(), PollFlags::empty())];
    poll(&mut fd, 0_u8)?;
    if fd[0]
        .revents()
        .unwrap_or(PollFlags::empty())
        .intersects(PollFlags::POLLHUP | PollFlags::POLLERR)
    {
        return Err(io::ErrorKind::ConnectionAborted.into());
    }
    Ok(())
}

struct Chunks<'a> {
    conn: &'a Connection,
    left: usize,
    quota: u64,
    complete: bool,
    overflow: bool,
}

impl Read for Chunks<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.complete || buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut header = [0; 4];
            (&*self.conn).read_exact(&mut header)?;
            self.left = u32::from_be_bytes(header) as usize;
            if self.left == 0 {
                self.complete = true;
                return Ok(0);
            }
            if self.left as u64 > self.quota {
                self.overflow = true;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "INSTREAM size limit exceeded",
                ));
            }
            self.quota -= self.left as u64;
        }
        let count = buf.len().min(self.left);
        let n = (&*self.conn).read(&mut buf[..count])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.left -= n;
        Ok(n)
    }
}

impl Chunks<'_> {
    fn finish(&mut self, reply: Reply<'_>) -> io::Result<bool> {
        // The scanner can reach its own file limit before the last network chunk.
        if !self.complete && !self.overflow {
            let _ = io::copy(self, &mut io::sink());
        }
        if self.overflow {
            reply.line(None, "INSTREAM size limit exceeded. ERROR")?;
        } else if !self.complete {
            reply.line(Some(OsStr::new("stream")), "Incomplete INSTREAM. ERROR")?;
        } else {
            return Ok(true);
        }
        reply.conn.finish_input()?;
        Ok(false)
    }
}

fn instream<'a>(reply: Reply<'a>, jobs: Option<&Jobs<'a, '_>>) -> io::Result<bool> {
    let state = reply.state;
    // Stock applies ReadTimeout to inactivity between reads during an upload.
    reply.conn.read_timeout(state.config.read_timeout)?;
    let mut data = Chunks {
        conn: reply.conn,
        left: 0,
        quota: state.config.stream_max_length,
        complete: false,
        overflow: false,
    };
    let generation = state.snapshot();
    if let Some(jobs) = jobs {
        // Consume frames in order. A bounded pipe lets an available worker hash
        // bytes as they arrive, without buffering a whole upload or writing a file.
        let (input, mut output) = io::pipe()?;
        let (valid, finalized) = std::sync::mpsc::channel();
        let engine = generation.clone();
        let declined = jobs.try_submit(move || {
            let result = reply.scan(&engine, input);
            if finalized.recv().is_ok() {
                reply.stream_result(result)?;
            }
            Ok(())
        })?;
        if declined.is_none() {
            let _ = io::copy(&mut data, &mut output);
            drop(output);
            if !data.finish(reply)? {
                return Ok(false);
            }
            let _ = valid.send(());
            return Ok(true);
        }
    }
    let result = reply.scan(&generation, &mut data);
    if !data.finish(reply)? {
        return Ok(false);
    }
    reply.stream_result(result)?;
    Ok(true)
}

fn receive_fd(stream: &UnixStream) -> io::Result<File> {
    let mut bytes = [0];
    // Reserve the full platform maximum (512 on Darwin, 253 on Linux).
    // A truncated SCM_RIGHTS record cannot expose every installed descriptor.
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(512))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    #[cfg(target_os = "linux")]
    let flags = RecvFlags::CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = RecvFlags::empty();
    let msg = net::recvmsg(
        stream,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut control,
        flags,
    )?;
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "expected one FILDES descriptor");
    if msg.bytes == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if msg.bytes != 1 || msg.flags.contains(ReturnFlags::CTRUNC) {
        return Err(invalid());
    }
    let mut incoming = None;
    for message in control.drain() {
        #[allow(irrefutable_let_patterns)]
        if let RecvAncillaryMessage::ScmRights(fds) = message {
            for fd in fds {
                if incoming.replace(fd).is_some() {
                    return Err(invalid());
                }
            }
        }
    }
    let fd = incoming.ok_or_else(invalid)?;
    #[cfg(not(target_os = "linux"))]
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
    Ok(File::from(fd))
}

// SCM_RIGHTS shares the sender's open-file description. Read from offset zero
// without changing the sender's position.
struct FromStart(File, u64);

impl Read for FromStart {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.0.read_at(buf, self.1)?;
        self.1 += n as u64;
        Ok(n)
    }
}

pub(super) fn handle(
    mut conn: &Connection,
    state: &State,
    mut id: Option<u64>,
) -> io::Result<Option<u64>> {
    let output = Mutex::new(());
    std::thread::scope(|scope| {
        let jobs = Jobs::new(scope, state, conn);
        while !state.stopping() {
            if id.is_some() {
                use nix::poll::{PollFd, PollFlags, poll};
                let idle = jobs.idle();
                let mut fd = [PollFd::new(conn.as_fd(), PollFlags::POLLIN)];
                if poll(&mut fd, if idle { 0_u8 } else { 10 })? == 0 {
                    if idle {
                        return Ok(id);
                    }
                    continue;
                }
            }
            let Frame {
                command,
                term,
                legacy,
            } = match frame(
                conn,
                if id.is_some() {
                    state.config.read_timeout
                } else {
                    state.config.command_read_timeout
                },
            ) {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    let _guard = output.lock().unwrap();
                    conn.write_all(b"COMMAND READ TIMED OUT\n")?;
                    break;
                }
                Err(e) => return Err(e),
            };
            let reply = Reply {
                state,
                output: &output,
                conn,
                id,
                term,
            };
            let mut parts = command.splitn(2, |&b| b == b' ');
            let cmd = parts.next().unwrap_or_default();
            let name = std::str::from_utf8(cmd).unwrap_or("");
            state.set_activity(if COMMANDS.split_ascii_whitespace().any(|c| c == name) {
                name
            } else {
                "UNKNOWN"
            });
            let arg = parts.next().map(OsStr::from_bytes);
            if id.is_some()
                && (legacy
                    || !matches!(
                        cmd,
                        b"FILDES"
                            | b"SCAN"
                            | b"END"
                            | b"INSTREAM"
                            | b"VERSION"
                            | b"PING"
                            | b"STATS"
                            | b"VERSIONCOMMANDS"
                    ))
            {
                reply.line(None, "Command invalid inside IDSESSION. ERROR")?;
                break;
            }
            if legacy
                && matches!(
                    cmd,
                    b"IDSESSION"
                        | b"END"
                        | b"STATS"
                        | b"INSTREAM"
                        | b"ALLMATCHSCAN"
                        | b"VERSIONCOMMANDS"
                )
            {
                reply.line(None, "UNKNOWN COMMAND")?;
                break;
            }
            match (cmd, arg) {
                (b"IDSESSION", None) => {
                    id = Some(1);
                    continue;
                }
                (b"END", None) if id.is_some() => break,
                (b"PING", None) => reply.line(None, "PONG")?,
                (b"VERSION", None) => reply.line(None, state.snapshot().version())?,
                (b"VERSIONCOMMANDS", None) => reply.line(
                    None,
                    &format!("{}| COMMANDS: {COMMANDS}", state.snapshot().version()),
                )?,
                (b"STATS", None) => {
                    let body = state.stats();
                    reply.line(None, &format!("{}\nEND", body.trim_end_matches('\n')))?;
                }
                (b"DETSTATS" | b"DETSTATSCLEAR", None) => break,
                (b"QUIT" | b"SHUTDOWN", None) => {
                    state.stop();
                    break;
                }
                (b"RELOAD", None) => {
                    state.request_reload();
                    reply.line(None, "RELOADING")?;
                }
                (b"INSTREAM", None) => {
                    if !instream(reply, id.is_some().then_some(&jobs))? {
                        break;
                    }
                }
                (b"FILDES", None) => {
                    conn.read_timeout(state.config.read_timeout)?;
                    let received = match conn {
                        Connection::Unix(socket) => receive_fd(socket),
                        Connection::Tcp(_) => conn.read_exact(&mut [0]).and_then(|()| {
                            Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "TCP carries no descriptors",
                            ))
                        }),
                    };
                    let file = match received {
                        Ok(file) => file,
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                            ) =>
                        {
                            let _guard = output.lock().unwrap();
                            conn.write_all(b"COMMAND READ TIMED OUT\n")?;
                            break;
                        }
                        Err(_) => {
                            reply.line(None, "No file descriptor received. ERROR")?;
                            conn.finish_input()?;
                            break;
                        }
                    };
                    let generation = state.snapshot();
                    let scan = move || {
                        let label = format!("fd[{}]", file.as_raw_fd());
                        if file.metadata().is_ok_and(|meta| meta.is_file()) {
                            let path = descriptor_path(&file);
                            reply.named_result(
                                OsStr::new(&label),
                                path.as_deref()
                                    .map(Path::as_os_str)
                                    .unwrap_or_else(|| OsStr::new(&label)),
                                reply.scan(&generation, FromStart(file, 0)),
                            )?;
                        } else {
                            reply.line(Some(OsStr::new(&label)), "Not a regular file ERROR")?;
                        }
                        Ok(())
                    };
                    if id.is_some() {
                        jobs.submit(scan)?;
                    } else {
                        scan()?;
                    }
                }
                (b"SCAN" | b"CONTSCAN" | b"MULTISCAN" | b"ALLMATCHSCAN", Some(path)) => {
                    let generation = state.snapshot();
                    if id.is_some() {
                        let path = Path::new(path).to_owned();
                        jobs.submit(move || {
                            paths::scan(state, reply, b"SCAN", &path, generation, None)
                        })?;
                    } else {
                        paths::scan(
                            state,
                            reply,
                            cmd,
                            Path::new(path),
                            generation,
                            (cmd == b"MULTISCAN").then_some(&jobs),
                        )?;
                    }
                }
                _ => {
                    reply.line(None, "UNKNOWN COMMAND")?;
                    break;
                }
            }
            let Some(current) = id else {
                break;
            };
            id = Some(
                current
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("session ID exhausted"))?,
            );
        }
        Ok(None)
    })
}

#[cfg(test)]
mod tests;
