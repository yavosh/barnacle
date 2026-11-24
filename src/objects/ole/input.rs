//! Identify data errors from the in-memory CFB reader separately from scan and filesystem errors.
use super::{Document, Inventory, Stream};
use std::{
    error::Error,
    fmt,
    io::{self, Cursor, Read, Seek, SeekFrom},
};

#[derive(Debug)]
struct Malformed(io::Error);

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl Error for Malformed {}

pub(super) fn mark(e: io::Error) -> io::Error {
    match e.kind() {
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof | io::ErrorKind::NotFound => {
            io::Error::new(e.kind(), Malformed(e))
        }
        _ => e,
    }
}

pub(super) fn malformed(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|cause| cause.is::<Malformed>())
}

pub(super) struct Input<'a>(cfb::Stream<Cursor<&'a [u8]>>);

impl<'a> Input<'a> {
    pub(super) fn open(
        doc: &mut Document<'a>,
        dir: &Inventory,
        entry: &Stream,
    ) -> io::Result<Self> {
        doc.open_stream(dir.path(entry)).map(Self).map_err(mark)
    }
    pub(super) fn len(&self) -> u64 {
        self.0.len()
    }
}

impl Read for Input<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(mark)
    }
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.0.read_exact(buf).map_err(mark)
    }
}
impl Seek for Input<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos).map_err(mark)
    }
}
