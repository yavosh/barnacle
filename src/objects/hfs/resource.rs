//! Read the cmpf resource block table without collecting it or inflating an entire fork.
use super::{ChildSink, Fork, Handling, Parts, Volume, invalid};
use flate2::read::ZlibDecoder;
use std::io::{self, Read};

struct Resource<'a, 'v> {
    volume: &'v Volume<'a>,
    fork: Fork<'v>,
}
impl<'a> Resource<'a, '_> {
    fn range(&self, from: u64, n: u64) -> io::Result<Parts<'a>> {
        let end = from.checked_add(n).ok_or_else(invalid)?;
        if end > self.fork.size {
            return Err(invalid());
        }
        self.volume.parts(self.fork, from..end)
    }
    fn bytes<const N: usize>(&self, at: u64) -> io::Result<[u8; N]> {
        let mut result = [0; N];
        self.range(at, N as u64)?.read_exact(&mut result)?;
        Ok(result)
    }
    fn table(&self, sink: &mut dyn ChildSink) -> io::Result<(u64, u32)> {
        let header = self.bytes::<8>(0)?;
        let data = u64::from(u32::from_be_bytes(
            header[..4].try_into().expect("resource data offset"),
        ));
        let map = u64::from(u32::from_be_bytes(
            header[4..].try_into().expect("resource map offset"),
        ));
        let types = i16::from_be_bytes(self.bytes(map + 28)?) as i32 + 1;
        if types <= 0 {
            return Err(invalid());
        }
        let mut references = 0u64;
        let mut selected = None;
        for i in 0..types as u64 {
            sink.check()?;
            let entry = self.bytes::<8>(map + 30 + 8 * i)?;
            if &entry[..4] == b"cmpf" && selected.replace(references).is_some() {
                return Err(invalid());
            }
            references += u64::from(u16::from_be_bytes([entry[4], entry[5]])) + 1;
        }
        let reference = map + 30 + types as u64 * 8 + selected.ok_or_else(invalid)? * 12;
        let relative = self.bytes::<3>(reference + 5)?;
        let start = data
            + u64::from(u32::from_be_bytes([
                0,
                relative[0],
                relative[1],
                relative[2],
            ]));
        let size = u64::from(u32::from_be_bytes(self.bytes(start)?));
        let table = start + 4;
        if table + size > self.fork.size || size < 4 {
            return Err(invalid());
        }
        let blocks = u32::from_le_bytes(self.bytes(table)?);
        if blocks == 0 || 4 + 8 * u64::from(blocks) > size {
            return Err(invalid());
        }
        Ok((table, blocks))
    }
}

struct Blocks<'a, 'v> {
    resource: Resource<'a, 'v>,
    table: u64,
    count: u32,
    index: u32,
    decoder: Option<ZlibDecoder<Parts<'a>>>,
}

impl Read for Blocks<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if let Some(d) = &mut self.decoder {
            let n = d.read(out)?;
            if n != 0 {
                return Ok(n);
            }
            self.decoder = None;
        }
        if self.index == self.count {
            return Ok(0);
        }
        let entry = self
            .resource
            .bytes::<8>(self.table + 4 + 8 * u64::from(self.index))?;
        self.index += 1;
        let offset = u64::from(u32::from_le_bytes(
            entry[..4].try_into().expect("block offset"),
        ));
        let len = u64::from(u32::from_le_bytes(
            entry[4..].try_into().expect("block length"),
        ));
        let at = self.table + offset;
        if len == 0 || self.resource.bytes::<1>(at)?[0] & 15 == 15 {
            return Err(invalid());
        }
        let mut decoder = ZlibDecoder::new(self.resource.range(at, len)?);
        let n = decoder.read(out)?;
        if n == 0 {
            return Err(invalid());
        }
        self.decoder = Some(decoder);
        Ok(n)
    }
}

pub(super) fn scan(
    volume: &Volume,
    fork: Fork,
    sink: &mut dyn ChildSink,
    name: Option<&[u8]>,
) -> io::Result<Option<Handling>> {
    if fork.size < 4096 {
        return Err(invalid());
    }
    if sink.skip_declared_size(fork.size) {
        return Ok(Some(Handling::Complete));
    }
    let resource = Resource { volume, fork };
    let (table, count) = resource.table(sink)?;
    let mut blocks = Blocks {
        resource,
        table,
        count,
        index: 0,
        decoder: None,
    };
    let stop = sink.child(&mut blocks, None, name)?;
    Ok(stop.then_some(Handling::Stopped))
}
