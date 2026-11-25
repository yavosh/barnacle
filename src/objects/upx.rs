//! Unpack UPX 4.2.4 NRV2B, NRV2D, and NRV2E PE32 files and rebuild them as stock does.
//! Other UPX versions, methods, stubs, and PE32+ files stay unrecognized.
use super::{ChildSink, Handling};
use std::io;

// UPX 4.24 writes its version string and then a 32-byte pack header. The header
// starts with its magic, format version 13, and format 9 (Win32 PE).
const VERSION: &[u8] = b"4.24\0";
const PACK_HEADER: &[u8] = b"UPX!\x0d\x09";
const PACK_HEADER_SIZE: usize = 32;
const ALIGNMENT: u32 = 0x1000;
const CHECK_BLOCK: usize = 64 * 1024;

// Stock writes this DOS header and stub before the original PE header.
const DOS_HEADER: &[u8; 0xd0] = b"\
    MZ\x90\0\x02\0\0\0\x04\0\x0f\0\xff\xff\0\0\xb0\0\0\0\0\0\0\0@\0\x1a\0\0\0\0\0\
    \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd0\0\0\0\
    \x0e\x1f\xb4\x09\xba\x0d\0\xcd\x21\xb4\x4c\xcd\x21\
    This file was created by ClamAV for internal use and should not be run.\r\n\
    ClamAV - A GPL virus scanner - http://www.clamav.net\r\n$\0\0\0";

fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(*bytes.get(at..)?.first_chunk()?))
}

fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(*bytes.get(at..)?.first_chunk()?))
}

fn aligned(size: u32) -> u64 {
    u64::from(size).next_multiple_of(ALIGNMENT.into())
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(packed) = Packed::recognize(bytes) else {
        return Ok(Handling::Unrecognized);
    };
    // Stock checks its decompression buffer against the limits before it decodes.
    if sink.skip_declared_size(packed.buffer) {
        return Ok(Handling::Complete);
    }
    let limit = sink.remaining();
    let Some(image) = packed.unpack(limit, &mut || sink.check())? else {
        return Ok(Handling::Incomplete);
    };
    Ok(if sink.child_bytes(&image, None)? {
        Handling::Stopped
    } else {
        Handling::Complete
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Method {
    Nrv2b,
    Nrv2d,
    Nrv2e,
}

struct Section {
    size: u32,
    rva: u32,
    raw_size: u32,
    raw: u32,
}

impl Section {
    fn read(table: &[u8], at: usize) -> Option<Self> {
        Some(Self {
            size: le32(table, at + 8)?,
            rva: le32(table, at + 12)?,
            raw_size: le32(table, at + 16)?,
            raw: le32(table, at + 20)?,
        })
    }

    fn raw_bytes<'a>(&self, bytes: &'a [u8], delta: u32, size: u32) -> Option<&'a [u8]> {
        if delta.checked_add(size)? > self.raw_size {
            return None;
        }
        let start = (self.raw as usize).checked_add(delta as usize)?;
        bytes.get(start..start.checked_add(size as usize)?)
    }
}

struct Packed<'a> {
    method: Method,
    stream: &'a [u8],
    unpacked: usize,
    buffer: u64,
    rva: usize,
}

impl<'a> Packed<'a> {
    fn recognize(bytes: &'a [u8]) -> Option<Self> {
        let header = bytes.get(le32(bytes, 0x3c)? as usize..)?;
        let optional = header.get(24..)?;
        if !bytes.starts_with(b"MZ")
            || !header.starts_with(b"PE\0\0")
            || le16(header, 4)? != 0x14c
            || le16(header, 6)? < 2
            || le16(optional, 0)? != 0x10b
            || le32(optional, 32)? != ALIGNMENT
        {
            return None;
        }
        let entry = le32(optional, 16)?;
        let image_base = le32(optional, 28)?;
        let table = 24 + le16(header, 20)? as usize;
        let upx0 = Section::read(header, table)?;
        let upx1 = Section::read(header, table + 40)?;
        if upx0.raw_size != 0 || upx0.size == 0 || upx1.raw_size == 0 || upx1.size == 0 {
            return None;
        }
        // The stub starts with pushad, mov esi, stream and lea edi, [esi + disp].
        let code = upx1.raw_bytes(bytes, entry.checked_sub(upx1.rva)?, 12)?;
        let esi = le32(code, 2)?;
        if code[..2] != [0x60, 0xbe]
            || code[6..8] != [0x8d, 0xbe]
            || esi.wrapping_add(le32(code, 8)?) != image_base.wrapping_add(upx0.rva)
        {
            return None;
        }
        let start = esi.checked_sub(image_base)?.checked_sub(upx1.rva)?;
        // The pack header ends where the compressed stream starts.
        let offset = (upx1.raw as usize).checked_add(start as usize)?;
        let pack = bytes.get(offset.checked_sub(PACK_HEADER_SIZE)?..offset)?;
        let version = bytes.get(offset.checked_sub(PACK_HEADER_SIZE + VERSION.len())?..)?;
        if !pack.starts_with(PACK_HEADER) || !version.starts_with(VERSION) {
            return None;
        }
        let method = match pack[6] {
            2 => Method::Nrv2b,
            5 => Method::Nrv2d,
            8 => Method::Nrv2e,
            _ => return None,
        };
        Some(Self {
            method,
            stream: upx1.raw_bytes(bytes, start, le32(pack, 20)?)?,
            unpacked: le32(pack, 16)? as usize,
            // Stock rounds each section size up before it sizes its decompression buffer.
            buffer: aligned(upx0.size) + aligned(upx1.size),
            rva: upx0.rva as usize,
        })
    }

    /// Return the rebuilt image, or None when stock's result is uncertain.
    fn unpack(
        &self,
        limit: u64,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Option<Vec<u8>>> {
        if self.unpacked as u64 > self.buffer || self.rva as u64 > limit {
            return Ok(None);
        }
        // Stock tries several decoders. Another accepted decoding makes its choice uncertain.
        for method in [Method::Nrv2b, Method::Nrv2d, Method::Nrv2e] {
            if method != self.method
                && decode(method, self.stream, self.unpacked, 0, check)?.is_some()
            {
                return Ok(None);
            }
        }
        // Keep room for the headers below UPX0, so the image reuses this buffer.
        let data = decode(self.method, self.stream, self.unpacked, self.rva, check)?;
        Ok(data.and_then(|data| rebuild(data, self.rva, limit)))
    }
}

// UPX stores the original PE header after the image. Stock uses the last
// "PE\0\0" in the decompressed data and gives up on sections it cannot map.
// It also sizes the image from the sections. Other layouts stay unverified.
fn rebuild(mut data: Vec<u8>, rva: usize, limit: u64) -> Option<Vec<u8>> {
    let at = memchr::memmem::rfind(&data, b"PE\0\0")?;
    let header = &data[at..];
    let count = le16(header, 6)? as usize;
    let header = header.get(..24 + 0xe0 + 40 * count)?;
    let size = le32(header, 24 + 56)?;
    let end = DOS_HEADER.len() + header.len();
    if le16(header, 4)? != 0x14c
        || le16(header, 20)? != 0xe0
        || le16(header, 24)? != 0x10b
        || count == 0
        || le32(header, 24 + 32)? != ALIGNMENT
        || end > rva
        || u64::from(size) > limit
    {
        return None;
    }
    let stored = (rva + at) as u64;
    let mut image_end = 0;
    for section in header[24 + 0xe0..].as_chunks::<40>().0 {
        let start = le32(section, 12)?;
        let virtual_size = le32(section, 8)?;
        image_end = u64::from(start) + aligned(virtual_size);
        if virtual_size == 0
            || start % ALIGNMENT != 0
            || (start as usize) < rva
            || image_end > stored.min(size.into())
        {
            return None;
        }
    }
    if image_end != u64::from(size) {
        return None;
    }
    let header = header.to_vec();
    let size = size as usize;
    // The stored header lies past the image. Move the image to UPX0's RVA in place.
    data.resize(size, 0);
    data.copy_within(..size - rva, rva);
    data[..DOS_HEADER.len()].copy_from_slice(DOS_HEADER);
    data[end..rva].fill(0);
    let pe = &mut data[DOS_HEADER.len()..end];
    pe.copy_from_slice(&header);
    // Stock stamps "CLAM" as the time and maps each section at its RVA.
    pe[8..12].copy_from_slice(b"CLAM");
    pe[24 + 36..24 + 40].copy_from_slice(&ALIGNMENT.to_le_bytes());
    for section in pe[24 + 0xe0..].as_chunks_mut::<40>().0 {
        // Each aligned section ends inside the image, so its size fits in 32 bits.
        let size = (aligned(le32(section, 8)?) as u32).to_le_bytes();
        section[8..12].copy_from_slice(&size);
        section[16..20].copy_from_slice(&size);
        section.copy_within(12..16, 20);
    }
    Some(data)
}

struct Bits<'a> {
    input: &'a [u8],
    pos: usize,
    word: u32,
    count: u32,
}

impl Bits<'_> {
    // Control bits come from little-endian 32-bit words, most significant bit first.
    fn bit(&mut self) -> Option<u32> {
        if self.count == 0 {
            self.word = le32(self.input, self.pos)?;
            self.pos += 4;
            self.count = 32;
        }
        self.count -= 1;
        Some((self.word >> self.count) & 1)
    }

    fn byte(&mut self) -> Option<u8> {
        let byte = *self.input.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    // Each value bit is followed by a stop bit. Overflow marks a corrupt stream.
    fn gamma(&mut self, mut value: u32) -> Option<u32> {
        loop {
            value = value.checked_mul(2)? | self.bit()?;
            if self.bit()? == 1 {
                return Some(value);
            }
        }
    }
}

struct Decoder<'a> {
    method: Method,
    bits: Bits<'a>,
    out: Vec<u8>,
    size: usize,
    last: u32,
}

impl Decoder<'_> {
    /// Decode one literal or one match. Return false after the end marker.
    fn step(&mut self) -> Option<bool> {
        let nrv2b = self.method == Method::Nrv2b;
        let bits = &mut self.bits;
        if bits.bit()? == 1 {
            let byte = bits.byte()?;
            if self.out.len() == self.size {
                return None;
            }
            self.out.push(byte);
            return Some(true);
        }
        let offset = if nrv2b {
            bits.gamma(1)?
        } else {
            let mut value = 1u32;
            loop {
                value = value.checked_mul(2)? | bits.bit()?;
                if bits.bit()? == 1 {
                    break value;
                }
                value = (value - 1).checked_mul(2)? | bits.bit()?;
            }
        };
        let (offset, low) = if offset == 2 {
            (self.last, if nrv2b { 0 } else { bits.bit()? })
        } else {
            let offset = (offset - 3).checked_mul(256)? | u32::from(bits.byte()?);
            if offset == u32::MAX {
                return Some(false);
            }
            // NRV2D and NRV2E keep the inverted first length bit in the lowest offset bit.
            let (offset, low) = if nrv2b {
                (offset, 0)
            } else {
                (offset >> 1, !offset & 1)
            };
            self.last = offset + 1;
            (self.last, low)
        };
        // NRV2B reads its first length bit after the offset.
        let low = if nrv2b { bits.bit()? } else { low };
        let length = if self.method != Method::Nrv2e {
            match low * 2 + bits.bit()? {
                0 => bits.gamma(1)?.checked_add(2)?,
                length => length,
            }
        } else if low == 1 {
            1 + bits.bit()?
        } else if bits.bit()? == 1 {
            3 + bits.bit()?
        } else {
            bits.gamma(1)?.checked_add(3)?
        };
        let far = if nrv2b { 0xd00 } else { 0x500 };
        let count = (length as usize).checked_add(1 + usize::from(offset > far))?;
        let distance = offset as usize;
        if distance > self.out.len() || count > self.size - self.out.len() {
            return None;
        }
        let start = self.out.len() - distance;
        for at in start..start + count {
            let byte = self.out[at];
            self.out.push(byte);
        }
        Some(true)
    }
}

/// Decode exactly `size` bytes from the whole input. None marks an invalid stream.
/// The buffer reserves `spare` more bytes, so the caller can grow it in place.
fn decode(
    method: Method,
    input: &[u8],
    size: usize,
    spare: usize,
    check: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    if out.try_reserve_exact(size + spare).is_err() {
        return Ok(None);
    }
    let mut decoder = Decoder {
        method,
        bits: Bits {
            input,
            pos: 0,
            word: 0,
            count: 0,
        },
        out,
        size,
        last: 1,
    };
    let mut next_check = 0;
    loop {
        if decoder.out.len() >= next_check {
            check()?;
            next_check = decoder.out.len() + CHECK_BLOCK;
        }
        match decoder.step() {
            Some(true) => {}
            Some(false) => break,
            None => return Ok(None),
        }
    }
    let Decoder { bits, out, .. } = decoder;
    Ok((out.len() == size && bits.pos == input.len()).then_some(out))
}

#[cfg(test)]
mod tests {
    use super::{Method, Packed, decode};
    use crate::objects::{Options, Verdict};
    use std::io;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/upx/");
    const METHODS: [Method; 3] = [Method::Nrv2b, Method::Nrv2d, Method::Nrv2e];

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{DIR}{name}")).unwrap()
    }

    fn md5(bytes: &[u8]) -> String {
        crate::hash_reader(bytes).unwrap().md5_hex()
    }

    fn packed() -> [(Vec<u8>, Method); 3] {
        [
            (fixture("ledger-nrv2b.exe"), Method::Nrv2b),
            (fixture("ledger-nrv2d.exe"), Method::Nrv2d),
            (fixture("ledger-nrv2e.exe"), Method::Nrv2e),
        ]
    }

    #[test]
    fn decoders_read_each_method() -> io::Result<()> {
        for (bytes, method) in packed() {
            let packed = Packed::recognize(&bytes).unwrap();
            assert_eq!(packed.method, method);
            assert_eq!((packed.unpacked, packed.buffer), (0x10701, 0x12000));
            for other in METHODS {
                let data = decode(other, packed.stream, packed.unpacked, 0, &mut || Ok(()))?;
                if other == method {
                    let data = data.unwrap();
                    assert_eq!(data.len(), 0x10701);
                    assert_eq!(md5(&data), "1e23fddba97e6c7501185cbcd57913b0");
                } else {
                    assert!(data.is_none(), "{method:?} stream decoded as {other:?}");
                }
            }
        }
        Ok(())
    }

    #[test]
    fn rebuild_matches_stock() -> io::Result<()> {
        for (bytes, _) in packed() {
            let packed = Packed::recognize(&bytes).unwrap();
            let image = packed.unpack(u64::MAX, &mut || Ok(()))?.unwrap();
            assert_eq!(image.len(), 0x11000);
            assert_eq!(md5(&image), "52bd7b6f5b3a2c728c73c46d48c1ac51");
            assert!(packed.unpack(0x10fff, &mut || Ok(()))?.is_none());
        }
        Ok(())
    }

    #[test]
    fn other_layouts_stay_unrecognized() {
        for name in [
            "ledger.exe",
            "ledger-lzma.exe",
            "ledger-dll-nrv2b.dll",
            "ledger64-nrv2b.exe",
        ] {
            assert!(Packed::recognize(&fixture(name)).is_none(), "{name}");
        }
    }

    #[test]
    fn corrupt_streams_fail_without_panic() -> io::Result<()> {
        for (bytes, method) in packed() {
            let packed = Packed::recognize(&bytes).unwrap();
            let stream = packed.stream;
            for cut in [0, 1, 4, 5, stream.len() / 2, stream.len() - 1] {
                let data = decode(method, &stream[..cut], packed.unpacked, 0, &mut || Ok(()))?;
                assert!(data.is_none(), "{method:?} cut at {cut}");
            }
            let mut longer = stream.to_vec();
            longer.push(0);
            assert!(decode(method, &longer, packed.unpacked, 0, &mut || Ok(()))?.is_none());
            let short = packed.unpacked - 1;
            assert!(decode(method, stream, short, 0, &mut || Ok(()))?.is_none());
            for at in (0..stream.len()).step_by(61) {
                let mut corrupt = stream.to_vec();
                corrupt[at] ^= 0xa5;
                for other in METHODS {
                    decode(other, &corrupt, packed.unpacked, 0, &mut || Ok(()))?;
                }
            }
        }
        let mut state = 0x2545_f491_u32;
        let noise: Vec<u8> = (0..4096)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect();
        for method in METHODS {
            for size in [0, 1, 0x10000] {
                assert!(decode(method, &noise, size, 0, &mut || Ok(()))?.is_none());
            }
            assert!(decode(method, &[0xff; 64], 0x10000, 0, &mut || Ok(()))?.is_none());
            assert!(decode(method, &[0; 64], 0x10000, 0, &mut || Ok(()))?.is_none());
        }
        Ok(())
    }

    #[test]
    fn decoding_stops_when_the_scan_is_cancelled() {
        let bytes = fixture("ledger-nrv2b.exe");
        let packed = Packed::recognize(&bytes).unwrap();
        let error = packed
            .unpack(u64::MAX, &mut || Err(io::ErrorKind::TimedOut.into()))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn buffer_rounds_each_section_size() {
        let bytes = fixture("ledger-nrv2b.exe");
        // UPX0's VirtualSize is at 0x180 and UPX1's is at 0x1a8.
        for (at, size, buffer) in [(0x180, 0xc001u32, 0x13000), (0x1a8, 0x5401, 0x12000)] {
            let mut patched = bytes.clone();
            patched[at..at + 4].copy_from_slice(&size.to_le_bytes());
            assert_eq!(Packed::recognize(&patched).unwrap().buffer, buffer);
        }
        let mut patched = bytes;
        patched[0xb8..0xbc].copy_from_slice(&0x2000u32.to_le_bytes());
        assert!(Packed::recognize(&patched).is_none());
    }

    // NRV2B control bits fill little-endian words from the most significant bit.
    #[derive(Default)]
    struct Writer {
        out: Vec<u8>,
        word: usize,
        count: u32,
    }

    impl Writer {
        fn bit(&mut self, bit: bool) {
            if self.count == 0 {
                self.word = self.out.len();
                self.out.extend([0; 4]);
                self.count = 32;
            }
            self.count -= 1;
            if bit {
                self.out[self.word + self.count as usize / 8] |= 1 << (self.count % 8);
            }
        }
    }

    /// Encode every byte as an NRV2B literal, then the end marker.
    fn literal_stream(data: &[u8]) -> Vec<u8> {
        let mut writer = Writer::default();
        for &byte in data {
            writer.bit(true);
            writer.out.push(byte);
        }
        // The end marker is a match with offset 0xffffffff: gamma 0x1000002, then 0xff.
        writer.bit(false);
        for shift in (0..24).rev() {
            writer.bit((0x100_0002 >> shift) & 1 == 1);
            writer.bit(shift == 0);
        }
        writer.out.push(0xff);
        writer.out
    }

    /// Replace the stream in ledger-nrv2b.exe and move the entry code after it.
    fn repack(data: &[u8]) -> Vec<u8> {
        let mut bytes = fixture("ledger-nrv2b.exe");
        let stream = literal_stream(data);
        let code = bytes[0x52f0..0x52fc].to_vec();
        bytes.truncate(0x215);
        bytes[0x205..0x209].copy_from_slice(&(data.len() as u32).to_le_bytes());
        bytes[0x209..0x20d].copy_from_slice(&(stream.len() as u32).to_le_bytes());
        let entry = 0xd015 + stream.len() as u32;
        bytes.extend(stream);
        bytes.extend(code);
        let raw_size = bytes.len() as u32 - 0x200;
        bytes[0xa8..0xac].copy_from_slice(&entry.to_le_bytes());
        bytes[0x1b0..0x1b4].copy_from_slice(&raw_size.to_le_bytes());
        bytes
    }

    /// Scan a file and return the verdict with the size and MD5 of each child.
    fn scan_children(bytes: &[u8]) -> io::Result<(Verdict, Vec<(usize, String)>)> {
        let dir = tempfile::tempdir()?;
        let mut children = Vec::new();
        let verdict = crate::objects::scan(
            bytes,
            &Options::default(),
            dir.path(),
            |object, _| {
                if !object.parents.is_empty() {
                    children.push((object.bytes.len(), md5(object.bytes)));
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        Ok((verdict, children))
    }

    #[test]
    fn unverified_layouts_are_incomplete() -> io::Result<()> {
        let bytes = fixture("ledger-nrv2b.exe");
        let packed = Packed::recognize(&bytes).unwrap();
        let data = decode(
            Method::Nrv2b,
            packed.stream,
            packed.unpacked,
            0,
            &mut || Ok(()),
        )?;
        let data = data.unwrap();
        let (verdict, children) = scan_children(&repack(&data))?;
        assert_eq!(verdict, Verdict::Miss);
        let unpacked = (0x11000, "52bd7b6f5b3a2c728c73c46d48c1ac51".to_string());
        assert!(children.contains(&unpacked));

        let header = memchr::memmem::rfind(&data, b"PE\0\0").unwrap();
        let table = header + 24 + 0xe0;
        let count = u16::from_le_bytes([data[header + 6], data[header + 7]]) as usize;
        let copy = data[header..table + 40 * count].to_vec();
        let set = |at: usize, value: u32| {
            let mut data = data.clone();
            data[at..at + 4].copy_from_slice(&value.to_le_bytes());
            data
        };
        let later = |at: usize, value: u16| {
            let mut data = data.clone();
            let mut copy = copy.clone();
            copy[at..at + 2].copy_from_slice(&value.to_le_bytes());
            data.extend(copy);
            data
        };
        let mut inside = data.clone();
        inside[0x8000..0x8000 + copy.len()].copy_from_slice(&copy);
        let mut moved = inside.clone();
        moved[header] = b'X';
        let mut garbage = data.clone();
        garbage.extend(b"PE\0\0garbage");
        let rva = u32::from_le_bytes(data[table + 52..table + 56].try_into().unwrap());
        for (name, data) in [
            ("empty section", set(table + 48, 0)),
            (
                "section past the image",
                set(table + 40 * count - 28, 0x20000),
            ),
            ("unaligned section", set(table + 52, rva + 0x10)),
            ("unaligned image size", set(header + 80, 0x11010)),
            ("small image size", set(header + 80, 0x10000)),
            ("header inside the image", moved),
            ("later PE32+ header", later(24, 0x20b)),
            ("later AMD64 header", later(4, 0x8664)),
            ("later garbage", garbage),
        ] {
            assert_eq!(
                scan_children(&repack(&data))?.0,
                Verdict::Incomplete,
                "{name}"
            );
        }
        // An earlier valid header, such as an embedded PE, does not change the choice.
        let (verdict, children) = scan_children(&repack(&inside))?;
        assert_eq!(verdict, Verdict::Miss);
        assert!(children.iter().any(|&(size, _)| size == 0x11000));
        Ok(())
    }
}
