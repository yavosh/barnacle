use super::{ChildSink, Handling, workspace};
use crate::objects::Snapshot;
use sevenz_rust2::{Archive, ArchiveEntry, Block, BlockDecoder, EncoderMethod, Password};
use std::io::{self, Cursor, Write};

const MEMORY_LIMIT_KIB: usize = 1024 * 1024;
// Bound speculative storage while preserving large individually eligible members.
const SOLID_BATCH_BYTES: u64 = 64 << 20;
const SEPARATE_MEMBER_BYTES: u64 = 4 << 20;

fn has_data(entry: &ArchiveEntry) -> bool {
    entry.has_stream && !entry.is_directory && entry.size != 0
}

fn header_workspace(bytes: &[u8]) -> Option<u64> {
    let offset = u64::from_le_bytes(bytes.get(12..20)?.try_into().ok()?);
    let size = u64::from_le_bytes(bytes.get(20..28)?.try_into().ok()?);
    let position = usize::try_from(offset.checked_add(32)?).ok()?;
    // The ordinary Header record is uncompressed. An encoded or recovered
    // header can select any supported codec before its properties are known.
    (size > 0 && bytes.get(position) == Some(&1)).then_some(size.saturating_add(2 << 20))
}

fn block_workspace(block: &Block) -> (u64, u64) {
    let history = if block.coders.len() == 1 {
        workspace::history(block.get_unpack_size())
    } else {
        u64::MAX
    };
    let mut total = 0u64;
    let mut models = 0u64;
    for coder in &block.coders {
        let props = coder.properties();
        let dictionary = || {
            props
                .get(1..5)
                .map(|bytes| u64::from(u32::from_le_bytes(bytes.try_into().expect("four bytes"))))
                .unwrap_or(workspace::BUDGET)
        };
        let bytes = match coder.encoder_method_id() {
            EncoderMethod::ID_PPMD => {
                let model = dictionary();
                models = models.saturating_add(model);
                model
            }
            EncoderMethod::ID_LZMA => props
                .first()
                .and_then(|&property| {
                    lzma_rust2::lzma_get_memory_usage_by_props(
                        dictionary().min(history) as u32,
                        property,
                    )
                    .ok()
                })
                .map_or(workspace::BUDGET, |kib| u64::from(kib) * 1024),
            EncoderMethod::ID_LZMA2 => match props.first().copied() {
                Some(bits @ 0..=39) => {
                    ((2u64 | u64::from(bits & 1)) << (bits / 2 + 11)).min(history)
                }
                _ => history,
            },
            EncoderMethod::ID_BZIP2 => 8 << 20,
            _ => 0,
        };
        total = total.saturating_add(bytes).saturating_add(2 << 20);
    }
    (total, models)
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let mut source = Cursor::new(bytes);
    let password = Password::empty();
    // Stock's 7z allocator uses the same individual-allocation ceiling as its XZ decoder.
    let header_result = {
        // Compressed headers can select their own decoder and model before
        // the archive exposes the block metadata.
        let _lease =
            workspace::acquire(header_workspace(bytes).unwrap_or(workspace::BUDGET), || {
                sink.check()
            })?;
        Archive::read_with_memory_limit(&mut source, &password, MEMORY_LIMIT_KIB)
    };
    let Ok(archive) = header_result else {
        return Ok(Handling::Incomplete);
    };
    for index in 0..archive.blocks.len() {
        let first = archive.stream_map.block_first_file_index[index];
        let count = BlockDecoder::new_with_memory_limit(
            1,
            MEMORY_LIMIT_KIB,
            index,
            &archive,
            &password,
            &mut source,
        )
        .entry_count();
        let end = first + count;
        let entries = &archive.files[first..end];
        let mut start = 0;
        while start < entries.len() {
            sink.check()?;
            let limit = sink.remaining();
            // Skip an ineligible leading member without instantiating a decoder.
            if !has_data(&entries[start]) || sink.skip_declared_size(entries[start].size) {
                start += 1;
                continue;
            }
            let mut end = start + 1;
            let mut size = entries[start].size;
            while let Some(entry) = entries.get(end) {
                if has_data(entry) && entry.size <= limit {
                    if size.saturating_add(entry.size) > SOLID_BATCH_BYTES {
                        break;
                    }
                    size += entry.size;
                }
                end += 1;
            }
            let block = BlockDecoder::new_with_memory_limit(
                1,
                MEMORY_LIMIT_KIB,
                index,
                &archive,
                &password,
                &mut source,
            );
            let (bytes, models) = block_workspace(&archive.blocks[index]);
            let lease = workspace::acquire_with_ppmd(bytes, models, || sink.check())?;
            let result = scan_batch(block, entries, start..end, limit, lease, sink)?;
            if result != Handling::Complete {
                return Ok(result);
            }
            start = end;
        }
    }
    Ok(Handling::Complete)
}

fn scan_batch(
    block: BlockDecoder<'_, Cursor<&[u8]>>,
    entries: &[ArchiveEntry],
    batch: std::ops::Range<usize>,
    limit: u64,
    lease: workspace::Lease,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let mut snapshot = Snapshot::new(sink.temporary_directory());
    let mut large_members = std::collections::VecDeque::new();
    let mut error = None;
    let mut index = 0;
    let mut completed = batch.start;
    let mut buffer = [0; 8192];
    let last = entries[batch.clone()]
        .iter()
        .rposition(|entry| has_data(entry) && entry.size <= limit)
        .expect("first entry is eligible")
        + batch.start;
    // Releasing the decoder before visiting *any* member prevents nested solid
    // blocks from pinning one dictionary per archive depth. One private spool
    // also bounds descriptor use independently of the number of small files.
    let decoded = block.for_each_entries(&mut |entry, reader| {
        let current = index;
        index += 1;
        if current > last {
            return Ok(false);
        }
        let keep = current >= batch.start && has_data(entry) && entry.size <= limit;
        // Release large siblings individually after scanning. The 64 MiB
        // batch admits at most 16 such private files, or one larger member.
        let mut separate = (keep && entry.size >= SEPARATE_MEMBER_BYTES)
            .then(|| Snapshot::new(sink.temporary_directory()));
        loop {
            if let Err(e) = sink.check() {
                error = Some(e);
                return Ok(false);
            }
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) if keep => {
                    if let Err(e) = separate
                        .as_mut()
                        .unwrap_or(&mut snapshot)
                        .write_all(&buffer[..count])
                    {
                        error = Some(e);
                        return Ok(false);
                    }
                }
                Ok(_) => (),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Ok(false),
            }
        }
        if let Some(separate) = separate {
            large_members.push_back(separate);
        }
        completed = completed.max(current + 1);
        Ok(true)
    });
    drop(lease);
    if let Some(error) = error {
        return Err(error);
    }
    // A valid earlier member can win even if a later member fails to decode.
    let visit_end = if completed > last {
        batch.end
    } else {
        completed
    };
    let stopped = snapshot.with_bytes(|bytes| {
        let mut offset = 0;
        for entry in &entries[batch.start..visit_end] {
            sink.check()?;
            if !has_data(entry) {
                continue;
            }
            if entry.size > limit {
                sink.skip_declared_size(entry.size);
                continue;
            }
            // Stock passes the low byte of each UTF-16 unit as metadata.
            let name: Vec<_> = entry
                .name
                .encode_utf16()
                .map(|unit| unit as u8)
                .take_while(|&byte| byte != 0)
                .collect();
            let skip = sink.skip_declared_size(entry.size);
            let found = if entry.size >= SEPARATE_MEMBER_BYTES {
                let member = large_members.pop_front().expect("completed member");
                !skip && member.with_bytes(|member| sink.child_bytes(member, Some(&name)))?
            } else {
                let length = usize::try_from(entry.size).map_err(io::Error::other)?;
                let Some(member) = bytes.get(offset..).and_then(|data| data.get(..length)) else {
                    return Ok(Handling::Incomplete);
                };
                offset += length;
                !skip && sink.child_bytes(member, Some(&name))?
            };
            if found {
                return Ok(Handling::Stopped);
            }
        }
        Ok(Handling::Complete)
    })?;
    if stopped != Handling::Complete {
        return Ok(stopped);
    }
    Ok(if completed <= last || decoded.is_err() {
        Handling::Incomplete
    } else {
        Handling::Complete
    })
}
