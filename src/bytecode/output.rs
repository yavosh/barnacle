//! Per-invocation bytecode output.
use crate::objects::{Limit, Snapshot};
use std::io::{self, Write};
use std::path::Path;

#[derive(Clone, Copy)]
pub(crate) struct OutputLimits {
    pub file_size: u64,
    pub scan_remaining: u64,
    pub file_slot: bool,
}

pub(crate) struct Output {
    pub limits: OutputLimits,
    pub rejected: Option<Limit>,
    pub snapshot: Option<Snapshot>,
    pub size: u64,
}

impl Output {
    pub fn new(limits: OutputLimits) -> Self {
        Self {
            limits,
            rejected: None,
            snapshot: None,
            size: 0,
        }
    }

    pub fn accepts(&mut self, len: usize) -> bool {
        let total = self.size.saturating_add(len as u64);
        let reject = if total > self.limits.scan_remaining {
            Limit::MaxScanSize
        } else if total > self.limits.file_size {
            Limit::MaxFileSize
        } else if !self.limits.file_slot {
            Limit::MaxFiles
        } else {
            return true;
        };
        self.rejected.get_or_insert(reject);
        false
    }

    pub fn append(
        &mut self,
        directory: &Path,
        bytes: &[u8],
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        for chunk in bytes.chunks(64 * 1024) {
            check()?;
            self.snapshot
                .get_or_insert_with(|| Snapshot::new(directory))
                .write_all(chunk)?;
            self.size += chunk.len() as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spilled_output_is_cancellable_between_chunks() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let limits = OutputLimits {
            file_size: u64::MAX,
            scan_remaining: u64::MAX,
            file_slot: true,
        };
        let mut output = Output::new(limits);
        let mut calls = 0;
        let error = output
            .append(dir.path(), &vec![b'x'; 3 * 64 * 1024], &mut || {
                calls += 1;
                if calls == 3 {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(output.size, 2 * 64 * 1024);
        output.snapshot.unwrap().with_bytes(|bytes| {
            assert!(bytes.iter().all(|&b| b == b'x'));
            assert_eq!(bytes.len(), 2 * 64 * 1024);
            Ok(())
        })
    }
}
