//! Interpreted 8-bit PCRE2 matches against a single immutable scan object.
use pcre2_sys::*;
use std::ffi::{c_int, c_void};
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::ptr::{self, NonNull};

#[derive(Debug)]
pub struct Code {
    pointer: NonNull<pcre2_code_8>,
    heap_kib: u32,
    utf: bool,
}

// SAFETY: PCRE2 permits concurrent interpretive matches on immutable compiled
// code. This wrapper never modifies the code or installs a JIT program.
unsafe impl Send for Code {}
unsafe impl Sync for Code {}

const FLAGS: u32 = PCRE2_ANCHORED
    | PCRE2_CASELESS
    | PCRE2_DOLLAR_ENDONLY
    | PCRE2_DOTALL
    | PCRE2_EXTENDED
    | PCRE2_MULTILINE
    | PCRE2_UNGREEDY;

impl Code {
    pub fn compile(pattern: &[u8], options: u32) -> io::Result<Self> {
        if options & !FLAGS != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported PCRE2 compile option",
            ));
        }
        let mut error = 0;
        let mut at = 0;
        // Long valid patterns sometimes fit only without automatic callouts.
        // Both forms retain the same offset, match, depth, and heap limits.
        for callouts in [PCRE2_AUTO_CALLOUT, 0] {
            // SAFETY: the input and outputs live through the call. No unchecked
            // UTF option is allowed, including for patterns using (*UTF).
            let code = unsafe {
                pcre2_compile_8(
                    pattern.as_ptr(),
                    pattern.len(),
                    options | PCRE2_USE_OFFSET_LIMIT | callouts,
                    &mut error,
                    &mut at,
                    ptr::null_mut(),
                )
            };
            if let Some(code) = NonNull::new(code) {
                return Ok(Self::from_pointer(code));
            }
            if error != PCRE2_ERROR_PATTERN_TOO_LARGE as i32 {
                break;
            }
        }
        let kind = if error == PCRE2_ERROR_HEAP_FAILED as i32 {
            io::ErrorKind::OutOfMemory
        } else {
            io::ErrorKind::InvalidData
        };
        Err(io::Error::new(
            kind,
            format!("PCRE2 compile error at byte {at}: {}", error_text(error)),
        ))
    }

    fn from_pointer(pointer: NonNull<pcre2_code_8>) -> Self {
        let mut options = 0u32;
        let mut heap_kib = u32::MAX;
        // SAFETY: each query only reads compiled code and writes one u32.
        let (options_status, heap_status) = unsafe {
            (
                pcre2_pattern_info_8(
                    pointer.as_ptr(),
                    PCRE2_INFO_ALLOPTIONS,
                    ptr::from_mut(&mut options).cast(),
                ),
                pcre2_pattern_info_8(
                    pointer.as_ptr(),
                    PCRE2_INFO_HEAPLIMIT,
                    ptr::from_mut(&mut heap_kib).cast(),
                ),
            )
        };
        debug_assert_eq!(options_status, 0);
        debug_assert!(heap_status == 0 || heap_status == PCRE2_ERROR_UNSET);
        Self {
            pointer,
            heap_kib,
            utf: options & PCRE2_UTF != 0,
        }
    }

    pub fn is_utf(&self) -> bool {
        self.utf
    }
}

impl Drop for Code {
    fn drop(&mut self) {
        // SAFETY: this is the unique owner of the allocation returned by compile.
        unsafe { pcre2_code_free_8(self.pointer.as_ptr()) }
    }
}

fn error_text(code: c_int) -> String {
    let mut buf = [0; 256];
    // SAFETY: PCRE2 receives the actual length of a writable buffer.
    let n = unsafe { pcre2_get_error_message_8(code, buf.as_mut_ptr(), buf.len()) };
    if n < 0 {
        format!("error {code}")
    } else {
        format!("{} ({code})", String::from_utf8_lossy(&buf[..n as usize]))
    }
}

#[derive(Debug)]
pub enum MatchError {
    MatchLimit,
    DepthLimit,
    HeapLimit,
    PatternHeapLimit,
    UtfSubject,
    UtfOffset,
    Check(io::Error),
    Engine(io::Error),
}

// pcre2-sys 0.2.10 omits this declaration. The callback ignores the native block.
#[repr(C)]
struct CalloutBlock {
    _opaque: [u8; 0],
}

unsafe extern "C" {
    fn pcre2_set_callout_8(
        ctx: *mut pcre2_match_context_8,
        call: Option<unsafe extern "C" fn(*mut CalloutBlock, *mut c_void) -> c_int>,
        data: *mut c_void,
    ) -> c_int;
}

struct Poll<'a> {
    check: &'a mut dyn FnMut() -> io::Result<()>,
    ticks: u8,
    outcome: std::thread::Result<io::Result<()>>,
}

unsafe extern "C" fn callout(_: *mut CalloutBlock, data: *mut c_void) -> c_int {
    // SAFETY: find installs a pointer to its live Poll for this synchronous
    // match only. PCRE2 calls it on the matching thread without reentrancy.
    let poll = unsafe { &mut *data.cast::<Poll<'_>>() };
    poll.ticks = poll.ticks.wrapping_add(1);
    if poll.ticks == 0 {
        poll.outcome = catch_unwind(AssertUnwindSafe(&mut *poll.check));
        if !matches!(poll.outcome, Ok(Ok(()))) {
            return PCRE2_ERROR_CALLOUT;
        }
    }
    0
}

pub struct Session {
    ctx: NonNull<pcre2_match_context_8>,
    data: NonNull<pcre2_match_data_8>,
    heap_kib: u32,
}

impl Session {
    /// Reuse matching storage within one scan. The heap limit counts KiB of
    /// interpreter backtracking frames. It remains fixed for this session.
    pub fn new(match_limit: u32, depth_limit: u32, heap_kib: u32) -> io::Result<Self> {
        // SAFETY: null selects PCRE2's default allocator. Each allocation
        // is either transferred to Session or freed on partial failure.
        unsafe {
            let ctx = NonNull::new(pcre2_match_context_create_8(ptr::null_mut()))
                .ok_or(io::ErrorKind::OutOfMemory)?;
            let Some(data) = NonNull::new(pcre2_match_data_create_8(1, ptr::null_mut())) else {
                pcre2_match_context_free_8(ctx.as_ptr());
                return Err(io::ErrorKind::OutOfMemory.into());
            };
            let session = Self {
                ctx,
                data,
                heap_kib,
            };
            // Each of these setters accepts every u32 and returns zero on a live context.
            pcre2_set_match_limit_8(ctx.as_ptr(), match_limit);
            pcre2_set_depth_limit_8(ctx.as_ptr(), depth_limit);
            pcre2_set_heap_limit_8(ctx.as_ptr(), heap_kib);
            Ok(session)
        }
    }

    /// Search for one match starting within the inclusive interval. Lookbehind,
    /// anchors, and bytes after the last allowed start see the full subject.
    pub fn find(
        &mut self,
        code: &Code,
        subject: &[u8],
        start: usize,
        max_start: usize,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> Result<Option<(usize, usize)>, MatchError> {
        check().map_err(MatchError::Check)?;
        if start > max_start || start > subject.len() {
            return Ok(None);
        }
        let pattern_heap = (code.heap_kib <= self.heap_kib).then_some(code.heap_kib);
        if let Some(kib) = pattern_heap {
            // PCRE2 reuses existing frames without enforcing a lower inline cap
            // until it needs to grow them. Start fresh if a prior rule used more.
            // SAFETY: data is exclusively owned and no match is in progress.
            unsafe {
                let bytes = pcre2_get_match_data_heapframes_size_8(self.data.as_ptr());
                if bytes as u64 > u64::from(kib) * 1024 {
                    let data = NonNull::new(pcre2_match_data_create_8(1, ptr::null_mut()))
                        .ok_or_else(|| MatchError::Engine(io::ErrorKind::OutOfMemory.into()))?;
                    pcre2_match_data_free_8(self.data.as_ptr());
                    self.data = data;
                }
            }
        }
        let mut poll = Poll {
            check,
            ticks: 0,
            outcome: Ok(Ok(())),
        };
        // SAFETY: the context and data are exclusive. The immutable code and
        // subject outlive the call. The callback catches Rust panics before
        // returning to C. Clear its borrowed pointer before inspecting results.
        let rc = unsafe {
            let ctx = self.ctx.as_ptr();
            pcre2_set_offset_limit_8(ctx, max_start.min(subject.len()));
            pcre2_set_callout_8(ctx, Some(callout), ptr::from_mut(&mut poll).cast());
            let result = pcre2_match_8(
                code.pointer.as_ptr(),
                subject.as_ptr(),
                subject.len(),
                start,
                PCRE2_NO_JIT,
                self.data.as_ptr(),
                ctx,
            );
            pcre2_set_callout_8(ctx, None, ptr::null_mut());
            result
        };
        match poll.outcome {
            Ok(Ok(())) => (),
            Ok(Err(e)) => return Err(MatchError::Check(e)),
            Err(payload) => resume_unwind(payload),
        }
        // Optimized searches can skip callouts. Also poll after a long opcode.
        check().map_err(MatchError::Check)?;
        match rc {
            // Zero means a successful match with more captures than we requested.
            0.. => {
                // SAFETY: the one allocated pair is initialized on every success.
                let span = unsafe {
                    let offsets = pcre2_get_ovector_pointer_8(self.data.as_ptr());
                    (*offsets, *offsets.add(1))
                };
                Ok(Some(span))
            }
            PCRE2_ERROR_NOMATCH => Ok(None),
            PCRE2_ERROR_MATCHLIMIT => Err(MatchError::MatchLimit),
            PCRE2_ERROR_DEPTHLIMIT => Err(MatchError::DepthLimit),
            PCRE2_ERROR_HEAPLIMIT if pattern_heap.is_some() => Err(MatchError::PatternHeapLimit),
            PCRE2_ERROR_HEAPLIMIT => Err(MatchError::HeapLimit),
            PCRE2_ERROR_UTF8_ERR21..=PCRE2_ERROR_UTF8_ERR1 => Err(MatchError::UtfSubject),
            PCRE2_ERROR_BADUTFOFFSET => Err(MatchError::UtfOffset),
            _ => {
                let kind = if rc == PCRE2_ERROR_NOMEMORY {
                    io::ErrorKind::OutOfMemory
                } else {
                    io::ErrorKind::InvalidData
                };
                Err(MatchError::Engine(io::Error::new(kind, error_text(rc))))
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: both allocations are uniquely owned. No match is in progress.
        unsafe {
            pcre2_match_data_free_8(self.data.as_ptr());
            pcre2_match_context_free_8(self.ctx.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(
        session: &mut Session,
        code: &Code,
        input: &[u8],
    ) -> Result<Option<(usize, usize)>, MatchError> {
        session.find(code, input, 0, input.len(), &mut || Ok(()))
    }

    #[test]
    fn binary_and_captures() {
        let mut session = Session::new(100_000, 2000, 512).unwrap();
        let code = Code::compile(b"(\xff\0A)", PCRE2_CASELESS).unwrap();
        assert_eq!(
            find(&mut session, &code, b"note\xff\0a").unwrap(),
            Some((4, 7))
        );
        assert_eq!(find(&mut session, &code, b"note\xff\0b").unwrap(), None);
        let code = Code::compile(br"([A-Z]{2})-\1", 0).unwrap();
        assert_eq!(
            find(&mut session, &code, b"receipt AB-AB").unwrap(),
            Some((8, 13))
        );
        let code = Code::compile(b"^$", 0).unwrap();
        assert_eq!(find(&mut session, &code, b"").unwrap(), Some((0, 0)));
    }

    #[test]
    fn inclusive_start_preserves_full_subject() {
        let mut session = Session::new(100_000, 2000, 512).unwrap();
        let code = Code::compile(br"(?<=ref )[0-9]{4} done$", 0).unwrap();
        let subject = b"ledger ref 1234 done";
        for (start, end, expected) in [
            (0, 10, None),
            (11, 11, Some((11, 20))),
            (12, usize::MAX, None),
            (11, 10, None),
            (21, 22, None),
        ] {
            assert_eq!(
                session
                    .find(&code, subject, start, end, &mut || Ok(()))
                    .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn limits_and_invalid_patterns() {
        let code = Code::compile(br"(?i)receipt ([0-9]{4}) due", 0).unwrap();
        let input = b"ledger RECEIPT 1784 due";
        let run = |m, d, h| find(&mut Session::new(m, d, h).unwrap(), &code, input);
        assert!(matches!(run(2, 2000, 512), Err(MatchError::MatchLimit)));
        assert!(matches!(run(100_000, 2, 512), Err(MatchError::DepthLimit)));
        assert!(matches!(run(100_000, 2000, 0), Err(MatchError::HeapLimit)));
        assert_eq!(run(3, 3, 512).unwrap(), Some((7, 23)));

        assert!(
            Code::compile(b"[", 0)
                .unwrap_err()
                .to_string()
                .contains("byte 1")
        );
        assert!(Code::compile(b"receipt", PCRE2_NO_UTF_CHECK).is_err());
    }

    #[test]
    fn previous_regex_cannot_lend_frames_to_a_lower_pattern_heap_limit() {
        let receipt = [b"ledger ".as_slice(), &b"row ".repeat(30), b"paid"].concat();
        let warm = Code::compile(b"ledger", 0).unwrap();
        let limited = Code::compile(b"(*LIMIT_HEAP=1)(?:row )+paid", 0).unwrap();
        let adequate = Code::compile(b"(*LIMIT_HEAP=100)(?:row )+paid", 0).unwrap();
        let mut session = Session::new(100_000, 2000, 512).unwrap();
        assert!(matches!(
            find(&mut session, &limited, &receipt),
            Err(MatchError::PatternHeapLimit)
        ));
        assert!(find(&mut session, &warm, &receipt).unwrap().is_some());
        assert!(matches!(
            find(&mut session, &limited, &receipt),
            Err(MatchError::PatternHeapLimit)
        ));
        assert!(find(&mut session, &adequate, &receipt).unwrap().is_some());
        let mut smaller = Session::new(100_000, 2000, 1).unwrap();
        assert!(matches!(
            find(&mut smaller, &adequate, &receipt),
            Err(MatchError::HeapLimit)
        ));
    }

    #[test]
    fn inline_utf_checks_subject_and_start_offset() {
        let mut session = Session::new(100_000, 2000, 512).unwrap();
        let code = Code::compile(b"(*UTF)r.sum.", 0).unwrap();
        assert!(code.is_utf());
        assert!(!Code::compile(b"r.sum.", 0).unwrap().is_utf());
        let subject = "résumé".as_bytes();
        assert_eq!(
            find(&mut session, &code, subject).unwrap(),
            Some((0, subject.len()))
        );
        assert!(matches!(
            find(&mut session, &code, b"r\xffsum\xff"),
            Err(MatchError::UtfSubject)
        ));
        assert!(matches!(
            session.find(&code, subject, 2, subject.len(), &mut || Ok(())),
            Err(MatchError::UtfOffset)
        ));
    }

    #[test]
    fn stock_sized_item_list_fits_without_automatic_callouts() {
        let items = (0..1024)
            .map(|id| format!("Item{id:04}"))
            .collect::<Vec<_>>()
            .join("|");
        let code = Code::compile(items.as_bytes(), 0).unwrap();
        let subject = b"ledger Item0004";
        let mut session = Session::new(100_000, 2000, 512).unwrap();
        assert_eq!(find(&mut session, &code, subject).unwrap(), Some((7, 15)));
        assert!(
            session
                .find(&code, subject, 0, 6, &mut || Ok(()))
                .unwrap()
                .is_none()
        );
        let mut checks = 0;
        let result = session.find(&code, subject, 0, subject.len(), &mut || {
            checks += 1;
            if checks == 2 {
                Err(io::ErrorKind::Interrupted.into())
            } else {
                Ok(())
            }
        });
        assert!(
            matches!(result, Err(MatchError::Check(e)) if e.kind() == io::ErrorKind::Interrupted)
        );
        assert!(matches!(
            find(&mut Session::new(0, 2000, 512).unwrap(), &code, subject),
            Err(MatchError::MatchLimit)
        ));
    }

    #[test]
    fn cancellation_and_panics_clear_callback_before_reuse() {
        let code = Code::compile(br"(?:[a-z][0-9] )+END", 0).unwrap();
        let mut subject = b"r4 ".repeat(1000);
        subject.extend(b"END");
        let mut session = Session::new(100_000, 6000, 2048).unwrap();
        let mut calls = 0;
        let result = session.find(&code, &subject, 0, subject.len(), &mut || {
            calls += 1;
            if calls == 3 {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "scan interrupted",
                ))
            } else {
                Ok(())
            }
        });
        assert!(
            matches!(result, Err(MatchError::Check(e)) if e.kind() == io::ErrorKind::Interrupted)
        );
        let mut calls = 0;
        let result = catch_unwind(AssertUnwindSafe(|| {
            session.find(&code, &subject, 0, subject.len(), &mut || {
                calls += 1;
                assert_ne!(calls, 3, "stop");
                Ok(())
            })
        }));
        assert!(result.is_err());
        assert_eq!(
            find(&mut session, &code, &subject).unwrap(),
            Some((0, subject.len()))
        );
    }

    #[test]
    fn interpreters_share_immutable_code() {
        let code = Code::compile(b"tax [0-9]+", 0).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let code = &code;
                scope.spawn(move || {
                    let mut session = Session::new(100_000, 2000, 512).unwrap();
                    assert_eq!(find(&mut session, code, b"tax 23").unwrap(), Some((0, 6)));
                });
            }
        });
    }
}
