//! Admission for concurrent XZ and 7z decoder workspaces on the reference host.

use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Condvar, Mutex, Weak},
    time::Duration,
};

pub(super) const BUDGET: u64 = 512 << 20;
static DECODERS: Pool = Pool::new(BUDGET);
// PPMd eagerly initializes the entire model. Large simultaneous models did
// not improve throughput on the one-CPU deployment.
static PPMD_MODELS: Pool = Pool::new(64 << 20);

struct Pool {
    budget: u64,
    state: Mutex<State>,
    available: Condvar,
}

struct State {
    used: u64,
    waiting: VecDeque<Weak<()>>,
}

struct Reservation {
    pool: &'static Pool,
    bytes: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self
            .pool
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.used -= self.bytes;
        self.pool.available.notify_all();
    }
}

impl Pool {
    const fn new(budget: u64) -> Self {
        Self {
            budget,
            state: Mutex::new(State {
                used: 0,
                waiting: VecDeque::new(),
            }),
            available: Condvar::new(),
        }
    }

    fn reserve(
        &'static self,
        bytes: u64,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<Reservation> {
        check()?;
        let bytes = bytes.clamp(1, self.budget);
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.waiting.is_empty() && state.used + bytes <= self.budget {
            state.used += bytes;
            return Ok(Reservation { pool: self, bytes });
        }
        let ticket = Arc::new(());
        let position = Arc::downgrade(&ticket);
        state.waiting.push_back(position.clone());
        loop {
            // A user-supplied cancellation callback can also unwind. Its weak
            // queue entry must not block subsequent scanner requests.
            while state
                .waiting
                .front()
                .is_some_and(|head| head.strong_count() == 0)
            {
                state.waiting.pop_front();
            }
            if state.used + bytes <= self.budget
                && state
                    .waiting
                    .front()
                    .is_some_and(|head| Weak::ptr_eq(head, &position))
            {
                state.waiting.pop_front();
                state.used += bytes;
                self.available.notify_all();
                return Ok(Reservation { pool: self, bytes });
            }
            let (guard, _) = self
                .available
                .wait_timeout(state, Duration::from_millis(10))
                .unwrap_or_else(|error| error.into_inner());
            drop(guard);
            let checked = check();
            state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if let Err(error) = checked {
                state
                    .waiting
                    .retain(|entry| !Weak::ptr_eq(entry, &position));
                self.available.notify_all();
                return Err(error);
            }
        }
    }
}

pub(in crate::objects) struct Lease {
    _decoder: Reservation,
    _model: Option<Reservation>,
}

pub(in crate::objects) fn acquire(
    bytes: u64,
    check: impl FnMut() -> io::Result<()>,
) -> io::Result<Lease> {
    acquire_with_ppmd(bytes, 0, check)
}

pub(super) fn acquire_with_ppmd(
    bytes: u64,
    ppmd: u64,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<Lease> {
    // A queued model holds no general workspace. All decoders acquire in
    // this order and release both reservations before scanning a child.
    let model = if ppmd > 0 {
        Some(PPMD_MODELS.reserve(ppmd, &mut check)?)
    } else {
        None
    };
    Ok(Lease {
        _decoder: DECODERS.reserve(bytes, &mut check)?,
        _model: model,
    })
}

// The LZ window starts at 64 KiB and grows geometrically. Include lookahead,
// range and literal decoder buffers, independently of the declared dictionary.
pub(super) fn history(output: u64) -> u64 {
    output.saturating_add(8192).saturating_mul(2).max(64 << 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancelled_waiter_releases_its_place() -> io::Result<()> {
        let first = acquire(BUDGET, || Ok(()))?;
        let mut checks = 0;
        let cancelled = acquire_with_ppmd(1, PPMD_MODELS.budget, || {
            checks += 1;
            if checks > 2 {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Ok(())
            }
        });
        assert!(matches!(cancelled, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        drop(first);
        let _next = acquire_with_ppmd(1, PPMD_MODELS.budget + 1, || Ok(()))?;
        let _other_codec = acquire(BUDGET - 1, || Ok(()))?;
        Ok(())
    }
}
