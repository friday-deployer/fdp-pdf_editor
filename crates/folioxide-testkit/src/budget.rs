//! Time and memory budgets for resource-exhaustion tests.
//!
//! A hostile file is a bug when it makes the reader do far more work, or hold far more memory,
//! than its size and the [`Limits`](folioxide_syntax::Limits) justify, even when nothing panics.
//! These helpers turn that into test failures:
//!
//! - [`within`] runs a closure on its own thread and gives up when it overruns its wall-clock
//!   budget (a hang or a quadratic loop fails the test instead of stalling it);
//! - [`peak_rss`] and [`current_rss`] read the process's resident set size where the platform
//!   reports it (Linux `/proc/self/status`), for coarse memory ceilings;
//! - [`WorkBudget`] turns the work an input justifies (its length, the bytes the store decoded)
//!   into a time allowance, for harnesses that cannot know a fixed budget in advance (fuzz
//!   targets running at the default limits, where decoding hundreds of megabytes is allowed);
//! - [`Watchdog`] aborts the process when one run takes far too long, so a fuzz target reports
//!   a hang as a crash with its input instead of stalling.
//!
//! Wall-clock budgets are noisy, so tests should pair them with deterministic work bounds
//! (decoded bytes, revisions read, objects kept) and keep the time budget generous: it is there
//! to catch seconds-to-minutes regressions, not milliseconds.
//!
//! ```
//! use std::time::Duration;
//! use folioxide_testkit::budget::within;
//!
//! let (value, elapsed) = within(Duration::from_secs(10), || 6 * 7).unwrap();
//! assert_eq!(value, 42);
//! assert!(elapsed < Duration::from_secs(10));
//!
//! let overrun = within(Duration::from_millis(10), || {
//!     std::thread::sleep(Duration::from_millis(500));
//! });
//! assert!(overrun.is_err());
//! ```

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, mpsc};
use std::time::{Duration, Instant};

/// A closure run by [`within`] did not finish in time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overrun {
    /// The budget it was given.
    pub budget: Duration,
}

impl fmt::Display for Overrun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "did not finish within {:.1?}", self.budget)
    }
}

impl std::error::Error for Overrun {}

/// Runs `f` on a new thread and waits at most `budget` for it.
///
/// Returns `f`'s value and how long it took, or [`Overrun`] when it is still running after
/// `budget` (the thread is then left to finish on its own; the test fails anyway). A panic in
/// `f` is resumed on the calling thread, so assertions inside `f` fail the test as usual.
pub fn within<T, F>(budget: Duration, f: F) -> Result<(T, Duration), Overrun>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let started = Instant::now();
        let value = f();
        let _ = tx.send((value, started.elapsed()));
    });
    match rx.recv_timeout(budget) {
        Ok(done) => {
            // The thread has sent its result and is about to return.
            let _ = handle.join();
            Ok(done)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => match handle.join() {
            // `f` panicked: report its panic, not a timeout.
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => Err(Overrun { budget }),
        },
        Err(mpsc::RecvTimeoutError::Timeout) => Err(Overrun { budget }),
    }
}

/// A time allowance proportional to the work an input justifies: `base`, plus `per_input_byte`
/// for each byte of the input (lexing, scanning and parsing are linear), plus `per_object` for
/// each object resolved and reference followed, plus `per_decoded_byte` for each byte the store
/// decoded (decompressing up to the [`Limits`](folioxide_syntax::Limits) is allowed, however
/// small the input).
///
/// A run that takes longer than [`WorkBudget::allowance`] did super-linear work somewhere.
///
/// ```
/// use std::time::Duration;
/// use folioxide_testkit::budget::WorkBudget;
///
/// let budget = WorkBudget::FUZZ;
/// assert_eq!(budget.allowance(0, 0, 0), budget.base);
/// // A 4 KB input with 10 objects that decodes 512 MiB gets about eleven more seconds.
/// let allowed = budget.allowance(4096, 10, 512 << 20);
/// assert!(allowed > Duration::from_secs(12) && allowed < Duration::from_secs(14));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkBudget {
    /// The fixed part.
    pub base: Duration,
    /// Allowed per input byte.
    pub per_input_byte: Duration,
    /// Allowed per object resolved or reference followed.
    pub per_object: Duration,
    /// Allowed per decoded byte.
    pub per_decoded_byte: Duration,
}

impl WorkBudget {
    /// For the `fuzz_parse_document` targets (optimized, with AddressSanitizer), about four
    /// times what reading costs there: 2 s, plus 300 ns per input byte, plus 40 µs per object
    /// or reference, plus 20 ns per decoded byte.
    ///
    /// Measured with M1 (per strictness mode): the 1M cross-reference rows any file may list
    /// take 0.5 s; then about 70 ns per input byte (an 8 MB reconstruction in 0.6 s), 10 µs per
    /// object (200,000 objects in 2 s) and 2–4 ns per decoded byte (512 MiB in 1.2 s). The
    /// amplification bugs this catches cost 2–10 times the allowance at the sizes tested, and
    /// grow faster than it.
    pub const FUZZ: WorkBudget = WorkBudget {
        base: Duration::from_secs(2),
        per_input_byte: Duration::from_nanos(300),
        per_object: Duration::from_micros(40),
        per_decoded_byte: Duration::from_nanos(20),
    };

    /// The time an input of `input_len` bytes, with `objects` objects resolved and references
    /// followed, that made the store decode `decoded` bytes may take (saturating).
    pub fn allowance(&self, input_len: usize, objects: usize, decoded: u64) -> Duration {
        let nanos = self
            .base
            .as_nanos()
            .saturating_add(
                self.per_input_byte
                    .as_nanos()
                    .saturating_mul(input_len as u128),
            )
            .saturating_add(self.per_object.as_nanos().saturating_mul(objects as u128))
            .saturating_add(
                self.per_decoded_byte
                    .as_nanos()
                    .saturating_mul(u128::from(decoded)),
            );
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

/// Aborts the process when one run (between [`Watchdog::arm`] and dropping its guard) lasts
/// longer than the limit: a hang then ends as a crash that the harness reports with its input
/// (libFuzzer handles `SIGABRT` that way), instead of stalling until an outer timeout.
///
/// There is one watchdog per process; [`Watchdog::global`] starts it, with the limit of its
/// first call. It checks every 100 ms on a thread of its own.
///
/// ```no_run
/// use std::time::Duration;
/// use folioxide_testkit::budget::Watchdog;
///
/// let watchdog = Watchdog::global(Duration::from_secs(120));
/// let _armed = watchdog.arm("one fuzz input");
/// // ... run the input; the guard disarms the watchdog when dropped.
/// ```
#[derive(Debug)]
pub struct Watchdog {
    epoch: Instant,
    limit: Duration,
    /// When the current run started, in milliseconds since `epoch` plus one; 0 when idle.
    started: AtomicU64,
    /// What the current run is, for the message.
    label: std::sync::Mutex<&'static str>,
}

/// Disarms the [`Watchdog`] when dropped.
#[derive(Debug)]
#[must_use = "the watchdog is disarmed when the guard is dropped"]
pub struct Armed {
    watchdog: &'static Watchdog,
}

impl Drop for Armed {
    fn drop(&mut self) {
        self.watchdog.started.store(0, Ordering::SeqCst);
    }
}

impl Watchdog {
    /// The process's watchdog, started on the first call with `limit` (later calls get the same
    /// watchdog, whatever limit they pass).
    pub fn global(limit: Duration) -> &'static Watchdog {
        static WATCHDOG: OnceLock<Watchdog> = OnceLock::new();
        let mut first = false;
        let watchdog = WATCHDOG.get_or_init(|| {
            first = true;
            Watchdog {
                epoch: Instant::now(),
                limit,
                started: AtomicU64::new(0),
                label: std::sync::Mutex::new(""),
            }
        });
        if first {
            std::thread::spawn(move || watchdog.watch());
        }
        watchdog
    }

    /// The limit of one run.
    pub fn limit(&self) -> Duration {
        self.limit
    }

    /// Starts timing a run called `label`; the returned guard ends it.
    pub fn arm(&'static self, label: &'static str) -> Armed {
        *self
            .label
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = label;
        self.started.store(self.now_ms() + 1, Ordering::SeqCst);
        Armed { watchdog: self }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX - 1)
    }

    fn watch(&self) {
        let limit_ms = u64::try_from(self.limit.as_millis()).unwrap_or(u64::MAX);
        loop {
            std::thread::sleep(Duration::from_millis(100));
            let started = self.started.load(Ordering::SeqCst);
            if started == 0 {
                continue;
            }
            let running = self.now_ms().saturating_sub(started - 1);
            if running > limit_ms {
                let label = *self
                    .label
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                eprintln!(
                    "watchdog: {label} has run for {:.1?}, over the {:.1?} limit: a hang; aborting",
                    Duration::from_millis(running),
                    self.limit
                );
                std::process::abort();
            }
        }
    }
}

/// The highest resident set size of this process so far, in bytes (`VmHWM`), where the platform
/// reports it: Linux only, `None` elsewhere or when `/proc` is not readable.
///
/// It is process-wide and never goes down, so a ceiling checked with it holds for everything
/// the process did so far, including tests running in parallel threads: a test that asserts
/// `peak_rss() < ceiling` fails if *any* earlier allocation peak crossed it.
pub fn peak_rss() -> Option<u64> {
    proc_status_kib("VmHWM:").map(|kib| kib.saturating_mul(1024))
}

/// The current resident set size of this process, in bytes (`VmRSS`); Linux only, like
/// [`peak_rss`].
pub fn current_rss() -> Option<u64> {
    proc_status_kib("VmRSS:").map(|kib| kib.saturating_mul(1024))
}

/// The value in kB of the `/proc/self/status` line that starts with `key`.
fn proc_status_kib(key: &str) -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with(key))?;
    let mut fields = line.get(key.len()..)?.split_whitespace();
    let value = fields.next()?.parse().ok()?;
    match fields.next() {
        Some("kB") | None => Some(value),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_returns_the_value() {
        let (value, elapsed) = within(Duration::from_secs(30), || "done").unwrap();
        assert_eq!(value, "done");
        assert!(elapsed < Duration::from_secs(30));
    }

    #[test]
    fn within_reports_an_overrun() {
        let err = within(Duration::from_millis(20), || {
            std::thread::sleep(Duration::from_millis(400));
        })
        .unwrap_err();
        assert_eq!(err.budget, Duration::from_millis(20));
        assert!(err.to_string().contains("did not finish"), "{err}");
    }

    #[test]
    #[should_panic(expected = "inner assertion")]
    fn within_resumes_a_panic() {
        let _ = within(Duration::from_secs(30), || panic!("inner assertion"));
    }

    #[test]
    fn work_budget_allowance() {
        let budget = WorkBudget {
            base: Duration::from_secs(1),
            per_input_byte: Duration::from_micros(1),
            per_object: Duration::from_millis(1),
            per_decoded_byte: Duration::from_nanos(10),
        };
        assert_eq!(budget.allowance(0, 0, 0), Duration::from_secs(1));
        assert_eq!(budget.allowance(1_000_000, 0, 0), Duration::from_secs(2));
        assert_eq!(budget.allowance(0, 1000, 0), Duration::from_secs(2));
        assert_eq!(budget.allowance(0, 0, 100_000_000), Duration::from_secs(2));
        assert_eq!(
            budget.allowance(usize::MAX, usize::MAX, u64::MAX),
            Duration::from_nanos(u64::MAX)
        );
    }

    #[test]
    fn watchdog_arms_and_disarms() {
        // A run that ends in time never trips it (the limit is the first caller's).
        let watchdog = Watchdog::global(Duration::from_secs(600));
        assert_eq!(watchdog.limit(), Duration::from_secs(600));
        for _ in 0..3 {
            let armed = watchdog.arm("a quick run");
            assert_ne!(watchdog.started.load(Ordering::SeqCst), 0);
            std::thread::sleep(Duration::from_millis(150));
            drop(armed);
            assert_eq!(watchdog.started.load(Ordering::SeqCst), 0);
        }
        assert!(std::ptr::eq(watchdog, Watchdog::global(Duration::ZERO)));
    }

    #[test]
    fn rss_is_reported_on_linux() {
        if cfg!(target_os = "linux") {
            // Current first: the peak, read later, can only be higher.
            let current = current_rss().unwrap();
            let peak = peak_rss().unwrap();
            assert!(peak >= current, "{peak} < {current}");
            // A test process holds at least a megabyte, and far less than a terabyte.
            assert!((1 << 20..1 << 40).contains(&peak), "{peak}");
        } else {
            assert_eq!(peak_rss(), None);
        }
    }
}
