#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! `no_panic_on_mutated_input` (M1 brief WP1.5, acceptance criterion 4; ARCHITECTURE §A.9
//! layer 3): a stable-toolchain stand-in for fuzzing.
//!
//! Every committed syntax fixture, the linearized files qpdf wrote (`fixtures/qpdf/`), a small
//! generated page tree in object streams, and a small instance of every resource-exhaustion
//! shape in [`folioxide_testkit::fixtures::hostile`] are mutated [`MUTATIONS_PER_BASE`] times
//! with [`folioxide_testkit::mutate`]: bit flips, byte changes, truncations, insertions, chunk
//! duplication and deletion, and PDF tokens, one to four per mutation. Each mutation is opened with [`Store::open`](folioxide_syntax::Store::open),
//! every object is resolved, every reference followed and every stream decoded
//! ([`folioxide_testkit::exercise`]). For every mutation:
//!
//! - nothing may panic, and the store's documented guarantees must hold
//!   ([`folioxide_testkit::exercise::Report::violations`], which include the object cap);
//! - it must finish within [`MUTATION_BUDGET`] (the slowest take a few milliseconds in a debug
//!   build, so a mutation over budget means quadratic or worse work on a small input). A
//!   mutation still running after [`hang_limit`] is a hang: a watchdog saves the input and
//!   aborts the process, so a hang fails the test instead of stalling it.
//!
//! After the run, the process's peak resident memory must be under [`RSS_CEILING`] (Linux
//! only; [`folioxide_testkit::budget::peak_rss`]): the peak is process-wide, so no mutation can
//! have needed more.
//!
//! The run is deterministic: each base has a fixed seed derived from its name, and the open
//! options cycle through lenient and strict with the default limits and lenient with tiny limits
//! by mutation index. It takes a few seconds in debug builds, so `cargo test --workspace` (and
//! CI) runs it as is; no release build is needed. Set `FOLIOXIDE_MUTATIONS=<n>` to run `n`
//! mutations per base instead (for example a million in `--release` to hunt for rare bugs), and
//! `FOLIOXIDE_MUTATION_BUDGET_MS=<ms>` to change the time budget (for a slow machine, or a tighter
//! one in `--release`).
//!
//! A failing input is written to `$CARGO_TARGET_TMPDIR/no-panic-failures/` and can be replayed
//! with `cargo +nightly fuzz run fuzz_parse_document_default_limits <file>` (or
//! `fuzz_parse_document`, which also uses tiny limits) from the repository root.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use folioxide_syntax::{ErrorCode, Limits, OpenOptions, Strictness};
use folioxide_testkit::budget::peak_rss;
use folioxide_testkit::exercise::{Report, exercise};
use folioxide_testkit::fixtures::{self, hostile, qpdf, syntax};
use folioxide_testkit::mutate::Mutator;

/// Mutations per base file: 39 bases × 1,000 = 39,000 mutations (the brief asks for at least
/// 20,000).
const MUTATIONS_PER_BASE: usize = 1_000;

/// Overrides [`MUTATIONS_PER_BASE`].
const MUTATIONS_ENV: &str = "FOLIOXIDE_MUTATIONS";

/// The wall-clock budget of one mutation (open, resolve and decode everything, count the pages).
/// The slowest mutation takes a few milliseconds in a debug build; the bases are at most a few
/// hundred kilobytes, so work that is linear in the input never comes near this.
const MUTATION_BUDGET: Duration = Duration::from_secs(5);

/// Overrides [`MUTATION_BUDGET`], in milliseconds.
const BUDGET_ENV: &str = "FOLIOXIDE_MUTATION_BUDGET_MS";

/// The ceiling on the process's peak resident memory after the run. Reading every mutation
/// needs well under 100 MiB in all (eight threads at a time).
const RSS_CEILING: u64 = 512 << 20;

/// Tight limits, so mutations also reach every limit check.
const TINY_LIMITS: Limits = Limits::DEFAULT
    .with_max_objects(10_000)
    .with_max_nesting_depth(16)
    .with_max_decoded_stream(4096)
    .with_max_total_decoded(16 * 1024)
    .with_max_xref_sections(4)
    .with_max_page_tree_depth(4)
    .with_max_string_len(4096)
    .with_max_ref_chain(3)
    .with_max_diagnostics(16);

/// The open options for mutation number `index`: half lenient, a quarter strict, a quarter
/// lenient with [`TINY_LIMITS`].
fn options(index: usize) -> OpenOptions {
    match index % 4 {
        0 | 1 => OpenOptions::default(),
        2 => OpenOptions::default().with_strictness(Strictness::Strict),
        _ => OpenOptions::default().with_limits(TINY_LIMITS),
    }
}

/// A mutation still running after this long is a hang (twelve times the budget, at least a
/// minute): the watchdog saves it and aborts the process.
fn hang_limit(budget: Duration) -> Duration {
    budget.saturating_mul(12).max(Duration::from_secs(60))
}

/// The files that are mutated: every committed syntax fixture, the qpdf-linearized files, a
/// 12-page document whose dictionaries are all in object streams, and the small hostile files
/// (their mutations are where amplification bugs hide).
fn bases() -> Vec<(String, Vec<u8>)> {
    let mut bases: Vec<(String, Vec<u8>)> = syntax::infos()
        .iter()
        .map(|info| {
            let bytes = syntax::read_committed(info.name).unwrap_or_else(|err| {
                panic!(
                    "fixtures/syntax/{}.pdf: {err} (run `cargo xtask fixtures`)",
                    info.name
                )
            });
            (info.name.to_owned(), bytes)
        })
        .collect();
    bases.extend(qpdf::infos().iter().map(|info| {
        let bytes = qpdf::read_committed(info.name)
            .unwrap_or_else(|err| panic!("fixtures/qpdf/{}.pdf: {err}", info.name));
        (format!("qpdf-{}", info.name), bytes)
    }));
    bases.push((
        "many-pages-compressed-12".to_owned(),
        syntax::many_pages_compressed(12),
    ));
    bases.extend(
        hostile::seeds()
            .into_iter()
            .map(|(name, bytes)| (name.to_owned(), bytes)),
    );
    bases
}

/// Mutation number `index` of a base, as [`run_base`] makes it.
fn nth_mutation(name: &str, bytes: &[u8], index: usize) -> Vec<u8> {
    let mut mutator = Mutator::new(seed(name));
    let mut input = Vec::new();
    for _ in 0..=index {
        input = mutator.mutate(bytes);
    }
    input
}

/// The fixed seed of a base: the first 8 bytes of its deterministic file identifier.
fn seed(name: &str) -> u64 {
    let id = fixtures::file_id(name);
    u64::from_be_bytes(id[..8].try_into().unwrap())
}

/// One mutation that panicked or broke a documented guarantee.
struct Failure {
    base: String,
    index: usize,
    options: OpenOptions,
    problem: String,
    input: Vec<u8>,
}

/// What one base's run saw.
#[derive(Default)]
struct Tally {
    mutations: usize,
    opened: usize,
    open_errors: Vec<(ErrorCode, usize)>,
    objects: usize,
    streams: usize,
    slowest: (Duration, String),
    failures: Vec<Failure>,
}

impl Tally {
    fn record(&mut self, report: &Report) {
        match report.open_error {
            None => self.opened += 1,
            Some(code) => match self.open_errors.iter_mut().find(|(c, _)| *c == code) {
                Some((_, n)) => *n += 1,
                None => self.open_errors.push((code, 1)),
            },
        }
        self.objects += report.objects;
        self.streams += report.streams;
    }

    fn merge(&mut self, other: Tally) {
        self.mutations += other.mutations;
        self.opened += other.opened;
        for (code, n) in other.open_errors {
            match self.open_errors.iter_mut().find(|(c, _)| *c == code) {
                Some((_, total)) => *total += n,
                None => self.open_errors.push((code, n)),
            }
        }
        self.objects += other.objects;
        self.streams += other.streams;
        if other.slowest.0 > self.slowest.0 {
            self.slowest = other.slowest;
        }
        self.failures.extend(other.failures);
    }
}

/// What one worker thread is running, for the watchdog: the base (by index), the mutation
/// index, and when it started.
type Busy = Mutex<Option<(usize, usize, Instant)>>;

fn set_busy(busy: &Busy, value: Option<(usize, usize, Instant)>) {
    *busy.lock().unwrap_or_else(PoisonError::into_inner) = value;
}

/// Mutates base number `base` (`name`, `bytes`) `count` times and exercises every mutation.
fn run_base(
    base: usize,
    (name, bytes): (&str, &[u8]),
    count: usize,
    budget: Duration,
    busy: &Busy,
) -> Tally {
    let mut tally = Tally::default();
    let mut mutator = Mutator::new(seed(name));
    for index in 0..count {
        let input = mutator.mutate(bytes);
        let options = options(index);
        let started = Instant::now();
        set_busy(busy, Some((base, index, started)));
        let outcome = catch_unwind(AssertUnwindSafe(|| exercise(&input, &options)));
        let elapsed = started.elapsed();
        set_busy(busy, None);
        if elapsed > tally.slowest.0 {
            tally.slowest = (elapsed, format!("{name} #{index}"));
        }
        tally.mutations += 1;
        let mut problems = Vec::new();
        match outcome {
            Ok(report) => {
                tally.record(&report);
                problems.extend(report.violations);
            }
            Err(payload) => {
                let message = payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "non-string panic payload".to_owned());
                problems.push(format!("panicked: {message}"));
            }
        }
        if elapsed > budget {
            problems.push(format!(
                "took {elapsed:.2?}, over the {budget:.2?} budget for one mutation"
            ));
        }
        if problems.is_empty() {
            continue;
        }
        tally.failures.push(Failure {
            base: name.to_owned(),
            index,
            options,
            problem: problems.join("; "),
            input,
        });
    }
    tally
}

/// Watches the workers until `done`: a mutation that has run for longer than `limit` is a hang,
/// so its input is saved and the process aborts (joining the hung worker would never return).
fn watchdog(busy: &[Busy], bases: &[(String, Vec<u8>)], done: &AtomicBool, limit: Duration) {
    while !done.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
        for slot in busy {
            let current = *slot.lock().unwrap_or_else(PoisonError::into_inner);
            let Some((base, index, started)) = current else {
                continue;
            };
            let elapsed = started.elapsed();
            if elapsed <= limit {
                continue;
            }
            let (name, bytes) = &bases[base];
            let input = nth_mutation(name, bytes, index);
            let saved = save_failure(name, index, &input);
            eprintln!(
                "no_panic_on_mutated_input: {name} mutation #{index} (seed {:#018x}, {:?}) has \
                 run for {elapsed:.1?}, over the {limit:.1?} hang limit; aborting.\n  input: {saved}",
                seed(name),
                options(index),
            );
            std::process::abort();
        }
    }
}

fn mutation_budget() -> Duration {
    match std::env::var(BUDGET_ENV) {
        Ok(value) => Duration::from_millis(
            value
                .trim()
                .parse()
                .unwrap_or_else(|_| panic!("{BUDGET_ENV}={value:?} is not a number")),
        ),
        Err(_) => MUTATION_BUDGET,
    }
}

fn mutations_per_base() -> usize {
    match std::env::var(MUTATIONS_ENV) {
        Ok(value) => value
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{MUTATIONS_ENV}={value:?} is not a number")),
        Err(_) => MUTATIONS_PER_BASE,
    }
}

/// Writes a failing input to `$CARGO_TARGET_TMPDIR/no-panic-failures/` and returns where it
/// went (or why it did not).
fn save_failure(base: &str, index: usize, input: &[u8]) -> String {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("no-panic-failures");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{base}-{index}.pdf"));
    match std::fs::write(&path, input) {
        Ok(()) => path.display().to_string(),
        Err(err) => format!("(not saved: {err})"),
    }
}

/// Saves the failing inputs and describes them.
fn report_failures(failures: &[Failure]) -> String {
    let mut text = format!("{} mutation(s) failed:\n", failures.len());
    for failure in failures.iter().take(20) {
        let saved = save_failure(&failure.base, failure.index, &failure.input);
        text.push_str(&format!(
            "- {} mutation #{} (seed {:#018x}, {:?}, max_decoded_stream {}): {}\n  input: {saved}\n",
            failure.base,
            failure.index,
            seed(&failure.base),
            failure.options.strictness,
            failure.options.limits.max_decoded_stream,
            failure.problem,
        ));
    }
    text
}

#[test]
fn no_panic_on_mutated_input() {
    let bases = bases();
    let per_base = mutations_per_base();
    let budget = mutation_budget();
    let threads = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .clamp(1, 8);
    let busy: Vec<Busy> = (0..threads).map(|_| Mutex::new(None)).collect();
    let done = AtomicBool::new(false);
    let started = Instant::now();
    // Bases are dealt round-robin to the threads; each base's run is deterministic on its own.
    let tally = std::thread::scope(|scope| {
        let watch = scope.spawn(|| watchdog(&busy, &bases, &done, hang_limit(budget)));
        let handles: Vec<_> = busy
            .iter()
            .enumerate()
            .map(|(t, slot)| {
                let bases = &bases;
                scope.spawn(move || {
                    let mut tally = Tally::default();
                    for (base, (name, bytes)) in bases.iter().enumerate().skip(t).step_by(threads) {
                        tally.merge(run_base(base, (name, bytes), per_base, budget, slot));
                    }
                    tally
                })
            })
            .collect();
        let mut total = Tally::default();
        for handle in handles {
            total.merge(
                handle
                    .join()
                    .expect("a worker thread panicked outside catch_unwind"),
            );
        }
        done.store(true, Ordering::Relaxed);
        watch.join().expect("the watchdog panicked");
        total
    });
    let peak = peak_rss();
    eprintln!(
        "no_panic_on_mutated_input: {} mutations of {} bases in {:.1?} ({} threads): {} opened \
         ({} objects, {} streams), open errors {:?}; slowest {:.1?} ({}), budget {:.1?}; peak \
         resident memory {}",
        tally.mutations,
        bases.len(),
        started.elapsed(),
        threads,
        tally.opened,
        tally.objects,
        tally.streams,
        tally.open_errors,
        tally.slowest.0,
        tally.slowest.1,
        budget,
        peak.map_or_else(|| "unknown".to_owned(), |p| format!("{} MiB", p >> 20)),
    );
    assert_eq!(tally.mutations, bases.len() * per_base);
    if per_base == MUTATIONS_PER_BASE {
        assert!(tally.mutations >= 20_000, "{}", tally.mutations);
    }
    assert!(
        tally.failures.is_empty(),
        "{}",
        report_failures(&tally.failures)
    );
    // The mutations must reach deep into the store, not just bounce off the header: most of
    // them still open, and their objects and streams are read.
    assert!(
        tally.opened * 2 > tally.mutations,
        "only {} of {} mutations opened",
        tally.opened,
        tally.mutations
    );
    if let Some(peak) = peak {
        assert!(
            peak < RSS_CEILING,
            "peak resident memory {} MiB is over the {} MiB ceiling",
            peak >> 20,
            RSS_CEILING >> 20
        );
    }
}

#[test]
fn a_mutation_over_budget_is_a_failure() {
    // A zero budget makes every mutation a failure, with the input kept for replay.
    let (name, bytes) = &bases()[0];
    let slot: Busy = Mutex::new(None);
    let tally = run_base(0, (name, bytes), 3, Duration::ZERO, &slot);
    assert_eq!(tally.failures.len(), 3);
    for (index, failure) in tally.failures.iter().enumerate() {
        assert!(failure.problem.contains("over the"), "{}", failure.problem);
        assert_eq!(failure.input, nth_mutation(name, bytes, index));
    }
    assert!(slot.lock().unwrap().is_none());
    assert!(hang_limit(Duration::ZERO) >= Duration::from_secs(60));
    assert_eq!(hang_limit(MUTATION_BUDGET), Duration::from_secs(60));
}

#[test]
fn seeds_are_distinct_and_stable() {
    let bases = bases();
    let mut seeds: Vec<u64> = bases.iter().map(|(name, _)| seed(name)).collect();
    seeds.sort_unstable();
    seeds.dedup();
    assert_eq!(seeds.len(), bases.len());
    // FNV-1a 64 of "minimal" (fixtures::file_id), so the mutations never change silently.
    assert_eq!(seed("minimal"), 0xc974_02ad_0481_b7d0);
    assert!(bases.len() * MUTATIONS_PER_BASE >= 20_000);
}
