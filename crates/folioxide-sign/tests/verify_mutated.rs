#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! `no_panic_verify_mutated_signed` (M3 brief §6.2 "robustness", R-18): a stable-toolchain
//! stand-in for fuzzing the verifier.
//!
//! Signed files of every layout the verifier meets are mutated [`MUTATIONS_PER_BASE`] times each
//! with [`folioxide_testkit::mutate`] (bit flips, byte changes, truncations, insertions, chunk
//! duplication and deletion, PDF tokens; one to four per mutation): our RSA-2048 signature, a
//! P-256 signature on a cross-reference-stream file, two sequential signatures (RSA, then
//! P-384), two sequential signatures on a form with a text field, an AcroForm `/DA` and `/DR`,
//! `/Info` and XMP metadata (RSA, then P-256), two sequential signatures on a form with an orphan
//! text widget and an appearance stream without `/Resources` (RSA, then P-256), and pyHanko's two
//! signatures (`/Contents` before `/ByteRange`), document timestamp and P=2 certification
//! fixtures. Every mutation goes through [`verify_bytes`], with no trust anchors, with anchors
//! at a fixed validation time, or with anchors at the claimed time, by mutation index. For every
//! mutation:
//!
//! - nothing may panic, and it must finish within [`MUTATION_BUDGET`] (a verification takes a
//!   few tens of milliseconds in a debug build); one still running after [`HANG_LIMIT`] is a
//!   hang: its input is saved and the process aborts, so a hang fails the test instead of
//!   stalling it;
//! - every report keeps the documented invariants: [`SignatureReport::is_valid`] implies a sound
//!   byte range, an intact and valid signature and no problem; `pades_level` and
//!   `trusted == Some(true)` imply an intact, valid signature;
//! - **no forgery**: a report that is valid and covers the whole file, on a mutation of the
//!   same length as its base, may differ from the base only inside that signature's own
//!   `/Contents` gap (the zero padding after the CMS, which is not signed).
//!
//! The run is deterministic: each chunk of [`CHUNK`] mutations of a base has a fixed seed
//! derived from the base's name and the chunk number, and the chunks are spread over up to eight
//! threads. Set `FOLIOXIDE_MUTATIONS=<n>` to run `n` mutations per base instead. A failing input
//! is written to `$CARGO_TARGET_TMPDIR/verify-mutated-failures/` and can be replayed with `cargo
//! +nightly fuzz run fuzz_verify <file>` from the repository root.

mod sign_support;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use folioxide_sign::report::{Coverage, SignatureReport};
use folioxide_sign::verify_pdf::{VerifyOptions, verify_bytes};
use folioxide_testkit::fixtures::{self, sign_attacks, syntax};
use folioxide_testkit::mutate::Mutator;
use sign_support::*;

/// Mutations per base: 8 bases × 4,000 = 32,000 mutations (the brief asks for at least 10,000,
/// the manager for 20,000).
const MUTATIONS_PER_BASE: usize = 4_000;

/// Overrides [`MUTATIONS_PER_BASE`].
const MUTATIONS_ENV: &str = "FOLIOXIDE_MUTATIONS";

/// The wall-clock budget of one verification. The slowest take well under a second in a debug
/// build (a few RSA and ECDSA operations on a 20 KB file).
const MUTATION_BUDGET: Duration = Duration::from_secs(5);

/// A verification still running after this long is a hang.
const HANG_LIMIT: Duration = Duration::from_secs(60);

/// The signed files that are mutated.
fn bases() -> Vec<(String, Vec<u8>)> {
    let minimal = syntax::minimal();
    let rsa = sign_default(&minimal, &rsa2048());
    let two = sign_default(&rsa, &p384());
    let mut bases = vec![
        ("rsa2048-minimal".to_owned(), rsa),
        (
            "p256-xref-stream".to_owned(),
            sign_default(&syntax::xref_stream(), &p256()),
        ),
        ("rsa2048-then-p384".to_owned(), two),
        // The AcroForm controls and role objects the modification whitelist compares: a text
        // field, an AcroForm /DA and /DR, an /Info dictionary and an XMP /Metadata stream,
        // signed twice (QA round 3).
        ("form-roles-rsa2048-then-p256".to_owned(), {
            let input = sign_attacks::text_field_form_input(&minimal).unwrap();
            let input = sign_attacks::info_metadata_input(&input).unwrap();
            sign_default(&sign_default(&input, &rsa2048()), &p256())
        }),
        // What the /DR guard reads from the pages (expert round 5): an orphan text widget with a
        // /DA of its own, and a field whose appearance stream has no /Resources (decoded).
        ("orphan-widget-bare-ap-rsa2048-then-p256".to_owned(), {
            let input = sign_attacks::orphan_widget_bare_appearance_input(&minimal).unwrap();
            sign_default(&sign_default(&input, &rsa2048()), &p256())
        }),
    ];
    for name in [
        "pyhanko-two-signatures.pdf",
        "pyhanko-doc-timestamp.pdf",
        "pyhanko-certified-p2.pdf",
    ] {
        let bytes = interop_fixtures()
            .into_iter()
            .find(|(file, _)| file == name)
            .unwrap_or_else(|| panic!("fixtures/sign/pdf/{name}"))
            .1;
        bases.push((name.trim_end_matches(".pdf").to_owned(), bytes));
    }
    bases
}

/// The verification options of mutation number `index`: half without trust anchors, a quarter
/// with anchors at the signing time, a quarter with anchors at the claimed time (`/M`).
fn options(index: usize) -> VerifyOptions {
    match index % 4 {
        0 | 1 => VerifyOptions::default(),
        2 => VerifyOptions::new()
            .with_trust_anchors_der(anchors())
            .with_validation_time(Some(time())),
        _ => VerifyOptions::new().with_trust_anchors_der(anchors()),
    }
}

/// Mutations per chunk: each chunk of a base has its own seed, so the chunks of one base run on
/// several threads.
const CHUNK: usize = 500;

/// The fixed seed of chunk `chunk` of a base: the first 8 bytes of the base's deterministic file
/// identifier, plus the chunk number.
fn seed(name: &str, chunk: usize) -> u64 {
    let id = fixtures::file_id(name);
    u64::from_be_bytes(id[..8].try_into().unwrap()).wrapping_add(chunk as u64)
}

/// Mutation number `index` of chunk `chunk` of a base, as [`run_chunk`] makes it.
fn nth_mutation(name: &str, bytes: &[u8], chunk: usize, index: usize) -> Vec<u8> {
    let mut mutator = Mutator::new(seed(name, chunk));
    let mut input = Vec::new();
    for _ in 0..=index {
        input = mutator.mutate(bytes);
    }
    input
}

/// The broken invariants of the reports on `input`, a mutation of `base`.
fn violations(base: &[u8], input: &[u8], reports: &[SignatureReport]) -> Vec<String> {
    let mut out = Vec::new();
    for r in reports {
        let what = format!("{:?}: {}", r.field_name, summary(r));
        if r.is_valid()
            && !(r.byte_range_ok && r.intact && r.signature_valid && r.problems.is_empty())
        {
            out.push(format!("is_valid without its conditions: {what}"));
        }
        if r.pades_level.is_some() && !(r.intact && r.signature_valid && r.byte_range_ok) {
            out.push(format!("PAdES level on a broken signature: {what}"));
        }
        if r.trusted == Some(true) && !(r.intact && r.signature_valid) {
            out.push(format!("trusted although not intact and valid: {what}"));
        }
        // No forgery: the bytes a valid signature covers are, at the same offsets, the bytes
        // the base signed (a mutation cannot make a CMS, so a valid one is the base's).
        if r.is_valid() {
            let Some(&[o1, l1, o2, l2]) = r.byte_range.as_deref() else {
                out.push(format!("valid without four byte range values: {what}"));
                continue;
            };
            for (start, len) in [(o1, l1), (o2, l2)] {
                let range = start as usize..(start + len) as usize;
                if input.get(range.clone()) != base.get(range.clone()) {
                    out.push(format!(
                        "valid although the signed bytes {range:?} differ from the base's: {what}"
                    ));
                }
            }
            if r.coverage == Coverage::EntireFile && (o2 + l2) as usize != input.len() {
                out.push(format!(
                    "entireFile not ending at the end of the file: {what}"
                ));
            }
        }
    }
    out
}

/// One mutation that panicked, overran its budget or broke an invariant.
struct Failure {
    base: String,
    chunk: usize,
    index: usize,
    problem: String,
    input: Vec<u8>,
}

/// What one base's run saw.
#[derive(Default)]
struct Tally {
    mutations: usize,
    open_errors: usize,
    reports: usize,
    valid: usize,
    slowest: (Duration, String),
    failures: Vec<Failure>,
}

impl Tally {
    fn merge(&mut self, other: Tally) {
        self.mutations += other.mutations;
        self.open_errors += other.open_errors;
        self.reports += other.reports;
        self.valid += other.valid;
        if other.slowest.0 > self.slowest.0 {
            self.slowest = other.slowest;
        }
        self.failures.extend(other.failures);
    }
}

/// What one worker thread is running, for the watchdog: the base (by index), the chunk, the
/// mutation index in the chunk, and when it started.
type Busy = Mutex<Option<(usize, usize, usize, Instant)>>;

fn set_busy(busy: &Busy, value: Option<(usize, usize, usize, Instant)>) {
    *busy.lock().unwrap_or_else(PoisonError::into_inner) = value;
}

/// Makes the `count` mutations of chunk `chunk` of base number `base` and verifies each.
fn run_chunk(
    (base, chunk): (usize, usize),
    (name, bytes): (&str, &[u8]),
    count: usize,
    busy: &Busy,
) -> Tally {
    let mut tally = Tally::default();
    let mut mutator = Mutator::new(seed(name, chunk));
    for index in 0..count {
        let input = mutator.mutate(bytes);
        let options = options(index);
        let started = Instant::now();
        set_busy(busy, Some((base, chunk, index, started)));
        let outcome = catch_unwind(AssertUnwindSafe(|| verify_bytes(input.clone(), &options)));
        let elapsed = started.elapsed();
        set_busy(busy, None);
        if elapsed > tally.slowest.0 {
            tally.slowest = (elapsed, format!("{name} chunk {chunk} #{index}"));
        }
        tally.mutations += 1;
        let mut problems = Vec::new();
        match outcome {
            Ok(Ok(reports)) => {
                tally.reports += reports.len();
                tally.valid += reports.iter().filter(|r| r.is_valid()).count();
                problems.extend(violations(bytes, &input, &reports));
            }
            Ok(Err(_)) => tally.open_errors += 1,
            Err(payload) => {
                let message = payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "non-string panic payload".to_owned());
                problems.push(format!("panicked: {message}"));
            }
        }
        if elapsed > MUTATION_BUDGET {
            problems.push(format!(
                "took {elapsed:.2?}, over the {MUTATION_BUDGET:.2?} budget for one mutation"
            ));
        }
        if !problems.is_empty() {
            tally.failures.push(Failure {
                base: name.to_owned(),
                chunk,
                index,
                problem: problems.join("; "),
                input,
            });
        }
    }
    tally
}

/// Watches the workers until `done`: a verification that has run for longer than
/// [`HANG_LIMIT`] is a hang, so its input is saved and the process aborts.
fn watchdog(busy: &[Busy], bases: &[(String, Vec<u8>)], done: &AtomicBool) {
    while !done.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
        for slot in busy {
            let current = *slot.lock().unwrap_or_else(PoisonError::into_inner);
            let Some((base, chunk, index, started)) = current else {
                continue;
            };
            if started.elapsed() <= HANG_LIMIT {
                continue;
            }
            let (name, bytes) = &bases[base];
            let input = nth_mutation(name, bytes, chunk, index);
            let saved = save_failure(name, chunk, index, &input);
            eprintln!(
                "no_panic_verify_mutated_signed: {name} chunk {chunk} mutation #{index} (seed \
                 {:#018x}) has run for over {HANG_LIMIT:.1?}: a hang; aborting.\n  input: {saved}",
                seed(name, chunk),
            );
            std::process::abort();
        }
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

/// Writes a failing input to `$CARGO_TARGET_TMPDIR/verify-mutated-failures/` and returns where
/// it went.
fn save_failure(base: &str, chunk: usize, index: usize, input: &[u8]) -> String {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("verify-mutated-failures");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{base}-{chunk}-{index}.pdf"));
    match std::fs::write(&path, input) {
        Ok(()) => path.display().to_string(),
        Err(err) => format!("(not saved: {err})"),
    }
}

#[test]
fn no_panic_verify_mutated_signed() {
    let bases = bases();
    let per_base = mutations_per_base();
    let threads = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .clamp(1, 8);
    let busy: Vec<Busy> = (0..threads).map(|_| Mutex::new(None)).collect();
    let done = AtomicBool::new(false);
    let started = Instant::now();
    // The work: every chunk of every base, dealt round-robin to the threads.
    let mut work: Vec<(usize, usize, usize)> = Vec::new();
    for base in 0..bases.len() {
        for chunk in 0..per_base.div_ceil(CHUNK) {
            work.push((base, chunk, CHUNK.min(per_base - chunk * CHUNK)));
        }
    }
    let tally = std::thread::scope(|scope| {
        let watch = scope.spawn(|| watchdog(&busy, &bases, &done));
        let handles: Vec<_> = busy
            .iter()
            .enumerate()
            .map(|(t, slot)| {
                let (bases, work) = (&bases, &work);
                scope.spawn(move || {
                    let mut tally = Tally::default();
                    for &(base, chunk, count) in work.iter().skip(t).step_by(threads) {
                        let (name, bytes) = &bases[base];
                        tally.merge(run_chunk((base, chunk), (name, bytes), count, slot));
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
    eprintln!(
        "no_panic_verify_mutated_signed: {} mutations of {} bases in {:.1?}: {} unreadable, {} \
         reports, {} valid; slowest {:.1?} ({})",
        tally.mutations,
        bases.len(),
        started.elapsed(),
        tally.open_errors,
        tally.reports,
        tally.valid,
        tally.slowest.0,
        tally.slowest.1,
    );
    if !tally.failures.is_empty() {
        let mut text = format!("{} mutation(s) failed:\n", tally.failures.len());
        for failure in tally.failures.iter().take(20) {
            let saved = save_failure(&failure.base, failure.chunk, failure.index, &failure.input);
            text.push_str(&format!(
                "- {} chunk {} mutation #{} (seed {:#018x}): {}\n  input: {saved}\n",
                failure.base,
                failure.chunk,
                failure.index,
                seed(&failure.base, failure.chunk),
                failure.problem,
            ));
        }
        panic!("{text}");
    }
    assert_eq!(tally.mutations, bases.len() * per_base);
    // The mutations reach the verifier: most still open, and some signatures stay valid (a
    // mutation in the unsigned padding, or one the repair undoes).
    if per_base >= 1_000 {
        assert!(
            tally.reports > tally.mutations / 2,
            "{} reports",
            tally.reports
        );
        assert!(tally.valid > 0, "no valid report at all");
    }
}

#[test]
fn mutations_are_deterministic() {
    let (name, bytes) = &bases()[0];
    assert_eq!(
        nth_mutation(name, bytes, 1, 5),
        nth_mutation(name, bytes, 1, 5)
    );
    assert_ne!(seed("rsa2048-minimal", 0), seed("p256-xref-stream", 0));
    assert_ne!(seed("rsa2048-minimal", 0), seed("rsa2048-minimal", 1));
    // A mutation that changes only the unsigned zero padding of /Contents keeps the signature
    // valid, and is no forgery.
    let report = &verify(bytes)[0];
    let range = report.byte_range.clone().unwrap();
    let mut padded = bytes.clone();
    let last_digit = range[2] as usize - 2;
    assert_eq!(padded[last_digit], b'0');
    padded[last_digit] = b'7';
    let reports = verify(&padded);
    assert!(reports[0].is_valid(), "{}", summary(&reports[0]));
    assert!(violations(bytes, &padded, &reports).is_empty());
    // A changed signed byte reported valid would be flagged (a forged report).
    let mut changed = padded.clone();
    changed[range[2] as usize + 1] ^= 1;
    assert!(!violations(bytes, &changed, &reports).is_empty());
    changed[range[2] as usize + 1] ^= 1;
    changed[10] ^= 1;
    assert!(!violations(bytes, &changed, &reports).is_empty());
}
