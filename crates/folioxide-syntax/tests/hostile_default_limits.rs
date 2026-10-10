#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Resource-exhaustion regression tests at the **default** [`Limits`] (M1 QA robustness
//! findings; ARCHITECTURE §A.3 "Opening is linear in the file size", §A.9 layer 3).
//!
//! Each test builds a hostile file with [`folioxide_testkit::fixtures::hostile`], scaled up so
//! that the amplification it targets would take minutes or gigabytes, and opens it with
//! `OpenOptions::default()` (lenient and strict). Three kinds of bound are checked:
//!
//! - **work**, deterministically: the cross-reference rows and sections read, the objects kept,
//!   and the bytes decoded ([`Store::total_decoded`]) stay within the budgets that the store
//!   documents for a file of that length;
//! - **time**: opening and reading the document finish within a wall-clock budget
//!   ([`folioxide_testkit::budget::within`]), generous enough for a slow debug build;
//! - **memory**: each test runs in a process of its own ([`bounded`] runs the test binary again
//!   with `--exact <test>`), so the process's peak resident set size
//!   ([`folioxide_testkit::budget::peak_rss`], Linux only) is that test's own, and it must stay
//!   under the test's ceiling: a few times what the test needs, and a fraction of what the
//!   regression it guards against needed. This measures memory independently of the store's own
//!   accounting ([`Store::objstm_cache_bytes`], [`Store::objstm_parsed_bytes`]), so an
//!   allocation the store does not count still fails the test. Where the peak cannot be read,
//!   the tests run in the harness's process without the memory check.
//!
//! Every hostile file is also a readable document, and each test checks that it still reads.
//! `Limits::default()` is used as is: the unit tests in `src/` and the mutation and fuzz
//! harnesses cover reduced limits.

use std::time::Duration;

use folioxide_syntax::{
    DiagnosticKind, ErrorCode, Limits, Object, ObjectId, OpenOptions, Store, Strictness,
};
use folioxide_testkit::budget::{peak_rss, within};
use folioxide_testkit::exercise::{self, Report, exercise_store};
use folioxide_testkit::fixtures::hostile::{self, CLAIM_START, TEXT};

/// The wall-clock budget of one test: opening and reading its hostile file (both strictness
/// modes). Each one takes well under a second in a debug build; the regressions they guard
/// against took minutes in a release build.
const BUDGET: Duration = Duration::from_secs(if cfg!(debug_assertions) { 60 } else { 20 });

/// One mebibyte, for the resident memory ceilings of the tests.
const MIB: u64 = 1 << 20;

/// Set (to the test's name) in the process that [`bounded`] starts to run one test alone.
const ISOLATED_ENV: &str = "FOLIOXIDE_HOSTILE_ISOLATED";

/// What a test run alone prints when it passed its checks, followed by its name.
const ISOLATED_DONE: &str = "hostile_default_limits: isolated test passed:";

/// Rows the cross-reference reader may read over all sections, for a file of `len` bytes
/// (`max(2^20, 4 × len)`, ARCHITECTURE §A.3; `Limits::max_objects`).
fn row_budget(len: usize) -> u64 {
    (4 * len as u64).max(1 << 20)
}

/// The most bytes the cross-reference reader may decode from `sections` cross-reference streams
/// of one-byte rows (`/W [0 1 0]`), for a file of `len` bytes: each stream's data is capped at
/// twice the rows left (room for a PNG predictor's tag byte per row) plus 64 bytes, and the rows
/// read are charged to [`row_budget`].
fn xref_decode_budget(len: usize, sections: u64) -> u64 {
    2 * row_budget(len) + 64 * sections
}

/// Source bytes the cross-reference reader may parse over all sections (`max(1 MiB, 4 × len)`).
fn byte_budget(len: usize) -> u64 {
    (4 * len as u64).max(1 << 20)
}

/// In-use objects the store keeps for a file of `len` bytes (`min(max_objects, max(4096, len))`).
fn object_cap(len: usize) -> usize {
    exercise::object_cap(Limits::DEFAULT.max_objects, len) as usize
}

/// Decoded bytes a reconstruction may spend on object streams (`max(16 MiB, 16 × len)`).
fn reconstruct_budget(len: usize) -> u64 {
    (16 * len as u64).max(16 << 20)
}

/// The most the object-stream cache holds: `max_objstm_cache`, plus the container in use (at
/// most `max_objstm_decoded`) and its tables.
fn cache_ceiling(container: u64) -> u64 {
    Limits::DEFAULT.max_objstm_cache as u64 + container + (1 << 20)
}

/// The memory the objects parsed from object streams may take (`max(64 MiB, 128 × len)`).
fn objstm_parsed_budget(len: usize) -> u64 {
    (128 * len as u64).max(64 << 20)
}

/// What one open-and-read of a hostile file saw.
struct Outcome {
    /// The open error, or the store.
    store: Result<Store, ErrorCode>,
    /// [`Store::total_decoded`] right after opening.
    decoded_at_open: u64,
    /// How long opening took.
    open_time: Duration,
}

/// Opens `bytes` with the default limits and `strictness`, timing the open.
fn open(bytes: &[u8], strictness: Strictness) -> Outcome {
    let options = OpenOptions::default().with_strictness(strictness);
    assert_eq!(options.limits, Limits::DEFAULT);
    let started = std::time::Instant::now();
    let store = Store::open_bytes(bytes.to_vec(), &options).map_err(|err| err.code());
    let open_time = started.elapsed();
    let decoded_at_open = store.as_ref().map_or(0, Store::total_decoded);
    Outcome {
        store,
        decoded_at_open,
        open_time,
    }
}

/// Uses everything in `store` ([`exercise_store`]) and checks the store's guarantees.
fn exercise_all(store: &Store, name: &str) -> Report {
    let report = exercise_store(store);
    assert!(
        report.violations.is_empty(),
        "{name}: {:?}",
        report.violations
    );
    report
}

/// The readable part of every hostile file: catalog 1, page tree 2, page 3, content stream 4.
fn check_document(store: &Store, name: &str) {
    let catalog = store.resolve(hostile::ROOT).unwrap();
    assert!(catalog.as_dict().unwrap().is_type(b"Catalog"), "{name}");
    let pages = store.resolve(ObjectId::new(2, 0)).unwrap();
    assert!(pages.as_dict().unwrap().is_type(b"Pages"), "{name}");
    let content = store.resolve(ObjectId::new(4, 0)).unwrap();
    let Object::Stream(stream) = &*content else {
        panic!("{name}: object 4 is a {}", content.type_name());
    };
    let text = store.stream_data(stream).unwrap().data;
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains(&format!("({TEXT})")), "{name}: {text}");
}

/// The decoded length of a hostile file's content stream (object 4).
fn hostile_content_len() -> u64 {
    format!("BT /F1 24 Tf 72 720 Td ({TEXT}) Tj ET").len() as u64
}

fn has(store: &Store, kind: DiagnosticKind) -> bool {
    store.diagnostics().iter().any(|d| d.kind == kind)
}

/// Runs the test `test` (the name of the calling `#[test]` function): `f` must finish within
/// [`BUDGET`], and the peak resident memory of the process that ran it must stay under
/// `ceiling` bytes.
///
/// The test harness runs tests in parallel threads of one process, whose peak resident memory
/// mixes them all. So, where the peak can be read (Linux), this starts the test binary again
/// with `--exact <test>` (and [`ISOLATED_ENV`] set), which runs `f` alone in a fresh process and
/// checks that process's peak, and waits for it. A name that does not match the calling test
/// fails (the child runs no test and never prints [`ISOLATED_DONE`]).
fn bounded(test: &'static str, ceiling: u64, f: impl FnOnce() + Send + 'static) {
    let isolated = std::env::var(ISOLATED_ENV).is_ok_and(|name| name == test);
    if isolated || peak_rss().is_none() {
        run_bounded(test, ceiling, f);
    } else {
        run_isolated(test);
    }
}

/// Runs `f` in this process within [`BUDGET`], then checks the peak against `ceiling`.
fn run_bounded(test: &'static str, ceiling: u64, f: impl FnOnce() + Send + 'static) {
    let ((), elapsed) = within(BUDGET, f).unwrap_or_else(|overrun| panic!("{test}: {overrun}"));
    eprintln!(
        "{test}: {elapsed:.2?}, peak resident memory {} MiB (ceiling {} MiB)",
        peak_rss().unwrap_or(0) / MIB,
        ceiling / MIB
    );
    check_rss(test, ceiling);
    println!("{ISOLATED_DONE} {test}");
}

/// Runs the test `test` alone in a new process (this test binary with `--exact`), forwards its
/// output, and fails unless it ran and passed.
fn run_isolated(test: &'static str) {
    let exe = std::env::current_exe().unwrap();
    let output = std::process::Command::new(exe)
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(ISOLATED_ENV, test)
        .output()
        .unwrap_or_else(|err| panic!("{test}: cannot run the test binary: {err}"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprint!("{stderr}");
    assert!(
        output.status.success(),
        "{test} failed in its own process ({}):\n{stdout}\n{stderr}",
        output.status
    );
    assert!(
        stdout.contains(&format!("{ISOLATED_DONE} {test}\n")),
        "{test} did not run in its own process (is the name given to `bounded` the test's \
         name?):\n{stdout}"
    );
}

/// Checks that opening and reading `hostile` takes at most [`SLOWDOWN`] times as long as
/// `benign`, a file of the same length without the hostile part, plus a second: the work is
/// linear in the file size, whatever the file holds. Machine speed cancels out, so this catches
/// a regression that a fixed budget would let through on a fast machine.
fn assert_linear(name: &str, hostile: &[u8], benign: &[u8]) {
    assert_eq!(hostile.len(), benign.len(), "{name}: the lengths differ");
    let time = |bytes: &[u8]| {
        let started = std::time::Instant::now();
        let store = open(bytes, Strictness::Lenient).store.unwrap();
        exercise_all(&store, name);
        started.elapsed()
    };
    let benign_time = time(benign);
    let hostile_time = time(hostile);
    eprintln!("  {name}: {hostile_time:.2?} (benign file of the same length: {benign_time:.2?})");
    assert!(
        hostile_time <= benign_time * SLOWDOWN + Duration::from_secs(1),
        "{name}: {hostile_time:.2?}, against {benign_time:.2?} for a benign file of the same length"
    );
}

/// How much slower than a benign file of the same length a hostile file may be to read.
const SLOWDOWN: u32 = 4;

/// Fails when the process's peak resident memory (where it can be read) is `ceiling` or more.
fn check_rss(name: &str, ceiling: u64) {
    if let Some(peak) = peak_rss() {
        assert!(
            peak < ceiling,
            "{name}: peak resident memory {} MiB is over the {} MiB ceiling",
            peak / MIB,
            ceiling / MIB
        );
    }
}

// ---- cross-reference streams -------------------------------------------------------------------

#[test]
fn chained_xref_streams_default_limits() {
    // 1,000 sections of 200,000 rows: 200 million rows from about 400 KB. The reader stops
    // after max(2^20, 4 × len) rows over all sections, cuts the chain, and finds the base
    // table's objects by scanning.
    const SECTIONS: u32 = 1_000;
    const ROWS: u32 = 200_000;
    // Memory: about 20 MiB; keeping every row claimed would take gigabytes.
    const TEST: &str = "chained_xref_streams_default_limits";
    bounded(TEST, 128 * MIB, || {
        let bytes = hostile::xref_stream_chain(SECTIONS, ROWS);
        let len = bytes.len();
        assert!(len < 1 << 20, "{len}");
        let lenient = open(&bytes, Strictness::Lenient);
        eprintln!("  open ({len} B) {:.2?}", lenient.open_time);
        let store = lenient.store.unwrap();
        let read = store.revisions().len() as u64;
        assert!(read < u64::from(SECTIONS), "{read} sections read");
        // Every section read (but the base table) is ROWS rows; the last one may be partial.
        assert!(
            read.saturating_sub(2) * u64::from(ROWS) <= row_budget(len),
            "{read} sections of {ROWS} rows"
        );
        assert!(
            lenient.decoded_at_open <= xref_decode_budget(len, read),
            "{} bytes decoded",
            lenient.decoded_at_open
        );
        assert!(store.structure_repaired());
        assert!(
            has(&store, DiagnosticKind::XrefLoop),
            "{:?}",
            store.diagnostics()
        );
        assert!(store.object_ids().len() <= object_cap(len));
        check_document(&store, "chained xref streams");
        let report = exercise_all(&store, "chained xref streams");
        assert_eq!(report.pages, Some(1));
        drop(store);

        let strict = open(&bytes, Strictness::Strict);
        assert_eq!(strict.store.err(), Some(ErrorCode::LimitExceeded));
    });
}

#[test]
fn overlapping_xref_streams_default_limits() {
    // 1,500 sections whose data all runs to the end of one 300 KB tail: each would parse every
    // later header plus the tail, about 600 MB in all from a 540 KB file. The reader charges
    // every section's bytes to max(1 MiB, 4 × len) and cuts the chain there.
    const SECTIONS: u32 = 1_500;
    const TAIL: u32 = 300_000;
    // Memory: about 30 MiB.
    const TEST: &str = "overlapping_xref_streams_default_limits";
    bounded(TEST, 128 * MIB, || {
        let bytes = hostile::overlapping_xref_streams(SECTIONS, TAIL);
        let len = bytes.len();
        let lenient = open(&bytes, Strictness::Lenient);
        eprintln!("  open ({len} B) {:.2?}", lenient.open_time);
        let store = lenient.store.unwrap();
        let read = store.revisions().len() as u64;
        assert!(read < u64::from(SECTIONS), "{read} sections read");
        // Each section read parses at least the tail.
        assert!(
            read.saturating_sub(2) * u64::from(TAIL) <= byte_budget(len),
            "{read} sections of more than {TAIL} bytes"
        );
        assert!(store.structure_repaired());
        assert!(
            has(&store, DiagnosticKind::XrefLoop),
            "{:?}",
            store.diagnostics()
        );
        assert!(store.object_ids().len() <= object_cap(len));
        check_document(&store, "overlapping xref streams");
        exercise_all(&store, "overlapping xref streams");
        drop(store);

        let strict = open(&bytes, Strictness::Strict);
        assert_eq!(strict.store.err(), Some(ErrorCode::LimitExceeded));
    });
}

#[test]
fn huge_index_default_limits() {
    // Memory: about 45 MiB (the largest file is 20 million rows of real data, 20 MB decoded).
    const TEST: &str = "huge_index_default_limits";
    bounded(TEST, 128 * MIB, || {
        // /Index [1000 4294967295] over 64 rows of data: the claim allocates nothing, the rows
        // that exist are read (and nothing else is decoded), and the objects kept stay under
        // the object cap.
        let bytes = hostile::huge_index(u64::from(u32::MAX), 64);
        let lenient = open(&bytes, Strictness::Lenient);
        let store = lenient.store.unwrap();
        assert!(store.object_ids().len() <= object_cap(bytes.len()));
        assert_eq!(lenient.decoded_at_open, 64);
        check_document(&store, "huge /Index, claimed");
        exercise_all(&store, "huge /Index, claimed");

        // 20 million real rows from about 20 KB: far more than a file of that size may list.
        // The stream is refused before its rows are merged; the table's objects remain. (More
        // rows would change nothing for the reader; they would only make exercise_all decode a
        // bigger stream, which the per-stream limit allows up to 512 MiB.)
        const ROWS: u64 = 20_000_000;
        let bytes = hostile::huge_index(ROWS, ROWS);
        let len = bytes.len();
        assert!(len < 40_000, "{len}");
        assert!(ROWS > 4 * row_budget(len));
        let lenient = open(&bytes, Strictness::Lenient);
        eprintln!("  open ({len} B) {:.2?}", lenient.open_time);
        let store = lenient.store.unwrap();
        assert!(store.object_ids().len() <= object_cap(len));
        assert!(
            lenient.decoded_at_open <= xref_decode_budget(len, 1),
            "{} bytes decoded",
            lenient.decoded_at_open
        );
        check_document(&store, "huge /Index, real rows");
        exercise_all(&store, "huge /Index, real rows");
        drop(store);
        let strict = open(&bytes, Strictness::Strict);
        assert_eq!(strict.store.err(), Some(ErrorCode::LimitExceeded));

        // Exactly as many rows as the object cap allows are kept, the lowest numbers first.
        let rows = 900_000u64;
        let bytes = hostile::huge_index(rows, rows);
        let len = bytes.len();
        let lenient = open(&bytes, Strictness::Lenient);
        let store = lenient.store.unwrap();
        let ids = store.object_ids();
        assert_eq!(ids.len(), object_cap(len));
        assert_eq!(
            ids[..5],
            (1..=5).map(|n| ObjectId::new(n, 0)).collect::<Vec<_>>()
        );
        assert!(ids[5..].iter().all(|id| id.num >= CLAIM_START));
        check_document(&store, "huge /Index, capped");
    });
}

#[test]
fn many_index_subsections_default_limits() {
    // Memory: about 90 MiB (200,000 objects kept, and the 20 MB stream that exercise_all
    // decodes).
    const TEST: &str = "many_index_subsections_default_limits";
    bounded(TEST, 256 * MIB, || {
        // 200,000 one-row subsections: the /Index array is 1.7 MB of text, and 200,000
        // objects are kept (one per byte of the file at most).
        let bytes = hostile::many_subsections(200_000, 1, 2);
        let len = bytes.len();
        let lenient = open(&bytes, Strictness::Lenient);
        eprintln!("  open (200,000 pairs, {len} B) {:.2?}", lenient.open_time);
        let store = lenient.store.unwrap();
        assert!(store.object_ids().len() <= object_cap(len));
        check_document(&store, "many subsections");
        exercise_all(&store, "many subsections");

        // 20,000 subsections that all claim the same 1,000 numbers: 20 million rows, all in
        // the data, from about 260 KB. The reader stops at its row budget.
        let bytes = hostile::many_subsections(20_000, 1_000, 0);
        let len = bytes.len();
        assert!(20_000_000 > 4 * row_budget(len));
        let lenient = open(&bytes, Strictness::Lenient);
        eprintln!(
            "  open (20,000 overlapping pairs, {len} B) {:.2?}",
            lenient.open_time
        );
        let store = lenient.store.unwrap();
        assert!(store.object_ids().len() <= object_cap(len));
        assert!(
            lenient.decoded_at_open <= xref_decode_budget(len, 1),
            "{} bytes decoded",
            lenient.decoded_at_open
        );
        check_document(&store, "overlapping subsections");
        exercise_all(&store, "overlapping subsections");
    });
}

// ---- reconstruction ------------------------------------------------------------------------------

#[test]
fn reconstruct_with_many_object_streams_default_limits() {
    // No cross-reference data and 40 object streams of 64 MiB each (2.5 GiB decoded, 2.6 MB of
    // file). Opening reconstructs the file: it reads object streams for their member lists
    // only, within max(16 MiB, 16 × len) decoded bytes, and keeps none of them.
    const CONTAINERS: u32 = 40;
    const DECODED: u64 = 64 << 20;
    // Memory: about 50 MiB; caching the containers would keep 2.5 GiB.
    const TEST: &str = "reconstruct_with_many_object_streams_default_limits";
    bounded(TEST, 128 * MIB, || {
        let bytes = hostile::objstm_bombs(CONTAINERS, DECODED);
        let len = bytes.len();
        assert!(len < 4 << 20, "{len}");
        let lenient = open(&bytes, Strictness::Lenient);
        eprintln!("  open {:.2?}", lenient.open_time);
        let store = lenient.store.unwrap();
        assert!(
            lenient.decoded_at_open <= reconstruct_budget(len),
            "opening decoded {} bytes",
            lenient.decoded_at_open
        );
        assert!(has(&store, DiagnosticKind::XrefReconstructed));
        // The containers that did not fit the budget are reported, not decoded.
        assert!(
            store
                .diagnostics()
                .iter()
                .any(|d| d.kind == DiagnosticKind::ObjectStream
                    && d.message.contains("bytes left for reconstructing")),
            "{:?}",
            store.diagnostics()
        );
        // Resolving the document's objects (not the members) decodes only its content stream.
        for id in store.object_ids() {
            if id.num < CLAIM_START {
                store.resolve(id).unwrap();
            }
        }
        check_document(&store, "object stream bombs");
        let content = hostile_content_len();
        assert_eq!(store.total_decoded(), lenient.decoded_at_open + content);
        check_rss("object stream bombs, after open", 128 * MIB);
        drop(store);

        // Strict mode refuses to reconstruct.
        let strict = open(&bytes, Strictness::Strict);
        assert_eq!(strict.store.err(), Some(ErrorCode::Xref));

        // Within the reconstruction budget: 6 containers of 2 MiB. Every member is found, and
        // reading everything decodes each container once (a stream's bytes count once, however
        // often it is decoded).
        const SMALL: u32 = 6;
        const SMALL_DECODED: u64 = 2 << 20;
        let bytes = hostile::objstm_bombs(SMALL, SMALL_DECODED);
        let lenient = open(&bytes, Strictness::Lenient);
        let store = lenient.store.unwrap();
        assert!(lenient.decoded_at_open <= reconstruct_budget(bytes.len()));
        let report = exercise_all(&store, "small object stream bombs");
        assert_eq!(report.non_null, 5 + 2 * SMALL as usize, "{report:?}");
        for k in 0..SMALL {
            let member = store.resolve(ObjectId::new(CLAIM_START + k, 0)).unwrap();
            assert_eq!(
                member.as_str_bytes(),
                Some(format!("member {k}").as_bytes())
            );
        }
        assert_eq!(
            store.total_decoded(),
            u64::from(SMALL) * SMALL_DECODED + hostile_content_len()
        );
    });
}

#[test]
fn compressed_objects_in_large_object_streams_default_limits() {
    // 4 object streams that decode to 16 MiB each (a 70 KB file), listed by a cross-reference
    // stream. Resolving an object decodes its container once; resolving it again, decoding the
    // container's own stream data, or reading everything costs nothing more, and each source
    // stream is counted once against max_total_decoded. The cache keeps at most
    // max_objstm_cache (64 MiB) of them, plus the one in use.
    const CONTAINERS: u32 = 4;
    const DECODED: u64 = 16 << 20;
    // Memory: about 100 MiB (the 64 MiB cache, one container in use, and exercise_all's decode
    // of a container's own stream data).
    const TEST: &str = "compressed_objects_in_large_object_streams_default_limits";
    bounded(TEST, 256 * MIB, || {
        let bytes = hostile::objstm_cache_bombs(CONTAINERS, DECODED);
        let lenient = open(&bytes, Strictness::Lenient);
        let store = lenient.store.unwrap();
        assert!(store.diagnostics().is_empty(), "{:?}", store.diagnostics());
        let members = |store: &Store| {
            for k in 0..CONTAINERS {
                let member = store.resolve(ObjectId::new(CLAIM_START + k, 0)).unwrap();
                assert_eq!(
                    member.as_str_bytes(),
                    Some(format!("member {k}").as_bytes())
                );
            }
        };
        members(&store);
        assert!(store.objstm_cache_bytes() <= cache_ceiling(DECODED));
        let decoded = store.total_decoded();
        assert_eq!(
            decoded,
            lenient.decoded_at_open + u64::from(CONTAINERS) * DECODED
        );
        members(&store);
        assert_eq!(store.total_decoded(), decoded);
        let report = exercise_all(&store, "compressed objects in large object streams");
        assert_eq!(report.pages, Some(1));
        assert_eq!(report.total_decoded, decoded + hostile_content_len());
        drop(store);

        let strict = open(&bytes, Strictness::Strict);
        members(&strict.store.unwrap());
    });
}

#[test]
fn reconstruct_with_unterminated_trailers_default_limits() {
    // 2,000 trailer candidates with an unterminated string each, then 8 MB of padding: parsed
    // to the end of the file, the 64 candidates tried would read half a gigabyte. Each is parsed
    // only up to the next `trailer` keyword or object header, so reading the file costs about
    // what a file of the same length with one good trailer costs.
    const COUNT: u32 = 2_000;
    const PADDING: usize = 8 << 20;
    // Memory: about 35 MiB (the 8 MB file and its copies).
    const TEST: &str = "reconstruct_with_unterminated_trailers_default_limits";
    bounded(TEST, 128 * MIB, || {
        let bytes = hostile::unterminated_trailers(COUNT, PADDING);
        let lenient = open(&bytes, Strictness::Lenient);
        eprintln!("  open {:.2?}", lenient.open_time);
        let store = lenient.store.unwrap();
        assert_eq!(store.root_id(), Some(hostile::ROOT));
        assert!(has(&store, DiagnosticKind::XrefReconstructed));
        check_document(&store, "unterminated trailers");
        exercise_all(&store, "unterminated trailers");
        drop(store);

        let extra = bytes.len() - hostile::unterminated_trailers(0, PADDING).len();
        let benign = hostile::unterminated_trailers(0, PADDING + extra);
        assert_linear("unterminated trailers", &bytes, &benign);
    });
}

// ---- object streams (M1 QA round 2) -------------------------------------------------------------

#[test]
fn object_stream_cache_bombs_default_limits() {
    // QA round 2: `objstm_cache_bombs(10, 400 << 20)`, a 4 MB file, kept 4 GiB of decoded
    // containers (5 GiB resident) once its objects were resolved. A container may decode to at
    // most max_objstm_decoded (64 MiB): these are refused after that much, and nothing is kept.
    const BIG: u64 = 400 << 20;
    // Memory: about 125 MiB. At M1 fix round 1 the store kept every decoded container: the
    // second file alone took it to 290 MiB (opening and resolving the six members), and the
    // three 400 MiB containers would have stayed resident.
    const TEST: &str = "object_stream_cache_bombs_default_limits";
    bounded(TEST, 256 * MIB, || {
        let bytes = hostile::objstm_cache_bombs(3, BIG);
        let len = bytes.len();
        for strictness in [Strictness::Lenient, Strictness::Strict] {
            let outcome = open(&bytes, strictness);
            let store = outcome.store.unwrap();
            for k in 0..3 {
                let err = store
                    .resolve(ObjectId::new(CLAIM_START + k, 0))
                    .unwrap_err();
                assert_eq!(err.code(), ErrorCode::LimitExceeded, "{err}");
                assert!(err.to_string().contains("max_objstm_decoded"), "{err}");
            }
            assert_eq!(store.objstm_cache_bytes(), 0);
            let cap = Limits::DEFAULT.max_objstm_decoded as u64;
            assert!(
                store.total_decoded() <= outcome.decoded_at_open + 3 * cap,
                "{} bytes decoded",
                store.total_decoded()
            );
            check_document(&store, "object stream cache bombs");
        }
        eprintln!("  refused 3 containers of 400 MiB ({len} B)");

        // Six containers of 24 MiB (144 MiB decoded, a 160 KB file): each is decoded, and the
        // cache keeps at most 64 MiB of them plus the one in use; the members all read.
        const CONTAINERS: u32 = 6;
        const DECODED: u64 = 24 << 20;
        let bytes = hostile::objstm_cache_bombs(CONTAINERS, DECODED);
        let lenient = open(&bytes, Strictness::Lenient);
        let store = lenient.store.unwrap();
        for k in 0..CONTAINERS {
            let member = store.resolve(ObjectId::new(CLAIM_START + k, 0)).unwrap();
            assert_eq!(
                member.as_str_bytes(),
                Some(format!("member {k}").as_bytes())
            );
            assert!(
                store.objstm_cache_bytes() <= cache_ceiling(DECODED),
                "{} bytes cached",
                store.objstm_cache_bytes()
            );
        }
        assert_eq!(
            store.total_decoded(),
            lenient.decoded_at_open + u64::from(CONTAINERS) * DECODED
        );
        let report = exercise_all(&store, "object stream cache bombs, cached");
        assert_eq!(report.pages, Some(1));
        assert!(store.objstm_cache_bytes() <= cache_ceiling(DECODED));
    });
}

#[test]
fn object_stream_header_pairs_default_limits() {
    // QA round 2: a header of millions of `1 0` pairs made the store build 48 bytes of tables
    // per pair, 14 bytes of memory per decoded byte. Here 8 million pairs, 32 MB decoded from a
    // 34 KB file, took the store at M1 fix round 1 to 430 MiB just to open the file and resolve
    // the member. A container lists at most object_cap members (one per byte of the file here);
    // the rest are ignored with a diagnostic, and the tables cost 20 bytes per member kept.
    const PAIRS: u32 = 8_000_000;
    // Memory: about 125 MiB (the 32 MB container, cached, and decoded once more by
    // exercise_all).
    const TEST: &str = "object_stream_header_pairs_default_limits";
    bounded(TEST, 256 * MIB, || {
        let bytes = hostile::objstm_header_pairs(PAIRS);
        let len = bytes.len();
        assert!(len < 100_000, "{len}");
        let lenient = open(&bytes, Strictness::Lenient);
        let store = lenient.store.unwrap();
        let member = store.resolve(ObjectId::new(CLAIM_START, 0)).unwrap();
        assert_eq!(member.as_str_bytes(), Some(&b"member"[..]));
        let decoded = hostile::objstm_header_pairs_decoded(PAIRS);
        let kept = object_cap(len) as u64;
        assert!(
            store.objstm_cache_bytes() <= decoded + 20 * kept + 4096,
            "{} bytes cached for {kept} members",
            store.objstm_cache_bytes()
        );
        assert!(
            store
                .diagnostics()
                .iter()
                .any(|d| d.kind == DiagnosticKind::ObjectStream
                    && d.message
                        .contains(&format!("lists more than {kept} objects"))),
            "{:?}",
            store.diagnostics()
        );
        check_document(&store, "object stream header pairs");
        exercise_all(&store, "object stream header pairs");
        drop(store);

        // Strict mode refuses the container (offsets that do not increase are an error there).
        let strict = open(&bytes, Strictness::Strict).store.unwrap();
        assert!(strict.resolve(ObjectId::new(CLAIM_START, 0)).is_err());
        check_document(&strict, "object stream header pairs, strict");
    });
}

#[test]
fn object_stream_big_array_default_limits() {
    // QA round 2: a member `[0 0 0 ...]` of 16 million elements (32 MB decoded from a 50 KB
    // file) became 1 GB of objects. The objects parsed from object streams may take
    // max(64 MiB, 128 × file length) over the life of the store: the parse stops there.
    const ELEMENTS: u32 = 16_000_000;
    // Memory: about 130 MiB. At M1 fix round 1 opening this file and resolving the member took
    // 1.1 GiB.
    const TEST: &str = "object_stream_big_array_default_limits";
    bounded(TEST, 256 * MIB, || {
        let bytes = hostile::objstm_big_array(ELEMENTS);
        let len = bytes.len();
        assert!(len < 100_000, "{len}");
        let budget = objstm_parsed_budget(len);
        for strictness in [Strictness::Lenient, Strictness::Strict] {
            let store = open(&bytes, strictness).store.unwrap();
            let err = store.resolve(ObjectId::new(CLAIM_START, 0)).unwrap_err();
            assert_eq!(err.code(), ErrorCode::LimitExceeded, "{err}");
            assert!(err.to_string().contains("objstm_parsed"), "{err}");
            assert!(err.to_string().contains("budget_scale"), "{err}");
            let used = store.objstm_parsed_bytes();
            assert!(used > budget && used <= budget + 64, "{used} of {budget}");
            // The failure is cached: resolving again costs nothing.
            assert!(store.resolve(ObjectId::new(CLAIM_START, 0)).is_err());
            assert_eq!(store.objstm_parsed_bytes(), used);
            check_document(&store, "object stream big array");
        }
        let store = open(&bytes, Strictness::Lenient).store.unwrap();
        exercise_all(&store, "object stream big array");
    });
}
