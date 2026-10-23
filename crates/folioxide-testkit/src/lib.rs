//! # folioxide-testkit: test support (not published)
//!
//! Shared helpers for Folioxide's tests. It is a dev-dependency only (`publish = false`) and never
//! part of the shipped library.
//!
//! - [`builder`]: [`PdfBuilder`], a byte-level PDF builder that records true offsets, so it can
//!   produce well-formed files and deliberately broken ones (wrong xref offsets, `/Prev` loops,
//!   junk before the header, wrong `/Length`, zero-width `/W` fields, hybrid files, ...)
//! - [`fixtures`]: fixture generators. [`fixtures::syntax::all`] and
//!   [`fixtures::hostile::seeds`] are reproduced byte for byte under `fixtures/syntax/` and
//!   `fixtures/hostile/` by `cargo xtask fixtures` (checked with `--check`);
//!   [`fixtures::hostile`] builds resource-exhaustion files at test time; [`fixtures::qpdf`]
//!   reads the linearized files qpdf wrote into `fixtures/qpdf/`
//! - [`budget`]: wall-clock budgets ([`budget::within`]) and resident-memory readings for
//!   resource-exhaustion tests
//! - [`mutate`]: seeded, deterministic byte mutations for no-panic robustness tests
//! - [`emit`]: the oracle-output emitter used by `cargo xtask oracle`
//! - [`exercise`]: opens a document and uses all of it, checking the store's documented
//!   guarantees (for `no_panic_on_mutated_input` and the `fuzz_parse_document` fuzz target)
//! - [`graph`]: graph equality of two documents modulo renumbering, with a readable difference
//!   (writer and model round-trip tests)
//! - [`tsa`]: [`MockTsa`](tsa::MockTsa), a deterministic RFC 3161 timestamp authority with its
//!   own DER writer (M4)
//!
//! Later milestones add a loader for the test PKI in `fixtures/pki/`.
//!
//! ## Oracle output
//!
//! With the `emit` feature, tests write `<suite dir>/<name>.pdf` plus `<name>.expect.json`, which
//! `tools/oracles/run_suite.py` then checks with external tools (`docs/ARCHITECTURE.md` §A.9).
//! [`oracle_dir`] gives the suite directory and [`emit_case`] writes one case. `cargo xtask
//! oracle` passes the absolute base directory in the [`ORACLE_DIR_ENV`] environment variable.

pub mod budget;
pub mod builder;
pub mod emit;
pub mod exercise;
pub mod fixtures;
pub mod mutate;
// M2 WP2.4: graph equality of two documents (writer acceptance).
pub mod graph;
// M4 WP4.0: the mock RFC 3161 timestamp authority.
pub mod tsa;

pub use builder::{
    LengthSpec, ObjStmOpts, PdfBuilder, XrefEntry, XrefEol, XrefOpts, XrefStreamOpts,
};
pub use emit::{ExpectJson, emit_case};

use std::ffi::OsStr;
use std::path::PathBuf;

/// `true` when this crate is compiled with the `emit` feature, as under `cargo xtask oracle`.
///
/// Tests that produce oracle cases should only write files when this is set.
pub const EMIT_ENABLED: bool = cfg!(feature = "emit");

/// Name of the environment variable that holds the oracle output base directory.
///
/// `cargo xtask oracle` sets it to the absolute path of `<workspace>/target/oracle`.
pub const ORACLE_DIR_ENV: &str = "FOLIOXIDE_ORACLE_DIR";

/// Returns whether `suite` is a valid oracle suite name.
///
/// A suite name is a single, non-empty path component made of ASCII letters, digits, `-` and `_`,
/// so it can never escape the oracle base directory. `cargo xtask oracle --suite` applies the same
/// rule.
///
/// ```
/// assert!(folioxide_testkit::is_valid_suite_name("writer"));
/// assert!(!folioxide_testkit::is_valid_suite_name("../etc"));
/// ```
pub fn is_valid_suite_name(suite: &str) -> bool {
    !suite.is_empty()
        && suite
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Returns the directory that oracle cases of `suite` are written to.
///
/// This is `$FOLIOXIDE_ORACLE_DIR/<suite>` when the variable is set and non-empty, and
/// `<workspace>/target/oracle/<suite>` otherwise. Returns `None` if `suite` is not a valid suite
/// name (see [`is_valid_suite_name`]). The directory is not created.
pub fn oracle_dir(suite: &str) -> Option<PathBuf> {
    oracle_dir_from(std::env::var_os(ORACLE_DIR_ENV).as_deref(), suite)
}

/// [`oracle_dir`] with the environment lookup factored out, so it can be tested without mutating
/// the process environment.
fn oracle_dir_from(base: Option<&OsStr>, suite: &str) -> Option<PathBuf> {
    if !is_valid_suite_name(suite) {
        return None;
    }
    let base = match base {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => default_oracle_base(),
    };
    Some(base.join(suite))
}

/// `<workspace>/target/oracle`, derived from this crate's location (`<workspace>/crates/folioxide-testkit`).
fn default_oracle_base() -> PathBuf {
    fixtures::workspace_root().join("target").join("oracle")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_names() {
        for good in ["syntax", "writer", "sign-pades", "m1_xref", "A1"] {
            assert!(is_valid_suite_name(good), "{good:?} should be valid");
        }
        for bad in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            "a\\b",
            "a b",
            "suite.pdf",
            "é",
        ] {
            assert!(!is_valid_suite_name(bad), "{bad:?} should be invalid");
        }
    }

    #[test]
    fn oracle_dir_uses_env_base_when_set() {
        let dir = oracle_dir_from(Some(OsStr::new("/tmp/oracle-base")), "writer").unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/oracle-base").join("writer"));
    }

    #[test]
    fn oracle_dir_defaults_to_workspace_target() {
        for base in [None, Some(OsStr::new(""))] {
            let dir = oracle_dir_from(base, "syntax").unwrap();
            assert!(dir.ends_with("target/oracle/syntax"), "{dir:?}");
            // The default base is the workspace root, which holds the root Cargo.toml.
            let root = dir.ancestors().nth(3).unwrap();
            assert!(root.join("Cargo.toml").is_file(), "{root:?}");
            assert!(
                root.join("crates").join("folioxide-testkit").is_dir(),
                "{root:?}"
            );
        }
    }

    #[test]
    fn oracle_dir_rejects_invalid_suite() {
        assert_eq!(oracle_dir_from(None, "../escape"), None);
        assert_eq!(oracle_dir("../escape"), None);
    }
}
