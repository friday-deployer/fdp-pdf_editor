//! `cargo xtask oracle [--suite <name>]`: cross-validation against external tools.
//!
//! Contract (docs/milestones/M0.md, ARCHITECTURE §A.9 "Oracle mechanism"):
//!
//! 1. `cargo test --workspace --features folioxide-testkit/emit` writes oracle cases
//!    (`<name>.pdf` plus `<name>.expect.json`) below `target/oracle/<suite>/`. The absolute base
//!    directory is passed to the tests in `FOLIOXIDE_ORACLE_DIR`.
//! 2. `.venv/bin/python -I tools/oracles/run_suite.py target/oracle[/<suite>]` checks them and exits
//!    0 (all passed, or no cases), 1 (a failure) or 2 (usage or environment error).
//!
//! The venv and the runner are checked before the (slow) test run, so a missing setup fails fast
//! with exit code 2 and a hint. `target/oracle` is emptied before the test run, so only cases from
//! the current tests are checked.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Outcome, cargo, display_command, run_status};

/// Environment variable that tells the emitting tests where to write. Must match
/// `folioxide_testkit::ORACLE_DIR_ENV`.
const ORACLE_DIR_ENV: &str = "FOLIOXIDE_ORACLE_DIR";

/// The runner, relative to the workspace root.
const RUNNER: &str = "tools/oracles/run_suite.py";

/// Runs the oracle task for `suite`, or for every suite when `None`.
pub(crate) fn run(root: &Path, suite: Option<&str>) -> Outcome {
    let python = venv_python(root);
    if !python.is_file() {
        eprintln!(
            "xtask: error: the oracle venv is missing (no interpreter at {})",
            python.display()
        );
        eprintln!("xtask: hint: run: bash tools/setup-venv.sh");
        return Outcome::EnvError;
    }
    let runner = root.join(RUNNER);
    if !runner.is_file() {
        eprintln!(
            "xtask: error: the oracle runner {RUNNER} is missing (expected at {})",
            runner.display()
        );
        eprintln!(
            "xtask: hint: the oracle tooling lives in tools/oracles/ (see docs/ARCHITECTURE.md §A.9)"
        );
        return Outcome::EnvError;
    }

    // Start from an empty output directory, so cases of deleted or renamed tests are not checked.
    let oracle_base = root.join("target").join("oracle");
    if oracle_base.exists()
        && let Err(err) = std::fs::remove_dir_all(&oracle_base)
    {
        eprintln!(
            "xtask: error: cannot clear stale oracle output {}: {err}",
            oracle_base.display()
        );
        return Outcome::EnvError;
    }
    let mut test = cargo(root);
    test.args([
        "test",
        "--workspace",
        "--features",
        "folioxide-testkit/emit",
    ])
    .env(ORACLE_DIR_ENV, &oracle_base);
    match run_status(&mut test) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("xtask: error: the emitting test run failed; oracle checks not run");
            return Outcome::Failure;
        }
        Err(message) => {
            eprintln!("xtask: error: {message}");
            return Outcome::EnvError;
        }
    }

    let relative_dir = suite_dir(suite);
    if let Err(err) = std::fs::create_dir_all(root.join(&relative_dir)) {
        eprintln!(
            "xtask: error: cannot create {}: {err}",
            root.join(&relative_dir).display()
        );
        return Outcome::EnvError;
    }

    let mut check = Command::new(&python);
    check
        .current_dir(root)
        .arg("-I")
        .arg(RUNNER)
        .arg(&relative_dir);
    let shown = display_command(&check);
    println!("xtask: running `{shown}`");
    match check.status() {
        Ok(status) => runner_outcome(status.code()),
        Err(err) => {
            eprintln!("xtask: error: could not start `{shown}`: {err}");
            Outcome::EnvError
        }
    }
}

/// The interpreter inside `<root>/.venv`.
fn venv_python(root: &Path) -> PathBuf {
    let venv = root.join(".venv");
    if cfg!(windows) {
        venv.join("Scripts").join("python.exe")
    } else {
        venv.join("bin").join("python")
    }
}

/// `target/oracle/<suite>`, or `target/oracle` for all suites, relative to the workspace root.
fn suite_dir(suite: Option<&str>) -> PathBuf {
    let base = Path::new("target").join("oracle");
    match suite {
        Some(suite) => base.join(suite),
        None => base,
    }
}

/// Maps the runner's exit code onto ours. Codes 0, 1 and 2 keep their meaning; anything else
/// (including termination by a signal, `None`) counts as a failure.
fn runner_outcome(code: Option<i32>) -> Outcome {
    match code {
        Some(0) => Outcome::Success,
        Some(2) => Outcome::EnvError,
        Some(1) => Outcome::Failure,
        other => {
            eprintln!("xtask: error: the oracle runner ended unexpectedly ({other:?})");
            Outcome::Failure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_dirs() {
        assert_eq!(suite_dir(None), Path::new("target").join("oracle"));
        assert_eq!(
            suite_dir(Some("writer")),
            Path::new("target").join("oracle").join("writer")
        );
    }

    #[test]
    fn runner_exit_codes_map_to_outcomes() {
        assert_eq!(runner_outcome(Some(0)), Outcome::Success);
        assert_eq!(runner_outcome(Some(1)), Outcome::Failure);
        assert_eq!(runner_outcome(Some(2)), Outcome::EnvError);
        assert_eq!(runner_outcome(Some(3)), Outcome::Failure);
        assert_eq!(runner_outcome(None), Outcome::Failure);
    }

    #[test]
    fn missing_venv_is_an_environment_error() {
        // An empty directory has neither `.venv` nor the runner; nothing is run.
        let empty = std::env::temp_dir().join(format!("xtask-oracle-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        let outcome = run(&empty, Some("syntax"));
        std::fs::remove_dir_all(&empty).unwrap();
        assert_eq!(outcome, Outcome::EnvError);
    }

    #[test]
    fn missing_runner_is_an_environment_error() {
        // A venv interpreter exists but tools/oracles/run_suite.py does not; nothing is run.
        let root =
            std::env::temp_dir().join(format!("xtask-oracle-no-runner-{}", std::process::id()));
        let python = venv_python(&root);
        std::fs::create_dir_all(python.parent().unwrap()).unwrap();
        std::fs::write(&python, b"").unwrap();
        let outcome = run(&root, None);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(outcome, Outcome::EnvError);
    }

    #[test]
    fn venv_python_location() {
        let python = venv_python(Path::new("/repo"));
        assert!(python.starts_with(Path::new("/repo").join(".venv")));
    }
}
