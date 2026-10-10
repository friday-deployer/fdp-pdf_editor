//! # xtask: Folioxide developer tasks
//!
//! Run through the cargo alias in `.cargo/config.toml`:
//!
//! - `cargo xtask fixtures`: regenerates the generated fixtures (a no-op in M0).
//! - `cargo xtask oracle [--suite <name>]`: runs the tests that emit oracle cases, then checks them
//!   with the Python oracle runner (`tools/oracles/run_suite.py`) from the `.venv`.
//! - `cargo xtask ci`: runs the gate commands from `CLAUDE.md` in order and prints a summary.
//!
//! Exit codes follow the oracle runner contract: `0` success, `1` a check failed, `2` a usage or
//! environment error (for example a missing venv or tool).

mod ci;
mod oracle;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "\
usage: cargo xtask <task>

tasks:
  fixtures                regenerate the generated fixtures (no-op in M0)
  oracle [--suite <name>] run the emitting tests, then tools/oracles/run_suite.py on
                          target/oracle[/<name>]
  ci                      run the CLAUDE.md gate commands (fmt, clippy, test, deny, tree checks)
  help                    print this message";

/// A parsed command line.
#[derive(Debug, PartialEq, Eq)]
enum Task {
    Fixtures,
    Oracle { suite: Option<String> },
    Ci,
    Help,
}

/// How a task ended; converted into the process exit code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// Everything passed (exit code 0).
    Success,
    /// A check or test failed (exit code 1).
    Failure,
    /// A usage or environment error, such as a missing tool (exit code 2).
    EnvError,
}

impl From<Outcome> for ExitCode {
    fn from(outcome: Outcome) -> Self {
        match outcome {
            Outcome::Success => ExitCode::SUCCESS,
            Outcome::Failure => ExitCode::from(1),
            Outcome::EnvError => ExitCode::from(2),
        }
    }
}

fn main() -> ExitCode {
    let task = match parse_args(std::env::args().skip(1)) {
        Ok(task) => task,
        Err(message) => {
            eprintln!("xtask: error: {message}\n\n{USAGE}");
            return Outcome::EnvError.into();
        }
    };
    let root = workspace_root();
    let outcome = match task {
        Task::Help => {
            println!("{USAGE}");
            Outcome::Success
        }
        Task::Fixtures => fixtures(),
        Task::Oracle { suite } => oracle::run(&root, suite.as_deref()),
        Task::Ci => ci::run(&root),
    };
    outcome.into()
}

/// Parses the arguments that follow `cargo xtask`.
fn parse_args<I>(args: I) -> Result<Task, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let Some(task) = args.next() else {
        return Err("missing task".to_owned());
    };
    let task = match task.as_str() {
        "fixtures" => Task::Fixtures,
        "ci" => Task::Ci,
        "help" | "-h" | "--help" => Task::Help,
        "oracle" => {
            let mut suite = None;
            while let Some(arg) = args.next() {
                let value = if arg == "--suite" {
                    args.next()
                        .ok_or_else(|| "--suite needs a value".to_owned())?
                } else if let Some(value) = arg.strip_prefix("--suite=") {
                    value.to_owned()
                } else {
                    return Err(format!("unexpected argument {arg:?} for `oracle`"));
                };
                if suite.is_some() {
                    return Err("--suite given more than once".to_owned());
                }
                if !is_valid_suite_name(&value) {
                    return Err(format!(
                        "invalid suite name {value:?} (use ASCII letters, digits, '-' and '_')"
                    ));
                }
                suite = Some(value);
            }
            return Ok(Task::Oracle { suite });
        }
        other => return Err(format!("unknown task {other:?}")),
    };
    match args.next() {
        Some(extra) => Err(format!("unexpected argument {extra:?}")),
        None => Ok(task),
    }
}

/// Whether `suite` is a single, safe path component. Must match
/// `folioxide_testkit::is_valid_suite_name`, which the emitting tests use.
fn is_valid_suite_name(suite: &str) -> bool {
    !suite.is_empty()
        && suite
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `cargo xtask fixtures`. M0 has no generated fixtures yet.
fn fixtures() -> Outcome {
    println!("xtask: fixtures: nothing to generate yet (M0)");
    Outcome::Success
}

/// The workspace root: the parent of this crate's directory.
fn workspace_root() -> PathBuf {
    let xtask_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    xtask_dir.parent().unwrap_or(xtask_dir).to_path_buf()
}

/// A `Command` for the cargo that runs this xtask (`$CARGO`), so nested builds use the same
/// toolchain, started in the workspace root.
fn cargo(root: &Path) -> Command {
    let program = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(program);
    command.current_dir(root);
    command
}

/// Renders a command for log output, e.g. `cargo test --workspace`.
fn display_command(command: &Command) -> String {
    let program = Path::new(command.get_program())
        .file_stem()
        .unwrap_or_else(|| command.get_program());
    std::iter::once(program)
        .chain(command.get_args())
        .map(OsStr::to_string_lossy)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Runs `command` with inherited stdio. `Ok(true)` if it exited with status 0, `Err` if it could
/// not be started.
fn run_status(command: &mut Command) -> Result<bool, String> {
    let shown = display_command(command);
    println!("xtask: running `{shown}`");
    command
        .status()
        .map(|status| status.success())
        .map_err(|err| format!("could not start `{shown}`: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Task, String> {
        parse_args(args.iter().map(|arg| (*arg).to_owned()))
    }

    #[test]
    fn parses_tasks() {
        assert_eq!(parse(&["fixtures"]), Ok(Task::Fixtures));
        assert_eq!(parse(&["ci"]), Ok(Task::Ci));
        assert_eq!(parse(&["help"]), Ok(Task::Help));
        assert_eq!(parse(&["--help"]), Ok(Task::Help));
        assert_eq!(parse(&["oracle"]), Ok(Task::Oracle { suite: None }));
        assert_eq!(
            parse(&["oracle", "--suite", "writer"]),
            Ok(Task::Oracle {
                suite: Some("writer".to_owned())
            })
        );
        assert_eq!(
            parse(&["oracle", "--suite=sign-pades"]),
            Ok(Task::Oracle {
                suite: Some("sign-pades".to_owned())
            })
        );
    }

    #[test]
    fn rejects_bad_arguments() {
        for bad in [
            &[][..],
            &["deploy"],
            &["ci", "--fast"],
            &["fixtures", "x"],
            &["oracle", "--suite"],
            &["oracle", "--suite", "../etc"],
            &["oracle", "--suite="],
            &["oracle", "--suite", "a", "--suite", "b"],
            &["oracle", "syntax"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn suite_names() {
        assert!(is_valid_suite_name("syntax"));
        assert!(is_valid_suite_name("m1_xref-2"));
        for bad in ["", ".", "..", "a/b", "a\\b", "a b", "x.pdf"] {
            assert!(!is_valid_suite_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn outcome_exit_codes() {
        assert_eq!(ExitCode::from(Outcome::Success), ExitCode::SUCCESS);
        assert_eq!(ExitCode::from(Outcome::Failure), ExitCode::from(1));
        assert_eq!(ExitCode::from(Outcome::EnvError), ExitCode::from(2));
    }

    #[test]
    fn workspace_root_holds_the_workspace_manifest() {
        let root = workspace_root();
        assert!(root.join("Cargo.toml").is_file());
        assert!(root.join("xtask").join("Cargo.toml").is_file());
    }

    #[test]
    fn displays_commands() {
        let mut command = Command::new("/usr/bin/cargo");
        command.args(["test", "--workspace"]);
        assert_eq!(display_command(&command), "cargo test --workspace");
    }
}
