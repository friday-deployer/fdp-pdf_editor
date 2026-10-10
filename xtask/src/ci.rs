//! `cargo xtask ci`: the Definition-of-Done gates from `CLAUDE.md`, in order.
//!
//! 1. `cargo fmt --all -- --check`
//! 2. `cargo clippy --workspace --all-targets -- -D warnings`
//! 3. `cargo test --workspace`
//! 4. `cargo xtask fixtures --check` (run in process): the committed `fixtures/syntax` and
//!    `fixtures/hostile` files and their `fixtures/README.md` tables match the generators (M1
//!    acceptance criterion 6)
//! 5. `cargo deny check` (skipped with a notice when cargo-deny is not installed)
//! 6. tree checks (ARCHITECTURE §A.5 gap 2 and §A.8):
//!    - no package named like `napi` or `tauri` in the normal dependency tree of `folioxide`
//!      (with default features and with all features)
//!    - exactly one `cms` version in the workspace graph
//!
//! Every step runs even if an earlier one failed, and a summary is printed at the end. The exit
//! code is 1 if any step failed. The Node and oracle gates have their own commands.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Stdio;

use crate::{Outcome, cargo, display_command, fixtures, run_status};

/// Name fragments that must never appear in the core dependency tree (Tauri readiness).
const FORBIDDEN_IN_CORE: [&str; 2] = ["napi", "tauri"];

/// The result of one gate.
#[derive(Debug, PartialEq, Eq)]
enum StepResult {
    Pass,
    Fail(String),
    Skip(String),
}

/// Runs every gate and prints a summary.
pub(crate) fn run(root: &Path) -> Outcome {
    const CLIPPY: [&str; 6] = [
        "clippy",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ];
    // Evaluated top to bottom, so the gates run in CLAUDE.md order.
    let results: Vec<(&str, StepResult)> = vec![
        ("fmt", cargo_step(root, &["fmt", "--all", "--", "--check"])),
        ("clippy", cargo_step(root, &CLIPPY)),
        ("test", cargo_step(root, &["test", "--workspace"])),
        ("fixtures --check", fixtures_step(root)),
        ("deny", deny_step(root)),
        ("tree: no napi/tauri in folioxide", core_tree_step(root)),
        ("tree: one cms version", cms_step(root)),
    ];

    println!("\nxtask ci summary");
    let mut failed = false;
    for (name, result) in &results {
        match result {
            StepResult::Pass => println!("  PASS  {name}"),
            StepResult::Skip(why) => println!("  SKIP  {name}: {why}"),
            StepResult::Fail(why) => {
                failed = true;
                println!("  FAIL  {name}: {why}");
            }
        }
    }
    if failed {
        Outcome::Failure
    } else {
        Outcome::Success
    }
}

/// Runs `cargo <args>` with inherited output.
fn cargo_step(root: &Path, args: &[&str]) -> StepResult {
    let mut command = cargo(root);
    command.args(args);
    match run_status(&mut command) {
        Ok(true) => StepResult::Pass,
        Ok(false) => StepResult::Fail(format!("`{}` failed", display_command(&command))),
        Err(message) => StepResult::Fail(message),
    }
}

/// `cargo xtask fixtures --check`, run in this process (the generators are linked into xtask, so
/// this checks exactly the generators `cargo xtask fixtures` would write with).
fn fixtures_step(root: &Path) -> StepResult {
    println!("xtask: running `cargo xtask fixtures --check`");
    fixtures_result(fixtures::run(root, true))
}

/// The gate result for an outcome of `cargo xtask fixtures --check`.
fn fixtures_result(outcome: Outcome) -> StepResult {
    match outcome {
        Outcome::Success => StepResult::Pass,
        Outcome::Failure => StepResult::Fail(
            "committed fixtures differ from their generators (run `cargo xtask fixtures`)"
                .to_owned(),
        ),
        Outcome::EnvError => StepResult::Fail(
            "could not read the generated fixtures or fixtures/README.md".to_owned(),
        ),
    }
}

/// `cargo deny check`, or a skip notice when cargo-deny is not installed.
fn deny_step(root: &Path) -> StepResult {
    let installed = cargo(root)
        .args(["deny", "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if installed {
        cargo_step(root, &["deny", "check"])
    } else {
        println!("xtask: cargo-deny is not installed; skipping `cargo deny check`");
        StepResult::Skip("cargo-deny not installed (cargo install cargo-deny)".to_owned())
    }
}

/// No `napi`/`tauri` package below `folioxide`, with default and with all features.
fn core_tree_step(root: &Path) -> StepResult {
    let mut offenders = BTreeSet::new();
    for extra in [&[][..], &["--all-features"][..]] {
        let mut args = vec!["-p", "folioxide", "-e", "normal"];
        args.extend_from_slice(extra);
        match tree_packages(root, &args) {
            Ok(packages) => offenders.extend(forbidden_packages(&packages)),
            Err(message) => return StepResult::Fail(message),
        }
    }
    if offenders.is_empty() {
        StepResult::Pass
    } else {
        let list: Vec<String> = offenders.into_iter().collect();
        StepResult::Fail(format!(
            "core depends on {} (only bindings/node may use napi)",
            list.join(", ")
        ))
    }
}

/// Exactly one `cms` version across the workspace, every feature and every target.
fn cms_step(root: &Path) -> StepResult {
    let args = ["--workspace", "--all-features", "-e", "normal,build,dev"];
    match tree_packages(root, &args) {
        Ok(packages) => {
            let versions = versions_of(&packages, "cms");
            if versions.len() == 1 {
                StepResult::Pass
            } else {
                let list: Vec<&str> = versions.iter().map(String::as_str).collect();
                StepResult::Fail(format!(
                    "expected exactly one cms version, found {} [{}]",
                    versions.len(),
                    list.join(", ")
                ))
            }
        }
        Err(message) => StepResult::Fail(message),
    }
}

/// `(name, version)` of every package in `cargo tree <args>` over all targets.
fn tree_packages(root: &Path, args: &[&str]) -> Result<BTreeSet<(String, String)>, String> {
    let mut command = cargo(root);
    command
        .arg("tree")
        .args(args)
        .args(["--target", "all", "--prefix", "none", "--format", "{p}"])
        .stderr(Stdio::inherit());
    let shown = display_command(&command);
    println!("xtask: running `{shown}`");
    let output = command
        .output()
        .map_err(|err| format!("could not start `{shown}`: {err}"))?;
    if !output.status.success() {
        return Err(format!("`{shown}` failed"));
    }
    Ok(parse_tree(&String::from_utf8_lossy(&output.stdout)))
}

/// Parses `cargo tree --prefix none --format {p}` output. Each line is `name vX.Y.Z`, optionally
/// followed by a source path and/or the ` (*)` de-duplication marker.
fn parse_tree(output: &str) -> BTreeSet<(String, String)> {
    output
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let name = words.next()?;
            let version = words.next()?.strip_prefix('v')?;
            Some((name.to_owned(), version.to_owned()))
        })
        .collect()
}

/// Packages whose name contains a forbidden fragment, as `name vX.Y.Z`.
fn forbidden_packages(packages: &BTreeSet<(String, String)>) -> Vec<String> {
    packages
        .iter()
        .filter(|(name, _)| FORBIDDEN_IN_CORE.iter().any(|bad| name.contains(bad)))
        .map(|(name, version)| format!("{name} v{version}"))
        .collect()
}

/// Every version of the package called `name`.
fn versions_of(packages: &BTreeSet<(String, String)>, name: &str) -> BTreeSet<String> {
    packages
        .iter()
        .filter(|(package, _)| package == name)
        .map(|(_, version)| version.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
folioxide v0.1.0 (/work/crates/folioxide)
folioxide-sign v0.1.0 (/work/crates/folioxide-sign)
cms v0.3.0-pre.1
der v0.8.2
p12-keystore v0.4.0
cms v0.3.0-pre.1 (*)

der v0.8.2 (*)
";

    #[test]
    fn fixtures_outcomes_map_to_gate_results() {
        assert_eq!(fixtures_result(Outcome::Success), StepResult::Pass);
        let StepResult::Fail(why) = fixtures_result(Outcome::Failure) else {
            panic!("a fixture mismatch must fail the gate");
        };
        assert!(why.contains("cargo xtask fixtures"), "{why}");
        assert!(matches!(
            fixtures_result(Outcome::EnvError),
            StepResult::Fail(_)
        ));
    }

    #[test]
    fn parses_tree_lines() {
        let packages = parse_tree(SAMPLE);
        assert_eq!(packages.len(), 5);
        assert!(packages.contains(&("cms".to_owned(), "0.3.0-pre.1".to_owned())));
        assert!(packages.contains(&("folioxide".to_owned(), "0.1.0".to_owned())));
    }

    #[test]
    fn ignores_lines_without_versions() {
        let packages = parse_tree("[build-dependencies]\nnoise\nname notaversion\n");
        assert!(packages.is_empty());
    }

    #[test]
    fn counts_cms_versions() {
        let one = parse_tree(SAMPLE);
        assert_eq!(versions_of(&one, "cms").len(), 1);

        let two = parse_tree(&format!("{SAMPLE}cms v0.3.0-pre.2\n"));
        assert_eq!(versions_of(&two, "cms").len(), 2);

        assert!(versions_of(&parse_tree(""), "cms").is_empty());
    }

    #[test]
    fn finds_forbidden_packages() {
        assert!(forbidden_packages(&parse_tree(SAMPLE)).is_empty());

        let bad =
            parse_tree("folioxide v0.1.0 (/w)\nnapi v3.14.2\nnapi-sys v3.4.0\ntauri v2.0.0\n");
        assert_eq!(
            forbidden_packages(&bad),
            vec!["napi v3.14.2", "napi-sys v3.4.0", "tauri v2.0.0"]
        );
    }

    #[test]
    fn source_path_is_not_mistaken_for_a_package_name() {
        // A checkout path containing "napi" must not trip the check: only names count.
        let packages = parse_tree("folioxide v0.1.0 (/home/napi/tauri/folioxide)\n");
        assert!(forbidden_packages(&packages).is_empty());
    }
}
