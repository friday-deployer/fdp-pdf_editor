"""Self-checks for the CI definitions in .github/workflows (docs/milestones/M0.md, WP0.2 item 6)."""

from __future__ import annotations

import json
import unittest

import yaml
from _support import REPO_ROOT

WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def load(name: str) -> dict:
    with open(WORKFLOWS / name, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def triggers(doc: dict) -> dict:
    # YAML 1.1 reads the bare key `on` as the boolean True.
    return doc.get("on", doc.get(True)) or {}


def all_steps(doc: dict) -> list[dict]:
    return [step for job in doc["jobs"].values() for step in job.get("steps", [])]


class WorkflowTests(unittest.TestCase):
    def test_every_workflow_parses(self):
        files = sorted(WORKFLOWS.glob("*.y*ml"))
        self.assertEqual([f.name for f in files], ["ci.yml", "fuzz-nightly.yml", "release-npm.yml"])
        for f in files:
            with self.subTest(f.name):
                self.assertIsInstance(load(f.name), dict)

    def test_actions_are_pinned_to_a_major_version(self):
        for name in ("ci.yml", "fuzz-nightly.yml", "release-npm.yml"):
            for step in all_steps(load(name)):
                if "uses" in step:
                    with self.subTest(workflow=name, uses=step["uses"]):
                        _, _, ref = step["uses"].partition("@")
                        self.assertRegex(ref, r"^v\d+$")

    def test_ci_jobs(self):
        ci = load("ci.yml")
        for job in ("fmt", "clippy", "test", "deny", "node", "oracle", "msrv"):
            self.assertIn(job, ci["jobs"])
        self.assertEqual(ci["jobs"]["test"]["strategy"]["matrix"]["os"],
                         ["ubuntu-latest", "macos-latest", "windows-latest"])
        runs = "\n".join(s.get("run", "") for s in all_steps(ci))
        for command in ("cargo fmt --all -- --check",
                        "cargo clippy --workspace --all-targets --locked -- -D warnings",
                        "cargo test --workspace --locked",
                        "pnpm install --frozen-lockfile", "pnpm build", "pnpm test", "pnpm test:types",
                        "apt-get install -y --no-install-recommends poppler-utils",
                        "bash tools/setup-venv.sh",
                        "-m unittest discover -s tools/oracles/tests",
                        "bash tools/gen-pki.sh --check",
                        "cargo xtask oracle",
                        "cargo +1.89 check"):
            self.assertIn(command, runs)
        deny = [s for s in ci["jobs"]["deny"]["steps"] if "uses" in s]
        self.assertTrue(any(s["uses"].startswith("EmbarkStudios/cargo-deny-action@") for s in deny))
        node = [s for s in ci["jobs"]["node"]["steps"] if s.get("uses", "").startswith("actions/setup-node@")]
        self.assertEqual(node[0]["with"]["node-version"], 22)

    def test_fuzz_nightly_is_scheduled(self):
        fuzz = load("fuzz-nightly.yml")
        self.assertIn("schedule", triggers(fuzz))
        runs = "\n".join(s.get("run", "") for s in all_steps(fuzz))
        self.assertIn("cargo install cargo-fuzz", runs)
        self.assertIn("cargo +nightly fuzz build", runs)
        self.assertIn("-max_total_time", runs)

    def test_release_is_manual_and_publish_is_gated(self):
        release = load("release-npm.yml")
        self.assertEqual(set(triggers(release)), {"workflow_dispatch"})
        self.assertEqual(triggers(release)["workflow_dispatch"]["inputs"]["publish"]["default"], False)
        targets = [s["target"] for s in release["jobs"]["build"]["strategy"]["matrix"]["settings"]]
        self.assertEqual(sorted(targets), sorted([
            "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
            "x86_64-apple-darwin", "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc",
        ]))
        package_json = REPO_ROOT / "bindings" / "node" / "package.json"
        if package_json.is_file():  # the napi target list is the source of truth (ARCHITECTURE §A.7)
            napi_targets = json.loads(package_json.read_text(encoding="utf-8"))["napi"]["targets"]
            self.assertEqual(sorted(targets), sorted(napi_targets))
        publish = release["jobs"]["publish"]
        self.assertEqual(publish["if"], "${{ inputs.publish }}")
        self.assertIn("secrets.NPM_TOKEN", yaml.safe_dump(publish["steps"][0]))


if __name__ == "__main__":
    unittest.main()
