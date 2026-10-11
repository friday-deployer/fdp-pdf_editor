# Folioxide team & workflow

This file describes how the AI team that builds Folioxide is organised. The agent role cards
live in `.claude/agents/`; project conventions live in `/CLAUDE.md`; design and plan live in `docs/`.

## Roster

| Role | Agent card | Model / effort | Access | Headcount |
|------|------------|----------------|--------|-----------|
| Engineering manager | (main session) | — | full | 1 |
| Senior Rust developer | `agents/rust-developer.md` | Opus, xhigh | read/write | up to 2 |
| QA engineer | `agents/qa-reviewer.md` | Sonnet, high | **read-only** (Bash only for running checks) | up to 2 |
| PDF domain expert | `agents/pdf-expert.md` | Opus, high | **read-only** (+ web) | 1 |
| Helper | `agents/helper.md` | Haiku, high | read/write, tiny tasks only | up to 10 |

> Custom agent types are only registered when a session starts. In a session where they are not yet
> registered, the manager launches a `general-purpose` agent with the matching model/effort and tells it
> to read and follow its role card first.

## Responsibilities
- **Manager**: owns the roadmap, writes milestone briefs, assigns work packages, resolves conflicts,
  merges worktrees, runs the QA gate, commits and pushes. The only role that commits to the main branch.
- **Developers**: implement work packages to the Definition of Done in `CLAUDE.md`. In a worktree they commit
  on the worktree branch; in the main tree they leave changes uncommitted for QA.
- **Expert**: designs with the manager up front, answers spec questions, and does a design/spec review of
  high-risk milestones (syntax layer, encryption, signatures, fonts/redaction).
- **QA**: independent verification against the milestone's acceptance criteria. Never fixes; reports.
- **Helpers**: fixtures, boilerplate, doc touch-ups, command runs. Never design.

## Where work happens (git worktrees)
Since M1, developers never work in the main checkout, so the main branch only ever receives QA-approved,
squashed milestone commits.
- The manager creates an integration branch `wip/m<n>` from the main branch, with a worktree at
  `/home/user/fdp-wt/m<n>`. Each parallel developer gets a branch `wip/m<n>-a`, `wip/m<n>-b`, … from the
  integration branch, with a worktree at `/home/user/fdp-wt/m<n>-a`, ….
- Developers commit freely on their own `wip/*` branch inside their worktree. Prefix every shell command with
  `cd <worktree> &&` and use absolute paths under the worktree for all file tools.
- At a stage boundary the manager merges the developer branches into `wip/m<n>`, then resets the developer
  branches to the new integration head for the next stage.
- QA runs against the integration worktree. Fix rounds happen in the integration worktree (or in the developer
  worktrees, followed by a merge).
- On PASS, the manager squash-merges `wip/m<n>` into the main branch as one commit `M<n>: <title>`, pushes,
  and deletes the `wip/*` branches and worktrees.

## Milestone loop
```
1. Plan     manager writes the milestone brief (scope, work packages, acceptance criteria) from docs/ROADMAP.md
2. Build    developer(s) implement in their own worktrees on wip/* branches (disjoint modules/crates), in stages
3. Merge    manager merges developer branches into the wip/m<n> integration branch after each stage
4. QA gate  1–2 QA reviewers (e.g. one on spec/correctness, one on robustness/tests/API) + expert for high-risk areas
5. Fix      developer fixes every Blocker/Major (Minor at manager's discretion); QA re-checks
6. Commit   when all QA verdicts are PASS: manager squash-merges wip/m<n> into the main branch as "M<n>: <title>" and pushes
7. Record   manager ticks the milestone in docs/ROADMAP.md and notes follow-ups
```

## Severity scale (QA and expert)
- **Blocker**: gate command fails, crash/panic on input, data loss/corruption, wrong spec behaviour in a core path, security issue.
- **Major**: acceptance criterion unmet, missing test for an important path, API that will be hard to change later.
- **Minor**: edge case, small inefficiency, unclear docs.
- **Nit**: style or naming.

A milestone may only be committed with zero open Blockers/Majors.

## Lessons learned
- **M0:** keep a fix round per QA verdict, and hand manager-owned items (docs, decisions) to the manager rather than to developers.
- **M1:** recovery and leniency features need an explicit *reference behaviour* agreed before implementation. For damaged files that reference is qpdf, plus our "a valid chain is never shadowed by text inside a parsed object" rule. Without it, QA rounds keep finding reader differentials one at a time.
- **M1:** prefer designs that are linear **by construction** (non-overlapping coverage) over budgets and cutoffs. Budgets produced a chain of new edge cases, and three patches in a row each introduced a regression.
- **M1:** when two consecutive fix rounds introduce regressions, stop patching. The manager decides on a simpler design, with the expert, before the next round.
- **M1:** the expert's differential probes (our store against pikepdf/qpdf on crafted files) were the most effective QA tool for the syntax layer. Reuse them, and keep them in `/tmp` or the scratchpad, never in the repo.
- **M3:** security classifiers (for example "what changed after signing") must be **whitelist-based** from day one. Emulating a reference validator rule by rule produced a new bypass in every QA round, and so did "safe" exceptions such as `/DA` added when fields have appearances. Each stricter-than-reference result gets a corpus case and a deliberate-difference row, so the oracle keeps confirming it.
- **M3:** expert design briefs that fix the reference behaviour up front (pyHanko) paid off. The QA rounds found policy gaps, not misunderstandings.
- **M3:** adversarial reviewers sometimes stop partway (a safety filter on attack-crafting). The manager then runs the gates and an end-to-end check personally, and schedules the missing pass for the next milestone's QA.

