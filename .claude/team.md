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

## Milestone loop
```
1. Plan     manager writes the milestone brief (scope, work packages, acceptance criteria) from docs/ROADMAP.md
2. Build    developer(s) implement; parallel work runs in isolated git worktrees on disjoint modules/crates
3. Merge    manager squash-merges worktree branches into the working tree (uncommitted)
4. QA gate  1–2 QA reviewers (e.g. one on spec/correctness, one on robustness/tests/API) + expert for high-risk areas
5. Fix      developer fixes every Blocker/Major (Minor at manager's discretion); QA re-checks
6. Commit   when all QA verdicts are PASS: manager commits ("M<n>: <title>") and pushes
7. Record   manager ticks the milestone in docs/ROADMAP.md and notes follow-ups
```

## Severity scale (QA and expert)
- **Blocker**: gate command fails, crash/panic on input, data loss/corruption, wrong spec behaviour in a core path, security issue.
- **Major**: acceptance criterion unmet, missing test for an important path, API that will be hard to change later.
- **Minor**: edge case, small inefficiency, unclear docs.
- **Nit**: style or naming.

A milestone may only be committed with zero open Blockers/Majors.
