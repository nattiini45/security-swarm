# NOTICE — `.zcode/` (ZCode dynamic-workflow port)

This directory holds the **ZCode dynamic-workflow port** of Security Swarm.

- Upstream: `nattiini45/security-swarm`
- Pinned tree: `63a493eb8912da86d60c065ba565a1a19a564634` (2026-11-04, main; `SKILL.md` v1.1.0)
- Upstream layout: repository root (`swarm.py`, `prompts/`, `references/`, `fixtures/`, `swarm.example.toml`)
- Port layout: this directory (`.zcode/`)
- License: MIT — see `LICENSE` in this directory (the same MIT text as the repository root)
- Port date: 2026-11-01 (live adaptation); published 2026-11-05

The upstream and this port are the same project by the same author
(MIT, "Copyright (c) 2026 Caspar (PawCommit Studio)"), so this notice records **what the port
changes**, not a third-party attribution.

## What the port changes

The review model is unchanged: a planner writes a repo-specific threat model and search rules,
parallel map workers review the files, **every** worker report gets its own adversarial refuter, a
lead reviewer dedupes and ranks, and **every** claim gets its own independent verifier that tries to
falsify it. Nothing is reported as "verified" that an independent agent did not fail to refute.

What changed is **who runs the model** — and, this time, **where the pipeline itself lives**.

### 1. Engine-driven → workflow script

Upstream's engine (`swarm.py`) shells out to a Hermes one-shot CLI; the `.minimax/` port hands each
model call to a host skill. This port collapses the whole pipeline into **one dynamic-workflow
script** (`security-swarm.dwf.ts`): the workflow runtime (`agent()` per role, `hole()` for the human
gate, `artifact.*` for the plan/report cards and the claims board, `files.grep`/`glob` for the
deterministic selector execution) drives the stages directly. There is no Python, no CLI, no config
file and no per-role model map — the runtime owns authentication, retries, rate limits and the run
journal (which replaces the upstream digest cache for resume).

### 2. Command surface

| Upstream | Port |
| --- | --- |
| `plan` / `approve` / `run` / `verify` | one workflow run; approval is a fillable hole mid-run |
| `swarm.toml` `[scan]` (batch size, concurrency, caps) | workflow args `batchSize`, `maxBatches` |
| `swarm.toml` `[repos.*]` notes for the planner | workflow arg `notes` |
| `swarm.toml` `[models.*]` role tiering | runtime-side subagent model selection |
| `status` / `ask` | the run's live log, dashboards and completion notification |
| `deps` (OSV-Scanner) | **not ported** — code findings only, stated in the report |

### 3. Platform

- **Live workspace instead of a `git archive` snapshot**: subagents run in the workspace read-only;
  a dirty tree is flagged in the report (upstream scans committed HEAD only).
- **Embedded references**: the compact attack-class playbook and the standards catalog are inlined
  in the script, so the port is a single self-contained file instead of a skill directory tree.
- **Output surfaces**: `threat-model` and `report` artifact cards plus a per-claim verification
  board, in addition to the run's structured return value (conclusion / findings / verified /
  notCovered).

### 4. What was *not* ported

The OSV-Scanner dependency scan (out of scope for this port; the report says dependencies were not
scanned), the per-role model map and wall-clock budgets (the workflow runtime owns both), and the
`teamboard-hardened` precision fixture (subagents execute in the live workspace; the upstream
fixture harness does not apply). Selector validation, the coverage ledger, the `unvalidated` bucket,
attack chains, P0–P3 discipline, fail-open refuters, fail-closed verifiers and the report renderer
are all present in the script.

## Live install

The port is installed as a global ZCode workflow at `~/.zcode/workflows/security-swarm.dwf.ts`
(saved workflow `security-swarm`). This directory is the source of truth for that install — copy the
file over after editing it here.
