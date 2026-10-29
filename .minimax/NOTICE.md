# NOTICE — `.minimax/` (MiniMax Code port)

This directory holds the **MiniMax Code port** of Security Swarm.

- Upstream: `nattiini45/security-swarm`
- Pinned commit: `1444ab57ccf5fefbe55a713457f05e5ff9963b69` (2026-10-18, the repository's only commit)
- Upstream layout: repository root (`swarm.py`, `prompts/`, `fixtures/`, `swarm.example.toml`)
- Port layout: this directory (`.minimax/`)
- License: MIT — see `LICENSE` in this directory (the same MIT text; the copyright line names the public handle)
- Port date: 2026-10-19 … 2026-10-22; synced 2026-10-29 with the upstream attack-playbook / coverage-ledger / unvalidated merge

The upstream and this port are the same project by the same author
(MIT, "Copyright (c) 2026 Caspar (PawCommit Studio)"), so this notice records **what the port
changes**, not a third-party attribution.

## What the port changes

The review model is unchanged: a planner writes a repo-specific threat model and search rules,
parallel map workers review the files, **every** worker report gets its own adversarial refuter, a
reducer dedupes and ranks, and **every** claim gets its own independent verifier that tries to
falsify it. Nothing is reported as "verified" that an independent agent did not fail to refute.

What changed is **who runs the model**.

### 1. Engine-driven → host-driven

Upstream's engine is the orchestrator: `swarm.py` shells out to a Hermes one-shot CLI and drives
the model itself. The port makes the engine purely **deterministic** — snapshot, shard, cache,
digest, rank, render — and the **host** (MiniMax Code) spawns every model call as a child agent
with the `task` tool.

Consequence: the port has **no API keys, no tokens, no provider endpoints**. The runtime owns
authentication. That is the studio rule — a skill never wires a direct model-API call.

### 2. Command surface

| Upstream | Port |
| --- | --- |
| `plan`, `approve`, `run`, `verify` (engine-driven, one-shot) | `plan-begin` / `plan-ingest`, `map-begin` / `map-ingest`, `refute-begin` / `refute-ingest`, `reduce-begin` / `reduce-ingest`, `verify-begin` / `verify-ingest`, `report` |

Each stage is now a pair: `<stage>-begin` writes a prompt file and prints a JSON manifest; the host
runs the child agents and writes each reply into the task's `out` file; `<stage>-ingest` parses
them and advances the scan. Everything is cached and resumable.

Added commands that upstream does not have: `bootstrap`, `report`, `roles` (report the configured agent
+ model per role) and `fixture-init` (materialize the test fixture). `status`, `ask` and `repos` are carried
over from upstream.

### 3. Configuration

| Upstream | Port |
| --- | --- |
| `swarm.example.toml`, copied by the operator | `swarm.toml`, shipped in this directory as the working configuration |
| `[models.*]` — a model id per role | `[roles.*]` — an **agent** and a model per role |
| `run_budget_s` — an engine-side wall-clock cap | Not ported: the host-driven design replaces it with the child agent's own time and context budget, which the host enforces |

The port's `swarm.toml` also pins the data directory to `~/.minimax/security-swarm` and leaves `rg_path`
empty, so the engine falls back to the ripgrep it bootstrapped into the data directory, then to `PATH`.

### 4. Platform

- **Windows / PowerShell**: `fixtures/setup.ps1` replaces `fixtures/setup.sh`. The engine
  bootstraps ripgrep into the data directory (`python swarm.py bootstrap`) instead of expecting a
  system-wide install.
- **Tool names in the prompts**: the prompts address MiniMax Code tools (`read`, `glob`, `grep`)
  instead of the upstream host's tool names.
- The port ships the **`teamboard-hardened`** fixture, which upstream does not have — the hardened
  twin of the vulnerable self-test fixture (every finding fixed), shipped as a precision test: the scanner must not flag it.

### 5. What was *not* ported

`run_budget_s` is the only upstream concept deliberately left behind, for the reason in the table
above. Every other upstream behaviour was checked feature by feature against the port: salvage,
`SWARM_JSON` output, confirmed / unverified / refuted verdicts, finding chains, coverage accounting,
the digest cache, the P0–P3 severities, the git-archive snapshot, the dirty-tree warning,
`ask` / `status` / `approve`, and the report renderer are all present.

### 6. Synced upstream changes (2026-10-29)

The upstream merge of three ideas from cloudflare/security-audit-skill is carried over unchanged in
behaviour: attack-class playbooks injected into every map prompt (`references/attack-classes/`,
vendored MIT text with `LICENSE-cloudflare`), the coverage ledger (`coverage-ledger.json`, written by
`map-begin`, re-runnable with `coverage <scan>`, rendered as **Not reviewed** / **Scope of this run**
in the report), and the `unvalidated` reducer bucket (no priority, named `missing_fact`, never sent to
a verifier). The only port-side difference: `coverage` prints a JSON manifest like every other port
command.

Also synced the same day: the security top-lists matrix (`references/standards/standards.json`,
`standards` + `owasp` tags in the plan and reduce prompts), the OSV-Scanner dependency scan
(`deps <scan>`, also run by `map-begin`), and the logging / alerting / error-handling checklist
(`references/checklists/`).

## Live install

The port is installed as a global skill at `~/.minimax/skills/security-swarm/` and appears in the
skill catalog as `security-swarm`. This directory is the source of truth for that install.
