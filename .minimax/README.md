# Security Swarm

An agentic **MapReduce security review** you can run against any repository: a planner drafts a
repo-specific threat model and a set of search rules, deterministic sharding picks the files,
parallel map workers review them, **every worker report gets its own adversarial refuter**, a
reducer dedupes and ranks what survived and builds cross-file attack chains, and then **every
single claim in the report gets its own independent verifier agent that tries to falsify it
against the source**.

Nothing is reported as "verified" that an independent agent did not fail to refute.

```
plan ──► approve (human) ──► shard (ripgrep) ──► map (N workers, one report each)
      ──► refute (ONE refuter per worker report) ──► reduce (dedupe, rank, chains)
      ──► verify (ONE fresh agent per claim: every finding + every chain) ──► report.md
```

> **Adapted for MiniMax Code.** Upstream drives the stages through a Hermes one-shot CLI. This
> fork makes the pipeline a **native Mavis skill**: the host agent spawns one isolated child
> agent per role with the `task` tool, so there are **no API keys, no tokens and no provider
> endpoints** — the runtime owns authentication. The stage graph, caching, digests, refutation
> semantics and report layout are unchanged.

## Why the refutation stages

A single-reviewer pipeline reports its own inferences as findings. Two extra stages fix the two
failure modes that matter:

- **Before the reduce**, each review worker's report is handed to its own refuter, which must name
  the concrete code that *blocks* the claimed path (the validation, the auth guard, the escaping, the
  line that does not exist). "I could not trace it" is not a refutation — when in doubt the finding
  stands. This removes false positives while keeping the evidence trail (`refute/<batch>.json`).
- **After the reduce**, each remaining claim — every finding *and* every chain, individually — goes to a
  fresh verifier process that receives only that claim and the source snapshot. It returns `confirmed`
  only if every decisive fact checks out and it quotes the proving lines; `unverified` when the code
  cannot settle it; `refuted` when a fact is wrong. One claim never shares a context with another, so a
  wrong claim cannot borrow credibility from the report around it.

Refuters fail **open** (a broken refuter must never delete findings); verifiers fail **closed** (a broken
verifier yields `unverified`, never `confirmed`).

## Requirements

- Python 3.11+ (uses `tomllib`) — no third-party packages
- `git` (the scanner snapshots committed `HEAD` with `git archive`; uncommitted work is not scanned)
- `ripgrep` — fetched automatically by `python swarm.py bootstrap` into the data dir
- MiniMax Code with the `security-swarm` skill installed

## Layout

```
<skill_dir>/
├── SKILL.md              the procedure the host agent follows
├── swarm.py              deterministic engine: snapshot, shard, cache, digest, rank, render
├── swarm.toml            repos, roles (agent + model per role), scan settings
├── prompts/              plan / map / refute / reduce / verify templates
├── references/attack-classes/  vendored attack-class playbooks (Cloudflare, MIT)
└── fixtures/teamboard/   self-test repo with five planted bugs
```

Runtime data (scans, caches, prompts, ripgrep) lives in `~/.minimax/security-swarm/`.

## How the host drives it

The engine never calls a model. Every stage is two commands:

| stage | begin | ingest |
|---|---|---|
| plan | writes `tasks/plan.md` | parses the reply → `plan.json` + `threat-model.md` |
| map | writes `tasks/map-<batch>.md` (with its attack playbook) + `coverage-ledger.json` | caches `map/<batch>.json` |
| refute | writes `tasks/refute-<batch>.md` | caches `refute/<batch>.json`, drops refuted findings |
| reduce | writes `tasks/reduce.md` | writes `findings.json` |
| verify | writes `tasks/verify-<claim>.md` | caches `verify/<claim>.json`, writes `report.md` |

The host spawns one child agent per task with the `task` tool, then writes each reply verbatim
into the task's `out` file. See `SKILL.md` for the full contract.

## CLI

```
swarm.py bootstrap [--force] [--from PATH]  # fetch ripgrep (pinned, checksum-verified)
swarm.py fixture-init                        # make the self-test fixture a git repo with a commit
swarm.py repos                               # registered repos / aliases
swarm.py roles                               # role -> {agent, model} for the host
swarm.py plan-begin <repo> [--ref REF] [--scan ID] [--feedback TEXT]
swarm.py plan-ingest <scan>
swarm.py approve <scan>
swarm.py map-begin <scan> [--batch-size N] [--max-batches N]
swarm.py map-ingest <scan>
swarm.py refute-begin <scan>
swarm.py refute-ingest <scan>
swarm.py reduce-begin <scan>
swarm.py reduce-ingest <scan>
swarm.py verify-begin <scan>
swarm.py verify-ingest <scan>
swarm.py report <scan>
swarm.py deps <scan>                         # dependency scan (OSV-Scanner) only
swarm.py coverage <scan>                     # coverage ledger: unreviewed / scoped-out files
swarm.py status [<scan>]
swarm.py ask
```

Every command prints a JSON manifest so the host agent can act on it without parsing prose.

Everything is resumable and cached:

| cache | key | effect |
|---|---|---|
| `map/<batch>.json` | file exists | finished batches cost nothing on re-run |
| `refute/<batch>.json` | report content digest | unchanged worker reports are not re-refuted |
| `verify/<claim>.json` | claim content digest (own verdict excluded) | unchanged claims are not re-verified |

Delete a single cache file to force exactly that unit to run again.

## Configuration

`swarm.toml` has three blocks:

- `[scan]` — `batch_size`, `concurrency` (max parallel child agents), `max_signals_per_file`,
  `data_dir`, `rg_path`, `playbook_max_companions`, `playbook_max_chars`.
- `[roles.<role>]` — the `agent` type and `model` the host spawns for that role. Every role
  currently runs on `minimax/MiniMax-M3.1-Flash`; promote a single role by changing one line.
- `[repos.<slug>]` — `path`, `aliases`, a one-line `notes` for the planner, `ask`.

Tiering that works well in practice: a strong model for planner/reducer/verifier, a cheap fast
model for mapper/refute. On a single model, raise `[scan].concurrency` only if the provider
tolerates it.

## Output

`scans/<scan-id>/report.md` — coverage line, P0–P3 counts, attack chains, per-finding verification
verdicts with the quoted evidence, an **Unvalidated** section (leads that hinge on an outside fact),
and a **Refuted** section listing dropped claims with the reason. `coverage-ledger.json` lists what
was not reviewed. `findings.json` carries the same data structurally; `threat-model.md` is the approved plan.

## Design notes

- **Coverage is selector recall — and the report says so.** A file no selector matches is never
  investigated. Every run writes `coverage-ledger.json` (in-scope files, selector-matched files,
  files batched by this run, and every in-scope file **no** selector matched, grouped by directory),
  and the report prints a **Not reviewed** line plus a **Scope of this run** line for partial runs
  (`--max-batches`). Unreviewed is not clean. Re-run the ledger any time with `swarm.py coverage <scan>`.
- **Attack-class playbooks.** Each map batch gets the core attack-class checklist plus up to
  `scan.playbook_max_companions` domain checklists (AI/LLM, web auth, client-side, supply chain, cloud,
  data isolation, resource exhaustion, protocols, desktop/mobile IPC, memory safety), picked
  deterministically from the batch's own paths. Selectors say *where* to look; the playbook says *what
  to look for*. Vendored from [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)
  (MIT) — see `references/attack-classes/README.md` and `LICENSE-cloudflare`.
- **Security top lists.** The planner picks which lists apply (OWASP Top 10:2025 always; API Security
  Top 10:2023, LLM Top 10:2025 and MASVS v2 when the codebase has an API, model calls or a mobile app)
  and tags every selector with the categories it looks for; the reducer tags every finding. The report
  then lists every category as *finding*, *lead only*, *checked, nothing found* or **not checked**.
  The lists live in `references/standards/standards.json` — update that file when OWASP publishes a
  new edition.
- **Dependency scan.** [OSV-Scanner](https://google.github.io/osv-scanner/) v2 runs over the snapshot's
  lockfiles and manifests before the map stage (no model call) and the report gets a *Dependency
  vulnerabilities* section with severity, fixed version and CVE ids. These are not counted in P0–P3:
  reachability of the vulnerable function is not checked. Package names and versions are sent to the
  osv.dev API; set `scan.deps_scan = false` to skip it. If the scanner is missing the report says so
  instead of implying the dependencies are clean. Re-run alone with `swarm.py deps <scan>`.
- **Logging, alerting and error handling.** `references/checklists/LOGGING-ALERTING-AND-ERROR-HANDLING.md`
  (OWASP A09 + A10: missing security events, secrets in logs, log injection, failing open,
  half-finished transactions, disclosing errors) joins the playbook for batches that touch logging,
  audit, error handlers or middleware.
- **Severity requires demonstrated impact.** Mappers and the reducer must name the concrete damage.
  A claim whose exploitability turns on a fact outside the repository (hosted DB grants, deployed
  limits, third-party behaviour) goes to an **Unvalidated** section with no priority and a named
  `missing_fact`; it is excluded from the P0–P3 counts and from verification, because a source-only
  verifier could only guess.
- **The defensive preamble is load-bearing.** Every prompt opens with an authorized, defensive-review
  framing and forbids exploit code. Provider safety filters refuse attack-framed planning prompts; keep
  the framing in any prompt edit.
- **No sandbox reproduction.** Findings are verified by adversarial source review, not by executing an
  exploit. Treat "confirmed" as "an independent agent failed to falsify this against the code", not as
  "proven exploitable".
- **Salvage, don't discard.** Long replies sometimes contain structurally broken JSON around an intact
  `verdicts` array; the extractor salvages the array rather than throwing the refutation away.
- **Prompts are per-stage templates** in `prompts/`. Adapt them freely; keep the defensive preamble
  and the `<<<SWARM_JSON ... SWARM_JSON>>>` contract.

## Limitations

- Static, source-level review. No running services, no secrets history search. Dependency CVEs come
  from OSV-Scanner (needs the binary and network access to osv.dev).
- One language-agnostic toolset (file read / search); no language servers.
- The reducer is a single agent over all raw findings — a very large scan needs a generous context
  budget and enough child-agent time.

## Credits

Adapted from [nattiini45/security-swarm](https://github.com/nattiini45/security-swarm) (MIT,
after Devin's Security Swarm). Original stage design, prompts and report layout are the upstream
author's; the host-driven call boundary is this fork's change.

MIT — see [LICENSE](LICENSE).
