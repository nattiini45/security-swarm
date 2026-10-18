# Security Swarm

An agentic **MapReduce security review** you can run against any repository: a planner drafts a
repo-specific threat model and a set of search rules, deterministic sharding picks the files, parallel
map workers review them, **every worker report gets its own adversarial refuter**, a reducer dedupes and
ranks what survived and builds cross-file attack chains, and then **every single claim in the report gets
its own independent verifier agent that tries to falsify it against the source**.

Nothing is reported as "verified" that an independent agent did not fail to refute.

```
plan ──► approve (human) ──► shard (ripgrep) ──► map (N workers, one report each)
      ──► refute (ONE refuter per worker report) ──► reduce (dedupe, rank, chains)
      ──► verify (ONE fresh agent per claim: every finding + every chain) ──► report.md
```

## Why the refutation stages

A single-reviewer pipeline reports its own inferences as findings. Two extra stages fix the two failure
modes that matter:

- **Before the reduce**, each review worker's report is handed to its own refuter, which must name the
  concrete code that *blocks* the claimed path (the validation, the auth guard, the escaping, the line
  that does not exist). "I could not trace it" is not a refutation — when in doubt the finding stands.
  This removes false positives while keeping the evidence trail (`refute/<batch>.json`).
- **After the reduce**, each remaining claim — every finding *and* every chain, individually — goes to a
  fresh verifier process that receives only that claim and the source snapshot. It returns `confirmed`
  only if every decisive fact checks out and it quotes the proving lines; `unverified` when the code
  cannot settle it; `refuted` when a fact is wrong. One claim never shares a context with another, so a
  wrong claim cannot borrow credibility from the report around it.

Refuters fail **open** (a broken refuter must never delete findings); verifiers fail **closed** (a broken
verifier yields `unverified`, never `confirmed`).

## Requirements

- Python 3.11+ (uses `tomllib`)
- [`ripgrep`](https://github.com/BurntSushi/ripgrep) (`rg`) on `PATH`
- `git` (the scanner snapshots committed `HEAD` with `git archive`; uncommitted work is not scanned)
- A one-shot agent CLI. This repo ships an adapter for Hermes (`hermes chat --safe-mode ...`); any
  harness that can run an isolated agent and return text is a drop-in replacement — see
  [Adapting to another harness](#adapting-to-another-harness).

## Quickstart

```sh
git clone https://github.com/nattiini45/security-swarm && cd security-swarm
pip install -r requirements.txt    # (no third-party deps; kept empty on purpose)

cp swarm.example.toml swarm.toml   # then fill in the five model blocks
sh fixtures/setup.sh               # make the self-test fixture a git repo

python swarm.py repos              # list registered repos / aliases
python swarm.py plan selftest      # planner drafts threat-model.md + selectors (5-15 min)
# read threat-model.md, then:
python swarm.py approve <scan-id>
python swarm.py run <scan-id>      # map -> refute -> reduce -> verify -> report.md
```

`plan` snapshots the repo and writes `threat-model.md` with a selector table (what each search rule
matches and how many files it selects). **Nothing runs until you approve it.** Re-plan with feedback:

```sh
python swarm.py plan --scan <scan-id> --feedback "also cover the admin CLI"
```

## CLI

```
swarm.py plan <repo> [--ref REF] [--feedback TEXT] [--scan ID]   # new plan / re-plan
swarm.py approve <scan>
swarm.py run <scan> [--concurrency N] [--batch-size N] [--max-batches N] [--force]
swarm.py verify <scan>                                           # re-run only the per-claim verifiers
swarm.py status [<scan>]
swarm.py ask                                                     # daily readiness text
swarm.py repos
```

Everything is resumable and cached:

| cache | key | effect |
|---|---|---|
| `map/<batch>.json` | file exists | finished batches cost nothing on re-run |
| `refute/<batch>.json` | report content digest | unchanged worker reports are not re-refuted |
| `verify/<claim>.json` | claim content digest (own verdict excluded) | unchanged claims are not re-verified |

`swarm.py run` re-runs the reduce every time (it is the cheap part); everything around it is cached.
Delete a single cache file to force exactly that unit to run again.

## Output

`scans/<scan-id>/report.md` — coverage line, P0–P3 counts, attack chains, per-finding verification
verdicts with the quoted evidence, and a **Refuted** section listing dropped claims with the reason.
`findings.json` carries the same data structurally; `threat-model.md` is the approved plan.

## Adapting to another harness

The whole pipeline depends on exactly one function:

```python
def run_agent(role: str, prompt: str, cwd: Path, log_path: Path) -> dict:
    m = CFG["models"][role]           # model / provider / reasoning / run_budget_s
    ...
    # run an isolated one-shot with `prompt`, working directory `cwd`, print the result to a file
    return extract_json(stdout)       # {"...": ...} parsed from a <<<SWARM_JSON ... SWARM_JSON>>> block
```

Replace its body with your harness's way of running an isolated agent (a subprocess per role, an SDK
call, a container). Keep these properties and the rest of the pipeline works unchanged:

1. **Fresh context per call.** No memory, plugins, MCP servers or fallback providers. A fallback model
   silently swapping in behind your back invalidates the model pinning the config promises.
2. **cwd = the snapshot**, and the prompt forbids writes. The live repo is never the working directory.
3. **Text out, JSON in.** Each prompt ends with the `<<<SWARM_JSON ... SWARM_JSON>>>` contract; parse
   the newest block. The prompts tolerate a model that restarts mid-reply.
4. **Fail loudly.** A refused or failed call raises; the pipeline decides what is fatal (map batches are
   recorded as failed and retried; a refuter fails open; a verifier fails closed).

Per-stage output contracts live in `prompts/`: `plan.md` (threat model + selectors), `map.md`
(findings), `refute.md` (per-report verdicts), `reduce.md` (ranked findings + chains), `verify.md`
(single-claim verdict). Each prompt is a plain Markdown template — adapt them freely; keep the defensive
preamble (see below).

## Configuration

See `swarm.example.toml`. `[models.*]` pins five roles; `[scan]` sets batch size, concurrency and the
data directory; `[repos.*]` registers repos with aliases and a one-line note for the planner.

## Design notes

- **Coverage is selector recall.** A file no selector matches is never investigated. Read the selector
  table; flag selectors that return 0 matches or a regex error before approving.
- **The defensive preamble is load-bearing.** Every prompt opens with an authorized, defensive-review
  framing and forbids exploit code. Provider safety filters refuse attack-framed planning prompts; keep
  the framing in any prompt edit.
- **No sandbox reproduction.** Findings are verified by adversarial source review, not by executing an
  exploit. Treat "confirmed" as "an independent agent failed to falsify this against the code", not as
  "proven exploitable".
- **Salvage, don't discard.** Long replies sometimes contain structurally broken JSON around an intact
  `verdicts` array; `_salvage_verdicts` extracts the array rather than throwing the refutation away.
- **Model tiering** (strong planner/reducer/verifier, cheap mapper/refuter) keeps a full scan affordable;
  see the comments in `swarm.example.toml`.

## Limitations

- Static, source-level review. No running services, no dependency scanning, no secrets history search.
- One language-agnostic toolset (`read_file` / `search_files`); no language servers.
- The reducer is a single agent over all raw findings — a very large scan needs a generous
  `run_budget_s` on the reducer and verify roles.

## License

MIT — see [LICENSE](LICENSE).
