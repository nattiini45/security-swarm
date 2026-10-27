---
name: security-swarm
description: Run an agentic MapReduce security review of a repository — a planner drafts a repo-specific threat model and search rules, parallel map workers review the files, every worker report gets its own adversarial refuter, a reducer dedupes and ranks, and every single claim gets its own independent verifier agent that tries to falsify it. Use when the user asks to security-scan, audit, or hunt for vulnerabilities in a codebase, or asks for a "security swarm" / "security review" run.
descriptions:
  zh-Hans: 对代码仓库执行 MapReduce 式安全审查：规划器生成威胁模型与检索规则，并行映射器逐文件审查，每份报告配一个对抗性反驳器，归约器去重排序，每条结论再由独立验证代理尝试证伪。当用户要求安全扫描、漏洞审计或代码安全审查时使用。
---

# Security Swarm

An agentic MapReduce security review. Nothing is reported as "verified" that an independent agent
did not fail to refute.

```
plan ──► approve (human) ──► shard (ripgrep) ──► map (N workers, one report each)
      ──► refute (ONE refuter per worker report) ──► reduce (dedupe, rank, chains)
      ──► verify (ONE fresh agent per claim: every finding + every chain) ──► report.md
```

**You are the host.** The engine (`swarm.py`) does only deterministic work — snapshot, shard,
cache, digest, rank, render. Every model call is a child agent that **you** spawn with the `task`
tool. There are no API keys, no tokens, no provider endpoints: the runtime owns authentication.

Each stage is a pair of commands: `<stage>-begin` writes a prompt file and prints a JSON
manifest; you run the child agents and write each reply into the task's `out` file; `<stage>-ingest`
parses them and advances the scan. Everything is cached and resumable.

- Engine: `<skill_dir>/swarm.py` (run with `python <skill_dir>/swarm.py ...`)
- Config: `<skill_dir>/swarm.toml` — `[repos.*]` registries, `[roles.*]` agent+model per role
- Scans, caches, tools: `~/.minimax/security-swarm/`

## One-time setup

```powershell
python <skill_dir>\swarm.py bootstrap    # fetch ripgrep into the data dir (pinned + checksummed)
python <skill_dir>\swarm.py fixture-init # only for the self-test fixture (makes it a git repo)
```

`bootstrap` needs network once. If it fails, `rg` on `PATH` is used instead.
`fixture-init` is the Python path because Windows blocks `.ps1` execution by default;
`fixtures/setup.ps1` does the same thing if script execution is allowed.

## The child-agent contract

For every task in a manifest you get `id`, `prompt` (a file path) and `out` (a file path):

1. Spawn one child per task with the `task` tool:
   - `agent_name` and `model` come from `[roles.<role>]` in `swarm.toml`.
   - `prompt`: `Read the file <prompt path> and execute its instructions exactly.`
   - `run_in_background: true`, and launch a stage's tasks in ONE turn so they run in parallel.
2. The child writes its own result: the prompt file ends with an `OUTPUT` section naming the exact
   `out` path to write, and the child is told to write that file and nothing else. **Verify it
   happened** — the child's reply is only a one-line confirmation, so check that `<out>` exists
   before ingesting.
3. Run the matching `<stage>-ingest`.

If an `out` file is missing after a child reported success, re-run that single child — its work is
not cached until ingest, so nothing is lost.

Do not paste the prompt text into the child yourself — let the child read the file, so its context
stays clean. Do not edit a prompt file; it is generated per stage. Do not write the `out` file
yourself unless the child failed to; the engine extracts the `<<<SWARM_JSON ... SWARM_JSON>>>` block
from whatever it finds there, so a child's narration around the block is harmless.

Concurrency: keep at most `[scan].concurrency` children running at once — but treat the limit the
`task` tool reports (`child_task_limit`) as authoritative, since the runtime's cap can be lower than
the config. If `task` reports `SUBAGENT_CONCURRENCY_LIMIT`, wait for a slot instead of retrying.

A stage's tasks are independent, so run them in waves: launch a wave in one turn, wait for it, then
launch the next. A full scan of a small repo is roughly one wave per stage.

## Procedure

1. **Resolve the repo.** `python <skill_dir>\swarm.py repos` lists registered repos and aliases.
   If the target has no `[repos.<slug>]` block, add one (`path`, `aliases`, a one-line `notes` for
   the planner) before planning. The scanner only sees committed `HEAD` — tell the user if the
   working tree is dirty.

2. **Plan.** `python <skill_dir>\swarm.py plan-begin <repo> [--ref BRANCH]`. It snapshots the repo
   with `git archive` and writes `tasks/plan.md`. Run the planner child, write its reply to the
   `out` file, then `plan-ingest <scan>`. Re-plan with feedback:
   `plan-begin --scan <id> --feedback "<words>"`.

3. **Show the plan and get an explicit OK.** Render the threat model: personas, scope, the
   selector table with match counts, files selected / in scope. Flag any selector with 0 matches
   or a regex error. **Nothing runs until the user approves.** Then `approve <scan>` (it refuses
   while a selector has an error).

4. **Map.** `map-begin <scan>` shards the snapshot and writes one `tasks/map-<batch>.md` per
   batch. Run one mapper child per batch, write each reply to its `out` file, then
   `map-ingest <scan>`.

5. **Refute.** `refute-begin <scan>` writes one `tasks/refute-<batch>.md` per worker report that
   has findings. Run one refuter child per report, write the replies, then `refute-ingest <scan>`.
   Refuters fail **open** — a broken refuter keeps its findings.

6. **Reduce.** `reduce-begin <scan>` writes `tasks/reduce.md`; one reducer child; then
   `reduce-ingest <scan>`.

7. **Verify.** `verify-begin <scan>` writes one `tasks/verify-<claim>.md` per claim — every
   finding and every chain, individually. Run one fresh verifier child per claim, write the
   replies, then `verify-ingest <scan>`. Verifiers fail **closed**: a broken verifier yields
   `unverified`, never `confirmed`.
   - `verify-begin` / `verify-ingest` can be re-run to redo only missing or changed claims.

8. **Report.** Summarize `report.md`: coverage line, P0–P3 counts, chains, top findings with
   file:line, failed batches as coverage gaps, and the **Verification** line
   (confirmed / unverified / refuted). Offer fix tasks per finding; never auto-fix.

## Pitfalls

- **Coverage is selector recall.** A file no selector matches is never investigated. Read the
  selector table before approving a plan.
- **A failed reduce falls back to raw, undeduplicated worker findings.** The report says
  `REDUCER FAILED` in the Summary: P0–P3 counts are then not authoritative and one issue repeats
  once per batch. Re-run the reduce (map is cached) instead of presenting duplicates as separate
  problems.
- **"no parseable SWARM_JSON block" is usually a truncated or restarted reply, not a bad model.**
  The extractor scans every start marker and repairs control characters, and a malformed reply
  with an intact `verdicts` array is salvaged. Re-read the child's reply before spending a round.
- **Refuters fail open, verifiers fail closed.** Never upgrade an `unverified` claim to confirmed
  in a summary — re-run the verifier or read the decisive code facts yourself.
- **The defensive preamble is load-bearing.** Provider safety filters refuse attack-framed
  prompts; never edit the prompts to drop the authorized-defensive framing, and never ask a
  child for exploit code.
- **Findings are leads, not proven exploits.** No sandbox reproduction is run; "confirmed" means an
  independent agent could not falsify the claim against the source.
- **The engine needs `swarm.toml` next to `swarm.py`.** A missing or malformed config fails at
  import with a clear error.
- **Self-test**: `python <skill_dir>\swarm.py fixture-init`, then
  `plan-begin selftest` → `approve` → map → refute → reduce → verify. The fixture plants SQLi,
  path traversal, SSRF, a hardcoded JWT secret fallback and an unauthenticated invite-token
  disclosure that chains into admin takeover, plus one safe decoy that must not be flagged.
- **Precision test**: `plan-begin hardened` → `approve` → map → refute → reduce → verify. The
  `hardened` repo is the fixed twin of the self-test fixture: every self-test finding is fixed
  there, so a clean run must report **no findings**. Anything it reports is a false positive
  unless it is a genuine residual risk — the hardened build's README lists the ones that are
  deliberately left open (mailbox verification, DNS-rebinding TOCTOU, in-process rate limits)
  so a run can tell "known and accepted" from "newly introduced".
  The two assets are complementary: `selftest` measures **recall** (does it find the planted
  bugs?), `hardened` measures **precision** (does it stay quiet on correct code?). A scanner
  that only ever sees the vulnerable fixture cannot tell the difference.
