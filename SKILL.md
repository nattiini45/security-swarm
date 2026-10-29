---
name: security-swarm
description: Run an agentic MapReduce security review of a repo (plan, refute, reduce, verify).
version: 1.1.0
metadata:
  tags: [security, scan, agentic-mapreduce, swarm]
---

# Security Swarm

An agentic MapReduce security review. A planner writes a repo-specific threat model plus ripgrep
selectors; deterministic sharding picks the files; parallel map workers review them; each worker report
gets its own adversarial refuter; a reducer dedupes, ranks and builds cross-file chains; and every claim
in the final report gets its own independent verifier agent. Only claims an independent agent failed to
falsify are reported as verified.

Run it with `python swarm.py` (see `README.md` for the CLI and `swarm.example.toml` for configuration).

## Procedure

1. **Trigger**: "scan <repo>". `python swarm.py repos` resolves aliases. If the repo has no
   `[repos.<slug>]` block in `swarm.toml`, add one (root path, aliases, one-line note) before planning.
   The scanner only sees committed `HEAD` — say so if the working tree is dirty.
2. **Plan** (5-15 min, background): `swarm.py plan <repo> [--ref BRANCH]`. It snapshots the repo with
   `git archive` and writes `threat-model.md`.
3. **Show the plan**: personas, scope, selector table with match counts, files selected / in scope. Flag
   selectors with 0 matches or regex errors.
4. **Feedback loop**: `swarm.py plan --scan <id> --feedback "<words>"`, then show again.
5. **Approve only on an explicit OK**: `swarm.py approve <id>` (refuses while any selector errors).
6. **Run** (background): `swarm.py run <id>`. Stages: map (one worker per batch) → refute (one refuter
   per worker report) → reduce (single agent) → verify (one fresh agent per claim: every finding and
   every chain). Everything is cached; a re-run only redoes what changed.
   - `swarm.py verify <id>` re-runs only the per-claim verifiers (cached claims are skipped at zero cost;
     delete `verify/<claim>.json` to force one).
   - Re-running `run` after a finished map re-refutes cached reports, re-runs the reduce, and re-verifies
     only claims whose content changed.
7. **Report**: summarize `report.md` — P0-P3 counts, chains, top findings with file:line, failed batches
   as coverage gaps, plus the **Verification** line (confirmed / unverified / refuted). Claims under
   "Refuted" are dropped: never present them as live issues. `unverified` is **not** a confirmation.
   If the Verification line is missing, the scan predates the verifier stage — run `swarm.py verify <id>`
   before presenting counts. Offer fix tasks per finding; never auto-fix.

## Pitfalls

- **Coverage is selector recall.** A file no selector matches is never investigated. Read the selector
  table before approving a plan. Then read the report's **Not reviewed** / **Scope of this run** lines
  (`coverage-ledger.json`, `swarm.py coverage <scan>`) and pass them on: unreviewed files are not clean.
- **Name the not-checked top-list categories.** The report's *Security top lists* table marks OWASP
  categories nobody looked for as **not checked**; say which ones in the summary instead of calling
  the scan complete. If a relevant category is not checked, re-plan with feedback to add a selector.
- **Dependency CVEs are a separate section.** They come from OSV-Scanner, are not part of P0–P3 and
  carry no reachability check. If the report says the dependency scan did not run, say that too.
- **Unvalidated is not a severity.** Claims that hinge on a fact outside the repo carry no priority and a
  named `missing_fact`; report them as open questions, never fold them into the P0–P3 counts.
- **A failed reduce falls back to raw, undeduplicated worker findings.** The report says so in the
  Summary (`REDUCER FAILED ...`): P0-P3 counts are then not authoritative and one issue repeats once per
  batch. Re-run the reduce (map is cached) instead of presenting duplicates as separate problems.
- **"no parseable SWARM_JSON block" is usually a truncated or restarted reply, not a bad model.** The
  extractor already scans every start marker and repairs control characters; `_salvage_verdicts` also
  recovers an intact `verdicts` array from otherwise broken JSON. Re-read the log before spending a
  round.
- **Refuters fail open, verifiers fail closed.** A broken refuter keeps its findings (logged); a broken
  verifier yields `unverified`. Never upgrade an `unverified` claim to confirmed in a summary — re-run
  the verifier or read the decisive code facts yourself.
- **The defensive preamble is load-bearing.** Provider safety filters refuse attack-framed prompts;
  keep the authorized-defensive framing in every prompt edit and never ask for exploit code.
- **Findings are leads, not proven exploits.** No sandbox reproduction is run; "confirmed" means an
  independent agent could not falsify the claim against the source.
- **Model pins fail loudly.** Each role runs as an isolated one-shot with its own model/provider and no
  fallback providers; a wrong provider fails the run rather than silently degrading it. Check that the
  provider is usable (no 429) before starting, and size `run_budget_s` to the finding count for the
  reducer.
- **Self-test**: `sh fixtures/setup.sh`, then `plan selftest` → `approve` → `run`. The fixture plants
  SQLi, path traversal, SSRF, a hardcoded JWT secret fallback and an unauthenticated invite-token
  disclosure that chains into admin takeover, plus one safe decoy that must not be flagged.
