# Security Swarm — ZCode dynamic-workflow port

An agentic **MapReduce security review** you can run against the repository in your ZCode
workspace: a planner drafts a repo-specific threat model and a set of search rules, deterministic
sharding picks the files, parallel map workers review them, **every worker report gets its own
adversarial refuter**, a lead reviewer dedupes and ranks what survived and builds cross-file attack
chains, and then **every single claim in the report gets its own independent verifier agent that
tries to falsify it against the source**.

Nothing is reported as "verified" that an independent agent did not fail to refute.

```
plan ──► approve (human gate) ──► shard ──► map (N reviewers, one report each)
      ──► refute (ONE refuter per report) ──► reduce (dedupe, rank, chains)
      ──► verify (ONE fresh verifier per claim) ──► report
```

> **Adapted for ZCode.** Upstream drives the stages through a Hermes one-shot CLI, and the
> `.minimax/` port drives them through a host skill. This port is a **single dynamic-workflow
> script** (`security-swarm.dwf.ts`): the ZCode workflow runtime spawns one isolated subagent per
> role, so there are **no API keys, no tokens, no provider endpoints and no Python** — the runtime
> owns authentication. The stage graph, refutation semantics and report layout are unchanged.

## Requirements & install

- ZCode with dynamic workflows enabled. Nothing else — the playbook and the security top lists are
  embedded in the script, so the port is one self-contained file.

Install as a user-level (global) workflow:

```sh
mkdir -p ~/.zcode/workflows
cp .zcode/security-swarm.dwf.ts ~/.zcode/workflows/
```

(or place it in `<project>/.zcode/workflows/` for a single project). It then appears as the saved
workflow `security-swarm` — run it by asking ZCode to security-scan / audit the repo, or explicitly
with `workflow security-swarm` in a session over the target workspace.

## Arguments

| arg | default | meaning |
|---|---|---|
| `notes` | `""` | Owner notes for the planner: what this app is, where it runs, what matters most. |
| `batchSize` | `5` | Files per review batch (each batch gets its own reviewer agent). |
| `maxBatches` | `8` | Cap on review batches per run; a partial run is flagged in the report. |

## How the stages map

| upstream stage | in this workflow |
|---|---|
| `plan` (threat model + selectors) | one **planner** subagent; the script then runs every selector itself (files.grep/glob), validates regexes/caps and publishes the plan card with real match counts |
| `approve` (human) | a fillable **hole** — nothing runs until the owner approves the published plan; not-approved returns for a re-plan |
| `map` | one **reviewer** subagent per batch, seeded with each file's selector signals |
| `refute` | one **refuter** subagent per non-empty report, fail-open (a broken refuter keeps the findings) |
| `reduce` | one **lead reviewer** subagent over all surviving findings; on failure the report falls back to raw findings with a banner |
| `verify` | one **fresh verifier** subagent per claim (findings **and** chains), fail-closed (a broken verifier yields `unverified`, never `confirmed`) |
| `report` | a **report card** (primary artifact) + a live claims board + the run's structured result |

## Differences from the Python pipeline (by design)

- **Live workspace, not a git-archive snapshot.** Subagents review the working tree read-only; a
  dirty tree is flagged in the report instead of refusing to scan.
- **No OSV-Scanner dependency scan.** Code findings only; the report says dependencies were not
  scanned rather than implying they are clean.
- **Self-contained.** The compact attack-class playbook and the standards catalog are embedded in
  the script — no `references/` directory to carry.

Everything else — selector recall as coverage, the coverage ledger (not-reviewed files, grouped by
top directory), P0–P3 with demonstrated impact, the **Unvalidated** bucket for claims that hinge on
a fact outside the repository, chains, refuted-with-reason, fail-open refuters / fail-closed
verifiers, and the defensive preamble on every prompt — is upstream behaviour.

## Output

The run publishes two cards plus a dashboard:

- **Threat model and scan plan** — personas, scope, the selector table with match counts, standards
  in scope, and coverage at plan time. The owner reads this before approving.
- **Security review report** — confirmed / unverified / refuted split, P0–P3 counts, per-claim
  verdicts with quoted evidence, unvalidated leads, dismissed findings, and the coverage ledger.
- **Claim verification board** — one card per claim, moving to its verdict as verifiers land.

## Credits

Adapted from [nattiini45/security-swarm](https://github.com/nattiini45/security-swarm) (MIT, after
Devin's Security Swarm). Stage design, prompts and report layout are the upstream author's; the
dynamic-workflow call boundary is this port's change. See [NOTICE.md](NOTICE.md) for the change
record.

MIT — see [LICENSE](LICENSE).
