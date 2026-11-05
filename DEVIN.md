# Devin port

The root is a Devin-loadable plugin (`.devin-plugin/plugin.json`); the skill and
native Python workflow are in `skills/security-swarm/`. Existing Hermes, MiniMax
and ZCode ports are unchanged. Install the **repository root**, not just SKILL.md,
so the engine, prompts, standards, MIT notices and vendored checklists travel with it.

Ask Devin to install the repository (or the PR branch) as a **personal** plugin via
`manage_plugin(kind="plugin", operation="install", scope="personal", plugin_url=...)`.
Use account scope only when the user explicitly wants organization-wide access.
Installation is approval-gated. A local checkout can be installed with `local_path`.
No API keys or external agent CLI are needed; runtime authentication is used.

## Running

Invoke the skill in a session with the target repository available. The host copies
the template, fills the `CONFIG` literal, and passes that file to `run_workflow`.
Python 3.11+, git and ripgrep must be available on the controller. Agents use separate
VMs and `git show` against the exact source SHA; uncommitted changes are excluded.
Each invocation first dispatches a read-only source preflight through the agent
repository integration. It must return the exact commit and root tree IDs before
the planner or reviewers run. Local-only/inaccessible commits fail explicitly;
publish them through your normal authorized Git workflow first, never as a scan
side effect. The extracted controller snapshot is digest-bound to approval and
checked again before reuse; altered snapshots require a fresh engagement directory.

```python
CONFIG = {
    "source_dir": "/absolute/path/to/installed/plugin",
    "repo_path": "/absolute/path/to/target-checkout",
    "repo": "github.com/owner/repository",
    "commit": "FULL_COMMIT_SHA",
    "output_dir": "/absolute/path/to/existing/engagement-directory",
    "mode": "plan",
    "notes": "Owner context and scope",
    "batch_size": 5,
    "max_batches": 8,
    "concurrency": 3,
}
```

Planning persists `scan.json`, `plan.json`, `threat-model.md` and a digest. Show the
plan to the user. After explicit approval, set `mode="run"` and
`approved_plan_sha256` to that digest; do not change other inputs. A changed plan,
SHA, prompts, references or batching invalidates approval. Replanning accepts
`feedback`; it always returns to the user gate. Never treat permission to launch a
workflow as permission to approve its as-yet unseen plan.

Map → per-report refute pipelines run independently, followed by a reduce barrier
and one verifier for **every finding and chain**. Refuters fail open; verifiers fail
closed, including malformed verdicts or confirmations without quoted evidence.
Reducer failures retain raw findings with a warning. Failed batches remain explicit
coverage gaps. Use the same script and `run_id` for runtime journal replay/resume.

## Deliberate differences

- Uses the existing deterministic selectors, snapshotter, coverage, standards,
  prompts and report renderer. `SWARM_CONFIG` optionally selects the engine config;
  default CLI behavior still reads root `swarm.toml`.
- Human gating is **two workflow invocations**, because Devin has no ZCode `hole()`.
- No ZCode dashboards: logs plus durable files are the interface.
- No OSV dependency scan, live workspace scanning, per-role provider pins or
  promise of plugin-free/sandboxed child agents. Read-only is an instruction, not
  OS-enforced isolation. Source-only confirmation is not sandbox reproduction.
- No live cloud scan is part of the offline test suite. Run
  `python tests/devin_smoke.py` and `python tests/smoke.py` with Python 3.11+.

For development checks, install `requirements-dev.txt` in an isolated venv, then
run `ruff check skills/security-swarm/workflow.py tests/devin_smoke.py` and
`mypy --check-untyped-defs skills/security-swarm/workflow.py`. The runtime names
are annotated without assigning or replacing Devin's injected functions.
