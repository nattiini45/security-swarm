---
name: security-swarm
description: Run an authorized defensive Security Swarm review with a threat-model approval gate, one refuter per worker report, and one independent verifier per finding and chain.
---

# Security Swarm for Devin

Use this port, not the Hermes CLI or ZCode TypeScript workflow. Read
`DEVIN.md` at the plugin root for configuration and limitations.

1. Invoke Devin's builtin `dynamic-workflows` skill before preparing or running
   the Python workflow. Confirm authorization and the repository/ref. Inspect its
   setup, available access, and dirty state before fan-out. This scans a committed
   snapshot only; disclose excluded local changes. Do not commit them for a scan.
2. Copy `workflow.py` beside this skill to a persistent engagement directory.
   Fill only the `CONFIG` dictionary with a Python literal containing the
   absolute `source_dir` (this plugin root), `repo_path`, cloud `repo`
   (`github.com/owner/name`), full `commit`, and absolute `output_dir`.
   Set `mode` to `plan`. Never edit the installed template. Explain the stage
   graph and approximate agent count (planner + up to N mapper/refuter pairs +
   reducer + one verifier per claim) before launching.
3. Call `run_workflow` with that script's absolute `script_path`. Attach the
   resulting threat model and selector counts to the user. Surface zero-match
   selectors and regex errors. Ask for explicit approval of the plan; workflow
   launch permission is NOT approval of a threat model not yet written.
4. Only after the user approves, prepare a copy with `mode="run"` and
   `approved_plan_sha256` equal to the digest printed by planning. Keep every
   other input unchanged. Run it with `run_workflow`. Re-plans require new approval.
5. Let completion notifications drive follow-up; do not poll. Resume an interrupted
   run using its `run_id` and the identical script. The runtime journals successful
   calls; local files are artifacts, not a substitute for the journal.
6. Deliver `report.md`, the coverage ledger and failures. Explain confirmed versus
   unverified versus refuted; never count refuted claims as live findings. Surface
   unreviewed files, failed batches, missing top-list categories, unvalidated leads,
   and the omitted dependency scan. Offer remediation; never auto-fix.

The host must not silently switch to shared-VM agents. This port uses separate
VMs and pinned source. Agent read-only instructions are not a filesystem sandbox,
and Devin does not promise per-role provider pins or plugin-free agent contexts.
