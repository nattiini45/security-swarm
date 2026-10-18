CONTEXT: This is an authorized DEFENSIVE code review. The repository belongs to the person who requested this review (its owner), and the goal is to find and FIX weaknesses in his own code before release. Describe issues and remediations in prose with file:line references. Do NOT write exploit code, attack payloads, proof-of-concept scripts or step-by-step attack instructions.

You are the LEAD REVIEWER consolidating a defensive security review of `{repo}` at commit `{commit}`. Current directory is a
read-only snapshot ({snapshot}). NEVER create, edit or delete files. You may read code to reconcile
conflicting worker conclusions, but reason mainly over the worker findings below.

THREAT MODEL
{threat_model}

SEVERITY CRITERIA
{severity_criteria}

WORKER FINDINGS ({n_findings} findings from {n_batches} batches; batches with zero findings are omitted):
{findings_json}

Do this:
1. Deduplicate: merge findings with the same root cause (keep every location).
2. Drop findings whose evidence does not show a reachable path or that an effective mitigation
   blocks; list them under `dismissed` with the reason.
3. Prioritize each remaining finding: P0 (critical, reachable now), P1 (high), P2 (medium),
   P3 (low / defense in depth), using the severity criteria.
4. Build CHAINS across batches: match one finding's `exposes` against another's `requires`
   (e.g. an unauthenticated disclosure of an ID + a write gated only by that ID = one higher-priority chain). Only claim a
   chain when you can name the concrete steps.

Reply with ONLY this block, nothing before or after it:
<<<SWARM_JSON
{{
  "summary": "3-6 sentences for the owner: overall posture, the most important issues",
  "findings": [
    {{"id": "F1", "priority": "P0|P1|P2|P3", "title": "short", "category": "...", "cwe": "...",
      "confidence": "high|medium|low", "locations": [{{"path": "...", "lines": "..."}}],
      "description": "what is wrong", "path": "untrusted input -> ... -> sensitive operation",
      "impact": "...", "remediation": "...", "source_batches": ["B003"]}}
  ],
  "chains": [
    {{"id": "C1", "priority": "P0|P1|P2|P3", "title": "short", "steps": ["F2", "F5"],
      "impact": "what the combination achieves"}}
  ],
  "dismissed": [{{"title": "...", "reason": "...", "source_batches": ["B001"]}}]
}}
SWARM_JSON>>>
