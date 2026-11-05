/* zcode-workflow
description: "Agentic MapReduce security review of the current workspace: a
  planner drafts a threat model and file selectors, the owner approves the plan
  at a gate, parallel reviewers investigate the selected files, each report gets
  an adversarial refuter, a lead reviewer dedupes/ranks/chains findings, and one
  fresh verifier per claim tries to falsify it against the source. Only claims
  an independent verifier failed to falsify are reported as confirmed."
whenToUse: 'Run a defensive, source-level security review of the repository in
  the current workspace — when the user asks to security-scan or audit a repo
  ("scan this repo", "security review"). Code findings only: no dependency CVE
  scanning (OSV-Scanner) and no dynamic testing.'
args:
  batchSize:
    type: number
    description: Files per review batch (each batch gets its own reviewer agent).
    default: 5
  maxBatches:
    type: number
    description: Cap on review batches per run; a partial run is flagged in the report.
    default: 8
  notes:
    type: string
    description: "Owner notes for the planner: what this app is, where it runs, what
      matters most."
    default: ""
*/
// Security Swarm — ZCode dynamic-workflow adaptation of the security-swarm skill
// (https://github.com/nattiini45/security-swarm, SKILL.md v1.1.0, adapted 2026-11).
//
// Agentic MapReduce security review of the current workspace:
//   plan (threat model + ripgrep selectors) -> human approval gate -> deterministic sharding
//   -> map (one reviewer per batch) -> refute (one adversarial refuter per report, fail-open)
//   -> reduce (dedupe, rank P0-P3, cross-file chains) -> verify (one fresh verifier per claim,
//   fail-closed) -> report. Only claims an independent verifier failed to falsify are
//   reported as confirmed.
//
// Differences from the Python pipeline, by design:
// - Subagents run in the live workspace (read-only by instruction), not a git-archive
//   snapshot; a dirty working tree is flagged in the report instead.
// - Dependency CVEs (OSV-Scanner) are out of scope for this workflow.
// - The compact attack-class playbook and the standards catalog are embedded, so the
//   workflow is self-contained at user (global) level.

interface Selector {
  /** Kebab-case id used in batch listings and the report. */
  id: string;
  /** One of: input, authz, sink, secrets, config, other. */
  category: string;
  /** What this selector catches and why it matters. */
  description: string;
  /** Regex run over file contents (JavaScript regex flavor: lookaround and backreferences allowed, but NO inline (?i) — use character classes like [Ss]ecret for case folding), or null to select every file matching `globs` (glob-only selectors must list globs). */
  pattern: string | null;
  /** Ripgrep -g style globs narrowing which files the pattern applies to; empty array = all files. */
  globs: string[];
  /** Standards categories this selector looks for, e.g. ["A01:2025", "API1:2023"]. A category no selector tags is reported as not checked. */
  owasp: string[];
}

interface Plan {
  /** Markdown threat model: misuse personas, sensitive assets, trust boundaries, untrusted inputs, explicit out-of-scope areas. */
  threat_model: string;
  /** How a reviewer should trace and judge a candidate in THIS codebase. */
  investigation_guidance: string;
  /** What counts as critical/high/medium/low for THIS app. */
  severity_criteria: string;
  /** 10-30 selectors. Selector recall is what makes the scan complete: a file no selector matches is never investigated. Prefer broad-but-meaningful patterns over clever narrow ones. */
  selectors: Selector[];
  /** Which security top lists apply: "top10" is always included; add "api" (serves an HTTP/RPC API), "llm" (calls models / runs agents), "masvs" (ships a mobile app) when they apply. */
  standards: string[];
  /** Extra exclude globs for generated/vendored/irrelevant code. Built-in excludes already cover node_modules, .git, dist/build, vendor, lockfiles, minified files, binaries and .zcode. */
  exclude_globs: string[];
}

interface Location {
  /** Workspace-relative file path. */
  path: string;
  /** Line range, e.g. "40-58". */
  lines: string;
}

interface WorkerFinding {
  /** Short title. */
  title: string;
  /** e.g. sqli, xss, ssrf, path-traversal, authz-bypass, idor, rce, secrets, csrf, dos, crypto, config, other. */
  category: string;
  /** CWE id if known, e.g. "CWE-89". */
  cwe: string;
  severity: "critical" | "high" | "medium" | "low";
  confidence: "high" | "medium" | "low";
  /** Every location the problem touches. */
  locations: Location[];
  /** Where untrusted input enters. */
  entry_point: string;
  /** Step-by-step path from input to sink with file:line references. */
  data_flow: string;
  /** What you checked (validation, auth, escaping) and why it does not block the path. */
  mitigations_checked: string;
  /** Concrete, owner-observable security impact. */
  impact: string;
  /** What a misuser would need (auth level, prior knowledge). */
  preconditions: string;
  /** Data/capabilities this discloses that other code relies on being secret, or empty. */
  exposes: string;
  /** What a misuser must already have, that other code might disclose, or empty. */
  requires: string;
  /** Smallest safe fix. */
  remediation: string;
  /** When the claim depends on a fact outside this repository: the exact missing fact. Empty otherwise. */
  needs_outside_fact: string;
}

interface WorkerReport {
  /** Every file of the batch you actually read. */
  files_reviewed: string[];
  /** Findings with a traced, reachable path only. Empty list if nothing real was found. */
  findings: WorkerFinding[];
  /** Leads you dismissed and why, one line each. */
  notes: string;
}

interface RefuterVerdict {
  /** 1-based position of the finding in the report you received, in order. */
  finding: number;
  verdict: "stands" | "refuted";
  /** One line; for refuted: the exact mitigation and why it blocks the path. */
  reason: string;
  /** path:line you checked, with the decisive line quoted. */
  evidence: string;
}

interface RefuterReport {
  /** Exactly one verdict per finding. */
  verdicts: RefuterVerdict[];
  /** Optional single-line note. */
  notes: string;
}

interface ReducedFinding {
  /** Stable id, e.g. "F1". */
  id: string;
  priority: "P0" | "P1" | "P2" | "P3";
  title: string;
  category: string;
  cwe: string;
  /** Catalog ids this finding falls under (e.g. ["A01:2025", "API1:2023"]). */
  owasp: string[];
  confidence: "high" | "medium" | "low";
  locations: Location[];
  /** What is wrong. */
  description: string;
  /** Untrusted input -> ... -> sensitive operation. */
  path: string;
  impact: string;
  remediation: string;
  /** Batches that reported this finding. */
  source_batches: string[];
}

interface Chain {
  /** Stable id, e.g. "C1". */
  id: string;
  priority: "P0" | "P1" | "P2" | "P3";
  title: string;
  /** Ids of the findings that compose this chain, in order. */
  steps: string[];
  /** What the combination achieves. */
  impact: string;
  owasp: string[];
}

interface UnvalidatedLead {
  title: string;
  /** Why the source alone cannot establish reachability. */
  reason: string;
  /** The ONE fact outside the repository that would settle it. */
  missing_fact: string;
  owasp: string[];
  locations: Location[];
}

interface ReducedReport {
  /** 3-6 sentences for the owner: overall posture, the most important issues. */
  summary: string;
  /** Deduplicated, prioritized findings. */
  findings: ReducedFinding[];
  /** Cross-batch chains: one finding's exposes matched against another's requires. */
  chains: Chain[];
  /** Leads whose exploitability depends on a fact outside the repository: no priority, not verified. */
  unvalidated: UnvalidatedLead[];
  /** Dropped findings with the reason. */
  dismissed: { title: string; reason: string; source_batches: string[] }[];
}

interface ClaimVerdict {
  verdict: "confirmed" | "refuted" | "unverified";
  /** 1-3 sentences: what you checked and why the verdict follows. */
  reason: string;
  /** The decisive lines that prove the verdict. */
  evidence: { path: string; lines: string; quote: string }[];
  /** If the claim is right in substance but a detail was imprecise: the corrected detail; else empty. */
  corrections: string;
}

interface GateDecision {
  /** True only on an explicit owner approval of the published plan. */
  approved: boolean;
}

interface ReportFinding {
  /** Workspace-relative path with lines when they apply: "src/a.ts:42". */
  where: string;
  /** One sentence: what is wrong. */
  what: string;
  /** What showed it: the verifier's reason and decisive quote, or the reducer's data flow. */
  evidence: string;
  /** "verified" when an independent verifier confirmed it; "unconfirmed" when unverified or not checked. */
  status: "verified" | "unconfirmed";
  /** Reserve "high" for data loss, a crash, or a wrong result. */
  severity: "low" | "medium" | "high";
}

interface WorkflowReport {
  /** Two or three sentences answering what the user asked for. */
  conclusion: string;
  findings: ReportFinding[];
  /** What the run checked and how. */
  verified: string[];
  /** What the run did not look at or could not check, and why. */
  notCovered: string[];
}

// ---------------------------------------------------------------------------
// Fixed content: defensive preamble (load-bearing — provider safety filters
// refuse attack-framed prompts), attack-class playbook, standards catalog,
// built-in excludes. Keep the framing in any edit; never ask for exploit code.
// ---------------------------------------------------------------------------

const DEFENSE =
  "CONTEXT: This is an authorized DEFENSIVE code review. The repository belongs to the person " +
  "who requested this review (its owner), and the goal is to find and FIX weaknesses in the " +
  "owner's own code before release. Describe issues and remediations in prose with file:line " +
  "references. Do NOT write exploit code, attack payloads, proof-of-concept scripts or " +
  "step-by-step attack instructions. If your instructions are impossible to satisfy or " +
  "contradict each other, escalate and say so plainly rather than working around it.";

const READONLY =
  "You are in the live workspace, read-only: NEVER create, edit or delete any file. " +
  "Use your Read, Grep and Glob tools to read anything you need, including files outside " +
  "your assigned scope, to trace data flows.";

const PLAYBOOK = `ATTACK-CLASS PLAYBOOK (what to look for; selectors said where)
- Injection: trace untrusted input from entry point to dangerous sink (SQL/query builders with string building, exec/spawn/eval/Function, template engines, HTML output, file paths, redirects, deserialization, LDAP/XPATH, log injection). Look for indirect injection: data stored safely then used in a dangerous context by other code; injection through field names, keys, headers, metadata — not just values; injection into secondary systems (logs, caches, search indexes, analytics).
- Access control: verify a caller cannot act outside its authority. Checks must gate the RIGHT permission for the RIGHT resource via the RIGHT mechanism. Look for: weaker parallel paths to the same state change; request-body fields overriding what permissions restrict; endpoints gating on authentication but forgetting authorization; multiple access paths with inconsistent checks; bulk/batch/export/import operations skipping per-item checks; tenant/user scoping missing from queries.
- Resource and file handling: path traversal (symlinks, encoded sequences, null bytes), SSRF (attacker-controlled URLs, redirects, DNS rebinding, URL parser differentials), unsafe deserialization, archive extraction (zip slip), temp files, TOCTOU races on file operations.
- Cryptography and secrets: weak randomness for tokens/keys/nonces, hardcoded secrets (including "fallback" secrets), secrets in logs, error messages or client-visible responses, broken key derivation, missing HMAC verification, nonce reuse, timing side channels on secret comparison, JWT/crypto configuration.
- Security configuration: CORS, cookies (flags, scoping), CSP and security headers, CSRF, rate limits, auth middleware order, exported components (Android manifest, deep links, IPC, webview bridges), database/Firestore/Supabase rules and RLS, storage bucket policies, debug modes.
- Logging, alerting and error handling: missing security events, secrets written to logs, log injection, failing OPEN on errors, half-finished transactions on failure, error responses disclosing internals or stack traces.
- Resource exhaustion: untrusted work that can consume CPU, memory, disk, connections, workers, queue depth, quotas or spend.
Severity requires demonstrated impact: name the lower-trust principal, the accepted input, the intended control, the crossed boundary, and the affected resource.`;

const STANDARDS = `SECURITY TOP LISTS (tag selectors and findings with these ids; use only ids that exist here)
OWASP Top 10:2025 (always applies): A01:2025 Broken Access Control; A02:2025 Security Misconfiguration; A03:2025 Software Supply Chain Failures; A04:2025 Cryptographic Failures; A05:2025 Injection; A06:2025 Insecure Design; A07:2025 Authentication Failures; A08:2025 Software or Data Integrity Failures; A09:2025 Security Logging and Alerting Failures; A10:2025 Mishandling of Exceptional Conditions.
OWASP API Security Top 10:2023 (when the codebase serves an HTTP/RPC API): API1:2023 Broken Object Level Authorization; API2:2023 Broken Authentication; API3:2023 Broken Object Property Level Authorization; API4:2023 Unrestricted Resource Consumption; API5:2023 Broken Function Level Authorization; API6:2023 Unrestricted Access to Sensitive Business Flows; API7:2023 Server Side Request Forgery; API8:2023 Security Misconfiguration; API9:2023 Improper Inventory Management; API10:2023 Unsafe Consumption of APIs.
OWASP Top 10 for LLM Applications 2025 (when the codebase calls models, builds prompts or runs agents/tools): LLM01:2025 Prompt Injection; LLM02:2025 Sensitive Information Disclosure; LLM03:2025 Supply Chain; LLM04:2025 Data and Model Poisoning; LLM05:2025 Improper Output Handling; LLM06:2025 Excessive Agency; LLM07:2025 System Prompt Leakage; LLM08:2025 Vector and Embedding Weaknesses; LLM09:2025 Misinformation; LLM10:2025 Unbounded Consumption.
OWASP MASVS v2 (when the codebase ships an Android or iOS app): MASVS-STORAGE; MASVS-CRYPTO; MASVS-AUTH; MASVS-NETWORK; MASVS-PLATFORM; MASVS-CODE; MASVS-RESILIENCE; MASVS-PRIVACY.`;

const BUILTIN_EXCLUDES = [
  "**/node_modules/**", "**/.git/**", "**/.zcode/**", "**/__pycache__/**",
  "**/.venv/**", "**/venv/**", "**/dist/**", "**/build/**", "**/out/**",
  "**/vendor/**", "**/third_party/**", "**/coverage/**",
  "**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml", "**/poetry.lock",
  "**/Cargo.lock", "**/go.sum", "**/Gemfile.lock", "**/composer.lock",
  "**/*.min.js", "**/*.min.css", "**/*.map",
  "**/*.png", "**/*.jpg", "**/*.jpeg", "**/*.gif", "**/*.bmp", "**/*.ico", "**/*.webp",
  "**/*.woff", "**/*.woff2", "**/*.ttf", "**/*.eot", "**/*.otf",
  "**/*.mp3", "**/*.mp4", "**/*.avi", "**/*.mov",
  "**/*.zip", "**/*.gz", "**/*.tar", "**/*.7z", "**/*.rar",
  "**/*.pdf", "**/*.wasm", "**/*.exe", "**/*.dll", "**/*.so", "**/*.dylib",
  "**/*.bin", "**/*.pyc", "**/*.class", "**/*.jar", "**/*.ipa", "**/*.apk",
];

/** A selector matching more files than this is a plan error (forces a re-plan),
 *  like swarm.py's selector caps — never a silently partial scan. */
const SELECTOR_FILE_CAP = 500;

/** Convert a ripgrep -g style glob to a regex tested against workspace-relative paths. */
function globToRe(glob: string): RegExp {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        if (glob[i + 2] === "/") {
          out += "(?:.*/)?";
          i += 2;
        } else {
          out += ".*";
          i += 1;
        }
      } else {
        out += "[^/]*";
      }
    } else if (c === "?") {
      out += "[^/]";
    } else if ("\\^$.|+()[]{}".includes(c)) {
      out += "\\" + c;
    } else {
      out += c;
    }
  }
  // gitignore / ripgrep -g semantics: a glob WITH a path separator is anchored to the
  // workspace root; without one it matches the basename at any depth.
  return new RegExp((glob.includes("/") ? "^" : "(?:^|/)") + out + "$");
}

// ---------------------------------------------------------------------------
// Arguments and run context
// ---------------------------------------------------------------------------

const notes = typeof args.notes === "string" ? args.notes : "";
const batchSize = typeof args.batchSize === "number" && Number.isInteger(args.batchSize) && args.batchSize > 0 ? args.batchSize : 5;
const maxBatches = typeof args.maxBatches === "number" && Number.isInteger(args.maxBatches) && args.maxBatches > 0 ? args.maxBatches : 8;
// Set by an amendment re-planning with owner feedback; empty on a first run.
const replanFeedback = "";

// ---------------------------------------------------------------------------
// Dashboard the owner can watch while the run goes: one card per claim,
// moving to its verification verdict.
// ---------------------------------------------------------------------------

artifact.board("claims", {
  title: "Claim verification",
  key: "id",
  status: "verdict",
  columns: ["confirmed", "unverified", "refuted"],
  cardTitle: "title",
  detail: [{ field: "priority", label: "Priority" }],
});

// ---------------------------------------------------------------------------
// Stage 1: plan — a fresh subagent surveys the workspace and drafts the threat
// model plus the selectors; the script then validates every selector
// deterministically (regex errors, caps, match counts) exactly like
// `swarm.py plan` does, and publishes the plan for approval.
// ---------------------------------------------------------------------------

phase("Survey the codebase and draft the threat model");

let commit = "unknown";
try {
  const log = await git.log(1);
  const head = log[0];
  if (head !== undefined) commit = head.hash.slice(0, 10);
} catch {
  commit = "unknown";
}
let treeClean = true;
let treeKnown = true;
try {
  const status = await git.status();
  treeClean = status.clean;
} catch {
  treeKnown = false;
}

const feedbackBlock =
  replanFeedback === ""
    ? ""
    : `\nOWNER FEEDBACK on the previous plan — address every point before returning:\n${replanFeedback}\n`;

const plan = await agent("Security planner", {
  system:
    DEFENSE +
    " You are the PLANNER of a defensive security review. Your job is NOT to find bugs: " +
    "you (1) write the threat model for this codebase and (2) author SELECTORS — ripgrep " +
    "regexes a script will run deterministically over every file. Every file that matches " +
    "no selector is never looked at by any agent, so selector RECALL is what makes the scan " +
    "complete. " +
    READONLY,
}).ask<Plan>(
  `You are planning a defensive security review of this workspace (HEAD ${commit}).` +
    (notes === "" ? "" : `\nRepo notes from the owner: ${notes}`) +
    (treeKnown && !treeClean
      ? "\nNOTE: the working tree has uncommitted changes; the scan reviews the working tree, not a committed snapshot."
      : "") +
    `\n\nSteps:
1. Explore the workspace with your file tools (list top-level dirs, read manifests/configs, routing, auth, storage, network code). Do not modify any file.
2. Write the threat model: who could misuse the app (e.g. anonymous internet user, signed-in user of another account), sensitive assets, trust boundaries, untrusted inputs, explicit out-of-scope areas, and severity criteria tuned to this app.
3. Author 10-30 selectors covering at least, where they exist in this codebase:
   - untrusted inputs: HTTP routes/handlers, server actions, API clients receiving untrusted data, IPC/deep links/intents/exported components, webviews, message/event handlers, CLI args
   - authn/authz boundaries: middleware, guards, session/token handling, permission checks, tenant/user scoping in queries
   - dangerous sinks: raw SQL/query builders with string building, exec/spawn/eval/Function, deserialization, filesystem paths from input, outbound fetch with user-controlled URLs (SSRF), HTML injection (innerHTML, dangerouslySetInnerHTML, v-html, WebView JS bridges), redirects
   - secrets & crypto: hardcoded keys/tokens (including fallback secrets), env handling, weak randomness, JWT/crypto config
   - security config: CORS, cookies, CSP/headers, CSRF, rate limits, Android manifest exports, Supabase/Firebase rules/RLS, storage bucket policies
   A selector may set pattern to null to select EVERY file matching its globs (use this for small security-critical areas such as auth modules, middleware, RLS/migration SQL, manifests) — such selectors MUST list globs.
4. List exclude globs for generated/vendored/irrelevant code beyond the built-in excludes (node_modules, .git, dist/build, vendor, lockfiles, minified files, binaries, .zcode are already excluded).
5. Map the review onto the security top lists: pick every list that applies (top10 always; api if it serves an HTTP/RPC API; llm if it calls models or runs agents; masvs if it ships a mobile app) and tag every selector with the catalog ids it looks for. A category no selector is tagged with is reported as NOT CHECKED — add a selector rather than leave a relevant category untagged. Dependency CVEs (A03) are covered by a separate scanner; still tag selectors for manifests, CI workflows and build scripts.

${STANDARDS}

Pattern rules: JavaScript regex syntax (lookaround and backreferences are allowed); escape literal parentheses and dots; there is no inline case-insensitive flag, so write character classes like [Ss]ecret when you need case folding. Globs use gitignore/ripgrep -g syntax (e.g. "*.ts" matches at any depth; "src/server/**" is anchored to the workspace root). Keep each selector's globs tight enough that the selector matches at most a few hundred files — a selector over the match cap is treated as an error.
${feedbackBlock}`,
);

// Deterministic validation and sharding, mirroring `swarm.py plan`: run every
// selector now so the approval gate shows real match counts, and refuse the
// plan (return for a re-plan) while any selector errors — like `swarm.py
// approve` refusing on selector errors.

const excludeRes = [...BUILTIN_EXCLUDES, ...plan.exclude_globs].map(globToRe);
const isExcluded = (p: string) => excludeRes.some((r) => r.test(p));

let allFiles: string[] | null = null;
try {
  allFiles = (await files.glob("**/*")).filter((p) => !isExcluded(p));
} catch {
  allFiles = null; // workspace over the file-listing cap; coverage ledger unavailable
}

interface Signal {
  selector: string;
  line: number;
  text: string;
}
const signals = new Map<string, Signal[]>();

interface SelectorOutcome {
  sel: Selector;
  ok: boolean;
  error: string;
  paths: string[];
}

const outcomes: SelectorOutcome[] = [];
for (const sel of plan.selectors) {
  const paths = new Set<string>();
  let ok = true;
  let error = "";
  const globs = sel.globs.length > 0 ? sel.globs : [""];
  try {
    for (const g of globs) {
      if (sel.pattern === null) {
        if (g === "") {
          throw new Error("glob-only selector (pattern null) must list globs");
        }
        for (const p of await files.glob(g)) paths.add(p);
      } else {
        const found = g === "" ? await files.grep(sel.pattern) : await files.grep(sel.pattern, g);
        for (const m of found) {
          paths.add(m.path);
          const list = signals.get(m.path) ?? [];
          if (list.length < 40) {
            list.push({ selector: sel.id, line: m.line, text: m.text });
            signals.set(m.path, list);
          }
        }
      }
    }
  } catch (err) {
    ok = false;
    error = String(err).slice(0, 300);
  }
  const matched = [...paths].filter((p) => !isExcluded(p));
  if (ok && matched.length > SELECTOR_FILE_CAP) {
    ok = false;
    error = `matched ${matched.length} files — over the ${SELECTOR_FILE_CAP}-file cap; tighten the globs`;
  }
  outcomes.push({ sel, ok, error, paths: matched });
}

const selectedSet = new Set<string>();
for (const o of outcomes) for (const p of o.paths) selectedSet.add(p);
const selected = [...selectedSet].sort();

const broken = outcomes.filter((o) => !o.ok);

if (plan.selectors.length === 0 || broken.length > 0) {
  const problems =
    plan.selectors.length === 0
      ? "the planner returned no selectors"
      : broken.map((o) => `- ${o.sel.id}: ${o.error}`).join("\n");
  try {
    await artifact.markdown(
      "threat-model",
      `# Scan plan — NEEDS A RE-PLAN\n\n${plan.threat_model}\n\n## Broken selectors\n\n${problems}\n`,
      { title: "Threat model and scan plan (needs a re-plan)" },
    );
  } catch (err) {
    log(`Could not publish the plan card (${String(err).slice(0, 200)}); the broken selectors are: ${problems}`);
  }
  return {
    conclusion:
      `The plan is not runnable: ${problems}. Approve nothing; amend this run with owner feedback to re-plan (everything before the planner's ask is cached).`,
    findings: [],
    verified: ["every selector was executed deterministically with ripgrep before any approval"],
    notCovered: ["nothing was reviewed — the plan was refused before the approval gate"],
  };
}

const chosenLists = [...new Set(["top10", ...plan.standards.filter((s) => s === "api" || s === "llm" || s === "masvs")])];
const chosenIds = chosenLists.flatMap((k) =>
  k === "top10"
    ? ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025"]
    : k === "api"
      ? ["API1:2023", "API2:2023", "API3:2023", "API4:2023", "API5:2023", "API6:2023", "API7:2023", "API8:2023", "API9:2023", "API10:2023"]
      : k === "llm"
        ? ["LLM01:2025", "LLM02:2025", "LLM03:2025", "LLM04:2025", "LLM05:2025", "LLM06:2025", "LLM07:2025", "LLM08:2025", "LLM09:2025", "LLM10:2025"]
        : ["MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-AUTH", "MASVS-NETWORK", "MASVS-PLATFORM", "MASVS-CODE", "MASVS-RESILIENCE", "MASVS-PRIVACY"],
);
const tagged = new Set<string>();
for (const o of outcomes) for (const id of o.sel.owasp) tagged.add(id);
const untagged = chosenIds.filter((id) => !tagged.has(id));

const inScopeCount = allFiles === null ? -1 : allFiles.length;
const notReviewed = allFiles === null ? [] : allFiles.filter((p) => !selectedSet.has(p));
const notReviewedDirs = new Map<string, number>();
for (const p of notReviewed) {
  const top = p.split("/")[0];
  notReviewedDirs.set(top, (notReviewedDirs.get(top) ?? 0) + 1);
}

const selectorTable = outcomes
  .map((o) => `- \`${o.sel.id}\` (${o.sel.category}, ${o.paths.length} files) — ${o.sel.description}${o.sel.owasp.length > 0 ? ` [${o.sel.owasp.join(", ")}]` : ""}`)
  .join("\n");

try {
  await artifact.markdown(
    "threat-model",
    [
      `# Threat model and scan plan (HEAD ${commit})`,
      "",
      plan.threat_model,
      "",
      "## Investigation guidance",
      "",
      plan.investigation_guidance,
      "",
      "## Severity criteria",
      "",
      plan.severity_criteria,
      "",
      "## Selectors",
      "",
      selectorTable,
      "",
      "## Standards in scope",
      "",
      chosenLists.join(", ") + (untagged.length > 0 ? `\n\nNOT CHECKED (no selector tagged): ${untagged.join(", ")}` : ""),
      "",
      "## Coverage at plan time",
      "",
      allFiles === null
        ? "Workspace is over the file-listing cap: the not-reviewed ledger is unavailable."
        : `${selected.length} of ${inScopeCount} in-scope files selected; ${notReviewed.length} files match no selector and will never be investigated.`,
    ].join("\n"),
    {
      title: "Threat model and scan plan",
      description: "Review this before approving: selectors decide what the scan can see.",
    },
  );
} catch (err) {
  log(`Could not publish the plan card (${String(err).slice(0, 200)}); the approval gate below still carries the summary.`);
}

log(`Plan ready: ${plan.selectors.length} selectors, ${selected.length} files selected${allFiles === null ? " (workspace over cap)" : ` of ${inScopeCount} in scope`}.`);

// ---------------------------------------------------------------------------
// The human gate: nothing runs until the owner approves the published plan.
// Fill with { approved: true } to scan; fill { approved: false } to stop for a
// re-plan (then amend the run with the owner's feedback in `replanFeedback`).
// ---------------------------------------------------------------------------

const gate = await hole<GateDecision>(
  "Approve the scan plan",
  `The threat model and selector table are published as the "Threat model and scan plan" card — the owner should read it before you fill this hole.\n\nSummary:\n- ${plan.selectors.length} selectors; ${selected.length} files selected${allFiles === null ? " (workspace over the file-listing cap; ledger unavailable)" : ` of ${inScopeCount} in scope; ${notReviewed.length} files match no selector`}\n- standards: ${chosenLists.join(", ")}\n- categories NOT CHECKED by any selector: ${untagged.length > 0 ? untagged.join(", ") : "none"}\n- working tree: ${treeKnown ? (treeClean ? "clean" : "DIRTY — the scan reviews the working tree, not committed HEAD") : "unknown"}\n\nFill with { "approved": true } only on the owner's explicit OK, or { "approved": false } to stop for a re-plan.`,
);

if (!gate.approved) {
  return {
    conclusion:
      "The scan plan was not approved. Amend this run with the owner's feedback in the `replanFeedback` constant to re-plan; the selector validation is cached.",
    findings: [],
    verified: ["every selector was executed deterministically before the gate"],
    notCovered: ["nothing was reviewed — the plan was stopped at the approval gate"],
  };
}

log("Plan approved; sharding the selected files and starting the reviewers.");

// ---------------------------------------------------------------------------
// Stage 2: map + refute. One reviewer per batch, chained to its own adversarial
// refuter (fail-open: a broken refuter keeps the findings, logged). A failed
// reviewer marks its batch as a coverage gap instead of failing the run.
// ---------------------------------------------------------------------------

phase("Review each file batch and try to refute its findings");

interface Batch {
  id: string;
  files: string[];
}
const batches: Batch[] = [];
for (let i = 0; i < selected.length && batches.length < maxBatches; i += batchSize) {
  batches.push({
    id: "B" + String(batches.length + 1).padStart(2, "0"),
    files: selected.slice(i, i + batchSize),
  });
}
const partialRun = selected.length > batches.length * batchSize;

interface KeptFinding {
  batch: string;
  finding: WorkerFinding;
}
const kept: KeptFinding[] = [];
const failedBatches: string[] = [];

await Promise.all(
  batches.map(async (b) => {
    const listing = b.files
      .map((p) => {
        const sig = signals.get(p) ?? [];
        if (sig.length === 0) return `- ${p} (selected by a glob-only selector)`;
        const lines = sig
          .slice(0, 6)
          .map((s) => `    L${s.line} [${s.selector}] ${s.text.trim().slice(0, 120)}`)
          .join("\n");
        return `- ${p}\n${lines}${sig.length > 6 ? `\n    ... ${sig.length - 6} more signals (read the file)` : ""}`;
      })
      .join("\n");

    let report: WorkerReport;
    try {
      report = await agent(`Reviewer ${b.id}`, {
        system:
          DEFENSE +
          " You are a REVIEWER in a defensive security review. " +
          READONLY +
          " A risky pattern is a LEAD, not a finding: report a finding only when you can trace a " +
          "reachable path from untrusted input to a concrete security impact, after checking " +
          "validation, authentication, authorization and escaping along the way. If an effective " +
          "mitigation blocks the path, do not report it (mention it in notes). Also report partial " +
          "conditions that could CHAIN with code elsewhere (e.g. an endpoint that discloses IDs or " +
          "tokens, or code that is safe only if its caller authenticates) with exposes/requires " +
          "filled in; the reducer combines them across batches.",
      }).ask<WorkerReport>(
        `THREAT MODEL\n${plan.threat_model}\n\nINVESTIGATION GUIDANCE\n${plan.investigation_guidance}\n\nSEVERITY CRITERIA\n${plan.severity_criteria}\n\nEvery finding needs a concrete, owner-observable result, not a deviation from good practice: name the lower-trust principal, the accepted input, the intended control, the crossed boundary, and the affected resource. If you cannot state the concrete damage, the severity is lower than it feels. If your claim depends on a fact outside this repository (how the service is deployed, what a third-party origin does, which grants the hosted database has), set needs_outside_fact to the exact missing fact — such claims carry no severity and are presented separately. Not findings: checklist deviations, defense-in-depth gaps behind a working control, guessed deployment behaviour, same-principal self-impact, a parser crash with no boundary crossing — put those in notes.\n\n${PLAYBOOK}\n\nYOUR BATCH (${b.id}): investigate EVERY file below. Signals show why each file was selected (selector id, line, matched text); read the whole file and anything else you need.\n${listing}\n\nUse an empty findings list if you found nothing real.`,
      );
    } catch (err) {
      failedBatches.push(b.id);
      log(`Batch ${b.id} failed and is recorded as a coverage gap: ${String(err).slice(0, 200)}`);
      return;
    }

    if (report.findings.length === 0) return;

    const refutedIdx = new Set<number>();
    try {
      const refutation = await agent(`Refuter ${b.id}`, {
        system:
          DEFENSE +
          " You are the ADVERSARIAL REFUTER. You receive ONE reviewer report and must try to REFUTE " +
          "each finding in it. A finding is refuted ONLY when you can name the concrete thing in " +
          "the source that blocks it: the validation that rejects the input, the authentication or " +
          "authorization guard on the mounted route, the escaping/parameterization at the sink, or " +
          "the claimed line/code simply not existing. \"I could not trace the whole path\" is NOT a " +
          "refutation — when in doubt, the finding STANDS. Do not merge, rank, rewrite or extend " +
          "findings; do not report new ones. " +
          READONLY,
      }).ask<RefuterReport>(
        `THREAT MODEL\n${plan.threat_model}\n\nSEVERITY CRITERIA\n${plan.severity_criteria}\n\nREVIEWER REPORT ${b.id} (${report.findings.length} findings, numbered from 1 in the order below):\n${JSON.stringify(report.findings, null, 1)}\n\nCheck the decisive facts of each finding in the source before judging it. Return exactly one verdict per finding, using its 1-based position in the list as \`finding\`.`,
      );
      for (const v of refutation.verdicts) {
        if (v.verdict === "refuted") refutedIdx.add(v.finding);
      }
    } catch (err) {
      log(`Refuter for ${b.id} failed; keeping ALL its findings (fail open): ${String(err).slice(0, 200)}`);
    }

    report.findings.forEach((f, i) => {
      if (!refutedIdx.has(i + 1)) kept.push({ batch: b.id, finding: f });
    });
  }),
);

log(`${kept.length} findings survived refutation from ${batches.length - failedBatches.length}/${batches.length} batches.`);

// ---------------------------------------------------------------------------
// Stage 3: reduce — the one barrier: dedupe and ranking need every batch's
// surviving findings. A failed reducer falls back to raw, undeduplicated
// findings (banner in the report), like the Python pipeline.
// ---------------------------------------------------------------------------

phase("Consolidate, rank and chain the surviving findings");

let reduced: ReducedReport;
let reducerFailed = false;
if (kept.length === 0) {
  reduced = {
    summary: "No findings survived the review and refutation stages.",
    findings: [],
    chains: [],
    unvalidated: [],
    dismissed: [],
  };
} else {
  const rawPayload = JSON.stringify(
    kept.map((k) => ({ batch: k.batch, finding: k.finding })),
    null,
    1,
  );
  try {
    reduced = await agent("Lead reviewer", {
      system:
        DEFENSE +
        " You are the LEAD REVIEWER consolidating a defensive security review. You may read code to " +
        "reconcile conflicting worker conclusions, but reason mainly over the worker findings you " +
        "are given. " +
        READONLY,
    }).ask<ReducedReport>(
      `THREAT MODEL\n${plan.threat_model}\n\nSEVERITY CRITERIA\n${plan.severity_criteria}\n\nWORKER FINDINGS (${kept.length} findings from ${batches.length} batches; batches with zero findings are omitted):\n${rawPayload}\n\nDo this:\n1. Deduplicate: merge findings with the same root cause (keep every location).\n2. Drop findings whose evidence does not show a reachable path, or that an effective mitigation blocks; list them under dismissed with the reason.\n3. Prioritize each remaining finding: P0 (critical, reachable now), P1 (high), P2 (medium), P3 (low / defense in depth), using the severity criteria.\n4. Build CHAINS across batches: match one finding's exposes against another's requires (e.g. an unauthenticated disclosure of an ID + a write gated only by that ID = one higher-priority chain). Only claim a chain when you can name the concrete steps.\n5. Route every finding whose exploitability depends on a fact OUTSIDE the repository (hosted service configuration, deployed limits, third-party behaviour, database grants, operator choices) into unvalidated instead of the findings list: no priority, and the single missing_fact that would settle it. This is not a demotion to P3 — it is a different kind of statement.\n\nSeverity discipline:\n- Severity comes from demonstrated impact, never from the pattern that was matched. If you cannot name the concrete damage, use the lower tier — or unvalidated when the unknown is reachability itself.\n- A defense-in-depth gap behind a working control is a hardening note, not a finding: dismissed with reason "hardening".\n- A claim you had to soften to keep it ("could", "may", "in some configurations") goes to unvalidated with the fact that would make it definite.\n- Do not invent a chain to raise priority. Two findings touching the same file are not a chain.\n\nTag every finding, chain and unvalidated lead with owasp ids from the catalog below. Use only ids that exist in the catalog; do not tag to make coverage look fuller.\n\n${STANDARDS}`,
    );
  } catch (err) {
    reducerFailed = true;
    log(`Reducer failed; falling back to raw, undeduplicated findings: ${String(err).slice(0, 200)}`);
    const sevToPriority: Record<string, "P0" | "P1" | "P2" | "P3"> = {
      critical: "P0",
      high: "P1",
      medium: "P2",
      low: "P3",
    };
    reduced = {
      summary: `REDUCER FAILED (${String(err).slice(0, 200)}). The findings below are raw and undeduplicated: one issue may appear once per batch, and priorities are the workers' severities mapped mechanically. Re-run the reduce before treating counts as authoritative.`,
      // Outside-fact findings stay unvalidated ONLY (no priority, no verifier):
      // a source-only verifier could only guess at the missing fact.
      findings: kept
        .filter((k) => k.finding.needs_outside_fact === "")
        .map((k, i) => ({
        id: "R" + String(i + 1),
        priority: sevToPriority[k.finding.severity] ?? "P3",
        title: k.finding.title,
        category: k.finding.category,
        cwe: k.finding.cwe,
        owasp: [],
        confidence: k.finding.confidence,
        locations: k.finding.locations,
        description: `${k.finding.data_flow}. Checked: ${k.finding.mitigations_checked}.`,
        path: k.finding.entry_point + " -> " + k.finding.data_flow,
        impact: k.finding.impact,
        remediation: k.finding.remediation,
        source_batches: [k.batch],
      })),
      chains: [],
      unvalidated: kept
        .filter((k) => k.finding.needs_outside_fact !== "")
        .map((k) => ({
          title: k.finding.title,
          reason: k.finding.impact,
          missing_fact: k.finding.needs_outside_fact,
          owasp: [],
          locations: k.finding.locations,
        })),
      dismissed: [],
    };
  }
}

// ---------------------------------------------------------------------------
// Stage 4: verify — one fresh verifier per claim (every finding and every
// chain; unvalidated leads are excluded by design). Verifiers fail CLOSED: a
// broken verifier yields unverified, never confirmed. Each verdict moves the
// claim's card on the board and is reported as it lands. The final report is
// built and published in this same stage.
// ---------------------------------------------------------------------------

phase("Verify every claim independently and report");

interface Claim {
  kind: "finding" | "chain";
  id: string;
  priority: string;
  title: string;
  payload: string;
}
const claims: Claim[] = [
  ...reduced.findings.map((f) => ({
    kind: "finding" as const,
    id: f.id,
    priority: f.priority,
    title: f.title,
    payload: JSON.stringify(f),
  })),
  ...reduced.chains.map((c) => ({
    kind: "chain" as const,
    id: c.id,
    priority: c.priority,
    title: c.title,
    payload: JSON.stringify({
      chain: c,
      member_findings: reduced.findings.filter((f) => c.steps.includes(f.id)),
    }),
  })),
];

const verdicts = new Map<string, ClaimVerdict>();
await Promise.all(
  claims.map(async (c, i) => {
    let v: ClaimVerdict;
    try {
      v = await agent(`Verifier ${String(i + 1).padStart(2, "0")} ${c.id}`, {
        system:
          DEFENSE +
          " You are an INDEPENDENT VERIFIER. You receive exactly ONE claim from the review's final " +
          "report. Nobody else will check this claim — you are the only verifier it gets, so " +
          "absolute certainty is required. Your job is to try to FALSIFY it: read the code and " +
          "check every decisive fact the claim depends on — the cited files and lines exist, the " +
          "guards described as missing really are missing, the route is really mounted and " +
          "reachable, the input really reaches the sink as described. " +
          READONLY,
      }).ask<ClaimVerdict>(
        `CLAIM (${c.kind} ${c.id})\n${c.payload}\n\nTHREAT MODEL\n${plan.threat_model}\n\nVerdict rules:\n- "confirmed" ONLY if every decisive fact checks out in the source and your evidence quotes the lines that prove it. If any step depends on something you could not verify in the code, do NOT confirm.\n- "refuted" if any decisive fact is wrong: a mitigation blocks the path, a guard or validation exists, the claimed code or line does not exist or differs, the route is not mounted, the sink is not reachable.\n- "unverified" if the code cannot settle it (files missing, behaviour depends on something external).\n- For a chain: confirm only if EVERY step holds and the steps really compose (the object disclosed by one step is the thing the next step takes as given). Any broken step refutes the chain.`,
      );
    } catch (err) {
      v = {
        verdict: "unverified",
        reason: `Verifier call failed (fail closed): ${String(err).slice(0, 200)}`,
        evidence: [],
        corrections: "",
      };
    }
    verdicts.set(c.id, v);
    report({ id: c.id, title: c.title, priority: c.priority, verdict: v.verdict }, "claims");
  }),
);

const byId = new Map(reduced.findings.map((f) => [f.id, f]));
const confirmedFindings = reduced.findings.filter((f) => verdicts.get(f.id)?.verdict === "confirmed");
const unverifiedFindings = reduced.findings.filter((f) => verdicts.get(f.id)?.verdict === "unverified" || verdicts.get(f.id) === undefined);
const refutedFindings = reduced.findings.filter((f) => verdicts.get(f.id)?.verdict === "refuted");
const confirmedChains = reduced.chains.filter((c) => verdicts.get(c.id)?.verdict === "confirmed");
const unverifiedChains = reduced.chains.filter((c) => verdicts.get(c.id)?.verdict === "unverified" || verdicts.get(c.id) === undefined);
const refutedChains = reduced.chains.filter((c) => verdicts.get(c.id)?.verdict === "refuted");

const pCounts = { P0: 0, P1: 0, P2: 0, P3: 0 };
for (const f of confirmedFindings) pCounts[f.priority] += 1;

function claimMd(header: string, id: string, title: string, body: string, v: ClaimVerdict | undefined): string {
  const ev = v === undefined ? [] : v.evidence;
  const quotes = ev.map((e) => `  - \`${e.path}:${e.lines}\` ${e.quote}`).join("\n");
  const verdictLine = v === undefined ? "unverified" : v.verdict;
  const reason = v === undefined ? "" : `\n\n  **Verifier**: ${v.reason}`;
  const corr = v !== undefined && v.corrections !== "" ? `\n\n  **Correction**: ${v.corrections}` : "";
  return `### ${header} ${id}: ${title} — ${verdictLine}\n\n${body}${reason}${corr}${quotes === "" ? "" : `\n\n**Evidence**\n${quotes}`}\n`;
}

const findingBody = (f: ReducedFinding) =>
  `- Priority ${f.priority} · ${f.category}${f.cwe === "" ? "" : ` · ${f.cwe}`}${f.owasp.length > 0 ? ` · ${f.owasp.join(", ")}` : ""}\n` +
  `- Where: ${f.locations.map((l) => `${l.path}:${l.lines}`).join(", ")}\n` +
  `- What: ${f.description}\n- Path: ${f.path}\n- Impact: ${f.impact}\n- Fix: ${f.remediation}`;

const reportMd: string[] = [
  `# Security review report (run ${run.id})`,
  "",
  `Workspace at ${commit}${treeKnown ? (treeClean ? "" : " — DIRTY working tree: this reviews the working tree, not a committed snapshot") : " — working-tree state unknown"}.`,
  "",
  reduced.summary,
  "",
  `**Verification: ${confirmedFindings.length + confirmedChains.length} confirmed / ${unverifiedFindings.length + unverifiedChains.length} unverified / ${refutedFindings.length + refutedChains.length} refuted (dropped).** Claims under "Refuted" are dropped and must not be presented as live issues. "Unverified" is NOT a confirmation.`,
  "",
  `**Confirmed findings by priority: P0 ${pCounts.P0} · P1 ${pCounts.P1} · P2 ${pCounts.P2} · P3 ${pCounts.P3}**`,
];
if (confirmedFindings.length + confirmedChains.length > 0) {
  reportMd.push("", "## Confirmed",
    ...confirmedFindings.map((f) => claimMd("Finding", f.id, f.title, findingBody(f), verdicts.get(f.id))),
    ...confirmedChains.map((c) =>
      claimMd("Chain", c.id, c.title, `- Priority ${c.priority} · steps: ${c.steps.join(" -> ")}\n- Impact: ${c.impact}`, verdicts.get(c.id)),
    ),
  );
}
if (unverifiedFindings.length + unverifiedChains.length > 0) {
  reportMd.push("", "## Unverified (kept, labelled — not confirmations)",
    ...unverifiedFindings.map((f) => claimMd("Finding", f.id, f.title, findingBody(f), verdicts.get(f.id))),
    ...unverifiedChains.map((c) =>
      claimMd("Chain", c.id, c.title, `- Priority ${c.priority} · steps: ${c.steps.join(" -> ")}\n- Impact: ${c.impact}`, verdicts.get(c.id)),
    ),
  );
}
if (refutedFindings.length + refutedChains.length > 0) {
  reportMd.push("", "## Refuted — dropped", "",
    "An independent verifier falsified these; do not report them as live issues.",
    ...[...refutedFindings, ...refutedChains].map((x) => {
      const v = verdicts.get(x.id);
      return `- **${x.id}: ${x.title}** — ${v === undefined ? "no verdict" : v.reason}`;
    }),
  );
}
if (reduced.unvalidated.length > 0) {
  reportMd.push("", "## Unvalidated leads — open questions, no priority", "",
    "These hinge on a fact outside the repository; they are excluded from P0–P3 and from verification.",
    ...reduced.unvalidated.map(
      (u) =>
        `- **${u.title}**${u.owasp.length > 0 ? ` (${u.owasp.join(", ")})` : ""}: ${u.reason}\n  - Missing fact: ${u.missing_fact}\n  - Where: ${u.locations.map((l) => `${l.path}:${l.lines}`).join(", ")}`,
    ),
  );
}
if (reduced.dismissed.length > 0) {
  reportMd.push("", "## Dismissed during consolidation",
    ...reduced.dismissed.map((d) => `- **${d.title}** — ${d.reason} (from ${d.source_batches.join(", ")})`),
  );
}
reportMd.push(
  "",
  "## Coverage",
  "",
  allFiles === null
    ? "- The workspace is over the file-listing cap: the not-reviewed ledger is unavailable."
    : `- ${selected.length} of ${inScopeCount} in-scope files were selected by the approved selectors; ${notReviewed.length} files matched NO selector and were never investigated — unreviewed is not clean.`,
);
if (allFiles !== null && notReviewedDirs.size > 0) {
  reportMd.push(
    `- Not reviewed, by top directory: ${[...notReviewedDirs.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([d, n]) => `${d} (${n})`).join(", ")}.`,
  );
}
if (partialRun) reportMd.push(`- Partial run: the batch cap covered ${batches.length * batchSize} of ${selected.length} selected files. Re-run with a higher cap for full coverage.`);
if (failedBatches.length > 0) reportMd.push(`- Failed batches (coverage gaps): ${failedBatches.join(", ")}.`);
if (untagged.length > 0) reportMd.push(`- Standards categories NOT CHECKED by any selector: ${untagged.join(", ")}.`);
if (reducerFailed) reportMd.push("- REDUCER FAILED: findings are raw and undeduplicated (see summary).");
reportMd.push(
  "- Dependency CVEs (OSV-Scanner) are not part of this workflow; dependencies were not scanned.",
  '- Static, source-level review: no sandbox reproduction. "Confirmed" means an independent agent failed to falsify the claim against the source, not "proven exploitable".',
);

try {
  await artifact.markdown("report", reportMd.join("\n"), {
    title: "Security review report",
    description: "Verified findings, coverage ledger and dropped claims from the swarm review.",
    primary: true,
  });
} catch (err) {
  log(`Could not publish the report card (${String(err).slice(0, 200)}); the return value carries the findings.`);
}

const sevOf = (p: string): "low" | "medium" | "high" => (p === "P0" || p === "P1" ? "high" : p === "P2" ? "medium" : "low");
const reportFindings: ReportFinding[] = [
  ...confirmedFindings.map((f) => {
    const v = verdicts.get(f.id);
    const loc = f.locations[0];
    return {
      where: loc === undefined ? f.source_batches.join(",") : `${loc.path}:${loc.lines}`,
      what: `${f.title} — ${f.impact}`,
      evidence:
        (v === undefined ? "" : v.reason + " ") +
        (v !== undefined && v.evidence.length > 0 ? `${v.evidence[0]?.path}:${v.evidence[0]?.lines} ${v.evidence[0]?.quote}` : f.path),
      status: "verified" as const,
      severity: sevOf(f.priority),
    };
  }),
  ...unverifiedFindings.map((f) => {
    const loc = f.locations[0];
    const v = verdicts.get(f.id);
    return {
      where: loc === undefined ? f.source_batches.join(",") : `${loc.path}:${loc.lines}`,
      what: `${f.title} — ${f.impact} (unverified)`,
      evidence: (v === undefined ? "no verdict recorded" : v.reason) + ` Data flow: ${f.path}`,
      status: "unconfirmed" as const,
      severity: sevOf(f.priority),
    };
  }),
  ...confirmedChains.map((c) => {
    const v = verdicts.get(c.id);
    return {
      where: `chain ${c.id}: ${c.steps.join(" -> ")}`,
      what: `${c.title} — ${c.impact}`,
      evidence:
        (v === undefined ? "" : v.reason + " ") +
        (v !== undefined && v.evidence.length > 0 ? `${v.evidence[0]?.path}:${v.evidence[0]?.lines} ${v.evidence[0]?.quote}` : "member findings verified individually"),
      status: "verified" as const,
      severity: sevOf(c.priority),
    };
  }),
  ...unverifiedChains.map((c) => {
    const v = verdicts.get(c.id);
    return {
      where: `chain ${c.id}: ${c.steps.join(" -> ")}`,
      what: `${c.title} — ${c.impact} (unverified chain)`,
      evidence: (v === undefined ? "no verdict recorded" : v.reason) + ` Steps: ${c.steps.join(" -> ")}`,
      status: "unconfirmed" as const,
      severity: sevOf(c.priority),
    };
  }),
];

const notCovered: string[] = [
  ...(allFiles === null
    ? ["workspace over the file-listing cap — the not-reviewed ledger is unavailable"]
    : [`${notReviewed.length} in-scope files matched no selector and were never investigated (unreviewed is not clean)`]),
  ...(partialRun ? [`batch cap reached: only ${batches.length * batchSize} of ${selected.length} selected files were reviewed`] : []),
  ...(failedBatches.length > 0 ? [`failed batches (coverage gaps): ${failedBatches.join(", ")}`] : []),
  ...(untagged.length > 0 ? [`standards categories not checked by any selector: ${untagged.join(", ")}`] : []),
  ...reduced.unvalidated.map((u) => `unvalidated lead "${u.title}" hinges on an outside fact (${u.missing_fact}) — presented as an open question, not a finding`),
  "dependency CVEs were not scanned (OSV-Scanner is not part of this workflow)",
  ...(treeKnown && !treeClean ? ["the working tree has uncommitted changes; the scan reviewed the working tree, not a committed snapshot"] : []),
];

const result: WorkflowReport = {
  conclusion:
    `Swarm review of this workspace (HEAD ${commit}): ${confirmedFindings.length + confirmedChains.length} claims confirmed by an independent verifier (${pCounts.P0} P0, ${pCounts.P1} P1, ${pCounts.P2} P2, ${pCounts.P3} P3 among confirmed findings), ${unverifiedFindings.length + unverifiedChains.length} unverified (kept, labelled), ${refutedFindings.length + refutedChains.length} refuted and dropped${reduced.unvalidated.length > 0 ? `, ${reduced.unvalidated.length} unvalidated open questions` : ""}. The full report with evidence quotes and the coverage ledger is the "Security review report" card.` +
    (reducerFailed ? " REDUCER FAILED: counts are raw and undeduplicated." : ""),
  findings: reportFindings,
  verified: [
    `selectors were executed deterministically (ripgrep): ${selected.length} files selected${allFiles === null ? " (workspace over cap)" : ` of ${inScopeCount} in scope`}`,
    "every reviewer report was adversarially refuted before consolidation (refuters fail open)",
    `every claim in the final report (${claims.length}) was re-checked by its own fresh verifier agent against the source (verifiers fail closed)`,
  ],
  notCovered,
};
return result;
