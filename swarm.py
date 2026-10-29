#!/usr/bin/env python3
"""Security Swarm for Hermes: Agentic MapReduce security scans (after Devin's Security Swarm).

Stages: plan (agentic) -> approve (human) -> shard (ripgrep, deterministic) ->
map (parallel workers) -> refute (ONE pass over raw findings, flash tier) -> reduce ->
verify (ONE FRESH AGENT PER CLAIM: each finding + each chain, main tier) -> report.

The refutation stages are a design choice: a claim is reported as verified
only when an independent agent failed to falsify it against the source.

Every agent call is a sandboxed-config Hermes one-shot (`--safe-mode`: no user config, memory,
plugins, MCP or fallback providers), file toolset only, cwd = a `git archive` snapshot of HEAD
so the live working tree is never touched and edits during the scan don't interfere.

Usage:
  swarm.py plan <repo> [--ref REF] [--feedback TEXT] [--scan ID]   # new plan / re-plan (REF default HEAD)
  swarm.py approve <scan>
  swarm.py run <scan> [--concurrency N] [--batch-size N] [--max-batches N] [--force]
  swarm.py verify <scan>                               # re-run only the per-claim verifiers
  swarm.py deps <scan>                                 # dependency scan (OSV-Scanner) only
  swarm.py coverage <scan>                             # coverage ledger (unreviewed / scoped-out files)
  swarm.py status [<scan>]
  swarm.py ask                                         # text of the daily readiness question
  swarm.py repos
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
CFG = tomllib.loads((HERE / "swarm.toml").read_text(encoding="utf-8"))
DATA = Path(CFG["scan"]["data_dir"])
CLASSES_DIR = HERE / "references" / "attack-classes"
PLAYBOOK_MAX_CHARS = int(CFG["scan"].get("playbook_max_chars", 60000))
PLAYBOOK_MAX_COMPANIONS = int(CFG["scan"].get("playbook_max_companions", 2))
# path/substring hints -> domain companion file (curated checklists vendored from
# cloudflare/security-audit-skill, MIT; see references/attack-classes/README.md)
COMPANION_HINTS = [
    ("AI-AND-LLM.md", ("src/lib/ai/", "/ai/agent/", "/llm/", "/prompts/", "openai", "anthropic",
                       "embedding", "tool_call", "mcp")),
    ("WEB-PROTOCOL-AND-AUTH.md", ("auth", "session", "jwt", "oauth", "login", "signin", "signup",
                                  "token", "csrf", "cookie", "password", "middleware")),
    ("CLIENT-SIDE.md", ("/components/", ".tsx", "webview", "postmessage", "innerhtml", "render",
                        "public/", "/app/(public)/")),
    ("SUPPLY-CHAIN-AND-RELEASE.md", ("package.json", "/.github/", "/workflows/", "dockerfile",
                                     "scripts/", "makefile", ".env")),
    ("CLOUD-AND-DEPLOYMENT.md", ("docker-compose", "k8s", "helm", "terraform", "vercel.json",
                                 "/infra/", "nginx", "caddy")),
    ("DATA-ISOLATION-AND-LIFECYCLE.md", ("migrations/", "/supabase/", "queries/", "rls", "tenant",
                                         "seed.sql", "backup", "export", "retention")),
    ("RESOURCE-EXHAUSTION-AND-AVAILABILITY.md", ("import", "upload", "xlsx", "csv", "buffer",
                                                 "rate-limit", "queue", "worker", "archive", "unzip")),
    ("PROTOCOLS-RPC-AND-MESSAGING.md", ("rpc", "grpc", "websocket", "/ws", "webhook", "broker",
                                        "subscriber", "stream")),
    ("DESKTOP-MOBILE-AND-LOCAL-IPC.md", ("android", "ios/", "electron", "deep-link", "/ipc",
                                         "binder", "xpc", "daemon")),
    ("checklists/LOGGING-ALERTING-AND-ERROR-HANDLING.md", ("log", "audit", "monitor", "alert",
                                                            "telemetry", "sentry", "error", "exception",
                                                            "handler")),
    ("MEMORY-SAFETY-AND-BINARY.md", (".c", ".cc", ".cpp", ".h", ".rs", "unsafe", "kernel", "ffi",
                                     "jni", "wasm")),
]
BUILTIN_EXCLUDES = [
    "**/node_modules/**", "**/.git/**", "**/dist/**", "**/build/**", "**/.next/**", "**/out/**",
    "**/coverage/**", "**/vendor/**", "**/.gradle/**", "**/*.min.js", "**/*.map", "**/*.lock",
    "**/package-lock.json", "**/pnpm-lock.yaml", "**/yarn.lock", "**/*.svg", "**/*.snap",
]
JSON_RE = re.compile(r"<<<SWARM_JSON\s*(.*?)\s*SWARM_JSON>>>", re.S)
_print_lock = threading.Lock()


def log(msg: str) -> None:
    with _print_lock:
        print(f"[{dt.datetime.now():%H:%M:%S}] {msg}", flush=True)


# ---------------------------------------------------------------- helpers

def resolve_repo(name: str) -> tuple[str, dict]:
    key = name.lower().strip()
    for rid, r in CFG["repos"].items():
        if key == rid or key in [a.lower() for a in r.get("aliases", [])]:
            return rid, r
    sys.exit(f"unknown repo '{name}'. Known: {', '.join(CFG['repos'])}")


def scan_dir(scan_id: str) -> Path:
    d = DATA / "scans" / scan_id
    if not (d / "scan.json").exists():
        sys.exit(f"no scan '{scan_id}' in {DATA / 'scans'}")
    return d


def load(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def save(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)


def git(repo: str, *args: str) -> str:
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", check=True).stdout


def _repair_json_strings(s: str) -> str:
    """Escape control chars and stray backslashes inside JSON strings.

    Models occasionally emit a raw newline or a `\\d`-style escape inside a string value; both are
    invalid JSON. Walk the text tracking string state and escape only what is illegal there.
    """
    out: list[str] = []
    i, n = 0, len(s)
    in_str = False
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\":
                nxt = s[i + 1] if i + 1 < n else ""
                if nxt in '"\\/bfnrt':
                    out.append(c); out.append(nxt); i += 2; continue
                if nxt == "u":
                    hexs = s[i + 2: i + 6]
                    if len(hexs) == 4 and all(h in "0123456789abcdefABCDEF" for h in hexs):
                        out.append(s[i: i + 6]); i += 6; continue
                out.append("\\\\"); i += 1; continue
            if c == "\n":
                out.append("\\n"); i += 1; continue
            if c == chr(13):
                out.append("\\r"); i += 1; continue
            if c == "\t":
                out.append("\\t"); i += 1; continue
            if c == '"':
                in_str = False
            out.append(c); i += 1; continue
        if c == '"':
            in_str = True
        out.append(c); i += 1
    return "".join(out)


def extract_json(text: str):
    m = JSON_RE.findall(text)
    candidates = list(reversed(m))
    # A model that restarts mid-answer leaves a truncated first block plus one end marker, so the
    # regex above hands back a broken candidate. Take every start marker up to the nearest end
    # marker as its own candidate, newest first.
    starts = [mm.start() for mm in re.finditer(r"<<<SWARM_JSON", text)]
    ends = [mm.start() for mm in re.finditer(r"SWARM_JSON>>>", text)]
    for st in reversed(starts):
        following = [e for e in ends if e > st]
        if following:
            candidates.append(text[st + len("<<<SWARM_JSON"): following[0]])
    if not candidates:  # fallback: last fenced json block, then outermost braces
        candidates = list(reversed(re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)))
        if "{" in text:
            candidates.append(text[text.index("{"): text.rindex("}") + 1])
    for c in candidates:
        for attempt in (c, _repair_json_strings(c)):
            try:
                return json.loads(attempt, strict=False)
            except json.JSONDecodeError:
                continue
    raise ValueError("no parseable SWARM_JSON block in agent output")



def run_agent(role: str, prompt: str, cwd: Path, log_path: Path) -> dict:
    """One Hermes one-shot with the role's pinned model. Returns parsed JSON (raises on failure)."""
    m = CFG["models"][role]
    hermes = shutil.which("hermes") or "hermes"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    qfile = log_path.with_suffix(".prompt.md")
    qfile.write_text(prompt, encoding="utf-8")
    cmd = [hermes, "chat", "--safe-mode", "-Q", "--oneshot", "--source", "tool",
           "-m", m["model"], "--provider", m["provider"], "--reasoning", m["reasoning"],
           "-t", "file", "--run-budget", str(m["run_budget_s"]), "--query-file", str(qfile)]
    proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=m["run_budget_s"] + 300,
                          env={**os.environ, "NO_COLOR": "1"})
    log_path.write_text(f"$ {' '.join(cmd)}\n# exit {proc.returncode}\n--- stdout\n{proc.stdout}\n"
                        f"--- stderr\n{proc.stderr}", encoding="utf-8")
    if "safety filter refused" in proc.stdout and "<<<SWARM_JSON" not in proc.stdout:
        raise RuntimeError(f"{role} REFUSED by Anthropic safety filter; see {log_path}")
    if proc.returncode != 0 and "<<<SWARM_JSON" not in proc.stdout:
        raise RuntimeError(f"{role} exited {proc.returncode}; see {log_path}")
    return extract_json(proc.stdout)


# ---------------------------------------------------------------- plan

def make_snapshot(repo_path: str, dest: Path, ref: str = "HEAD") -> dict:
    commit = git(repo_path, "rev-parse", ref + "^{commit}").strip()
    branch = git(repo_path, "rev-parse", "--abbrev-ref", "HEAD").strip() if ref == "HEAD" else ref
    dirty = [l for l in git(repo_path, "status", "--porcelain").splitlines() if l.strip()]
    tar_bytes = subprocess.run(["git", "-C", repo_path, "archive", "--format=tar", commit],
                               capture_output=True, check=True).stdout
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:  # nosemgrep: trailofbits.python.tarfile-extractall-traversal.tarfile-extractall-traversal
        # filter="data" (PEP 706) rejects absolute paths, ".." and links leaving dest; the tar is git archive output.
        tf.extractall(dest, filter="data")
    return {"commit": commit, "branch": branch, "uncommitted_changes_excluded": len(dirty)}


def cmd_plan(a) -> None:
    if a.scan:
        d = scan_dir(a.scan)
        meta = load(d / "scan.json")
        rid, r = resolve_repo(meta["repo"])
    else:
        rid, r = resolve_repo(a.repo)
        now = dt.datetime.now()
        commit = git(r["path"], "rev-parse", "--short=7", a.ref + "^{commit}").strip()
        sid = f"{rid}-{now:%Y%m%d-%H%M}-{commit}"
        d = DATA / "scans" / sid
        log(f"snapshot {r['path']} -> {d / 'snapshot'}")
        snap = make_snapshot(r["path"], d / "snapshot", a.ref)
        meta = {"id": sid, "repo": rid, "repo_path": r["path"], **snap,
                "created": now.isoformat(timespec="seconds"), "status": "planning",
                "models": CFG["models"], "plan_rounds": 0}
        save(d / "scan.json", meta)
    fb = ""
    if a.feedback:
        prev = (d / "plan.json").read_text(encoding="utf-8") if (d / "plan.json").exists() else "{}"
        fb = (f"OWNER FEEDBACK ON YOUR PREVIOUS PLAN (apply it):\n{a.feedback}\n\n"
              f"PREVIOUS PLAN:\n{prev}")
    prompt = (HERE / "prompts" / "plan.md").read_text(encoding="utf-8").format(
        repo=rid, commit=meta["commit"], snapshot=d / "snapshot", notes=r.get("notes", ""),
        feedback_block=fb, standards_catalog=standards_catalog())
    rnd = meta.get("plan_rounds", 0) + 1
    log(f"planner ({CFG['models']['planner']['model']}, {CFG['models']['planner']['reasoning']}) round {rnd}")
    plan = run_agent("planner", prompt, d / "snapshot", d / "logs" / f"plan-{rnd}.log")
    stats = selector_stats(d, plan)
    save(d / "plan.json", plan)
    meta.update(status="awaiting_approval", plan_rounds=rnd, selector_stats=stats)
    save(d / "scan.json", meta)
    (d / "threat-model.md").write_text(render_plan(meta, plan, stats), encoding="utf-8")
    print(f"\nSCAN {meta['id']} awaiting approval. Review: {d / 'threat-model.md'}")


def rg_cmd(sel: dict, excludes: list[str]) -> list[str]:
    rg = shutil.which("rg") or "rg"
    globs = [x for g in sel.get("globs") or [] for x in ("-g", g)]
    globs += [x for g in excludes for x in ("-g", "!" + g)]
    if sel.get("pattern") is None:
        return [rg, "--files", "--no-config", *globs, "."]
    cmd = [rg, "--json", "--no-config", "--max-columns", "300", "--max-columns-preview", *globs]
    if sel.get("case_insensitive"):
        cmd.append("-i")
    return cmd + ["-e", sel["pattern"], "."]


def run_selector(snapshot: Path, sel: dict, excludes: list[str]) -> list[dict]:
    """Deterministic: returns signals [{file, line, text, selector}]; raises on bad regex."""
    proc = subprocess.run(rg_cmd(sel, excludes), cwd=str(snapshot), capture_output=True,
                          text=True, encoding="utf-8", errors="replace")
    if proc.returncode not in (0, 1):
        raise ValueError(proc.stderr.strip()[:300])
    out = []
    if sel.get("pattern") is None:
        for f in proc.stdout.splitlines():
            if f.strip():
                out.append({"file": norm(f), "line": 0, "text": "(whole file selected)",
                            "selector": sel["id"]})
        return out
    for line in proc.stdout.splitlines():
        ev = json.loads(line)
        if ev.get("type") != "match":
            continue
        dat = ev["data"]
        text = dat["lines"].get("text") or ""
        out.append({"file": norm(dat["path"]["text"]), "line": dat["line_number"],
                    "text": text.strip()[:240], "selector": sel["id"]})
    return out


def norm(p: str) -> str:
    p = p.replace("\\", "/")
    return p[2:] if p.startswith("./") else p


def all_excludes(plan: dict) -> list[str]:
    return BUILTIN_EXCLUDES + list(plan.get("exclude_globs") or [])


# ---------------------------------------------------------------- standards (OWASP lists)

STANDARDS_FILE = HERE / "references" / "standards" / "standards.json"


def load_standards() -> list[dict]:
    try:
        return json.loads(STANDARDS_FILE.read_text(encoding="utf-8")).get("lists", [])
    except (OSError, json.JSONDecodeError):
        return []


def standards_catalog() -> str:
    """Compact catalog of the security top lists, injected into the plan and reduce prompts."""
    out = []
    for lst in load_standards():
        cats = "; ".join(f"{cid} {name}" for cid, name in lst["categories"])
        when = "always applies" if lst.get("always") else f"applies when {lst.get('applies_when', '')}"
        out.append(f"- `{lst['key']}` — {lst['name']} ({when}): {cats}")
    return "\n".join(out)


def _std_index() -> dict[str, tuple[str, str]]:
    """Canonical id -> (list key, category name); also maps short forms like A01 / API1 / LLM01."""
    idx: dict[str, tuple[str, str]] = {}
    for lst in load_standards():
        for cid, name in lst["categories"]:
            idx[cid.upper()] = (lst["key"], name)
            idx[cid.split(":")[0].upper()] = (lst["key"], name)
    return idx


def norm_std_ids(ids) -> list[str]:
    """Normalise model-supplied ids ("a01", "A01:2021", "API1") to catalog ids; drop unknown ones."""
    if isinstance(ids, str):
        ids = [ids]
    canon = {cid.split(":")[0].upper(): cid for lst in load_standards() for cid, _ in lst["categories"]}
    out = []
    for raw in ids or []:
        key = str(raw).strip().upper().split(":")[0].split(" ")[0]
        if key in canon and canon[key] not in out:
            out.append(canon[key])
    return out


def queued_selectors(batches: list[dict]) -> list[str]:
    return sorted({s["selector"] for b in batches for f in b.get("files", []) for s in f.get("signals", [])})


def standards_matrix(meta: dict, plan: dict, red: dict) -> list[str]:
    """One row per category of every applicable list: finding / lead only / checked / NOT checked.

    'checked' means a selector the planner tagged with that category matched files this run actually
    batched. A category nobody looked for is reported as not checked — silence is not a clean bill.
    """
    lists = load_standards()
    if not lists:
        return []
    live = [f for f in red.get("findings", []) if _verdict(f) != "refuted"]
    live += [c for c in red.get("chains", []) if _verdict(c) != "refuted"]
    hits: dict[str, list[str]] = {}
    for f in live:
        for cid in norm_std_ids(f.get("owasp")):
            hits.setdefault(cid, []).append(str(f.get("id", "?")))
    leads: dict[str, int] = {}
    for u in red.get("unvalidated") or []:
        for cid in norm_std_ids(u.get("owasp")):
            leads[cid] = leads.get(cid, 0) + 1
    queued = set(meta.get("selectors_queued") or [])
    checked: dict[str, list[str]] = {}
    for sel in plan.get("selectors", []):
        if sel.get("id") in queued:
            for cid in norm_std_ids(sel.get("owasp")):
                checked.setdefault(cid, []).append(sel["id"])
    deps = meta.get("deps") or {}
    wanted = {k for k in (plan.get("standards") or []) if isinstance(k, str)}
    used = {cid for cid in list(hits) + list(leads) + list(checked)}
    L = ["## Security top lists", "",
         "_Each category of the lists that apply to this codebase. **not checked** means no selector "
         "looked for it in this run — it is unreviewed, not clean._", ""]
    for lst in lists:
        ids = [cid for cid, _ in lst["categories"]]
        if not (lst.get("always") or lst["key"] in wanted or any(i in used for i in ids)):
            continue
        L += [f"**{lst['name']}**", "", "| category | status |", "|---|---|"]
        for cid, name in lst["categories"]:
            if cid in hits:
                st = "finding: " + ", ".join(hits[cid])
            elif cid in leads:
                st = f"lead only ({leads[cid]} unvalidated)"
            elif cid in checked:
                st = "checked, nothing found (" + ", ".join(f"`{s}`" for s in checked[cid][:4]) + ")"
            else:
                st = "**not checked**"
            if cid == "A03:2025" and deps.get("ran"):
                n = deps.get("vulnerable_packages", 0)
                st = (f"dependency scan: {n} vulnerable packages" if st == "**not checked**"
                      else st + f" · dependency scan: {n} vulnerable packages")
                if cid not in checked and cid not in hits:
                    st += " (CI/build pipeline not reviewed)"
            L.append(f"| {cid} {name} | {st} |")
        L.append("")
    return L


# ---------------------------------------------------------------- dependency scan (OSV-Scanner)

OSV_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}


def osv_bin() -> str | None:
    p = (CFG["scan"].get("osv_scanner_path") or "").strip()
    if p:
        return p
    return shutil.which("osv-scanner")


def _osv_band(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    return "CRITICAL" if s >= 9 else "HIGH" if s >= 7 else "MEDIUM" if s >= 4 else "LOW" if s > 0 else "UNKNOWN"


def dependency_scan(d: Path) -> dict:
    """Known-vulnerable dependencies in the snapshot's lockfiles/manifests via OSV-Scanner v2.

    Deterministic, no model call. Package names and versions are sent to the osv.dev API. Missing
    scanner or a disabled scan is recorded, never silently treated as 'no vulnerable packages'.
    """
    if not CFG["scan"].get("deps_scan", True):
        return {"ran": False, "reason": "disabled (scan.deps_scan = false)"}
    exe = osv_bin()
    if not exe:
        return {"ran": False, "reason": "osv-scanner not found (install it or set scan.osv_scanner_path)"}
    try:
        proc = subprocess.run([exe, "scan", "source", "-r", "--format", "json", "."], cwd=str(d / "snapshot"),
                              capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=int(CFG["scan"].get("deps_timeout_s", 600)))
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ran": False, "reason": f"osv-scanner failed to run: {str(e)[:200]}"}
    if proc.returncode == 128:
        return {"ran": True, "packages_scanned": 0, "vulnerable_packages": 0, "vulns": [],
                "note": "no lockfiles or manifests OSV-Scanner understands"}
    if proc.returncode not in (0, 1):
        return {"ran": False, "reason": f"osv-scanner exit {proc.returncode}: {proc.stderr.strip()[-300:]}"}
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {"ran": False, "reason": "osv-scanner output was not JSON"}
    snap = str((d / "snapshot").resolve()).replace("\\", "/").lower()
    vulns = []
    for res in data.get("results") or []:
        src = str((res.get("source") or {}).get("path", "")).replace("\\", "/")
        if src.lower().startswith(snap):
            src = src[len(snap):].lstrip("/")
        for p in res.get("packages") or []:
            pkg = p.get("package") or {}
            groups = p.get("groups") or [{"ids": [v.get("id")]} for v in p.get("vulnerabilities") or []]
            by_id = {v.get("id"): v for v in p.get("vulnerabilities") or []}
            for g in groups:
                ids = [i for i in g.get("ids") or [] if i]
                aliases = sorted({a for i in ids for a in (by_id.get(i) or {}).get("aliases") or []
                                  if str(a).startswith("CVE-")})
                fixed = sorted({ev["fixed"] for i in ids for aff in (by_id.get(i) or {}).get("affected") or []
                                if (aff.get("package") or {}).get("name") == pkg.get("name")
                                for rng in aff.get("ranges") or [] for ev in rng.get("events") or []
                                if ev.get("fixed")})
                summary = next(((by_id.get(i) or {}).get("summary") for i in ids
                                if (by_id.get(i) or {}).get("summary")), "")
                vulns.append({"package": pkg.get("name"), "version": pkg.get("version"),
                              "ecosystem": pkg.get("ecosystem"), "source": src, "ids": ids,
                              "cves": aliases, "cvss": g.get("max_severity") or "",
                              "severity": _osv_band(g.get("max_severity")),
                              "fixed": fixed[:3], "summary": str(summary)[:160]})
    vulns.sort(key=lambda v: (OSV_SEV_ORDER.get(v["severity"], 4), v["package"] or ""))
    n_pkgs = sum(len(r.get("packages") or []) for r in data.get("results") or [])
    return {"ran": True, "vulnerable_packages": n_pkgs, "advisories": len(vulns), "vulns": vulns}


def run_deps(d: Path, meta: dict) -> dict:
    deps = dependency_scan(d)
    save(d / "deps.json", deps)
    meta["deps"] = {k: deps.get(k) for k in ("ran", "reason", "vulnerable_packages", "advisories", "note")
                    if deps.get(k) is not None}
    log("dependency scan: " + (f"{deps.get('vulnerable_packages', 0)} vulnerable packages, "
                               f"{deps.get('advisories', 0)} advisories" if deps.get("ran")
                               else f"not run ({deps.get('reason')})"))
    return deps


def deps_section(d: Path | None, meta: dict) -> list[str]:
    info = meta.get("deps")
    if not info:
        return []
    L = ["## Dependency vulnerabilities (OSV-Scanner)", ""]
    if not info.get("ran"):
        return L + [f"_Not run: {info.get('reason')}. Known-vulnerable dependencies were NOT checked._", ""]
    deps = load(d / "deps.json") if d and (d / "deps.json").exists() else {"vulns": []}
    vulns = deps.get("vulns") or []
    if not vulns:
        return L + [f"No known-vulnerable dependencies found{' (' + info['note'] + ')' if info.get('note') else ''}.", ""]
    L += [f"{info.get('vulnerable_packages', 0)} packages with {len(vulns)} advisories. Not counted in "
          "P0–P3: these are known CVEs in third-party code; whether the vulnerable function is reachable "
          "from this app was not checked.", "",
          "| severity | package | version | fixed in | advisories | lockfile |", "|---|---|---|---|---|---|"]
    cap = int(CFG["scan"].get("deps_max_rows", 60))
    for v in vulns[:cap]:
        adv = ", ".join((v.get("cves") or [])[:2] or v.get("ids", [])[:2])
        L.append(f"| {v['severity']} {v.get('cvss') or ''} | {v['package']} | {v['version']} | "
                 f"{', '.join(v.get('fixed') or []) or '—'} | {adv} | `{v.get('source', '')}` |")
    if len(vulns) > cap:
        L.append(f"| … | {len(vulns) - cap} more in `deps.json` | | | | |")
    return L + [""]


# ---------------------------------------------------------------- attack playbook / coverage

def _read_class(name: str) -> str:
    p = (HERE / "references" / name) if "/" in name else (CLASSES_DIR / name)
    try:
        return p.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def attack_playbook(batch: dict) -> str:
    """Curated hunting checklists for one batch: the core class file always, plus up to
    PLAYBOOK_MAX_COMPANIONS domain companions chosen by path heuristics (deterministic).

    Ported from cloudflare/security-audit-skill's companion selection, which picks a domain file
    because reconnaissance found the trust boundary it describes - never because a language or a
    dependency name merely appears. Same rule here: a hint must match the batch's own paths.
    """
    files = [f["file"].lower() for f in batch.get("files", [])]
    if not files:
        return ""
    core = _read_class("ATTACK-CLASSES.md")
    scored = []
    for name, hints in COMPANION_HINTS:
        hits = sum(1 for path in files if any(h in path for h in hints))
        if hits:
            scored.append((hits, name))
    scored.sort(key=lambda t: (-t[0], t[1]))
    chosen = [name for _, name in scored[:PLAYBOOK_MAX_COMPANIONS]]
    parts = ["ATTACK-CLASS PLAYBOOK (curated checklists; use them to direct your reading, not as "
             "a checklist to tick - an item only becomes a finding if you can trace the reachable "
             "path).", "", "## Core classes", "", core]
    used = len(core)
    for name in chosen:
        body = _read_class(name)
        if not body or used + len(body) > PLAYBOOK_MAX_CHARS:
            continue
        parts += ["", f"## Domain companion: `{name}` (this batch touches the boundary it covers)", "",
                  body]
        used += len(body)
    return "\n".join(parts)


def coverage(d: Path, plan: dict, queued: set[str] | None = None) -> dict:
    """Deterministic coverage ledger: in-scope files, files any selector matched, and the ones
    NO selector matched (which therefore were never read by any worker).

    The gap this records is real and was the whole point of adopting Cloudflare's ledger: on a
    selective scan, 'no findings' must never be read as 'nothing there'.
    """
    snap, ex = d / "snapshot", all_excludes(plan)
    matched: set[str] = set()
    per_selector: dict[str, int] = {}
    for sel in plan.get("selectors", []):
        try:
            fs = {s["file"] for s in run_selector(snap, sel, ex)}
        except ValueError as e:
            per_selector[sel.get("id", "?")] = -1
            log(f"coverage: selector {sel.get('id')} errored: {str(e)[:80]}")
            continue
        per_selector[sel.get("id", "?")] = len(fs)
        matched |= fs
    listing = subprocess.run([shutil.which("rg") or "rg", "--files", "--no-config"] +
                             sum([["-g", "!" + g] for g in ex], []) + ["."],
                             cwd=str(snap), capture_output=True, text=True,
                             encoding="utf-8", errors="replace").stdout
    in_scope = sorted({norm(l.strip()) for l in listing.splitlines() if l.strip()})
    unmatched = [f for f in in_scope if f not in matched]
    by_dir: dict[str, int] = {}
    for f in unmatched:
        parts = f.split("/")
        key = "/".join(parts[:2]) if len(parts) > 1 else "(root)"
        by_dir[key] = by_dir.get(key, 0) + 1
    matched_in_scope = matched & set(in_scope)
    # A scoped run (hand-built queue, --max-batches) reviews only part of what the selectors
    # matched. That is a different hole from "no selector matched": the files are eligible but
    # were not batched. Both must be visible, or a partial run reads as a complete one.
    skipped_by_scope = sorted(matched_in_scope - queued) if queued else []
    return {
        "repo": d.name,
        "in_scope_files": len(in_scope),
        "matched_files": len(matched_in_scope),
        "queued_files": len(queued) if queued else None,
        "matched_not_queued": len(skipped_by_scope),
        "matched_not_queued_sample": skipped_by_scope[:500],
        "unmatched_files": len(unmatched),
        "files_per_selector": per_selector,
        "unmatched_by_dir": dict(sorted(by_dir.items(), key=lambda t: -t[1])[:25]),
        "unmatched_sample": unmatched[:500],
        "note": ("unmatched_sample = in scope, matched no selector. matched_not_queued_sample = "
                 "selector-matched but not batched by this run's queue. Neither set was read by any "
                 "worker: they are unreviewed, not clean."),
    }


def _plan_of(d: Path) -> dict:
    p = d / "plan.json"
    return load(p) if p.exists() else {}


def cmd_deps(a) -> None:
    d = scan_dir(a.scan)
    meta = load(d / "scan.json")
    deps = run_deps(d, meta)
    save(d / "scan.json", meta)
    if (d / "findings.json").exists():
        (d / "report.md").write_text(render_report(meta, load(d / "findings.json"), d, _plan_of(d)),
                                     encoding="utf-8")
    print(json.dumps({k: v for k, v in deps.items() if k != "vulns"}, indent=2))
    print(f"\ndeps: {d / 'deps.json'}")


def cmd_coverage(a) -> None:
    d = scan_dir(a.scan)
    plan = load(d / "plan.json")
    queued = None
    qpath = d / "queue.json"
    if qpath.exists():
        queued = {f["file"] for b in load(qpath).get("batches", []) for f in b.get("files", [])}
    cov = coverage(d, plan, queued)
    save(d / "coverage-ledger.json", cov)
    print(f"in scope {cov['in_scope_files']} · matched by selectors {cov['matched_files']} · "
          f"queued {cov['queued_files']} · matched-but-not-queued {cov['matched_not_queued']} · "
          f"UNREVIEWED (no selector) {cov['unmatched_files']}")
    for k, v in list(cov["unmatched_by_dir"].items())[:10]:
        print(f"  {v:5d}  {k}")
    print(f"\nledger: {d / 'coverage-ledger.json'}")


def selector_stats(d: Path, plan: dict) -> dict:
    snap, ex = d / "snapshot", all_excludes(plan)
    stats, files = {}, set()
    for sel in plan.get("selectors", []):
        try:
            sig = run_selector(snap, sel, ex)
            fs = {s["file"] for s in sig}
            files |= fs
            stats[sel["id"]] = {"matches": len(sig), "files": len(fs)}
        except ValueError as e:
            stats[sel["id"]] = {"error": str(e)}
    total = subprocess.run([shutil.which("rg") or "rg", "--files", "--no-config"] +
                           sum([["-g", "!" + g] for g in ex], []) + ["."], cwd=str(snap),
                           capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    n_total = len([l for l in total.splitlines() if l.strip()])
    return {"per_selector": stats, "files_in_scope": n_total, "files_selected": len(files)}


def render_plan(meta: dict, plan: dict, stats: dict) -> str:
    lines = [f"# Threat model: {meta['repo']} @ {meta['commit'][:7]} ({meta['branch']})", "",
             f"Scan `{meta['id']}` · planner round {meta['plan_rounds']} · "
             f"{meta['uncommitted_changes_excluded']} uncommitted changes NOT scanned (HEAD only)", "",
             plan.get("threat_model", ""), "", "## Investigation guidance", "",
             plan.get("investigation_guidance", ""), "", "## Severity criteria", "",
             plan.get("severity_criteria", ""), "",
             f"## Selectors: {stats['files_selected']} of {stats['files_in_scope']} files selected", "",
             "| id | category | matches | files | what it catches |", "|---|---|---|---|---|"]
    for s in plan.get("selectors", []):
        st = stats["per_selector"].get(s["id"], {})
        m = st.get("error") and f"ERROR: {st['error']}" or st.get("matches", "?")
        lines.append(f"| `{s['id']}` | {s.get('category', '')} | {m} | {st.get('files', '')} | "
                     f"{s.get('description', '').replace('|', '/')} |")
    lines += ["", "Excluded: " + ", ".join(f"`{g}`" for g in plan.get("exclude_globs") or []) or "-"]
    return "\n".join(lines) + "\n"


def cmd_approve(a) -> None:
    d = scan_dir(a.scan)
    meta = load(d / "scan.json")
    if meta["status"] not in ("awaiting_approval", "approved"):
        sys.exit(f"scan is '{meta['status']}', not awaiting approval")
    bad = [k for k, v in meta["selector_stats"]["per_selector"].items() if "error" in v]
    if bad:
        sys.exit(f"selectors with regex errors: {bad}. Re-plan with --feedback first.")
    meta.update(status="approved", approved=dt.datetime.now().isoformat(timespec="seconds"))
    save(d / "scan.json", meta)
    print(f"approved {meta['id']}")


# ---------------------------------------------------------------- shard / map / reduce

def shard(d: Path, plan: dict, batch_size: int) -> list[dict]:
    by_file: dict[str, list[dict]] = {}
    for sel in plan["selectors"]:
        for s in run_selector(d / "snapshot", sel, all_excludes(plan)):
            by_file.setdefault(s["file"], []).append(s)
    files = sorted(by_file)
    batches = []
    for i in range(0, len(files), batch_size):
        chunk = files[i:i + batch_size]
        batches.append({"id": f"B{len(batches) + 1:03d}",
                        "files": [{"file": f, "signals": sorted(by_file[f], key=lambda s: s["line"])}
                                  for f in chunk]})
    return batches


def batch_listing(batch: dict) -> str:
    cap = CFG["scan"]["max_signals_per_file"]
    out = []
    for f in batch["files"]:
        sig = f["signals"]
        out.append(f"\n### {f['file']}  ({len(sig)} signals)")
        for s in sig[:cap]:
            out.append(f"- [{s['selector']}] L{s['line']}: {s['text']}")
        if len(sig) > cap:
            out.append(f"- ... {len(sig) - cap} more signals; read the whole file")
    return "\n".join(out)


def map_one(d: Path, meta: dict, plan: dict, batch: dict) -> dict:
    out = d / "map" / f"{batch['id']}.json"
    if out.exists():
        return load(out)
    prompt = (HERE / "prompts" / "map.md").read_text(encoding="utf-8").format(
        repo=meta["repo"], commit=meta["commit"], snapshot=d / "snapshot",
        threat_model=plan.get("threat_model", ""),
        investigation_guidance=plan.get("investigation_guidance", ""),
        severity_criteria=plan.get("severity_criteria", ""), batch_id=batch["id"],
        attack_playbook=attack_playbook(batch),
        batch_listing=batch_listing(batch))
    err = None
    for attempt in (1, 2):
        try:
            res = run_agent("mapper", prompt, d / "snapshot", d / "logs" / f"{batch['id']}-{attempt}.log")
            res["batch"] = batch["id"]
            res.setdefault("findings", [])
            for f in res["findings"]:
                f["source_batch"] = batch["id"]
            save(out, res)
            log(f"{batch['id']} done: {len(res['findings'])} findings")
            return res
        except Exception as e:  # noqa: BLE001 — worker failures are recorded, not fatal
            err = str(e)
            log(f"{batch['id']} attempt {attempt} failed: {err[:160]}")
    res = {"batch": batch["id"], "failed": True, "error": err, "findings": []}
    save(d / "map" / f"{batch['id']}.failed.json", res)
    return res


# ---------------------------------------------------------------- refute (one pass, before reduce)

def _claim_hash(payload) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False)
                          .encode("utf-8")).hexdigest()[:16]


def refute_pre(d: Path, meta: dict, plan: dict, results: list) -> tuple[list[dict], list[dict]]:
    """ONE refuter agent per mapper report (one report per batch), before the reduce.

    Design note: not one refuter over everything — every review worker's
    report gets its own adversarial agent. Refuted findings are dropped from the reduce input; all
    verdicts stay in refute/<batch>.json for audit. Per-report caching: an unchanged report is not
    re-refuted.
    """
    reports = [r for r in results if r.get("findings")]
    if not reports:
        return [], []
    conc = CFG["scan"]["concurrency"]
    log(f"refute before reduce: {len(reports)} mapper reports, one agent each "
        f"({CFG['models']['refute']['model']}, {CFG['models']['refute']['reasoning']})")
    with cf.ThreadPoolExecutor(max_workers=conc) as ex:
        all_verdicts = list(ex.map(lambda r: refute_one(d, meta, plan, r), reports))
    kept, refuted = [], []
    for report, verdicts in zip(reports, all_verdicts):
        by = {}
        for v in verdicts:
            if isinstance(v, dict):
                try:
                    by[int(v.get("finding"))] = v
                except (TypeError, ValueError):
                    continue
        for i, f in enumerate(report["findings"], 1):
            f["raw_ref"] = f"{report['batch']}#{i}"
            v = by.get(i)
            if v and str(v.get("verdict", "")).lower() == "refuted":
                f["pre_refute"] = v
                refuted.append(f)
            else:
                kept.append(f)
    log(f"refute done: {len(kept)} stand, {len(refuted)} refuted before reduce")
    return kept, refuted


def _stdout_of(log_path: Path) -> str:
    t = log_path.read_text(encoding="utf-8", errors="replace")
    i, j = t.find("--- stdout"), t.find("--- stderr")
    return t[i + 10:j] if i >= 0 and j > i else ""


def _salvage_verdicts(text: str):
    """Last resort: pull the `verdicts` array out of a reply whose surrounding JSON is broken.

    Flash-class models occasionally repeat the `notes` key or leak extra strings after it; the
    verdict array itself is usually intact. Returns None when even that does not parse.
    """
    k = text.find('"verdicts"')
    if k < 0:
        return None
    b = text.find("[", k)
    if b < 0:
        return None
    depth, in_str, esc = 0, False, False
    for i in range(b, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                try:
                    arr = json.loads(text[b:i + 1], strict=False)
                except json.JSONDecodeError:
                    return None
                return arr if isinstance(arr, list) else None
    return None


def refute_one(d: Path, meta: dict, plan: dict, report: dict) -> list:
    bid = report.get("batch", "B?")
    findings = [_strip_runtime(f) for f in report.get("findings", [])]
    digest = _claim_hash({"batch": bid, "findings": findings})
    out = d / "refute" / f"{bid}.json"
    if out.exists():
        cached = load(out)
        if cached.get("digest") == digest:
            verdicts = cached.get("verdicts") or []
            nref = sum(1 for v in verdicts if str(v.get("verdict", "")).lower() == "refuted")
            log(f"refute {bid}: cached ({len(findings)} findings, {nref} refuted)")
            return verdicts
    prompt = (HERE / "prompts" / "refute.md").read_text(encoding="utf-8").format(
        repo=meta["repo"], commit=meta["commit"], snapshot=d / "snapshot",
        threat_model=plan.get("threat_model", ""), severity_criteria=plan.get("severity_criteria", ""),
        batch_id=bid, n_findings=len(findings),
        findings_json=json.dumps(findings, indent=1, ensure_ascii=False))
    err = None
    for attempt in (1, 2):
        try:
            res = run_agent("refute", prompt, d / "snapshot", d / "logs" / f"refute-{bid}-{attempt}.log")
            verdicts = res.get("verdicts") or []
            save(out, {"batch": bid, "digest": digest, "verdicts": verdicts})
            nref = sum(1 for v in verdicts if str(v.get("verdict", "")).lower() == "refuted")
            log(f"refute {bid}: {len(findings) - nref} stand, {nref} refuted")
            return verdicts
        except Exception as e:  # noqa: BLE001 — a broken refuter must not lose findings
            err = str(e)
            log(f"refute {bid} attempt {attempt} failed: {err[:140]}")
            salv = _salvage_verdicts(_stdout_of(d / "logs" / f"refute-{bid}-{attempt}.log"))
            if salv:
                save(out, {"batch": bid, "digest": digest, "verdicts": salv})
                nref = sum(1 for v in salv if isinstance(v, dict)
                           and str(v.get("verdict", "")).lower() == "refuted")
                log(f"refute {bid}: salvaged {len(salv)} verdicts from a malformed reply "
                    f"({nref} refuted)")
                return salv
    log(f"refute {bid} failed; its findings pass through unfiltered")
    return []


# ---------------------------------------------------------------- verify (one agent per claim)

def verify_claims(d: Path, meta: dict, plan: dict, red: dict) -> dict:
    """One FRESH agent per claim (every finding and every chain) after the reduce.

    Owner choice 2026-10-18: absolute certainty — a claim is 'confirmed' only when its own
    independent agent could not falsify it. Results cache per claim; re-running only redoes
    missing or changed claims (swarm.py verify <scan>).
    """
    findings, chains = red.get("findings", []), red.get("chains", [])
    # `unvalidated` claims carry no severity by design and are never sent to a verifier: the
    # missing fact is outside the repository, so a source-only verifier could only guess.
    if not findings and not chains:
        return red
    by_id = {f.get("id"): f for f in findings}
    claims = [("finding", f) for f in findings] + [("chain", c) for c in chains]
    log(f"verify: {len(findings)} findings + {len(chains)} chains, one agent per claim "
        f"({CFG['models']['verify']['model']}, {CFG['models']['verify']['reasoning']})")
    conc = CFG["scan"]["concurrency"]
    with cf.ThreadPoolExecutor(max_workers=conc) as ex:
        res = list(ex.map(lambda kc: verify_one(d, meta, plan, kc[0], kc[1], by_id), claims))
    for (kind, claim), v in zip(claims, res):
        claim["verification"] = v
    counts = {k: sum(1 for (kd, _c), v in zip(claims, res)
                     if kd == "finding" and v.get("verdict") == k)
              for k in ("confirmed", "refuted", "unverified")}
    meta.update(verify_counts=counts)
    log(f"verify done: findings {counts['confirmed']} confirmed, {counts['refuted']} refuted, "
        f"{counts['unverified']} unverified")
    return red


def _strip_runtime(obj: dict) -> dict:
    """Drop keys this tool attaches after a run, so a cached verdict never invalidates itself."""
    return {k: v for k, v in obj.items() if k not in ("verification", "pre_refute")}


def verify_one(d: Path, meta: dict, plan: dict, kind: str, claim: dict, by_id: dict) -> dict:
    cid = f"{kind}-{claim.get('id', '?')}"
    payload = {"claim": _strip_runtime(claim)}
    if kind == "chain":
        payload["step_details"] = [_strip_runtime(by_id.get(s, {"id": s, "MISSING_FROM_REPORT": True}))
                                   for s in claim.get("steps", [])]
    digest = _claim_hash(payload)
    out = d / "verify" / f"{cid}.json"
    if out.exists():
        cached = load(out)
        if cached.get("claim_digest") == digest:
            return cached
    prompt = (HERE / "prompts" / "verify.md").read_text(encoding="utf-8").format(
        repo=meta["repo"], commit=meta["commit"], snapshot=d / "snapshot",
        threat_model=plan.get("threat_model", ""), claim_kind=kind, claim_id=claim.get("id", "?"),
        claim_json=json.dumps(payload, indent=1, ensure_ascii=False))
    err = None
    for attempt in (1, 2):
        try:
            res = run_agent("verify", prompt, d / "snapshot", d / "logs" / f"{cid}-{attempt}.log")
            v = str(res.get("verdict", "unverified")).lower()
            res["verdict"] = v if v in ("confirmed", "refuted", "unverified") else "unverified"
            res.setdefault("reason", "")
            res.setdefault("evidence", [])
            res["claim_digest"] = digest
            save(out, res)
            log(f"{cid}: {res['verdict']}")
            return res
        except Exception as e:  # noqa: BLE001 — a broken verifier must not read as confirmed
            err = str(e)
            log(f"{cid} attempt {attempt} failed: {err[:140]}")
    return {"claim": claim.get("id"), "verdict": "unverified",
            "reason": f"verifier failed: {err}", "evidence": [], "claim_digest": digest}


def cmd_verify(a) -> None:
    d = scan_dir(a.scan)
    meta, plan = load(d / "scan.json"), load(d / "plan.json")
    red = load(d / "findings.json")
    red = verify_claims(d, meta, plan, red)
    save(d / "findings.json", red)
    (d / "report.md").write_text(render_report(meta, red, d, _plan_of(d)), encoding="utf-8")
    save(d / "scan.json", meta)
    print(f"\nREPORT {d / 'report.md'}")


def cmd_run(a) -> None:
    d = scan_dir(a.scan)
    meta = load(d / "scan.json")
    if meta["status"] not in ("approved", "mapping", "refuting", "reducing", "verifying", "done") and not a.force:
        sys.exit(f"scan is '{meta['status']}'; approve it first (or --force)")
    plan = load(d / "plan.json")
    bs = a.batch_size or CFG["scan"]["batch_size"]
    qpath = d / "queue.json"
    if not qpath.exists():
        batches = shard(d, plan, bs)
        save(qpath, {"batch_size": bs, "batches": batches})
    batches = load(qpath)["batches"]
    if a.max_batches:
        batches = batches[: a.max_batches]
    for stale in (d / "map").glob("*.failed.json"):  # failed batches get retried on re-run
        stale.unlink()
    n_files = sum(len(b["files"]) for b in batches)
    meta.update(status="mapping", batches=len(batches), files_queued=n_files,
                selectors_queued=queued_selectors(batches))
    run_deps(d, meta)
    cov = None
    try:  # coverage ledger: what NO selector matched, i.e. what nobody will read
        queued = {f["file"] for b in batches for f in b.get("files", [])}
        cov = coverage(d, plan, queued)
        save(d / "coverage-ledger.json", cov)
        meta["coverage"] = {k: cov[k] for k in
                            ("in_scope_files", "matched_files", "queued_files", "matched_not_queued",
                             "unmatched_files", "unmatched_by_dir")}
        log(f"coverage: {cov['matched_files']} of {cov['in_scope_files']} in-scope files matched a "
            f"selector · queued {cov['queued_files']} · not-queued {cov['matched_not_queued']} · "
            f"no-selector {cov['unmatched_files']}")
    except Exception as e:  # noqa: BLE001 — a broken ledger must not stop the scan, only warn
        log(f"coverage ledger failed: {str(e)[:140]}")
    save(d / "scan.json", meta)
    conc = a.concurrency or CFG["scan"]["concurrency"]
    log(f"map: {len(batches)} batches / {n_files} files, {conc} parallel "
        f"({CFG['models']['mapper']['model']}, {CFG['models']['mapper']['reasoning']})")
    with cf.ThreadPoolExecutor(max_workers=conc) as ex:
        results = list(ex.map(lambda b: map_one(d, meta, plan, b), batches))
    failed = [r["batch"] for r in results if r.get("failed")]
    findings = [f for r in results for f in r.get("findings", [])]
    raw_n = len(findings)
    meta.update(status="refuting", map_failed=failed, raw_findings=raw_n)
    save(d / "scan.json", meta)
    log(f"map done: {raw_n} raw findings, {len(failed)} failed batches {failed}")
    findings, pre_refuted = refute_pre(d, meta, plan, results)
    meta.update(status="reducing", refuted_before_reduce=len(pre_refuted),
                findings_after_refute=len(findings))
    save(d / "scan.json", meta)
    red = reduce_(d, meta, plan, results, findings)
    red["pre_refuted"] = [{"raw_ref": f.get("raw_ref"), "title": f.get("title"),
                           "reason": (f.get("pre_refute") or {}).get("reason", "")}
                          for f in pre_refuted]
    meta.update(status="verifying")
    save(d / "scan.json", meta)
    red = verify_claims(d, meta, plan, red)
    save(d / "findings.json", red)
    (d / "report.md").write_text(render_report(meta, red, d, _plan_of(d)), encoding="utf-8")
    meta.update(status="done", finished=dt.datetime.now().isoformat(timespec="seconds"))
    save(d / "scan.json", meta)
    print(f"\nREPORT {d / 'report.md'}")


def reduce_(d: Path, meta: dict, plan: dict, results: list, findings: list) -> dict:
    if not findings:
        red = {"summary": "No worker reported a finding.", "findings": [], "chains": [], "dismissed": []}
    else:
        prompt = (HERE / "prompts" / "reduce.md").read_text(encoding="utf-8").format(
            repo=meta["repo"], commit=meta["commit"], snapshot=d / "snapshot",
            threat_model=plan.get("threat_model", ""), severity_criteria=plan.get("severity_criteria", ""),
            n_findings=len(findings), n_batches=len([r for r in results if r.get("findings")]),
            findings_json=json.dumps(findings, indent=1, ensure_ascii=False),
            standards_catalog=standards_catalog())
        log(f"reduce ({CFG['models']['reducer']['model']}, {CFG['models']['reducer']['reasoning']})")
        try:
            red = run_agent("reducer", prompt, d / "snapshot", d / "logs" / "reduce.log")
        except Exception as e:  # noqa: BLE001 — keep raw findings rather than lose the scan
            log(f"reduce failed: {e}; report falls back to raw findings")
            red = {"summary": f"REDUCER FAILED ({e}). Raw, undeduplicated worker findings below.",
                   "findings": [{"id": f"R{i + 1}", "priority": {"critical": "P0", "high": "P1", "medium": "P2"}
                                 .get(f.get("severity"), "P3"), **f} for i, f in enumerate(findings)],
                   "chains": [], "dismissed": [], "reducer_failed": True}
    return red


def _verdict(obj: dict) -> str:
    return str((obj.get("verification") or {}).get("verdict", "")).lower()


def render_report(meta: dict, red: dict, d: Path | None = None, plan: dict | None = None) -> str:
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    fs = sorted(red.get("findings", []), key=lambda f: order.get(f.get("priority"), 9))
    live = [f for f in fs if _verdict(f) != "refuted"]
    refuted = [f for f in fs if _verdict(f) == "refuted"]
    chains = red.get("chains", [])
    live_chains = [c for c in chains if _verdict(c) != "refuted"]
    refuted_chains = [c for c in chains if _verdict(c) == "refuted"]
    counts = {p: sum(1 for f in live if f.get("priority") == p) for p in order}
    vc = {k: sum(1 for f in fs if _verdict(f) == k) for k in ("confirmed", "refuted", "unverified")}
    st = meta.get("selector_stats", {})
    pre = red.get("pre_refuted") or []
    L = [f"# Security Swarm report: {meta['repo']} @ {meta['commit'][:7]}", "",
         f"Scan `{meta['id']}` · branch {meta['branch']} · HEAD only "
         f"({meta['uncommitted_changes_excluded']} uncommitted changes not scanned)", "",
         f"**Coverage:** {meta.get('files_queued', '?')} files investigated in {meta.get('batches', '?')} batches "
         f"(selected by {len(st.get('per_selector', {}))} selectors out of {st.get('files_in_scope', '?')} files in scope). "
         f"Failed batches: {', '.join(meta.get('map_failed') or []) or 'none'}.", ""]
    cov = meta.get("coverage") or {}
    if cov:
        top = list((cov.get("unmatched_by_dir") or {}).items())[:5]
        L += [f"**Not reviewed:** {cov.get('unmatched_files', '?')} of {cov.get('in_scope_files', '?')} "
              f"in-scope files matched no selector, so no worker read them — they are unreviewed, "
              f"not clean. Worst directories: "
              + ", ".join(f"`{d}` ({n})" for d, n in top) + ".", ""]
        if cov.get("queued_files") is not None:
            L += [f"**Scope of this run:** {cov['queued_files']} of {cov['matched_files']} "
                  f"selector-matched files were batched"
                  + (f" — {cov['matched_not_queued']} matched files were NOT scanned (scoped run)."
                     if cov.get("matched_not_queued") else "."), ""]
    L += [f"**Findings:** P0 {counts['P0']} · P1 {counts['P1']} · P2 {counts['P2']} · P3 {counts['P3']} · "
          f"chains {len(live_chains)} · dismissed {len(red.get('dismissed', []))}"
          + (f" · unvalidated {len(red.get('unvalidated') or [])}" if red.get("unvalidated") else ""), "",
          f"**Verification:** {vc['confirmed']} confirmed · {vc['unverified']} unverified · "
          f"{vc['refuted']} refuted after reduce · {len(pre)} refuted before reduce "
          f"(one independent agent per claim)", "",
          "## Summary", "", red.get("summary", ""), ""]
    if live_chains:
        L += ["## Attack chains", ""]
        for c in live_chains:
            v = _verdict(c)
            L.append(f"- **{c.get('id')} [{c.get('priority')}] {c.get('title')}**"
                     f"{' · verified: ' + v if v else ''} — steps {' → '.join(c.get('steps', []))}. "
                     f"{c.get('impact', '')}")
            if (c.get("verification") or {}).get("reason"):
                L.append(f"  - verifier: {c['verification'].get('reason')}")
        L.append("")
    L += standards_matrix(meta, plan or {}, red)
    L += ["## Findings", ""]
    if not live:
        L += ["_No findings survived verification._", ""]
    for f in live:
        locs = ", ".join(f"`{l.get('path')}:{l.get('lines')}`" for l in f.get("locations", []))
        L += [f"### {f.get('id')} [{f.get('priority')}] {f.get('title')}", "",
              f"{f.get('category', '')} · {f.get('cwe', '')} · confidence {f.get('confidence', '?')} · {locs}", ""]
        for k in ("description", "path", "data_flow", "impact", "remediation"):
            if f.get(k):
                L.append(f"- **{k.replace('_', ' ')}:** {f[k]}")
        v = f.get("verification") or {}
        if v:
            ev = "; ".join(f"`{e.get('path')}:{e.get('lines')}`" for e in (v.get("evidence") or [])[:3])
            L.append(f"- **verification:** {v.get('verdict', '?')} — {v.get('reason', '')}"
                     + (f" Evidence: {ev}" if ev else ""))
        else:
            L.append("- **verification:** not run")
        L.append("")
    if red.get("unvalidated"):
        L += ["## Unvalidated (no severity assigned)", "",
              "_Claims whose exploitability turns on a fact outside this repository (hosted service "
              "configuration, deployed limits, third-party behaviour). They are leads, not findings: "
              "resolve the named fact before treating any of them as real._", ""]
        for u in red["unvalidated"]:
            locs = ", ".join(f"`{l.get('path')}:{l.get('lines')}`" for l in u.get("locations", []))
            L.append(f"- **{u.get('title')}**" + (f" · {locs}" if locs else ""))
            if u.get("reason"):
                L.append(f"  - why it is not a finding: {u['reason']}")
            if u.get("missing_fact"):
                L.append(f"  - missing fact: {u['missing_fact']}")
        L.append("")
    L += deps_section(d, meta)
    if red.get("dismissed"):
        L += ["## Dismissed by reducer", ""] + [f"- {x.get('title')}: {x.get('reason')}" for x in red["dismissed"]]
        L.append("")
    if pre or refuted or refuted_chains:
        L += ["## Refuted (dropped from the findings above)", ""]
        for x in pre:
            L.append(f"- {x.get('raw_ref')} {x.get('title')} — refuted before reduce: {x.get('reason')}")
        for f in refuted:
            L.append(f"- {f.get('id')} [{f.get('priority')}] {f.get('title')} — refuted after reduce by its "
                     f"verifier: {(f.get('verification') or {}).get('reason', '')}")
        for c in refuted_chains:
            L.append(f"- chain {c.get('id')} [{c.get('priority')}] {c.get('title')} — refuted: "
                     f"{(c.get('verification') or {}).get('reason', '')}")
        L.append("")
    L += ["", "_Verified = an independent verifier agent read the source and failed to falsify the claim; "
          "no sandbox reproduction was run._"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- status / ask

def all_scans() -> list[dict]:
    root = DATA / "scans"
    if not root.exists():
        return []
    return sorted((load(p) for p in root.glob("*/scan.json")), key=lambda m: m["created"])


def cmd_status(a) -> None:
    if a.scan:
        print(json.dumps(load(scan_dir(a.scan) / "scan.json"), indent=2))
        return
    for m in all_scans():
        print(f"{m['id']:45} {m['status']:18} raw={m.get('raw_findings', '-')}")


def cmd_ask(_a) -> None:
    scans = all_scans()
    lines = ["🛡️ Security Swarm: is any of these ready for a scan tonight?", ""]
    for rid, r in CFG["repos"].items():
        if r.get("ask", True) is False:
            continue
        try:
            last = git(r["path"], "log", "-1", "--format=%h|%cr|%s").strip().split("|", 2)
            dirty = len([l for l in git(r["path"], "status", "--porcelain").splitlines() if l.strip()])
            br = git(r["path"], "rev-parse", "--abbrev-ref", "HEAD").strip()
        except Exception:  # noqa: BLE001
            lines.append(f"• {rid}: repo not readable at {r['path']}")
            continue
        done = [s for s in scans if s["repo"] == rid and s["status"] == "done"]
        prev = f"last scan {done[-1]['commit'][:7]} ({done[-1]['created'][:10]})" if done else "never scanned"
        lines.append(f"• {rid} ({br}): last commit {last[0]} {last[1]} \"{last[2][:60]}\", "
                     f"{dirty} uncommitted, {prev}")
    lines += ["", "Reply e.g. \"scan traqprep\" or \"scan quire main\" (or \"none\"). I'll draft the threat "
              "model first for your OK. Only committed code is scanned (checked-out branch unless you name one)."]
    print("\n".join(lines))


def cmd_repos(_a) -> None:
    for rid, r in CFG["repos"].items():
        print(f"{rid:12} {r['path']:28} aliases={r.get('aliases')}")


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = p.add_subparsers(dest="cmd", required=True)
    x = sp.add_parser("plan"); x.add_argument("repo", nargs="?"); x.add_argument("--scan")
    x.add_argument("--feedback"); x.add_argument("--ref", default="HEAD", help="branch/tag/commit to scan")
    x.set_defaults(fn=cmd_plan)
    x = sp.add_parser("approve"); x.add_argument("scan"); x.set_defaults(fn=cmd_approve)
    x = sp.add_parser("run"); x.add_argument("scan"); x.add_argument("--concurrency", type=int)
    x.add_argument("--batch-size", type=int); x.add_argument("--max-batches", type=int)
    x.add_argument("--force", action="store_true"); x.set_defaults(fn=cmd_run)
    x = sp.add_parser("verify"); x.add_argument("scan"); x.set_defaults(fn=cmd_verify)
    x = sp.add_parser("status"); x.add_argument("scan", nargs="?"); x.set_defaults(fn=cmd_status)
    x = sp.add_parser("coverage"); x.add_argument("scan"); x.set_defaults(fn=cmd_coverage)
    x = sp.add_parser("deps"); x.add_argument("scan"); x.set_defaults(fn=cmd_deps)
    sp.add_parser("ask").set_defaults(fn=cmd_ask)
    sp.add_parser("repos").set_defaults(fn=cmd_repos)
    a = p.parse_args()
    if a.cmd == "plan" and not (a.repo or a.scan):
        p.error("plan needs <repo> or --scan")
    a.fn(a)


if __name__ == "__main__":
    main()
