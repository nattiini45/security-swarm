#!/usr/bin/env python3
"""Security Swarm — native MiniMax Code skill engine.

Host-driven pipeline. This module never calls a model API and never touches a
credential: the Mavis host agent spawns one isolated child agent per role (see
SKILL.md) and writes each reply into `tasks/<name>.out.json`. Everything that
must be deterministic stays here:

    plan ──► approve (human) ──► shard (ripgrep) ──► map (one worker per batch)
          ──► refute (one refuter per worker report) ──► reduce
          ──► verify (one fresh agent per claim) ──► report.md

Upstream (nattiini45/security-swarm) drove the same stages through a Hermes
one-shot CLI. The stage graph, caching, digests, refutation semantics and report
layout are unchanged; only the call boundary moved from a subprocess to the host.

Every stage is a pair of commands: `<stage>-begin` writes the prompt file(s) and
prints a JSON manifest; the host runs the child agents and writes the replies;
`<stage>-ingest` parses them, updates the cache and advances the scan.

Usage:
  swarm.py bootstrap [--force] [--from PATH]   # fetch ripgrep into the data dir
  swarm.py repos                                # registered repos / aliases
  swarm.py roles                                # role -> {agent, model} for the host
  swarm.py plan-begin <repo> [--ref REF] [--scan ID] [--feedback TEXT]
  swarm.py plan-ingest <scan>
  swarm.py approve <scan>
  swarm.py map-begin <scan> [--batch-size N]
  swarm.py map-ingest <scan>
  swarm.py refute-begin <scan>
  swarm.py refute-ingest <scan>
  swarm.py reduce-begin <scan>
  swarm.py reduce-ingest <scan>
  swarm.py verify-begin <scan>
  swarm.py verify-ingest <scan>
  swarm.py report <scan>
  swarm.py coverage <scan>                      # coverage ledger: unreviewed / scoped-out files
  swarm.py status [<scan>]
  swarm.py ask
"""
from __future__ import annotations

import argparse
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
import tomllib
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CFG = tomllib.loads((HERE / "swarm.toml").read_text(encoding="utf-8"))


def _resolve(p: str) -> Path:
    """Expand ~ and make relative paths relative to the skill directory."""
    path = Path(os.path.expanduser(p))
    return path if path.is_absolute() else (HERE / path)


DATA = _resolve(CFG["scan"]["data_dir"])
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
    ("MEMORY-SAFETY-AND-BINARY.md", (".c", ".cc", ".cpp", ".h", ".rs", "unsafe", "kernel", "ffi",
                                     "jni", "wasm")),
]
BUILTIN_EXCLUDES = [
    "**/node_modules/**", "**/.git/**", "**/dist/**", "**/build/**", "**/.next/**", "**/out/**",
    "**/coverage/**", "**/vendor/**", "**/.gradle/**", "**/*.min.js", "**/*.map", "**/*.lock",
    "**/package-lock.json", "**/pnpm-lock.yaml", "**/yarn.lock", "**/*.svg", "**/*.snap",
]
JSON_RE = re.compile(r"<<<SWARM_JSON\s*(.*?)\s*SWARM_JSON>>>", re.S)

# ripgrep 15.2.0, x86_64-pc-windows-msvc — pinned and checksum-verified.
RG_VERSION = "15.2.0"
RG_WINDOWS_URL = ("https://github.com/BurntSushi/ripgrep/releases/download/"
                  f"{RG_VERSION}/ripgrep-{RG_VERSION}-x86_64-pc-windows-msvc.zip")
RG_WINDOWS_SHA256 = "71b2fef860abe467217a538ff31de02f5258807c0129f771846f87bd029aafc5"


# ---------------------------------------------------------------- helpers

def log(msg: str) -> None:
    print(f"[{dt.datetime.now():%H:%M:%S}] {msg}", flush=True)


def emit(obj) -> None:
    """Print a machine-readable manifest for the host agent."""
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def resolve_repo(name: str) -> tuple[str, dict]:
    key = name.lower().strip()
    for rid, r in CFG["repos"].items():
        if key == rid or key in [a.lower() for a in r.get("aliases", [])]:
            r = dict(r)
            r["path"] = str(_resolve(r["path"]))
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
    proc = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip().splitlines()
        hint = detail[0] if detail else f"git exited {proc.returncode}"
        if "not a git repository" in hint:
            hint += (f" — {repo} is not a git repo. For the self-test fixture run: "
                     f"python swarm.py fixture-init")
        sys.exit(f"git {' '.join(args)} failed in {repo}: {hint}")
    return proc.stdout


def cmd_fixture_init(a) -> None:
    """Make the self-test fixture a git repo with one commit.

    The scanner snapshots COMMITTED HEAD via `git archive`, so the fixture needs a commit
    before it can be planned against. Provided as a Python command because Windows blocks
    .ps1 execution by default.
    """
    fixture = HERE / "fixtures" / "teamboard"
    if not fixture.exists():
        sys.exit(f"fixture not found at {fixture}")
    if not (fixture / ".git").exists():
        subprocess.run(["git", "init", "-q"], cwd=str(fixture), check=True)
    subprocess.run(["git", "add", "-A"], cwd=str(fixture), check=True)
    proc = subprocess.run(["git", "-c", "user.email=swarm@example.com",
                           "-c", "user.name=Security Swarm", "commit", "-qm", "self-test fixture"],
                          cwd=str(fixture), capture_output=True, text=True)
    short = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(fixture),
                           capture_output=True, text=True).stdout.strip()
    emit({"ok": True, "fixture": str(fixture), "commit": short,
          "note": "already committed" if proc.returncode != 0 else "committed"})


def rg_bin() -> str:
    """Locate ripgrep: explicit config -> bundled -> PATH."""
    explicit = (CFG["scan"].get("rg_path") or "").strip()
    if explicit:
        p = Path(os.path.expanduser(explicit))
        if p.exists():
            return str(p)
    bundled = DATA / "tools" / "ripgrep" / "rg.exe"
    if bundled.exists():
        return str(bundled)
    for name in ("rg", "rg.exe"):
        found = shutil.which(name)
        if found:
            return found
    sys.exit("ripgrep not found. Run:  python swarm.py bootstrap")


# ---------------------------------------------------------------- json extraction

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
    """Pull the newest SWARM_JSON block out of a child agent's reply."""
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


def _salvage_verdicts(text: str):
    """Last resort: pull the `verdicts` array out of a reply whose surrounding JSON is broken."""
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


def _claim_hash(payload) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False)
                          .encode("utf-8")).hexdigest()[:16]


def _strip_runtime(obj: dict) -> dict:
    """Drop keys this tool attaches after a run, so a cached verdict never invalidates itself."""
    return {k: v for k, v in obj.items() if k not in ("verification", "pre_refute")}


# ---------------------------------------------------------------- task plumbing

def task_path(d: Path, name: str) -> Path:
    return d / "tasks" / f"{name}.md"


def out_path(d: Path, name: str) -> Path:
    return d / "tasks" / f"{name}.out.json"


OUTPUT_BLOCK = """

OUTPUT
Write the JSON block above to this exact file, and nothing else:
{out_path}

That file is the ONLY file you may create or write. Do not create, edit, move or delete any other
file — the repository snapshot above stays strictly read-only. After writing, reply with one short
line confirming the write (for example: "written <path>"). Do not repeat the JSON in your reply.
"""


def write_task(d: Path, name: str, text: str) -> Path:
    p = task_path(d, name)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text + OUTPUT_BLOCK.format(out_path=out_path(d, name)), encoding="utf-8")
    return p


def read_result(d: Path, name: str) -> dict:
    """Parse the child agent reply the host wrote to tasks/<name>.out.json."""
    p = out_path(d, name)
    if not p.exists():
        raise FileNotFoundError(f"no result file for task '{name}' (expected {p})")
    return extract_json(p.read_text(encoding="utf-8", errors="replace"))


def task_manifest(d: Path, name: str, **extra) -> dict:
    m = {"id": name, "prompt": str(task_path(d, name)), "out": str(out_path(d, name))}
    m.update(extra)
    return m


def render_prompt(name: str, **fields) -> str:
    """Fill a prompt template, failing loudly on a missing or stray placeholder."""
    text = (HERE / "prompts" / name).read_text(encoding="utf-8")
    try:
        return text.format(**fields)
    except KeyError as e:
        sys.exit(f"prompt template {name} needs placeholder {e} — pass it to render_prompt()")
    except IndexError:
        sys.exit(f"prompt template {name} has an unescaped '{{' or '}}' — escape literal "
                 f"braces as '{{{{' and '}}}}'")


# ---------------------------------------------------------------- bootstrap

def cmd_bootstrap(a) -> None:
    """Fetch ripgrep into the data dir. Pinned version, checksum verified."""
    target = DATA / "tools" / "ripgrep" / "rg.exe"
    if target.exists() and not a.force:
        emit({"ok": True, "rg": str(target), "note": "already present"})
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    if a.from_:
        src = Path(a.from_).resolve()
        if not src.exists():
            sys.exit(f"--from path does not exist: {src}")
        shutil.copy2(src, target)
        emit({"ok": True, "rg": str(target), "source": "local", "from": str(src)})
        return
    if os.name != "nt":
        found = shutil.which("rg")
        if found:
            emit({"ok": True, "rg": found, "note": "rg already on PATH; nothing to install"})
            return
        sys.exit("no bundled ripgrep for this platform and none on PATH. Install ripgrep "
                 "and set [scan].rg_path in swarm.toml")
    log(f"downloading ripgrep {RG_VERSION} ...")
    zip_bytes = urllib.request.urlopen(RG_WINDOWS_URL, timeout=120).read()
    digest = hashlib.sha256(zip_bytes).hexdigest()
    if digest != RG_WINDOWS_SHA256:
        sys.exit(f"checksum mismatch for ripgrep {RG_VERSION}: got {digest}")
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        member = next(n for n in zf.namelist() if n.endswith("rg.exe"))
        with zf.open(member) as fh:
            target.write_bytes(fh.read())
    emit({"ok": True, "rg": str(target), "version": RG_VERSION, "sha256": digest})


# ---------------------------------------------------------------- plan

def make_snapshot(repo_path: str, dest: Path, ref: str = "HEAD") -> dict:
    commit = git(repo_path, "rev-parse", ref + "^{commit}").strip()
    branch = git(repo_path, "rev-parse", "--abbrev-ref", "HEAD").strip() if ref == "HEAD" else ref
    dirty = [l for l in git(repo_path, "status", "--porcelain").splitlines() if l.strip()]
    tar_bytes = subprocess.run(["git", "-C", repo_path, "archive", "--format=tar", commit],
                               capture_output=True, check=True).stdout
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        tf.extractall(dest, filter="data")
    return {"commit": commit, "branch": branch, "uncommitted_changes_excluded": len(dirty)}


def cmd_plan_begin(a) -> None:
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
                "roles": CFG.get("roles", {}), "plan_rounds": 0}
        save(d / "scan.json", meta)
    fb = ""
    if a.feedback:
        prev = (d / "plan.json").read_text(encoding="utf-8") if (d / "plan.json").exists() else "{}"
        fb = (f"OWNER FEEDBACK ON YOUR PREVIOUS PLAN (apply it):\n{a.feedback}\n\n"
              f"PREVIOUS PLAN:\n{prev}")
    prompt = render_prompt(
        "plan.md",
        repo=rid, commit=meta["commit"], snapshot=d / "snapshot", notes=r.get("notes", ""),
        feedback_block=fb)
    rnd = meta.get("plan_rounds", 0) + 1
    write_task(d, "plan", prompt)
    meta.update(status="planning", plan_rounds=rnd)
    save(d / "scan.json", meta)
    emit({"scan": meta["id"], "repo": rid, "commit": meta["commit"], "snapshot": str(d / "snapshot"),
          "plan_round": rnd, "task": task_manifest(d, "plan", role="planner"),
          "out": str(out_path(d, "plan"))})


def rg_cmd(sel: dict, excludes: list[str]) -> list[str]:
    rg = rg_bin()
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


# ---------------------------------------------------------------- attack playbook / coverage

def _read_class(name: str) -> str:
    p = CLASSES_DIR / name
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
    listing = subprocess.run([rg_bin(), "--files", "--no-config"] +
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


def cmd_coverage(a) -> None:
    d = scan_dir(a.scan)
    plan = load(d / "plan.json")
    queued = None
    qpath = d / "queue.json"
    if qpath.exists():
        queued = {f["file"] for b in load(qpath).get("batches", []) for f in b.get("files", [])}
    cov = coverage(d, plan, queued)
    save(d / "coverage-ledger.json", cov)
    emit({"ok": True, "scan": d.name, "in_scope_files": cov["in_scope_files"],
          "matched_files": cov["matched_files"], "queued_files": cov["queued_files"],
          "matched_not_queued": cov["matched_not_queued"], "unmatched_files": cov["unmatched_files"],
          "unmatched_by_dir": dict(list(cov["unmatched_by_dir"].items())[:10]),
          "ledger": str(d / "coverage-ledger.json")})


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
    total = subprocess.run([rg_bin(), "--files", "--no-config"] +
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
    lines += ["", "Excluded: " + (", ".join(f"`{g}`" for g in plan.get("exclude_globs") or []) or "-")]
    return "\n".join(lines) + "\n"


def cmd_plan_ingest(a) -> None:
    d = scan_dir(a.scan)
    meta = load(d / "scan.json")
    rid, r = resolve_repo(meta["repo"])
    plan = read_result(d, "plan")
    stats = selector_stats(d, plan)
    save(d / "plan.json", plan)
    meta.update(status="awaiting_approval", plan_rounds=meta.get("plan_rounds", 1),
                selector_stats=stats)
    save(d / "scan.json", meta)
    (d / "threat-model.md").write_text(render_plan(meta, plan, stats), encoding="utf-8")
    bad = [k for k, v in stats["per_selector"].items() if "error" in v]
    emit({"ok": True, "scan": meta["id"], "threat_model": str(d / "threat-model.md"),
          "selectors": len(plan.get("selectors", [])),
          "files_selected": stats["files_selected"], "files_in_scope": stats["files_in_scope"],
          "selector_errors": bad})


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
    emit({"ok": True, "scan": meta["id"], "status": "approved"})


# ---------------------------------------------------------------- shard / map

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


def cmd_map_begin(a) -> None:
    d = scan_dir(a.scan)
    meta = load(d / "scan.json")
    if meta["status"] not in ("approved", "mapping", "refuting", "reducing", "verifying", "done"):
        sys.exit(f"scan is '{meta['status']}'; approve it first")
    plan = load(d / "plan.json")
    bs = a.batch_size or CFG["scan"]["batch_size"]
    qpath = d / "queue.json"
    if not qpath.exists():
        batches = shard(d, plan, bs)
        save(qpath, {"batch_size": bs, "batches": batches})
    batches = load(qpath)["batches"]
    if a.max_batches:
        batches = batches[: a.max_batches]
    tasks = []
    for b in batches:
        prompt = render_prompt(
            "map.md",
            repo=meta["repo"], commit=meta["commit"], snapshot=d / "snapshot",
            threat_model=plan.get("threat_model", ""),
            investigation_guidance=plan.get("investigation_guidance", ""),
            severity_criteria=plan.get("severity_criteria", ""), batch_id=b["id"],
            attack_playbook=attack_playbook(b),
            batch_listing=batch_listing(b))
        write_task(d, f"map-{b['id']}", prompt)
        tasks.append(task_manifest(d, f"map-{b['id']}", role="mapper", batch=b["id"],
                                   files=[f["file"] for f in b["files"]]))
    n_files = sum(len(b["files"]) for b in batches)
    meta.update(status="mapping", batches=len(batches), files_queued=n_files)
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
    emit({"scan": meta["id"], "batches": len(batches), "files": n_files,
          "coverage": meta.get("coverage"), "tasks": tasks})


def cmd_map_ingest(a) -> None:
    d = scan_dir(a.scan)
    meta = load(d / "scan.json")
    batches = load(d / "queue.json")["batches"]
    results, failed = [], []
    for b in batches:
        out = d / "map" / f"{b['id']}.json"
        if out.exists():
            results.append(load(out))
            continue
        try:
            res = read_result(d, f"map-{b['id']}")
        except Exception as e:  # noqa: BLE001 — a missing/failed worker is a coverage gap, not fatal
            failed.append(b["id"])
            log(f"{b['id']} failed: {str(e)[:160]}")
            continue
        res["batch"] = b["id"]
        res.setdefault("findings", [])
        for f in res["findings"]:
            f["source_batch"] = b["id"]
        save(out, res)
        results.append(res)
        log(f"{b['id']} done: {len(res['findings'])} findings")
    raw_n = sum(len(r.get("findings", [])) for r in results)
    meta.update(status="mapping", map_failed=failed, raw_findings=raw_n)
    save(d / "scan.json", meta)
    emit({"ok": True, "scan": meta["id"], "batches": len(batches), "raw_findings": raw_n,
          "failed_batches": failed, "coverage_gap": bool(failed)})


# ---------------------------------------------------------------- refute (one per report)

def map_results(d: Path) -> list[dict]:
    """All cached map worker reports for a scan, in batch order."""
    d_map = d / "map"
    if not d_map.exists():
        return []
    out = []
    for p in sorted(d_map.glob("*.json")):
        if not re.fullmatch(r"B\d+\.json", p.name):
            continue
        try:
            out.append(load(p))
        except json.JSONDecodeError:
            continue
    return out


def cmd_refute_begin(a) -> None:
    d = scan_dir(a.scan)
    meta = load(d / "scan.json")
    plan = load(d / "plan.json")
    results = map_results(d)
    reports = [r for r in results if r.get("findings")]
    tasks = []
    for report in reports:
        bid = report.get("batch", "B?")
        findings = [_strip_runtime(f) for f in report.get("findings", [])]
        prompt = render_prompt(
            "refute.md",
            repo=meta["repo"], commit=meta["commit"], snapshot=d / "snapshot",
            threat_model=plan.get("threat_model", ""), severity_criteria=plan.get("severity_criteria", ""),
            batch_id=bid, n_findings=len(findings),
            findings_json=json.dumps(findings, indent=1, ensure_ascii=False))
        write_task(d, f"refute-{bid}", prompt)
        tasks.append(task_manifest(d, f"refute-{bid}", role="refute", batch=bid,
                                   n_findings=len(findings)))
    emit({"scan": meta["id"], "reports": len(reports), "tasks": tasks})


def cmd_refute_ingest(a) -> None:
    """ONE refuter agent per mapper report (one report per batch), before the reduce.

    Design note: not one refuter over everything — every review worker's
    report gets its own adversarial agent. Refuted findings are dropped from the reduce input; all
    verdicts stay in refute/<batch>.json for audit. Per-report caching: an unchanged report is not
    re-refuted.
    """
    d = scan_dir(a.scan)
    meta = load(d / "scan.json")
    results = map_results(d)
    reports = [r for r in results if r.get("findings")]
    kept, refuted, broken = [], [], []
    for report in reports:
        bid = report.get("batch", "B?")
        findings = [_strip_runtime(f) for f in report.get("findings", [])]
        digest = _claim_hash({"batch": bid, "findings": findings})
        out = d / "refute" / f"{bid}.json"
        verdicts = None
        if out.exists():
            cached = load(out)
            if cached.get("digest") == digest:
                verdicts = cached.get("verdicts") or []
                log(f"refute {bid}: cached ({len(findings)} findings)")
        if verdicts is None:
            try:
                res = read_result(d, f"refute-{bid}")
                verdicts = res.get("verdicts") or []
                save(out, {"batch": bid, "digest": digest, "verdicts": verdicts})
            except Exception as e:  # noqa: BLE001 — a broken refuter must not lose findings
                salv = None
                p = out_path(d, f"refute-{bid}")
                if p.exists():
                    salv = _salvage_verdicts(p.read_text(encoding="utf-8", errors="replace"))
                if salv is not None:
                    verdicts = salv
                    save(out, {"batch": bid, "digest": digest, "verdicts": salv})
                    log(f"refute {bid}: salvaged {len(salv)} verdicts from a malformed reply")
                else:
                    broken.append(bid)
                    log(f"refute {bid} failed ({str(e)[:120]}); its findings pass through unfiltered")
                    verdicts = []
        by = {}
        for v in verdicts:
            if isinstance(v, dict):
                try:
                    by[int(v.get("finding"))] = v
                except (TypeError, ValueError):
                    continue
        for i, f in enumerate(report.get("findings", []), 1):
            f["raw_ref"] = f"{report['batch']}#{i}"
            v = by.get(i)
            if v and str(v.get("verdict", "")).lower() == "refuted":
                f["pre_refute"] = v
                refuted.append(f)
            else:
                kept.append(f)
    save(d / "findings_raw.json", {"findings": kept})
    save(d / "refute_summary.json",
         [{"raw_ref": f.get("raw_ref"), "title": f.get("title"),
           "reason": (f.get("pre_refute") or {}).get("reason", "")} for f in refuted])
    meta.update(status="reducing", refuted_before_reduce=len(refuted),
                findings_after_refute=len(kept), refute_failed=broken)
    save(d / "scan.json", meta)
    emit({"ok": True, "scan": meta["id"], "kept": len(kept), "refuted": len(refuted),
          "refute_failed": broken, "reduce_input": str(d / "findings_raw.json")})


# ---------------------------------------------------------------- reduce

def cmd_reduce_begin(a) -> None:
    d = scan_dir(a.scan)
    meta = load(d / "scan.json")
    plan = load(d / "plan.json")
    raw = load(d / "findings_raw.json") if (d / "findings_raw.json").exists() else {"findings": []}
    findings = raw.get("findings", [])
    n_batches = len({f.get("source_batch") for f in findings if f.get("source_batch")})
    prompt = render_prompt(
        "reduce.md",
        repo=meta["repo"], commit=meta["commit"], snapshot=d / "snapshot",
        threat_model=plan.get("threat_model", ""), severity_criteria=plan.get("severity_criteria", ""),
        n_findings=len(findings), n_batches=n_batches,
        findings_json=json.dumps(findings, indent=1, ensure_ascii=False))
    write_task(d, "reduce", prompt)
    meta.update(status="reducing")
    save(d / "scan.json", meta)
    emit({"scan": meta["id"], "n_findings": len(findings), "n_batches": n_batches,
          "task": task_manifest(d, "reduce", role="reducer")})


def cmd_reduce_ingest(a) -> None:
    d = scan_dir(a.scan)
    meta = load(d / "scan.json")
    raw = load(d / "findings_raw.json") if (d / "findings_raw.json").exists() else {"findings": []}
    findings = raw.get("findings", [])
    try:
        red = read_result(d, "reduce")
        red.setdefault("findings", [])
        red.setdefault("chains", [])
        red.setdefault("dismissed", [])
        red.setdefault("unvalidated", [])
    except Exception as e:  # noqa: BLE001 — keep raw findings rather than lose the scan
        log(f"reduce failed: {e}; report falls back to raw findings")
        red = {"summary": f"REDUCER FAILED ({e}). Raw, undeduplicated worker findings below.",
               "findings": [{"id": f"R{i + 1}", "priority": {"critical": "P0", "high": "P1", "medium": "P2"}
                             .get(f.get("severity"), "P3"), **f} for i, f in enumerate(findings)],
               "chains": [], "dismissed": [], "reducer_failed": True}
    pre = load(d / "refute_summary.json") if (d / "refute_summary.json").exists() else []
    red["pre_refuted"] = pre
    save(d / "findings.json", red)
    meta.update(status="verifying")
    save(d / "scan.json", meta)
    (d / "report.md").write_text(render_report(meta, red), encoding="utf-8")
    emit({"ok": True, "scan": meta["id"], "findings": len(red.get("findings", [])),
          "chains": len(red.get("chains", [])), "dismissed": len(red.get("dismissed", [])),
          "reducer_failed": bool(red.get("reducer_failed"))})


# ---------------------------------------------------------------- verify (one agent per claim)

def cmd_verify_begin(a) -> None:
    d = scan_dir(a.scan)
    meta = load(d / "scan.json")
    plan = load(d / "plan.json")
    red = load(d / "findings.json")
    findings, chains = red.get("findings", []), red.get("chains", [])
    # `unvalidated` claims carry no severity by design and are never sent to a verifier: the
    # missing fact is outside the repository, so a source-only verifier could only guess.
    by_id = {f.get("id"): f for f in findings}
    claims = [("finding", f) for f in findings] + [("chain", c) for c in chains]
    tasks = []
    for kind, claim in claims:
        cid = f"{kind}-{claim.get('id', '?')}"
        payload = {"claim": _strip_runtime(claim)}
        if kind == "chain":
            payload["step_details"] = [_strip_runtime(by_id.get(s, {"id": s, "MISSING_FROM_REPORT": True}))
                                       for s in claim.get("steps", [])]
        prompt = render_prompt(
            "verify.md",
            repo=meta["repo"], commit=meta["commit"], snapshot=d / "snapshot",
            threat_model=plan.get("threat_model", ""),
            claim_kind=kind, claim_id=claim.get("id", "?"),
            claim_json=json.dumps(payload, indent=1, ensure_ascii=False))
        write_task(d, f"verify-{cid}", prompt)
        tasks.append(task_manifest(d, f"verify-{cid}", role="verify", claim=cid, kind=kind))
    meta.update(status="verifying")
    save(d / "scan.json", meta)
    emit({"scan": meta["id"], "claims": len(claims), "tasks": tasks})


def cmd_verify_ingest(a) -> None:
    d = scan_dir(a.scan)
    meta = load(d / "scan.json")
    red = load(d / "findings.json")
    findings, chains = red.get("findings", []), red.get("chains", [])
    by_id = {f.get("id"): f for f in findings}
    claims = [("finding", f) for f in findings] + [("chain", c) for c in chains]
    counts = {"confirmed": 0, "refuted": 0, "unverified": 0}
    for kind, claim in claims:
        cid = f"{kind}-{claim.get('id', '?')}"
        payload = {"claim": _strip_runtime(claim)}
        if kind == "chain":
            payload["step_details"] = [_strip_runtime(by_id.get(s, {"id": s, "MISSING_FROM_REPORT": True}))
                                       for s in claim.get("steps", [])]
        digest = _claim_hash(payload)
        out = d / "verify" / f"{cid}.json"
        v = None
        if out.exists():
            cached = load(out)
            if cached.get("claim_digest") == digest:
                v = cached
        if v is None:
            try:
                res = read_result(d, f"verify-{cid}")
                verdict = str(res.get("verdict", "unverified")).lower()
                res["verdict"] = verdict if verdict in ("confirmed", "refuted", "unverified") else "unverified"
                res.setdefault("reason", "")
                res.setdefault("evidence", [])
                res["claim_digest"] = digest
                v = res
                save(out, res)
            except Exception as e:  # noqa: BLE001 — a broken verifier must not read as confirmed
                v = {"claim": claim.get("id"), "verdict": "unverified",
                     "reason": f"verifier failed: {e}", "evidence": [], "claim_digest": digest}
        claim["verification"] = v
        counts[v.get("verdict", "unverified")] = counts.get(v.get("verdict", "unverified"), 0) + 1
    save(d / "findings.json", red)
    meta.update(status="done", verify_counts=counts,
                finished=dt.datetime.now().isoformat(timespec="seconds"))
    save(d / "scan.json", meta)
    (d / "report.md").write_text(render_report(meta, red), encoding="utf-8")
    emit({"ok": True, "scan": meta["id"], **counts, "report": str(d / "report.md")})


def cmd_report(a) -> None:
    d = scan_dir(a.scan)
    meta = load(d / "scan.json")
    red = load(d / "findings.json")
    (d / "report.md").write_text(render_report(meta, red), encoding="utf-8")
    emit({"ok": True, "scan": meta["id"], "report": str(d / "report.md")})


# ---------------------------------------------------------------- report rendering

def _verdict(obj: dict) -> str:
    return str((obj.get("verification") or {}).get("verdict", "")).lower()


def render_report(meta: dict, red: dict) -> str:
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


# ---------------------------------------------------------------- status / ask / repos

def all_scans() -> list[dict]:
    root = DATA / "scans"
    if not root.exists():
        return []
    return sorted((load(p) for p in root.glob("*/scan.json")), key=lambda m: m["created"])


def cmd_status(a) -> None:
    if a.scan:
        print(json.dumps(load(scan_dir(a.scan) / "scan.json"), indent=2, ensure_ascii=False))
        return
    for m in all_scans():
        print(f"{m['id']:45} {m['status']:18} raw={m.get('raw_findings', '-')}")


def cmd_ask(_a) -> None:
    scans = all_scans()
    lines = ["Security Swarm: is any of these ready for a scan tonight?", ""]
    for rid, r in CFG["repos"].items():
        if r.get("ask", True) is False:
            continue
        try:
            last = git(r["path"], "log", "-1", "--format=%h|%cr|%s").strip().split("|", 2)
            dirty = len([l for l in git(r["path"], "status", "--porcelain").splitlines() if l.strip()])
            br = git(r["path"], "rev-parse", "--abbrev-ref", "HEAD").strip()
        except Exception:  # noqa: BLE001
            lines.append(f"- {rid}: repo not readable at {r['path']}")
            continue
        done = [s for s in scans if s["repo"] == rid and s["status"] == "done"]
        prev = f"last scan {done[-1]['commit'][:7]} ({done[-1]['created'][:10]})" if done else "never scanned"
        lines.append(f"- {rid} ({br}): last commit {last[0]} {last[1]} \"{last[2][:60]}\", "
                     f"{dirty} uncommitted, {prev}")
    lines += ["", "Reply e.g. \"scan traqprep\" or \"scan quire main\" (or \"none\"). I'll draft the threat "
              "model first for your OK. Only committed code is scanned (checked-out branch unless you name one)."]
    print("\n".join(lines))


def cmd_repos(_a) -> None:
    for rid, r in CFG["repos"].items():
        print(f"{rid:12} {r['path']:28} aliases={r.get('aliases')}")


def cmd_roles(_a) -> None:
    """The host needs to know which child agent type and model to use per role."""
    emit({"roles": CFG.get("roles", {}),
          "concurrency": CFG["scan"].get("concurrency", 4),
          "note": "Spawn one child agent per task using agent+model; write the child's reply "
                  "verbatim into the task's `out` file."})


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001 — older/odd consoles
        pass
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = p.add_subparsers(dest="cmd", required=True)

    x = sp.add_parser("bootstrap"); x.add_argument("--force", action="store_true")
    x.add_argument("--from", dest="from_", help="use a local rg.exe instead of downloading")
    x.set_defaults(fn=cmd_bootstrap)
    x = sp.add_parser("fixture-init"); x.set_defaults(fn=cmd_fixture_init)

    x = sp.add_parser("plan-begin"); x.add_argument("repo", nargs="?"); x.add_argument("--scan")
    x.add_argument("--feedback"); x.add_argument("--ref", default="HEAD", help="branch/tag/commit to scan")
    x.set_defaults(fn=cmd_plan_begin)
    x = sp.add_parser("plan-ingest"); x.add_argument("scan"); x.set_defaults(fn=cmd_plan_ingest)
    x = sp.add_parser("approve"); x.add_argument("scan"); x.set_defaults(fn=cmd_approve)
    x = sp.add_parser("map-begin"); x.add_argument("scan"); x.add_argument("--batch-size", type=int)
    x.add_argument("--max-batches", type=int); x.set_defaults(fn=cmd_map_begin)
    x = sp.add_parser("map-ingest"); x.add_argument("scan"); x.set_defaults(fn=cmd_map_ingest)
    x = sp.add_parser("refute-begin"); x.add_argument("scan"); x.set_defaults(fn=cmd_refute_begin)
    x = sp.add_parser("refute-ingest"); x.add_argument("scan"); x.set_defaults(fn=cmd_refute_ingest)
    x = sp.add_parser("reduce-begin"); x.add_argument("scan"); x.set_defaults(fn=cmd_reduce_begin)
    x = sp.add_parser("reduce-ingest"); x.add_argument("scan"); x.set_defaults(fn=cmd_reduce_ingest)
    x = sp.add_parser("verify-begin"); x.add_argument("scan"); x.set_defaults(fn=cmd_verify_begin)
    x = sp.add_parser("verify-ingest"); x.add_argument("scan"); x.set_defaults(fn=cmd_verify_ingest)
    x = sp.add_parser("report"); x.add_argument("scan"); x.set_defaults(fn=cmd_report)
    x = sp.add_parser("status"); x.add_argument("scan", nargs="?"); x.set_defaults(fn=cmd_status)
    x = sp.add_parser("coverage"); x.add_argument("scan"); x.set_defaults(fn=cmd_coverage)
    sp.add_parser("ask").set_defaults(fn=cmd_ask)
    sp.add_parser("repos").set_defaults(fn=cmd_repos)
    sp.add_parser("roles").set_defaults(fn=cmd_roles)
    a = p.parse_args()
    if a.cmd == "plan-begin" and not (a.repo or a.scan):
        p.error("plan-begin needs <repo> or --scan")
    a.fn(a)


if __name__ == "__main__":
    main()
