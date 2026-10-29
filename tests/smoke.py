#!/usr/bin/env python3
"""Offline smoke test for both trees (repo root = Hermes engine, .minimax/ = MiniMax Code port).

No model calls, no network except what OSV-Scanner would do if installed (it is optional here).
Checks: syntax, standards.json, identical references/ in both trees, every prompt template formats
with exactly the fields the engine passes, the engine's pure functions, and a full MiniMax pipeline
(plan -> map -> refute -> reduce -> verify -> report) driven with synthetic agent replies.

Usage: python tests/smoke.py        (exit 0 = all good)
"""
from __future__ import annotations

import ast
import filecmp
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TREES = {"root": ROOT, "minimax": ROOT / ".minimax"}
FAILS: list[str] = []


def check(cond: bool, msg: str) -> None:
    print(("ok   " if cond else "FAIL ") + msg, flush=True)
    if not cond:
        FAILS.append(msg)


def prompt_fields(src: str) -> dict[str, list[str]]:
    """Field names each prompt is formatted with, read from the engine source itself."""
    out = {}
    pat = re.compile(r'(?:"prompts" / "(\w+)\.md"\)\.read_text\(encoding="utf-8"\)\.format\('
                     r'|render_prompt\(\s*"(\w+)\.md",)(.*?)\)\n', re.S)
    for m in pat.finditer(src):
        name = m.group(1) or m.group(2)
        out[name] = sorted(set(re.findall(r"(\w+)=", m.group(3))) - {"indent", "ensure_ascii"})
    return out


def dircmp_equal(a: Path, b: Path) -> bool:
    c = filecmp.dircmp(a, b)
    if c.left_only or c.right_only or c.funny_files or c.common_funny:
        return False
    for name in c.common_files + c.common_dirs:
        # is_file()/is_dir() follow symlinks, so a link to a matching target would pass
        # silently. Only real regular files / real directories count as identical.
        for side in (a / name, b / name):
            if side.is_symlink() or not side.exists():
                return False
        if (a / name).is_file() != (b / name).is_file():
            return False
        if (a / name).is_dir() != (b / name).is_dir():
            return False
    _, mismatch, errors = filecmp.cmpfiles(a, b, c.common_files, shallow=False)
    if mismatch or errors:
        return False
    return all(dircmp_equal(a / d, b / d) for d in c.common_dirs)


def fixture_lockfile_check() -> None:
    """The fixture lockfiles are hand-maintained: assert package.json and package-lock.json agree."""
    checked = 0
    for rel in ("fixtures", ".minimax/fixtures"):
        for name in ("teamboard", "teamboard-hardened"):
            base = ROOT / rel / name
            pj, pl = base / "package.json", base / "package-lock.json"
            if not pj.exists():
                continue
            want = json.loads(pj.read_text(encoding="utf-8")).get("dependencies", {})
            if not pl.exists():
                # teamboard (the vulnerable fixture) ships without a lockfile on purpose: the
                # smoke pipeline never installs it. Only the hardened twin is locked.
                if name == "teamboard":
                    continue
                check(not want, f"{rel}/{name}: no lockfile but package.json declares deps")
                continue
            checked += 1
            lock = json.loads(pl.read_text(encoding="utf-8"))
            root = lock.get("packages", {}).get("", {})
            have = root.get("dependencies", {})
            check(want == have,
                  f"{rel}/{name}: lockfile root deps match package.json ({sorted(want)})")
            entries = lock.get("packages", {})
            missing = [d for d in want if f"node_modules/{d}" not in entries]
            check(not missing, f"{rel}/{name}: every declared dependency is in the lockfile "
                               + (f"(missing: {missing})" if missing else ""))
    check(checked > 0, "lockfile check validated at least one fixture (not vacuous)")


def static_checks() -> None:
    for name, tree in TREES.items():
        src = (tree / "swarm.py").read_text(encoding="utf-8")
        try:
            ast.parse(src)
            check(True, f"{name}: swarm.py parses")
        except SyntaxError as e:
            check(False, f"{name}: swarm.py syntax error {e}")
            continue
        calls = re.findall(r"\.extractall\(([^)]*)\)", src)
        check(bool(calls), f"{name}: swarm.py still unpacks the archive (>=1 extractall call)")
        bad = [args for args in calls if "filter=\"data\"" not in args]
        check(not bad,
              f"{name}: every extractall call passes filter=\"data\""
              + (f" (offenders: {bad})" if bad else ""))
        fields = prompt_fields(src)
        check(set(fields) == {"plan", "map", "refute", "reduce", "verify"},
              f"{name}: engine formats all five prompts ({sorted(fields)})")
        for p, keys in fields.items():
            text = (tree / "prompts" / f"{p}.md").read_text(encoding="utf-8")
            try:
                text.format(**{k: "x" for k in keys})
                check(True, f"{name}: prompts/{p}.md formats with {len(keys)} fields")
            except (KeyError, IndexError, ValueError) as e:
                check(False, f"{name}: prompts/{p}.md does not format: {e!r}")
        try:
            json.loads((tree / "references" / "standards" / "standards.json").read_text(encoding="utf-8"))
            check(True, f"{name}: standards.json is valid JSON")
        except (OSError, json.JSONDecodeError) as e:
            check(False, f"{name}: standards.json {e}")
    check(dircmp_equal(ROOT / "references", ROOT / ".minimax" / "references"),
          "references/ is identical in both trees")
    fixture_lockfile_check()


def engine_checks(work: Path) -> None:
    root = work / "root"
    shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    toml = (root / "swarm.example.toml").read_text(encoding="utf-8")
    toml = re.sub(r'(?m)^data_dir = .*$', f'data_dir = "{(work / "rootdata").as_posix()}"', toml)
    (root / "swarm.toml").write_text(toml, encoding="utf-8")
    code = r'''
import json, sys, swarm
cat = swarm.standards_catalog()
assert "A01:2025" in cat and "API1:2023" in cat, "catalog incomplete"
pb = swarm.attack_playbook({"files": [{"file": "src/lib/logger.ts"}, {"file": "src/routes/auth.js"}]})
assert "Core classes" in pb and "LOGGING-ALERTING" in pb, "playbook selection broken"
assert swarm.norm_std_ids(["a01", "API1", "nope"]) == ["A01:2025", "API1:2023"], "id normalisation broken"
meta = {"id": "t", "repo": "t", "commit": "abcdef1", "branch": "main", "uncommitted_changes_excluded": 0,
        "selectors_queued": ["s1"], "deps": {"ran": False, "reason": "test"},
        "coverage": {"in_scope_files": 3, "matched_files": 2, "queued_files": 2, "matched_not_queued": 0,
                     "unmatched_files": 1, "unmatched_by_dir": {"src": 1}}}
plan = {"standards": ["top10"], "selectors": [{"id": "s1", "owasp": ["A01:2025"]}]}
red = {"summary": "s", "findings": [{"id": "F1", "priority": "P1", "title": "x", "owasp": ["A05"]}],
       "chains": [], "unvalidated": [{"title": "u", "missing_fact": "m", "owasp": ["A02"]}]}
r = swarm.render_report(meta, red, None, plan)
for s in ("Security top lists", "finding: F1", "lead only", "checked, nothing found", "Not reviewed",
          "Unvalidated", "Dependency vulnerabilities", "Not run"):
    assert s in r, "report misses: " + s
print("engine ok")
'''
    p = subprocess.run([sys.executable, "-c", code], cwd=str(root), capture_output=True, text=True)
    check(p.returncode == 0, "root: engine functions + report render" + ("" if p.returncode == 0 else
                                                                       f"\n{p.stdout}{p.stderr}"))
    # The CLI reads swarm.toml at import time, so run it in a scratch dir with a config copy.
    cli_dir = root / ".minimax"
    p = subprocess.run([sys.executable, "swarm.py", "--help"], cwd=str(cli_dir), capture_output=True, text=True)
    subs = set(re.findall(r"add_parser\(\"(\w+)\"", (root / "swarm.py").read_text(encoding="utf-8")))
    check(p.returncode == 0 and subs == {"plan", "approve", "run", "verify", "status", "coverage", "deps", "ask", "repos"},
          f"root: CLI exposes exactly the documented subcommands ({sorted(subs)})")
    # argparse errors are exit 2; a real "no such scan" is exit 1 (sys.exit(str)).
    for args, want in ((["badcmd"], 2), (["coverage"], 2), (["coverage", "nosuchscan"], 1)):
        p = subprocess.run([sys.executable, "swarm.py", *args], cwd=str(cli_dir),
                           capture_output=True, text=True)
        check(p.returncode == want,
              f"root: {' '.join(args)} exits exactly {want} (got {p.returncode})")


def catalog_fragments() -> list:
    """Real content from standards.json (not headings a prompt template can print on its own)."""
    data = json.loads((ROOT / "references" / "standards" / "standards.json").read_text(encoding="utf-8"))
    out = [lst["name"] for lst in data["lists"]]
    for lst in data["lists"]:
        out += [cid for cid, cname in lst["categories"][:2]]
        out += [lst["categories"][0][1]]
    return [frag for frag in out if frag]


CATALOG_FRAGS = catalog_fragments()


def minimax_pipeline(work: Path) -> None:
    mm = work / "mm"
    shutil.copytree(ROOT / ".minimax", mm, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    toml = (mm / "swarm.toml").read_text(encoding="utf-8")
    toml = re.sub(r'(?m)^data_dir = .*$', f'data_dir = "{(work / "mmdata").as_posix()}"', toml)
    rg = shutil.which("rg") or ""
    toml = re.sub(r'(?m)^rg_path = .*$', f'rg_path = "{Path(rg).as_posix() if rg else ""}"', toml)
    (mm / "swarm.toml").write_text(toml, encoding="utf-8")

    def run(*args):
        p = subprocess.run([sys.executable, "swarm.py", *args], cwd=str(mm), capture_output=True,
                           text=True, encoding="utf-8")
        if p.returncode != 0:
            raise RuntimeError(f"swarm.py {' '.join(args)} exit {p.returncode}\n{p.stdout}\n{p.stderr}")
        out = p.stdout
        return json.loads(out[out.index("{"):]) if "{" in out else {}

    def reply(path, obj):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text("<<<SWARM_JSON\n" + json.dumps(obj) + "\nSWARM_JSON>>>", encoding="utf-8")

    try:
        run("fixture-init")
        m = run("plan-begin", "selftest")
        sid = m["scan"]
        task = m.get("task") or m["tasks"][0]
        plan_text = Path(task["prompt"]).read_text(encoding="utf-8")
        missing = [f for f in CATALOG_FRAGS if f not in plan_text]
        check(not missing, f"minimax: plan prompt carries the standards catalog content (missing {missing})")
        reply(task["out"], {"threat_model": "tm", "investigation_guidance": "g", "severity_criteria": "s",
                            "exclude_globs": [], "standards": ["top10", "api"],
                            "selectors": [{"id": "routes", "category": "input", "description": "routes",
                                           "pattern": r"router\.", "globs": ["src/routes/**"],
                                           "owasp": ["A01:2025", "API1:2023"]}]})
        run("plan-ingest", sid)
        run("approve", sid)
        m = run("map-begin", sid)
        check(bool(m.get("coverage")), "minimax: map-begin reports coverage")
        first = Path(m["tasks"][0]["prompt"]).read_text(encoding="utf-8")
        core = (ROOT / ".minimax" / "references" / "attack-classes" / "ATTACK-CLASSES.md").read_text(encoding="utf-8")
        # Assert real checklist content, not the playbook's constant heading (review F2).
        bodies = [ln.strip() for ln in core.splitlines()
                  if len(ln.strip()) > 40 and not ln.startswith("#") and not ln.startswith("-")]
        check(len(bodies) >= 3,
              f"attack playbook has real checklist rows to assert ({len(bodies)} found)")
        missing = [b[:60] for b in bodies if b not in first]
        check(not missing, f"minimax: map prompt carries the attack playbook rows (missing {missing})")
        map_tasks = m["tasks"]
        for t in map_tasks:
            reply(t["out"], {"findings": [{"title": "SQLi", "severity": "high",
                                           "locations": [{"path": "src/routes/search.js", "lines": "1"}]}]})
        m = run("map-ingest", sid)
        check(m.get("raw_findings") == len(map_tasks) and not m.get("failed_batches")
              and not m.get("coverage_gap"), "minimax: every map batch ingested (manifest)")
        m = run("refute-begin", sid)
        refute_tasks = m["tasks"]
        check(len(refute_tasks) >= 1, "minimax: mapper finding reached the refuter")
        for t in refute_tasks:
            reply(t["out"], {"verdicts": [{"finding": 1, "verdict": "stands"}]})
        run("refute-ingest", sid)
        m = run("reduce-begin", sid)
        reduce_text = Path(m["task"]["prompt"]).read_text(encoding="utf-8")
        missing = [f for f in CATALOG_FRAGS if f not in reduce_text]
        check(not missing, f"minimax: reduce prompt carries the standards catalog content (missing {missing})")
        check(m.get("n_findings") == len(map_tasks), "minimax: every mapper finding reached the reducer")
        check("SQLi" in reduce_text and "src/routes/search.js" in reduce_text,
              "minimax: map -> reduce data path (finding content in the reduce prompt)")
        reply(m["task"]["out"], {"summary": "s", "chains": [], "dismissed": [],
                                 "findings": [{"id": "F1", "priority": "P1", "title": "SQLi", "owasp": ["A05:2025"],
                                               "locations": [{"path": "src/routes/search.js", "lines": "1"}]}],
                                 "unvalidated": [{"title": "SSRF", "missing_fact": "egress", "owasp": ["API7"]}]})
        run("reduce-ingest", sid)
        m = run("verify-begin", sid)
        for t in m["tasks"]:
            reply(t["out"], {"verdict": "confirmed", "reason": "r", "evidence": []})
        m = run("verify-ingest", sid)
        check(m.get("confirmed", 0) >= 1 and m.get("unverified", 0) == 0,
              "minimax: verifier verdicts ingested (manifest)")
        run("coverage", sid)
        run("deps", sid)
        rep = Path(run("report", sid)["report"]).read_text(encoding="utf-8")
        for s in ("Security top lists", "finding: F1", "checked, nothing found", "lead only",
                  "Not reviewed", "Unvalidated", "Dependency vulnerabilities"):
            check(s in rep, f"minimax: report contains '{s}'")
    except Exception as e:  # noqa: BLE001
        check(False, f"minimax: pipeline failed: {e}")


def main() -> int:
    static_checks()
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        engine_checks(work)
        minimax_pipeline(work)
    print(f"\n{len(FAILS)} failure(s)")
    return 1 if FAILS else 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    sys.exit(main())
