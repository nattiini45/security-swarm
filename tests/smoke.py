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
    if c.left_only or c.right_only or c.funny_files:
        return False
    _, mismatch, errors = filecmp.cmpfiles(a, b, c.common_files, shallow=False)
    if mismatch or errors:
        return False
    return all(dircmp_equal(a / d, b / d) for d in c.common_dirs)


def static_checks() -> None:
    for name, tree in TREES.items():
        src = (tree / "swarm.py").read_text(encoding="utf-8")
        try:
            ast.parse(src)
            check(True, f"{name}: swarm.py parses")
        except SyntaxError as e:
            check(False, f"{name}: swarm.py syntax error {e}")
            continue
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
    p = subprocess.run([sys.executable, "swarm.py", "--help"], cwd=str(root), capture_output=True, text=True)
    check(p.returncode == 0 and "deps" in p.stdout and "coverage" in p.stdout, "root: CLI help lists deps + coverage")


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
        check("SECURITY TOP LISTS" in plan_text, "minimax: plan prompt carries the standards catalog")
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
        check("ATTACK-CLASS PLAYBOOK" in first, "minimax: map prompt carries the attack playbook")
        for t in m["tasks"]:
            reply(t["out"], {"findings": [{"title": "SQLi", "severity": "high",
                                           "locations": [{"path": "src/routes/search.js", "lines": "1"}]}]})
        run("map-ingest", sid)
        m = run("refute-begin", sid)
        for t in m["tasks"]:
            reply(t["out"], {"verdicts": [{"finding": 1, "verdict": "stands"}]})
        run("refute-ingest", sid)
        m = run("reduce-begin", sid)
        reduce_text = Path(m["task"]["prompt"]).read_text(encoding="utf-8")
        check("SECURITY TOP LISTS" in reduce_text, "minimax: reduce prompt carries the standards catalog")
        reply(m["task"]["out"], {"summary": "s", "chains": [], "dismissed": [],
                                 "findings": [{"id": "F1", "priority": "P1", "title": "SQLi", "owasp": ["A05:2025"],
                                               "locations": [{"path": "src/routes/search.js", "lines": "1"}]}],
                                 "unvalidated": [{"title": "SSRF", "missing_fact": "egress", "owasp": ["API7"]}]})
        run("reduce-ingest", sid)
        m = run("verify-begin", sid)
        for t in m["tasks"]:
            reply(t["out"], {"verdict": "confirmed", "reason": "r", "evidence": []})
        run("verify-ingest", sid)
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
