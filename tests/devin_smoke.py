"""Offline native workflow contract tests; no cloud agents, network or provider keys."""
import asyncio
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("devin_workflow", ROOT / "skills/security-swarm/workflow.py")
workflow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workflow)


class AgentFailure(Exception):
    pass


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        (self.repo / "app.py").write_text("value = input()\nprint(value)\n")
        self.git("add", "app.py")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
        self.output = self.root / "scan"
        self.output.mkdir()
        workflow.CONFIG = {"source_dir": str(ROOT), "repo_path": str(self.repo),
                           "repo": "github.com/example/fixture", "commit": self.git("rev-parse", "HEAD").strip(),
                           "output_dir": str(self.output), "mode": "plan", "batch_size": 1}
        self.calls = []
        self.fail = set()
        self.plan = {"threat_model": "Local CLI input", "selectors": [
            {"id": "S1", "pattern": None, "globs": ["*.py"], "category": "input", "owasp": ["A01"]}]}
        workflow.WorkflowAgentError = AgentFailure
        workflow.log = lambda message: None

        async def register(meta):
            self.assertEqual(meta["subscribe"], "none")
            self.assertTrue(all(p["subscribe"] == "none" for p in meta["phases"]))

        async def agent(prompt, **kwargs):
            phase = kwargs["phase"]
            self.calls.append((phase, prompt))
            self.assertIn(workflow.CONFIG["commit"], prompt)
            self.assertNotIn("vm_mode", kwargs)
            if phase in self.fail:
                raise AgentFailure(phase)
            if phase == "plan":
                return self.plan
            if phase == "map":
                return {"findings": [{"title": "Synthetic lead", "severity": "high", "locations": []}]}
            if phase == "refute":
                return {"verdicts": [{"finding": 1, "verdict": "stands", "reason": "No blocker"}]}
            if phase == "reduce":
                return {"summary": "Synthetic only", "findings": [{"id": "F1", "priority": "P1", "title": "Lead"}],
                        "chains": [{"id": "C1", "priority": "P1", "title": "Chain", "steps": ["F1"]}],
                        "unvalidated": [{"title": "External limit", "missing_fact": "deployment"}]}
            if phase == "verify":
                claim = "C1" if kwargs["label"].startswith("chain-") else "F1"
                # Fallback reducer uses R1.
                if kwargs["label"] == "finding-R1":
                    claim = "R1"
                return {"claim": claim, "verdict": "confirmed", "reason": "Synthetic source evidence",
                        "evidence": [{"path": "app.py", "lines": "1", "quote": "value = input()"}]}
            raise AssertionError(phase)

        workflow.register_workflow = register
        workflow.agent = agent

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True)

    def run_workflow(self):
        asyncio.run(workflow.main())

    def approve(self):
        self.run_workflow()
        meta = json.loads((self.output / "scan.json").read_text())
        plan = json.loads((self.output / "plan.json").read_text())
        workflow.CONFIG.update(mode="run", approved_plan_sha256=workflow.digest(
            workflow.approval_payload(meta, plan, workflow.CONFIG)))

    def test_plan_stops_and_digest_binds_batching(self):
        self.approve()
        self.assertEqual([p for p, _ in self.calls], ["plan"])
        workflow.CONFIG["batch_size"] = 2
        with self.assertRaisesRegex(ValueError, "approval"):
            self.run_workflow()

    def test_all_claims_independently_verified(self):
        self.approve()
        self.run_workflow()
        report = json.loads((self.output / "findings.json").read_text())
        self.assertEqual(len([c for c in self.calls if c[0] == "verify"]), 2)
        self.assertEqual(report["chains"][0]["verification"]["verdict"], "confirmed")
        self.assertIn("Dependency", (self.output / "report.md").read_text())
        finding_prompt = next(p for phase, p in self.calls if phase == "verify" and '"id": "F1"' in p)
        self.assertNotIn('"id": "C1"', finding_prompt)

    def test_refuter_failure_keeps_findings(self):
        self.approve()
        self.fail.add("refute")
        self.run_workflow()
        self.assertTrue(json.loads((self.output / "findings.json").read_text())["findings"])

    def test_verifier_failure_never_confirms(self):
        self.approve()
        self.fail.add("verify")
        self.run_workflow()
        red = json.loads((self.output / "findings.json").read_text())
        for claim in red["findings"] + red["chains"]:
            self.assertEqual(claim["verification"]["verdict"], "unverified")

    def test_reducer_failure_keeps_raw_findings_with_warning(self):
        self.approve()
        self.fail.add("reduce")
        self.run_workflow()
        red = json.loads((self.output / "findings.json").read_text())
        self.assertTrue(red["reducer_failed"])
        self.assertIn("REDUCER FAILED", red["summary"])

    def test_mapper_failure_is_reported_as_coverage_gap(self):
        self.approve()
        self.fail.add("map")
        self.run_workflow()
        self.assertEqual(json.loads((self.output / "scan.json").read_text())["map_failed"], ["B001"])

    def test_bad_regex_blocks_execution(self):
        self.plan["selectors"][0]["pattern"] = "("
        self.approve()
        with self.assertRaisesRegex(ValueError, "regex"):
            self.run_workflow()

    def test_malformed_and_unsupported_verdicts_fail_closed(self):
        for reply in ({}, {"claim": "F", "verdict": "confirmed", "reason": "Trust me", "evidence": []},
                      {"claim": "other", "verdict": "confirmed", "reason": "x", "evidence": []}):
            self.assertEqual(workflow.normalize_verdict(reply, "F")["verdict"], "unverified")

    def test_duplicate_or_unsupported_refutations_fail_open(self):
        report = {"batch": "B1", "findings": [{"title": "Keep"}]}
        verdict = {"finding": 1, "verdict": "refuted", "reason": "guard", "evidence": "app.py:1 quoted"}
        self.assertEqual(len(workflow.filter_report(report, [verdict, verdict])[0]), 1)
        self.assertEqual(len(workflow.filter_report(report, [{**verdict, "evidence": ""}])[0]), 1)
        self.assertEqual(len(workflow.filter_report(report, [verdict])[1]), 1)


if __name__ == "__main__":
    unittest.main()
