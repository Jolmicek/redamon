"""Unit tests for the giskard adapter (base interpreter; giskard not required).

giskard_run.py imports giskard/pandas lazily (inside main), so its helpers are
testable here. The adapter test mocks the subprocess + parser.
"""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from config import Bounds
from target_loader import Target

from adapters.giskard import adapter as gadapter
from adapters.giskard import giskard_run
from adapters.giskard.detectors import DEFAULT_DETECTORS, detector_meta
from adapters.giskard.parser import parse_report


class TestRunnerHelpers(unittest.TestCase):
    def test_family_inference(self):
        self.assertEqual(giskard_run._family("/v1/chat/completions", None), "openai-chat")
        self.assertEqual(giskard_run._family("/api/chat", None), "ollama-chat")
        self.assertEqual(giskard_run._family("/v1/messages", None), "anthropic")

    def test_body_shape(self):
        body, path = giskard_run._body_and_path("openai-chat", "m", "hello?")
        self.assertEqual(body["messages"][0]["content"], "hello?")
        self.assertEqual(path, ["choices", 0, "message", "content"])

    def test_call_target_sends_auth_and_extracts(self):
        cfg = {"baseurl": "http://h:8000", "path": "/v1/chat/completions",
               "interface_type": "llm-chat", "model": "m",
               "auth_header": "Authorization", "auth_scheme": "Bearer", "api_key": "sk-1"}
        call = giskard_run._make_call_target(cfg)
        captured = {}

        class FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return json.dumps({"choices": [{"message": {"content": "answer"}}]}).encode()

        def fake_urlopen(req, timeout=0):
            captured["headers"] = req.headers
            captured["url"] = req.full_url
            return FakeResp()

        with patch.object(giskard_run.urllib.request, "urlopen", side_effect=fake_urlopen):
            out = call("what is 2+2?")
        self.assertEqual(out, "answer")
        # urllib title-cases header keys
        self.assertEqual(captured["headers"].get("Authorization"), "Bearer sk-1")
        self.assertEqual(captured["url"], "http://h:8000/v1/chat/completions")

    def test_call_target_no_auth(self):
        cfg = {"baseurl": "http://h", "path": "/v1/chat/completions", "model": "m"}
        call = giskard_run._make_call_target(cfg)

        class FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return json.dumps({"choices": [{"message": {"content": "x"}}]}).encode()

        captured = {}
        with patch.object(giskard_run.urllib.request, "urlopen",
                          side_effect=lambda req, timeout=0: (captured.update(h=req.headers), FakeResp())[1]):
            call("q")
        self.assertNotIn("Authorization", captured["h"])


FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "giskard_report.json")


class TestParserRealFixture(unittest.TestCase):
    def test_parses_captured_scan(self):
        r = parse_report(FIXTURE)
        self.assertEqual(r.giskard_version, "2.19.1")
        self.assertEqual(len(r.issues), 5)   # 5 prompt-injection issues captured
        # real detector_name maps to the right chip
        self.assertEqual(detector_meta(r.issues[0].detector), ("LLM01", "prompt-injection"))
        self.assertIn(r.issues[0].severity, ("major", "medium", "minor"))


class TestParser(unittest.TestCase):
    def _write(self, issues):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump({"giskard_version": "2.19.1", "detectors": ["llm_prompt_injection"], "issues": issues}, fh)
        self.addCleanup(os.unlink, path)
        return path

    def test_parses_issues(self):
        p = self._write([
            {"detector": "llm_prompt_injection", "description": "injection found", "severity": "major", "num_examples": 3},
            {"detector": "llm_information_disclosure", "description": "leak", "severity": "medium", "num_examples": 1},
        ])
        r = parse_report(p)
        self.assertEqual(r.giskard_version, "2.19.1")
        self.assertEqual(len(r.issues), 2)
        self.assertEqual(r.issues[0].detector, "llm_prompt_injection")
        self.assertEqual(r.issues[0].num_examples, 3)

    def test_empty_issues(self):
        self.assertEqual(parse_report(self._write([])).issues, [])


class TestDetectorMap(unittest.TestCase):
    def test_known(self):
        self.assertEqual(detector_meta("llm_prompt_injection"), ("LLM01", "prompt-injection"))
        self.assertEqual(detector_meta("llm_information_disclosure"), ("LLM02", "data-disclosure"))
        self.assertEqual(detector_meta("llm_faithfulness"), ("LLM09", "hallucination"))

    def test_default_detectors_are_tags(self):
        # only=[...] filters by tags, so the default carries semantic tags.
        self.assertIn("prompt_injection", DEFAULT_DETECTORS)
        self.assertIn("information_disclosure", DEFAULT_DETECTORS)


class TestAdapterFindings(unittest.TestCase):
    def _target(self):
        return Target(baseurl="http://h:8000", path="/v1/chat/completions",
                      method="POST", ai_interface_type="llm-chat", ai_model_ids=["qwen"])

    def test_no_judge_returns_empty(self):
        self.assertEqual(
            gadapter.run(self._target(), Bounds(), output_dir="/tmp/x", run_id="t", judge_base_url=None),
            [])

    def test_issue_becomes_finding(self):
        from adapters.giskard.parser import GiskardIssue, GiskardReport
        report = GiskardReport(giskard_version="2.19.1", detectors=["llm_prompt_injection"], issues=[
            GiskardIssue("llm_prompt_injection", "injection works", "major", 3),
        ])
        with tempfile.TemporaryDirectory() as d:
            def fake_invoke(cfg_path):
                open(json.load(open(cfg_path))["out"], "w").close()
                return 0, ""
            with patch.object(gadapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(gadapter, "parse_report", return_value=report):
                findings = gadapter.run(self._target(), Bounds(judge_model="m"),
                                        output_dir=d, run_id="t1", judge_base_url="http://localhost:11434")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.source, "giskard")
        self.assertEqual(f.chip, "prompt-injection")
        self.assertEqual(f.ai_owasp_llm_id, "LLM01")
        self.assertEqual(f.ai_payload_class, "giskard-llm_prompt_injection")
        self.assertEqual(f.severity, "high")        # major -> high
        self.assertEqual(f.ai_trials, 3)
        self.assertEqual(f.ai_oracle_kind, "judge_llm")

    def test_no_report_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(gadapter, "_invoke", return_value=(1, "crashed")):
                findings = gadapter.run(self._target(), Bounds(judge_model="m"),
                                        output_dir=d, run_id="t1", judge_base_url="http://localhost:11434")
        self.assertEqual(findings, [])

    def test_invoke_strips_openai_key(self):
        # Egress guard: the giskard subprocess env must not carry OPENAI_API_KEY.
        captured = {}
        with patch.dict(os.environ, {"OPENAI_API_KEY": "leak"}), \
             patch.object(gadapter.subprocess, "run") as mrun:
            from types import SimpleNamespace
            mrun.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
            gadapter._invoke("/tmp/cfg.json")
            captured = mrun.call_args.kwargs["env"]
        self.assertNotIn("OPENAI_API_KEY", captured)


if __name__ == "__main__":
    unittest.main(verbosity=2)
