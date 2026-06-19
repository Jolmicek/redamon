"""Tests for the main() control flow.

Error paths are unit-tested with everything mocked; the happy path runs against
a live Neo4j (skipped if unreachable) and asserts the phase markers advance in
numeric order (regression for the out-of-order Phase 2-before-1 bug).
"""
import io
import re
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

import graph
import main
import target_loader as tl
from config import Bounds, RunConfig


def _cfg(**kw):
    bounds = kw.pop("bounds", Bounds(judge_model="m"))
    base = dict(project_id="p", user_id="u", tool="skeleton",
                roe_confirmed=True, bounds=bounds)
    base.update(kw)
    return RunConfig(**base)


def _fake_driver(session):
    driver = MagicMock()
    driver.session.return_value.__enter__.return_value = session
    driver.session.return_value.__exit__.return_value = False
    return driver


def _phase_numbers(text):
    return [int(n) for n in re.findall(r"\[Phase (\d+)\]", text)]


class TestMainErrorPaths(unittest.TestCase):
    def test_missing_ids_returns_1(self):
        with patch.object(main, "load_config", return_value=_cfg(project_id="")):
            self.assertEqual(main.run(), 1)

    def test_safety_failure_returns_1(self):
        # RoE not confirmed and not dry-run -> SafetyError -> exit 1.
        with patch.object(main, "load_config", return_value=_cfg(roe_confirmed=False)):
            self.assertEqual(main.run(), 1)

    def test_neo4j_down_returns_1(self):
        with patch.object(main, "load_config", return_value=_cfg()), \
             patch.object(main, "make_driver", return_value=MagicMock()), \
             patch.object(main, "verify_connection", return_value=False):
            self.assertEqual(main.run(), 1)

    def test_no_targets_returns_0(self):
        session = MagicMock()
        with patch.object(main, "load_config", return_value=_cfg()), \
             patch.object(main, "make_driver", return_value=_fake_driver(session)), \
             patch.object(main, "verify_connection", return_value=True), \
             patch.object(main, "load_targets", return_value=[]):
            self.assertEqual(main.run(), 0)

    def test_crash_is_caught_and_returns_1(self):
        # main() wraps run(); an unexpected error must become exit 1, not a traceback.
        with patch.object(main, "run", side_effect=RuntimeError("boom")):
            self.assertEqual(main.main(), 1)

    def test_dry_run_writes_nothing(self):
        session = MagicMock()
        target = tl.Target(baseurl="http://h", path="/c", ai_interface_type="llm-chat")
        with patch.object(main, "load_config", return_value=_cfg(dry_run=True, roe_confirmed=False)), \
             patch.object(main, "make_driver", return_value=_fake_driver(session)), \
             patch.object(main, "verify_connection", return_value=True), \
             patch.object(main, "load_targets", return_value=[target]), \
             patch.object(main, "write_finding") as wf:
            self.assertEqual(main.run(), 0)
            wf.assert_not_called()

    def test_phase_order_monotonic_mocked(self):
        session = MagicMock()
        target = tl.Target(baseurl="http://h", path="/c", ai_interface_type="llm-chat")
        buf = io.StringIO()
        with patch.object(main, "load_config", return_value=_cfg()), \
             patch.object(main, "make_driver", return_value=_fake_driver(session)), \
             patch.object(main, "verify_connection", return_value=True), \
             patch.object(main, "load_targets", return_value=[target]), \
             patch.object(main, "write_finding", return_value=True):
            with redirect_stdout(buf):
                main.run()
        phases = _phase_numbers(buf.getvalue())
        self.assertEqual(phases, sorted(phases), f"phases not monotonic: {phases}")
        self.assertEqual(phases, [1, 2, 3, 4])


def _reachable():
    try:
        d = graph.make_driver()
        ok = graph.verify_connection(d)
        d.close()
        return ok
    except Exception:
        return False


@unittest.skipUnless(_reachable(), "no Neo4j reachable")
class TestMainLive(unittest.TestCase):
    UID = "aiatk-main-itest-user"
    PID = "aiatk-main-itest-proj"

    def setUp(self):
        self.driver = graph.make_driver()
        self._wipe()
        with self.driver.session() as s:
            s.run("""
                MERGE (b:BaseURL {url:$u, user_id:$uid, project_id:$pid})
                MERGE (e:Endpoint {baseurl:$u, path:'/v1/chat/completions', user_id:$uid, project_id:$pid})
                  SET e.method='POST', e.ai_interface_type='llm-chat'
                MERGE (b)-[:HAS_ENDPOINT]->(e)
            """, u="http://h:8000", uid=self.UID, pid=self.PID)

    def tearDown(self):
        self._wipe()
        self.driver.close()

    def _wipe(self):
        with self.driver.session() as s:
            s.run("MATCH (n {project_id:$pid}) DETACH DELETE n", pid=self.PID)

    def test_full_run_writes_linked_vuln_and_phases_ordered(self):
        cfg = _cfg(project_id=self.PID, user_id=self.UID)
        buf = io.StringIO()
        with patch.object(main, "load_config", return_value=cfg):
            with redirect_stdout(buf):
                rc = main.run()
        self.assertEqual(rc, 0)
        self.assertEqual(_phase_numbers(buf.getvalue()), [1, 2, 3, 4])
        with self.driver.session() as s:
            edges = s.run(
                "MATCH (:Endpoint {project_id:$pid})-[r:HAS_VULNERABILITY]->(:Vulnerability) RETURN count(r)",
                pid=self.PID).single()[0]
        self.assertEqual(edges, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
