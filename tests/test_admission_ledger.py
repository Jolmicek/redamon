"""Unit tests for recon_orchestrator/admission_ledger.py (memory-aware scan admission).

Deterministic: injects synthetic host memory via the governor override and fixed
env sizes, so no Docker/host dependency. Run:
    python3 -m unittest tests.test_admission_ledger
"""
import os
import sys
import unittest

# Import the orchestrator module + its governor copy directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'recon_orchestrator'))

import resource_governor as rg
import admission_ledger as al

GB = 1024 ** 3


class LedgerTestBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        for k in ("REDAMON_MEM_GOVERNOR", "OS_HEADROOM_MEM", "SERVICE_BASELINE_MEM",
                  "RECON_JOB_ENVELOPE_MEM", "RECON_MAX_CONCURRENT_GLOBAL",
                  "RECON_MAX_CONCURRENT_PER_USER", "RESOURCE_PROFILE_PATH"):
            os.environ.pop(k, None)
        # Deterministic pool: 32G total, 30G available, 2G OS, 6G baseline -> 24G pool.
        rg.set_mem_override(32 * GB, 30 * GB)
        rg.reset_profile_cache()
        os.environ["OS_HEADROOM_MEM"] = "2g"
        os.environ["SERVICE_BASELINE_MEM"] = "6g"
        os.environ["RECON_JOB_ENVELOPE_MEM"] = "4g"

    def tearDown(self):
        rg.set_mem_override(None, None)
        for k in ("OS_HEADROOM_MEM", "SERVICE_BASELINE_MEM", "RECON_JOB_ENVELOPE_MEM",
                  "RECON_MAX_CONCURRENT_GLOBAL", "RECON_MAX_CONCURRENT_PER_USER",
                  "REDAMON_MEM_GOVERNOR"):
            os.environ.pop(k, None)


class TestPoolMath(LedgerTestBase):
    async def test_scan_pool(self):
        led = al.ReservationLedger()
        self.assertEqual(led.scan_pool(), 24 * GB)

    async def test_remaining_for_new_starts_full(self):
        led = al.ReservationLedger()
        self.assertEqual(led.remaining_for_new(), 24 * GB)  # min(24, 30-2=28)


class TestAdmission(LedgerTestBase):
    async def test_admit_until_pool_full_then_ram_reject(self):
        led = al.ReservationLedger()
        env = 4 * GB
        # 24G pool / 4G envelope = 6 jobs fit.
        for i in range(6):
            r = await led.try_admit(f"job{i}", env)
            self.assertTrue(r.admitted, f"job{i} should fit")
        self.assertEqual(led.active_count(), 6)
        self.assertEqual(led.committed_bytes(), 24 * GB)
        # 7th must be rejected as a RAM limit.
        r = await led.try_admit("job6", env)
        self.assertFalse(r.admitted)
        self.assertEqual(r.limit_type, "ram")
        self.assertIn("memory", r.detail.lower())

    async def test_release_frees_budget(self):
        led = al.ReservationLedger()
        env = 4 * GB
        for i in range(6):
            await led.try_admit(f"job{i}", env)
        self.assertFalse((await led.try_admit("extra", env)).admitted)
        await led.release("job0")
        self.assertTrue((await led.try_admit("extra", env)).admitted)

    async def test_release_all_returns_to_zero(self):
        led = al.ReservationLedger()
        for i in range(3):
            await led.try_admit(f"job{i}", 4 * GB)
        for i in range(3):
            await led.release(f"job{i}")
        self.assertEqual(led.committed_bytes(), 0)
        self.assertEqual(led.active_count(), 0)

    async def test_idempotent_readmit(self):
        led = al.ReservationLedger()
        await led.try_admit("job", 4 * GB)
        await led.try_admit("job", 4 * GB)  # re-admit same key
        self.assertEqual(led.active_count(), 1)
        self.assertEqual(led.committed_bytes(), 4 * GB)

    async def test_hard_count_cap(self):
        os.environ["RECON_MAX_CONCURRENT_GLOBAL"] = "2"
        led = al.ReservationLedger()
        self.assertTrue((await led.try_admit("a", 1 * GB)).admitted)
        self.assertTrue((await led.try_admit("b", 1 * GB)).admitted)
        r = await led.try_admit("c", 1 * GB)
        self.assertFalse(r.admitted)
        self.assertEqual(r.limit_type, "hard")
        self.assertEqual(r.setting_name, "RECON_MAX_CONCURRENT_GLOBAL")

    async def test_critical_pressure_blocks(self):
        led = al.ReservationLedger(pressure_fn=lambda: "critical")
        r = await led.try_admit("a", 1 * GB)
        self.assertFalse(r.admitted)
        self.assertEqual(r.limit_type, "ram")

    async def test_low_availability_blocks_even_if_pool_ok(self):
        # Pool has room but live available is tiny.
        rg.set_mem_override(32 * GB, 3 * GB)  # available 3G < envelope(4G)+headroom(2G)
        led = al.ReservationLedger(pressure_fn=lambda: "ok")
        r = await led.try_admit("a", 4 * GB)
        self.assertFalse(r.admitted)
        self.assertEqual(r.limit_type, "ram")

    async def test_disabled_always_admits(self):
        os.environ["REDAMON_MEM_GOVERNOR"] = "false"
        led = al.ReservationLedger()
        for i in range(20):
            self.assertTrue((await led.try_admit(f"job{i}", 4 * GB)).admitted)


class TestReviewFixes(LedgerTestBase):
    async def test_fail_open_when_mem_unreadable(self):
        # /proc unreadable -> mem_reader returns None -> must ADMIT (fail open),
        # not deny everything (matches scaled_cap's fail-open contract).
        led = al.ReservationLedger(mem_reader=lambda: None, pressure_fn=lambda: "ok")
        r = await led.try_admit("a", 4 * GB)
        self.assertTrue(r.admitted)

    async def test_first_scan_admitted_even_when_pool_zero(self):
        # Tiny/zero pool but ample live RAM: the SOLE scan must not be denied on
        # budget grounds (small-host regression fix).
        os.environ["SERVICE_BASELINE_MEM"] = "40g"  # pool = max(0, 32-2-40) = 0
        led = al.ReservationLedger()
        r1 = await led.try_admit("first", 4 * GB)
        self.assertTrue(r1.admitted, "sole scan must be admitted when RAM physically fits")
        # But a SECOND concurrent scan is bounded by the (zero) pool.
        r2 = await led.try_admit("second", 4 * GB)
        self.assertFalse(r2.admitted)
        self.assertEqual(r2.limit_type, "ram")

    async def test_first_scan_denied_when_physically_too_big(self):
        # Sole scan still denied if live available can't hold envelope + headroom.
        rg.set_mem_override(32 * GB, 3 * GB)  # avail 3G < 4G+2G
        led = al.ReservationLedger()
        r = await led.try_admit("first", 4 * GB)
        self.assertFalse(r.admitted)
        self.assertEqual(r.limit_type, "ram")

    async def test_cap_zero_blocks_all(self):
        os.environ["RECON_MAX_CONCURRENT_GLOBAL"] = "0"
        led = al.ReservationLedger()
        r = await led.try_admit("a", 1 * GB)
        self.assertFalse(r.admitted)
        self.assertEqual(r.limit_type, "hard")

    async def test_envelope_zero_override_ignored(self):
        os.environ["RECON_JOB_ENVELOPE_MEM"] = "0"
        rg.reset_profile_cache()
        led = al.ReservationLedger()
        self.assertGreater(led.envelope_for("full_recon"), 0)  # falls back to profile

    async def test_idempotent_readmit_keeps_larger(self):
        led = al.ReservationLedger()
        await led.try_admit("scan", 1 * GB)
        await led.try_admit("scan", 4 * GB)  # escalated envelope
        self.assertEqual(led.committed_bytes(), 4 * GB)


class TestReconcileAndRelease(LedgerTestBase):
    async def test_reconcile_drops_stale(self):
        led = al.ReservationLedger()
        for i in range(3):
            await led.try_admit(f"job{i}", 4 * GB)
        # only job1 still active -> job0, job2 released
        dropped = led.reconcile({"job1"})
        self.assertEqual(dropped, 2)
        self.assertEqual(led.active_count(), 1)
        self.assertEqual(led.committed_bytes(), 4 * GB)

    async def test_reconcile_noop_when_all_active(self):
        led = al.ReservationLedger()
        await led.try_admit("a", 4 * GB)
        await led.try_admit("b", 4 * GB)
        self.assertEqual(led.reconcile({"a", "b"}), 0)
        self.assertEqual(led.active_count(), 2)

    async def test_release_nowait(self):
        led = al.ReservationLedger()
        await led.try_admit("a", 4 * GB)
        led.release_nowait("a")
        self.assertEqual(led.active_count(), 0)
        led.release_nowait("missing")  # no error on unknown key

    async def test_admission_error_carries_payload(self):
        os.environ["RECON_MAX_CONCURRENT_GLOBAL"] = "1"
        led = al.ReservationLedger()
        await led.try_admit("a", 1 * GB)
        r = await led.try_admit("b", 1 * GB)
        self.assertFalse(r.admitted)
        err = al.AdmissionError(r)
        self.assertIsInstance(err, ValueError)  # graceful today
        self.assertEqual(err.result.limit_type, "hard")
        self.assertEqual(err.result.payload()["settingName"], "RECON_MAX_CONCURRENT_GLOBAL")


class TestEnvelopeAndSnapshot(LedgerTestBase):
    async def test_envelope_env_override(self):
        led = al.ReservationLedger()
        self.assertEqual(led.envelope_for("full_recon"), 4 * GB)  # from env

    async def test_envelope_profile_fallback(self):
        os.environ.pop("RECON_JOB_ENVELOPE_MEM", None)
        rg.reset_profile_cache()
        led = al.ReservationLedger()
        self.assertGreater(led.envelope_for("full_recon"), 0)

    async def test_snapshot_shape(self):
        led = al.ReservationLedger()
        await led.try_admit("a", 4 * GB)
        snap = led.snapshot()
        for key in ("host_total", "available", "os_headroom", "service_baseline",
                    "scan_pool", "committed", "active_scans", "remaining_for_new",
                    "pressure"):
            self.assertIn(key, snap)
        self.assertEqual(snap["committed"], 4 * GB)
        self.assertEqual(snap["active_scans"], 1)


class TestScanCaps(LedgerTestBase):
    """D3: global + per-user concurrent-scan ceilings."""

    async def test_global_scan_cap(self):
        os.environ["RECON_MAX_CONCURRENT_GLOBAL"] = "2"
        led = al.ReservationLedger()
        self.assertTrue((await led.try_admit("a", 1 * GB, user_id="u1")).admitted)
        self.assertTrue((await led.try_admit("b", 1 * GB, user_id="u2")).admitted)
        r = await led.try_admit("c", 1 * GB, user_id="u3")
        self.assertFalse(r.admitted)
        self.assertEqual(r.limit_type, "hard")
        self.assertEqual(r.setting_name, "RECON_MAX_CONCURRENT_GLOBAL")

    async def test_per_user_scan_cap(self):
        os.environ["RECON_MAX_CONCURRENT_PER_USER"] = "2"
        led = al.ReservationLedger()
        self.assertTrue((await led.try_admit("a", 1 * GB, user_id="u1")).admitted)
        self.assertTrue((await led.try_admit("b", 1 * GB, user_id="u1")).admitted)
        # u1's 3rd is blocked...
        r = await led.try_admit("c", 1 * GB, user_id="u1")
        self.assertFalse(r.admitted)
        self.assertEqual(r.setting_name, "RECON_MAX_CONCURRENT_PER_USER")
        # ...but a DIFFERENT user is unaffected.
        self.assertTrue((await led.try_admit("d", 1 * GB, user_id="u2")).admitted)

    async def test_per_user_default_when_unset(self):
        # Unset -> generous default (10), NOT "no cap".
        led = al.ReservationLedger()
        self.assertEqual(led.max_concurrent_per_user(), al._FALLBACK_PER_USER_CAP)

    async def test_release_decrements_user_count(self):
        os.environ["RECON_MAX_CONCURRENT_PER_USER"] = "1"
        led = al.ReservationLedger()
        self.assertTrue((await led.try_admit("a", 1 * GB, user_id="u1")).admitted)
        self.assertFalse((await led.try_admit("b", 1 * GB, user_id="u1")).admitted)
        # Release frees the slot; user can scan again (no leak/self-DoS).
        await led.release("a")
        self.assertEqual(led.user_active_count("u1"), 0)
        self.assertTrue((await led.try_admit("b", 1 * GB, user_id="u1")).admitted)

    async def test_reconcile_releases_user_count(self):
        os.environ["RECON_MAX_CONCURRENT_PER_USER"] = "1"
        led = al.ReservationLedger()
        await led.try_admit("orphan", 1 * GB, user_id="u1")
        # The scan died; reconcile with no active keys must free the user's slot.
        led.reconcile(set())
        self.assertEqual(led.user_active_count("u1"), 0)
        self.assertTrue((await led.try_admit("fresh", 1 * GB, user_id="u1")).admitted)


if __name__ == "__main__":
    unittest.main()
