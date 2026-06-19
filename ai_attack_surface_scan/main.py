"""AI Attack Surface scan — container entrypoint (Step 2: skeleton).

Control flow (shared spine; no tool yet):
  [Phase 1] Target loading   — read selected AI nodes from the graph
  [Phase 2] Safety / bounds  — RoE + bounds + hard-guardrail floor
  [Phase 3] Attack           — (skeleton) emit one dummy finding per target
  [Phase 4] Findings         — normalize -> Vulnerability, link to Endpoint

The phase markers are printed to stdout so the orchestrator's SSE layer (Step 3)
can pick them up, mirroring the gvm/trufflehog log conventions.
"""
from __future__ import annotations

import logging
import sys

from config import load_config
from graph import make_driver, verify_connection
from normalizer import make_dummy_finding, write_finding
from safety import SafetyError, enforce
from target_loader import load_targets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ai-attack-surface")


def run() -> int:
    cfg = load_config()
    print("=" * 64)
    print(f"[*] AI Attack Surface scan — tool={cfg.tool} run_id={cfg.run_id or 'dev'}")
    print(f"[*] project={cfg.project_id} user={cfg.user_id}")
    print("=" * 64)

    if not cfg.project_id or not cfg.user_id:
        print("[!] ERROR: PROJECT_ID and USER_ID are required")
        return 1

    # [Phase 2] Safety / bounds — fail fast before touching the graph or target.
    print("[Phase 2] Safety / bounds")
    try:
        enforce(cfg)
    except SafetyError as e:
        print(f"[!] Safety check failed: {e}")
        return 1

    driver = make_driver()
    try:
        if not verify_connection(driver):
            print("[!] ERROR: Neo4j connection failed")
            return 1

        with driver.session() as session:
            # [Phase 1] Target loading
            print("[Phase 1] Target loading")
            targets = load_targets(
                session,
                user_id=cfg.user_id,
                project_id=cfg.project_id,
                selected=cfg.targets or None,
            )
            print(f"    [+] {len(targets)} target(s) selected")
            if not targets:
                print("[!] No AI targets found/selected — nothing to do")
                return 0

            # [Phase 3] Attack (skeleton: no tool, dummy findings)
            print("[Phase 3] Attack (skeleton — no tool)")
            findings = [make_dummy_finding(t, cfg.tool, cfg.run_id) for t in targets]

            if cfg.dry_run:
                print(f"    [+] dry-run: would write {len(findings)} finding(s); not persisting")
                return 0

            # [Phase 4] Findings -> graph
            print("[Phase 4] Findings")
            linked = 0
            for f in findings:
                if write_finding(session, f, cfg.user_id, cfg.project_id):
                    linked += 1
            print(f"    [+] wrote {len(findings)} Vulnerability finding(s); "
                  f"{linked} linked directly to an Endpoint")

        print("=" * 64)
        print(f"[*] Done. {len(targets)} target(s), {len(findings)} finding(s).")
        print("=" * 64)
        return 0
    finally:
        driver.close()


def main() -> int:
    try:
        return run()
    except Exception as e:  # never crash silently; surface to the orchestrator logs
        log.exception("AI Attack Surface scan crashed")
        print(f"[!] Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
