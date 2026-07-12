#!/usr/bin/env bash
# =============================================================================
# T3 — deploy patches: sha256 integrity + fatal-on-failure.
#
# The real apply_one lives inside deploy.sh's remote heredoc, so we (a) statically
# assert the deploy.sh wiring (pinned sha present, fatal exits, dropped patches
# gone) and (b) exercise a faithful re-implementation of apply_one to prove the
# integrity + apply gates return non-zero.
#
# Run: bash tests/deploy_patch_integrity_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$REPO_ROOT/deploy/single-host/deploy.sh"
PATCH_DIR="$REPO_ROOT/deploy/single-host/patches"
KEEP="webapp-dockerfile-ws-arg.patch"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }

echo "== dropped patches are gone (folded by S12/S4) =="
[ ! -f "$PATCH_DIR/secure-cookie.patch" ] && pass "secure-cookie.patch removed" || fail "secure-cookie.patch still present"
[ ! -f "$PATCH_DIR/cypherfix-ws-origin.patch" ] && pass "cypherfix-ws-origin.patch removed" || fail "cypherfix-ws-origin.patch still present"

echo "== deploy.sh no longer APPLIES the dropped patches =="
if grep -qE 'apply_one .*secure-cookie\.patch|apply_one .*cypherfix-ws-origin\.patch' "$DEPLOY"; then
  fail "deploy.sh still calls apply_one on a dropped patch"
else
  pass "no apply_one call for dropped patches"
fi

echo "== the remaining patch's sha256 is pinned in deploy.sh (init + update) =="
ACTUAL_SHA="$(sha256sum "$PATCH_DIR/$KEEP" | awk '{print $1}')"
PIN_COUNT="$(grep -c "$ACTUAL_SHA" "$DEPLOY")"
[ "$PIN_COUNT" -eq 2 ] && pass "pinned sha256 matches the file at both apply sites" || fail "expected pinned sha256 x2, got $PIN_COUNT (drifted?)"

echo "== apply is fatal (exit 1), not skip-with-warn =="
# The new apply_one must exit 1 on a bad patch; the old code warned "SKIPPED".
if grep -q 'SKIPPED' "$DEPLOY"; then fail "deploy.sh still has a non-fatal SKIPPED path"; else pass "no non-fatal SKIPPED path"; fi
grep -q 'aborting deploy' "$DEPLOY" && pass "apply failure aborts the deploy" || fail "no abort-on-apply-failure"

echo "== the remaining patch still applies cleanly against HEAD =="
( cd "$REPO_ROOT" && git apply --check "$PATCH_DIR/$KEEP" 2>/dev/null ) \
  && pass "git apply --check passes for $KEEP" || fail "$KEEP no longer applies (rotted)"

echo "== faithful apply_one: integrity + fatal behavior =="
# Re-implementation mirroring deploy.sh's apply_one (host-runnable).
apply_one() {
  local p="$1" expected="$2"
  local name; name="$(basename "$p")"
  local actual; actual="$(sha256sum "$p" | awk '{print $1}')"
  [ "$actual" = "$expected" ] || { echo "integrity FAILED for $name"; return 1; }
  ( cd "$REPO_ROOT" && git apply --check "$p" 2>/dev/null ) || { echo "apply FAILED for $name"; return 1; }
  return 0
}

# (iii) real patch + correct hash -> ok
apply_one "$PATCH_DIR/$KEEP" "$ACTUAL_SHA" >/dev/null 2>&1 && pass "correct sha + appliable -> ok" || fail "real patch wrongly rejected"

# (i) mismatched sha -> refused
apply_one "$PATCH_DIR/$KEEP" "deadbeef" >/dev/null 2>&1 && fail "mismatched sha wrongly accepted" || pass "mismatched sha256 -> non-zero (refused)"

# (ii) a patch that will not apply (corrupt content, but with a correct self-sha)
TMP="$(mktemp -d)"; BAD="$TMP/bad.patch"
printf 'diff --git a/nope.txt b/nope.txt\n--- a/nope.txt\n+++ b/nope.txt\n@@ -1 +1 @@\n-old\n+new\n' > "$BAD"
BAD_SHA="$(sha256sum "$BAD" | awk '{print $1}')"
apply_one "$BAD" "$BAD_SHA" >/dev/null 2>&1 && fail "un-appliable patch wrongly accepted" || pass "un-appliable patch -> non-zero (fatal)"
rm -rf "$TMP"

echo
echo "-----------------------------------------"
printf 'Deploy patch integrity suite: \033[0;32m%d passed\033[0m, ' "$PASS"
if [[ $FAIL -gt 0 ]]; then printf '\033[0;31m%d failed\033[0m\n' "$FAIL"; exit 1; else printf '%d failed\n' "$FAIL"; fi
