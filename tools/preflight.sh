#!/usr/bin/env bash
# preflight.sh — the pre-ship GO/NO-GO gate. Run this before packaging/shipping a build:
# it exercises the whole tool the way an operator would, not just the unit seams, so a
# regression is caught here instead of in the field.
#
#   ./tools/preflight.sh            # full gate (suite + high-fidelity + smoke)
#   ./tools/preflight.sh --fast     # skip the full pytest run (keep the high-signal checks)
#
# Exits non-zero on the first failure. Everything degrades cleanly on a bare box (a missing
# optional tool is reported, not failed), so it runs anywhere.
set -u
cd "$(dirname "$0")/.." || exit 2

FAST=0; [ "${1:-}" = "--fast" ] && FAST=1
PY=${PYTHON:-python3}
fails=0
step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✓ %s\033[0m\n' "$1"; }
bad()  { printf '  \033[31m✗ %s\033[0m\n' "$1"; fails=$((fails+1)); }
note() { printf '  · %s\n' "$1"; }

step "1/6  Environment self-check (recce doctor)"
if $PY -m recce doctor --no-self-scan >/tmp/pf_doctor.log 2>&1; then ok "doctor ran"; else bad "doctor failed (see /tmp/pf_doctor.log)"; fi

step "2/6  Import correctness + no-duplication (matrix)"
if $PY -m pytest -q -n0 tests/test_import_matrix.py tests/test_import_hardening.py >/tmp/pf_import.log 2>&1; then
  ok "$(grep -oE '[0-9]+ passed' /tmp/pf_import.log | tail -1) — every format + dedup"
else bad "import matrix FAILED (see /tmp/pf_import.log)"; fi

step "3/6  Import robustness (fuzz — no crash on malformed input)"
if $PY -m pytest -q -n0 tests/test_import_fuzz.py >/tmp/pf_fuzz.log 2>&1; then ok "fuzz clean"; else bad "fuzz FAILED (see /tmp/pf_fuzz.log)"; fi

step "4/6  High-fidelity: real nmap → import (if nmap present)"
if command -v nmap >/dev/null 2>&1; then
  if $PY -m pytest -q -n0 tests/test_import_fidelity.py tests/test_live_smoke.py >/tmp/pf_live.log 2>&1; then
    ok "real-tool scan + import + live smoke"
  else bad "live/fidelity FAILED (see /tmp/pf_live.log)"; fi
else note "nmap absent — skipped real-tool fidelity (install nmap for the full gate)"; fi

step "5/6  End-to-end: demo engagement + report build + serve API"
tmp=$(mktemp -d)
if $PY tools/mock_engagement.py "$tmp/eng" --hosts 12 >/tmp/pf_demo.log 2>&1 \
   && $PY -m recce report -o "$tmp/eng" >>/tmp/pf_demo.log 2>&1; then
  # workbook must exist and be non-trivial
  if [ -s "$tmp/eng/enumeration.xlsx" ]; then ok "engagement built + workbook written"; else bad "workbook missing/empty"; fi
  # serve API smoke: create_app + a few endpoints via the test client (no port bind needed)
  if $PY - "$tmp/eng" >>/tmp/pf_demo.log 2>&1 <<'PY'; then
import sys
from fastapi.testclient import TestClient
from recce.webui.app import create_app
c = TestClient(create_app(sys.argv[1]))
for p in ("/api/engagement", "/api/hosts", "/api/findings", "/api/credentials", "/api/collab"):
    r = c.get(p); assert r.status_code == 200, f"{p} -> {r.status_code}"
assert len(c.get("/api/hosts").json()) >= 10, "hosts missing from the API"
print("serve API ok")
PY
    ok "serve API serves the engagement"
  else bad "serve API smoke FAILED (see /tmp/pf_demo.log)"; fi
else bad "demo engagement / report build FAILED (see /tmp/pf_demo.log)"; fi
rm -rf "$tmp"

step "6/6  Full test suite"
if [ "$FAST" = "1" ]; then
  note "skipped (--fast); run without --fast before shipping a release"
elif $PY -m pytest -q >/tmp/pf_suite.log 2>&1; then
  ok "$(grep -oE '[0-9]+ passed[^,]*' /tmp/pf_suite.log | tail -1)"
else
  bad "suite FAILED — $(grep -oE '[0-9]+ failed' /tmp/pf_suite.log | tail -1) (see /tmp/pf_suite.log)"
fi

echo
if [ "$fails" -eq 0 ]; then
  printf '\033[1;32m✔ PREFLIGHT PASSED — GO for ship.\033[0m\n'; exit 0
else
  printf '\033[1;31mX PREFLIGHT FAILED (%d) - NO-GO. Fix before shipping.\033[0m\n' "$fails"; exit 1
fi
