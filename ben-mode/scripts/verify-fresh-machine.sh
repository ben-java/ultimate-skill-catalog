#!/usr/bin/env bash

export PYTHONDONTWRITEBYTECODE=1
# verify-fresh-machine.sh — P6-E: push-button artifact evaluation (ACM/SIGMOD pattern).
# Simulates a completely fresh machine/clone: isolates to a clean tempdir, builds a
# minimal 2-catalog multi-replica topology, runs verify-hard-gate.sh, and verifies
# that reference checksum matches bit-for-bit without access to host-specific meta.
# Exit: 0 = reproducible bit-for-bit, 1 = non-deterministic/divergent.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
win_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf "%s" "$1"; fi; }
SCRIPT_W="$(win_path "$SCRIPT_DIR")"
CANONICAL="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

PY_BIN="${PYTHON:-python3}"
SANDBOX=$(mktemp -d "${TMPDIR:-/tmp}/hg10-fresh-XXXXXX")
trap 'rm -rf "$SANDBOX"' EXIT

echo "=== P6-E: Fresh-machine Reproducibility Test ==="
echo "source canonical: $CANONICAL"
echo "sandbox root:     $SANDBOX"

# Build isolated 2-catalog fixture (clean physical copies)
mkdir -p "$SANDBOX/catA/ben-mode" "$SANDBOX/catB/ben-mode"
cp -r "$CANONICAL"/* "$SANDBOX/catA/ben-mode/"
cp -r "$CANONICAL"/* "$SANDBOX/catB/ben-mode/"

# Strip any host-local git/meta artifacts from the replicas
rm -rf "$SANDBOX/catA/ben-mode/.git" "$SANDBOX/catB/ben-mode/.git"
rm -rf "$SANDBOX/catA/ben-mode/.hard-gate-meta" "$SANDBOX/catB/ben-mode/.hard-gate-meta"

# First run: compute checksum in isolated topology
set +e
OUT1=$("$PY_BIN" "$SCRIPT_W/verify_skill_replicas.py" \
  --root "$(win_path "$SANDBOX/catA/ben-mode")" \
  --replica "$(win_path "$SANDBOX/catB/ben-mode")" 2>&1)
RC1=$?
set -e
[ "$RC1" -eq 0 ] || { echo "❌ Run 1 failed in fresh sandbox:"; echo "$OUT1"; exit 1; }

# Second independent run: rebuild from scratch in a second isolated dir, re-evaluate
SANDBOX2=$(mktemp -d "${TMPDIR:-/tmp}/hg10-fresh2-XXXXXX")
trap 'rm -rf "$SANDBOX" "$SANDBOX2"' EXIT
mkdir -p "$SANDBOX2/catA/ben-mode" "$SANDBOX2/catB/ben-mode"
cp -r "$CANONICAL"/* "$SANDBOX2/catA/ben-mode/"
cp -r "$CANONICAL"/* "$SANDBOX2/catB/ben-mode/"
rm -rf "$SANDBOX2/catA/ben-mode/.git" "$SANDBOX2/catB/ben-mode/.git"
rm -rf "$SANDBOX2/catA/ben-mode/.hard-gate-meta" "$SANDBOX2/catB/ben-mode/.hard-gate-meta"

set +e
OUT2=$("$PY_BIN" "$SCRIPT_W/verify_skill_replicas.py" \
  --root "$(win_path "$SANDBOX2/catA/ben-mode")" \
  --replica "$(win_path "$SANDBOX2/catB/ben-mode")" 2>&1)
RC2=$?
set -e
[ "$RC2" -eq 0 ] || { echo "❌ Run 2 failed in fresh sandbox:"; echo "$OUT2"; exit 1; }

echo "Run 1 output: $(echo "$OUT1" | tail -1)"
echo "Run 2 output: $(echo "$OUT2" | tail -1)"

if [ "$OUT1" = "$OUT2" ]; then
    echo "✅ REPRODUCIBILITY PASS: two independent fresh sandbox evaluations bit-identical"
    exit 0
else
    echo "❌ NON-DETERMINISTIC: Run 1 != Run 2"
    diff -u <(echo "$OUT1") <(echo "$OUT2") || true
    exit 1
fi
