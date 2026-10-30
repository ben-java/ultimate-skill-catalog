#!/usr/bin/env bash
# runtime-gate-scan.sh — run the runtime predicate gate over one or more agent
# action traces (JSONL), e.g. Hermes session logs exported as JSONL.
# Usage: runtime-gate-scan.sh <trace1.jsonl> [trace2.jsonl ...]
# Exit 0 = all traces PASS; 1 = any trace FAIL; 2 = precondition error.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"

find_python() {
    local cand
    for cand in "${PYTHON:-}" python3 python py; do
        [ -n "$cand" ] || continue
        if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "import sys" >/dev/null 2>&1; then
            printf '%s' "$cand"; return 0
        fi
    done
    return 1
}
PY_BIN=$(find_python) || { echo "❌ runtime-gate-scan: no python found"; exit 2; }

[ "$#" -ge 1 ] || { echo "❌ usage: runtime-gate-scan.sh <trace.jsonl> [...]"; exit 2; }

ALL_OK=0
for t in "$@"; do
    [ -f "$t" ] || { echo "❌ trace not found: $t"; ALL_OK=1; continue; }
    TW="$(cygpath -w "$t")"
    if "$PY_BIN" "$SCRIPT_W/runtime_gate.py" "$TW"; then
        echo "  ✓ $t"
    else
        echo "  ✗ $t"
        ALL_OK=1
    fi
done
exit "$ALL_OK"
