#!/usr/bin/env bash
# bootstrap-deps.sh — provision python deps for ben-mode gate scripts (z3 for BMC).
# Resolves a python the same way verify-hard-gate.sh does (env PYTHON first),
# ensures pip exists, installs requirements.txt, and verifies importability.
# Exit: 0 = ok, 1 = install/import failed, 2 = no python found.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Native Windows path: pip (a native tool) cannot open /c/... MSYS paths.
REQ_W="$(cygpath -w "$SCRIPT_DIR/requirements.txt")"

find_python() {
    local cand
    for cand in "${PYTHON:-}" python3 python py; do
        [ -n "$cand" ] || continue
        if command -v "$cand" >/dev/null 2>&1 \
           && "$cand" -c "import sys" >/dev/null 2>&1; then
            printf '%s' "$cand"
            return 0
        fi
    done
    return 1
}

PY_BIN=$(find_python) || { echo "❌ bootstrap: no python found"; exit 2; }
echo "bootstrap: using $PY_BIN"
"$PY_BIN" --version

# ensure pip
if ! "$PY_BIN" -m pip --version >/dev/null 2>&1; then
    echo "bootstrap: pip missing — attempting ensurepip"
    "$PY_BIN" -m ensurepip --upgrade >/dev/null 2>&1 || true
fi
if ! "$PY_BIN" -m pip --version >/dev/null 2>&1; then
    echo "❌ bootstrap: pip unavailable in $PY_BIN"
    exit 1
fi

"$PY_BIN" -m pip install -q -r "$REQ_W"

if ! "$PY_BIN" -c "import z3; print('z3', z3.get_version_string())" ; then
    echo "❌ bootstrap: z3 import failed"
    exit 1
fi
echo "✅ bootstrap: deps ready"
