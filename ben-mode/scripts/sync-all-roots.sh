#!/usr/bin/env bash

export PYTHONDONTWRITEBYTECODE=1
# sync-all-roots.sh — sync canonical ben-mode tree to all physical replicas,
# then verify full-tree quorum across every root (P3 #1/#3).
# Usage: sync-all-roots.sh [canonical] [root1 root2 ...]
# Defaults: canonical = hermes dsh-imported ben-mode; replicas = project,
# ~/.dsh/skills, Tools/dsh-skill-wrappers.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"

MODE="sync"
if [ "${1:-}" = "--diff" ] || [ "${1:-}" = "--check" ] || [ "${1:-}" = "--reverse" ]; then
    MODE="$1"; shift
fi
CANONICAL="C:/Users/AMMAR/AppData/Local/hermes/skills/dsh-imported/ben-mode"
REVERSE_SRC=""
if [ "$MODE" = "--reverse" ]; then
    [ "$#" -ge 1 ] || { echo "❌ --reverse needs a source replica"; exit 2; }
    REVERSE_SRC="$1"; shift
else
    [ "$#" -ge 1 ] && CANONICAL="$1" && shift
fi
shift || true
if [ "$#" -ge 1 ]; then
    REPLICAS=("$@")
else
    REPLICAS=(
        "C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog/ben-mode"
        "C:/Users/AMMAR/.dsh/skills/ben-mode"
        "C:/Users/AMMAR/Tools/dsh-skill-wrappers/ben-mode"
    )
fi

find_python() {
    local cand
    for cand in "${PYTHON:-}" python3 python py; do
        [ -n "$cand" ] || continue
        if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "import hashlib" >/dev/null 2>&1; then
            printf '%s' "$cand"; return 0
        fi
    done
    return 1
}
PY_BIN=$(find_python) || { echo "❌ sync-all: no python found"; exit 2; }

[ -d "$CANONICAL" ] || { echo "❌ sync-all: canonical missing: $CANONICAL"; exit 2; }

if [ "$MODE" = "--diff" ] || [ "$MODE" = "--check" ]; then
    for rep in "${REPLICAS[@]}"; do
        if [ -d "$rep" ]; then
            echo "--- drift: $(basename "$rep") vs canonical ---"
            diff -rq "$CANONICAL" "$rep" 2>&1 | head -20 || true
        fi
    done
    if [ "$MODE" = "--check" ]; then
        ARGS=(--strict "$(cygpath -w "$CANONICAL")")
        for rep in "${REPLICAS[@]}"; do ARGS+=("$(cygpath -w "$rep")"); done
        "$PY_BIN" "$SCRIPT_W/quorum-check.py" "${ARGS[@]}" || exit 1
    fi
    exit 0
fi

if [ "$MODE" = "--reverse" ]; then
    [ -d "$REVERSE_SRC" ] || { echo "❌ source replica missing: $REVERSE_SRC"; exit 2; }
    echo "↻ reverse sync: $(basename "$REVERSE_SRC") -> canonical"
    rm -rf "$CANONICAL"
    mkdir -p "$(dirname "$CANONICAL")"
    cp -r "$REVERSE_SRC" "$CANONICAL"
    echo "reverse-synced canonical <- $REVERSE_SRC"
    exit 0
fi

for rep in "${REPLICAS[@]}"; do
    rm -rf "$rep"
    mkdir -p "$(dirname "$rep")"
    cp -r "$CANONICAL" "$rep"
    echo "synced -> $rep"
done

ARGS=(--root "$(cygpath -w "$CANONICAL")")
for rep in "${REPLICAS[@]}"; do
    ARGS+=(--replica "$(cygpath -w "$rep")")
done

echo "→ verifying full-tree quorum across $(( ${#REPLICAS[@]} + 1 )) roots"
"$PY_BIN" "$SCRIPT_W/verify_skill_replicas.py" "${ARGS[@]}"
echo "SYNC_ALL_OK"
