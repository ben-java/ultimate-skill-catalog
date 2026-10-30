#!/usr/bin/env bash
# sync-all-roots.sh — sync canonical ben-mode tree to all physical replicas,
# then verify full-tree quorum across every root (P3 #1/#3).
# Usage: sync-all-roots.sh [canonical] [root1 root2 ...]
# Defaults: canonical = hermes dsh-imported ben-mode; replicas = project,
# ~/.dsh/skills, Tools/dsh-skill-wrappers.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"

CANONICAL="${1:-C:/Users/AMMAR/AppData/Local/hermes/skills/dsh-imported/ben-mode}"
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
