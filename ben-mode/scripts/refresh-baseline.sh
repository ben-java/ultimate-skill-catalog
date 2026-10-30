#!/usr/bin/env bash
# refresh-baseline.sh — regenerate the manifest baseline(s) for a skill AFTER
# intentional edits, then re-run the gate. Baseline lives OUTSIDE the skill tree
# (under <root>/.hard-gate-meta), so writing it never invalidates itself.
# Usage: refresh-baseline.sh <root> <skill>
#   <root>  default: C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog
#   <skill> default: ben-mode
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"
ROOT="${1:-C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog}"
SKILL="${2:-ben-mode}"
MDIR="$ROOT/.hard-gate-meta"
SKDIR="$ROOT/$SKILL"
[ -d "$SKDIR" ] || { echo "❌ refresh: skill dir not found: $SKDIR"; exit 2; }
mkdir -p "$MDIR"

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
PY_BIN=$(find_python) || { echo "❌ refresh: no python found"; exit 2; }

SIG="$MDIR/$SKILL.manifest.sha256"
MAN="$MDIR/$SKILL.manifest.json"
# generate_manifest returns after --baseline (skips --out); call twice:
"$PY_BIN" "$SCRIPT_W/generate_manifest.py" "$(cygpath -w "$SKDIR")" --baseline "$(cygpath -w "$SIG")" >/dev/null
"$PY_BIN" "$SCRIPT_W/generate_manifest.py" "$(cygpath -w "$SKDIR")" --out "$(cygpath -w "$MAN")" >/dev/null
echo "✅ baseline regenerated: $SIG"
echo "   full manifest: $MAN"

echo "→ re-running gate"
"$SCRIPT_DIR/verify-hard-gate.sh" "$ROOT"
