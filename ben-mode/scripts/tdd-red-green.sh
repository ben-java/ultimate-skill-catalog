#!/usr/bin/env bash
# tdd-red-green.sh — executable RED→GREEN proof for the HARD GATE #10 verifier.
#   RED   : inject a one-byte fault into a replica → verifier must FAIL (exit 1)
#   GREEN  : restore from canonical → verifier must PASS (exit 0)
# Usage: tdd-red-green.sh [python]
# Exit 0 = both phases proven; 1 = any phase failed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"
PY=${PYTHON:-python}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/hg10-tdd-XXXXXX")
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/canon/skill" "$TMP/replica/skill"
cat > "$TMP/canon/skill/SKILL.md" <<'EOF'
---
name: skill
description: test
---
EOF
cp "$TMP/canon/skill/SKILL.md" "$TMP/replica/skill/SKILL.md"

cw() { cygpath -w "$1"; }

# RED: flip one byte in the replica (canonical untouched)
"$PY" -c "import sys; p=sys.argv[1]; d=bytearray(open(p,'rb').read()); d[0]^=0xFF; open(p,'wb').write(bytes(d))" "$(cw "$TMP/replica/skill/SKILL.md")"

if "$PY" "$SCRIPT_W/verify_skill_replicas.py" --root "$(cw "$TMP/canon/skill")" --replica "$(cw "$TMP/replica/skill")" >/dev/null 2>&1; then
    echo "❌ RED phase failed: verifier PASSED on corrupted replica"
    exit 1
fi
echo "✅ RED  : injected fault correctly rejected (exit 1)"

# GREEN: restore pristine replica
cp "$TMP/canon/skill/SKILL.md" "$TMP/replica/skill/SKILL.md"
if ! "$PY" "$SCRIPT_W/verify_skill_replicas.py" --root "$(cw "$TMP/canon/skill")" --replica "$(cw "$TMP/replica/skill")" >/dev/null 2>&1; then
    echo "❌ GREEN phase failed: verifier rejected a clean replica"
    exit 1
fi
echo "✅ GREEN: restored replica accepted (exit 0)"
echo "🎉 TDD RED→GREEN proven"
