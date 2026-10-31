#!/usr/bin/env bash

export PYTHONDONTWRITEBYTECODE=1
# verify-incremental.sh — P5 E1: gate inkremental.
# Jika pohon skill tidak berubah sejak run terakhir (tree signature sama) -> quick PASS
# tanpa menjalankan verify penuh. Jika berubah/tidak ada sig -> verify penuh lalu simpan sig.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"
ROOT="${1:-C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog}"
MDIR="$ROOT/.hard-gate-meta"
SIG_FILE="$MDIR/last-tree.sig"
PY_BIN="${PYTHON:-python3}"

# Stable tree signature: CRLF-normalized md5 over SKILL.md + scripts/references files
tree_sig() {
  "$PY_BIN" -c "
import hashlib, os, sys
root=sys.argv[1]
h=hashlib.sha256()
seen=0
for base,dirs,files in os.walk(root):
    dirs[:]=[d for d in dirs if d not in ('.git','.hard-gate-meta','archive','backup','__pycache__')]
    for f in sorted(files):
        if f in ('SKILL.md','gate.conf') or (os.path.basename(base) in ('scripts','references','fixtures','tests','policies') and f.lower().endswith(('.py','.sh','.json','.jsonl','.rego'))):
            fp=os.path.join(base,f)
            try:
                data=open(fp,'rb').read().replace(b'\r\n',b'\n')
            except OSError:
                continue
            h.update(fp.encode('utf-8','replace')); h.update(b'\x00'); h.update(data)
            seen+=1
print(h.hexdigest())
" "$ROOT"
}

mkdir -p "$MDIR"
NEW_SIG=$(tree_sig "$ROOT")
OLD_SIG=""
[ -f "$SIG_FILE" ] && OLD_SIG=$(cat "$SIG_FILE")

if [ -n "$OLD_SIG" ] && [ "$OLD_SIG" = "$NEW_SIG" ]; then
    echo "INCREMENTAL: tree unchanged ($NEW_SIG) — quick PASS"
    exit 0
fi

echo "INCREMENTAL: tree changed (was ${OLD_SIG:-none}, now $NEW_SIG) — full verify"
HARD_GATE_CANONICAL="${HARD_GATE_CANONICAL:-}" "$SCRIPT_W/verify-hard-gate.sh" "$ROOT"
RC=$?
if [ "$RC" -eq 0 ]; then
    printf '%s' "$NEW_SIG" > "$SIG_FILE"
fi
exit $RC
