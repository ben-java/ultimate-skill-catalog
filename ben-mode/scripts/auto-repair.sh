#!/usr/bin/env bash
# auto-repair.sh — P13-B3: isolate drifted replicas, re-sync, re-verify.
# Usage: auto-repair.sh <root>
set -euo pipefail
ROOT="${1:-C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
META="$ROOT/.hard-gate-meta"
QUAR="$META/quarantine/$(date +%Y%m%dT%H%M%S)"
mkdir -p "$QUAR"

CANON="C:/Users/AMMAR/AppData/Local/hermes/skills/dsh-imported/ben-mode"
REPLICAS=(
  "$ROOT/ben-mode"
  "C:/Users/AMMAR/.dsh/skills/ben-mode"
  "C:/Users/AMMAR/Tools/dsh-skill-wrappers/ben-mode"
)

# Find drifted replicas by comparing the canonical hash to each replica.
CANON_HASH=$(find "$CANON" -type f ! -type l -exec md5sum {} + | sort -k2 | md5sum | cut -d' ' -f1)
for rep in "${REPLICAS[@]}"; do
  [ -d "$rep" ] || continue
  REP_HASH=$(find "$rep" -type f ! -type l -exec md5sum {} + | sort -k2 | md5sum | cut -d' ' -f1)
  if [ "$REP_HASH" != "$CANON_HASH" ]; then
    echo "auto-repair: drift in $rep — isolating to $QUAR"
    mkdir -p "$QUAR/$(basename "$rep")"
    cp -r "$rep"/. "$QUAR/$(basename "$rep")/"
    rm -rf "$rep"
  fi
done

# Re-sync canonical -> all replicas, then re-verify.
"$SCRIPT_DIR/sync-all-roots.sh" 2>/dev/null || true
if "$SCRIPT_DIR/benctl.sh" "$ROOT" >/dev/null 2>&1; then
  echo "auto-repair: GREEN after re-sync"
  exit 0
else
  echo "auto-repair: still FAIL after re-sync — manual intervention required"
  exit 1
fi
