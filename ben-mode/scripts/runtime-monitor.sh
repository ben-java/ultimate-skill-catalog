#!/usr/bin/env bash

export PYTHONDONTWRITEBYTECODE=1
# runtime-monitor.sh — continuous runtime-trace drift monitor (P4 C1).
# Slices the latest agent.log, converts to trace JSONL, scans with runtime_gate,
# appends PASS/FAIL to the aggregated audit, and tracks MTTR (time since last
# verified-clean run).
# Usage: runtime-monitor.sh [agent.log] [--verify-count N]
# Exit: 0 = trace clean; 1 = trace FAIL; 2 = precondition error.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"
AGENT_LOG="${1:-C:/Users/AMMAR/AppData/Local/hermes/logs/agent.log}"
N="${2:-3000}"
META="${3:-C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog/.hard-gate-meta}"

[ -f "$AGENT_LOG" ] || { echo "❌ agent log not found: $AGENT_LOG"; exit 2; }
mkdir -p "$META"

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
PY_BIN=$(find_python) || { echo "❌ runtime-monitor: no python found"; exit 2; }

TMPTRACE="$(mktemp --suffix=.jsonl)"
trap 'rm -f "$TMPTRACE"' EXIT

tail -n "$N" "$AGENT_LOG" > "$TMPTRACE.raw"
"$PY_BIN" "$SCRIPT_W/agentlog2trace.py" "$(cygpath -w "$TMPTRACE.raw")" --out "$(cygpath -w "$TMPTRACE")" >/dev/null

TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
set +e
"$PY_BIN" "$SCRIPT_W/runtime_gate.py" "$(cygpath -w "$TMPTRACE")" > "$TMPTRACE.out" 2>&1
RC=$?
set -e

STATUS=PASS; [ "$RC" -eq 0 ] || STATUS=FAIL
python - "$META" "$STATUS" "$TS" <<EOF
import json, os, sys
from datetime import datetime, timezone
meta, status, ts = sys.argv[1], sys.argv[2], sys.argv[3]
path = os.path.join(meta, "runtime-audit.jsonl")
# since_clean = duration since most recent previous PASS record (verified-clean), or N/A
since = "N/A"
try:
    now = datetime.fromisoformat(ts.replace("Z", "+00:00"))
except Exception:
    now = datetime.now(timezone.utc)
if os.path.exists(path):
    try:
        lines = [l for l in open(path, encoding="utf-8") if l.strip()]
        for l in reversed(lines):
            rec = json.loads(l)
            if rec.get("status") == "PASS":
                t = datetime.fromisoformat(rec["ts"].replace("Z", "+00:00"))
                d = now - t
                secs = int(d.total_seconds())
                since = "0s" if secs < 1 else (f"{secs//3600}h{(secs%3600)//60}m" if secs >= 3600 else (f"{secs//60}m{secs%60}s" if secs >= 60 else f"{secs}s"))
                break
    except Exception:
        since = "N/A"
entry = {"ts": ts, "status": status, "since_clean": since}
with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps(entry) + "\n")
print("runtime monitor:", json.dumps(entry))
EOF
cat "$TMPTRACE.out"
exit "$RC"
