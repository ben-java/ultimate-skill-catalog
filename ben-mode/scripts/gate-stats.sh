#!/usr/bin/env bash
# gate-stats.sh — record cheap observability metrics for one gate run (P3 #9):
# counts (catalogs/SKILL.md/symlinks) + total bytes of the ben-mode tree, plus
# a token-proxy estimate (bytes/4 ≈ tokens). Appends one line to
# <root>/.hard-gate-meta/gate-cost.jsonl
# Usage: gate-stats.sh [root] [skill]
set -euo pipefail

ROOT="${1:-C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog}"
SKILL="${2:-ben-mode}"
META="$ROOT/.hard-gate-meta"
mkdir -p "$META"

# Mirror gate semantics: active skill dirs only (skip .git/backup/root strays).
DIRS=$(find "$ROOT" -mindepth 1 -maxdepth 1 -type d ! -type l ! -name '.git' ! -name 'backup' | wc -l)
FILES=$(find "$ROOT" -name 'SKILL.md' -type f ! -path '*/backup/*' ! -path '*/.git/*' ! -path '*/archive/*' | wc -l)
LINKS=$(find "$ROOT" -type l | wc -l)
BYTES=$(find "$ROOT/$SKILL" -type f -exec cat {} + | wc -c)

TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
python - "$META" <<EOF
import json, os, sys
meta = sys.argv[1]
entry = {
    "ts": "$TS",
    "skill": "$SKILL",
    "catalogs": int($DIRS),
    "skill_files": int($FILES),
    "symlinks": int($LINKS),
    "tree_bytes": int($BYTES),
    "token_proxy": int($BYTES) // 4,
}
path = os.path.join(meta, "gate-cost.jsonl")
with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps(entry) + "\n")
print("stats recorded:", json.dumps(entry))
EOF
