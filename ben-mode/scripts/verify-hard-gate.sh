#!/usr/bin/env bash
# verify-hard-gate.sh v2 — HARD GATE #10 with book-pattern enhancements
# Patterns from: DDIA, TSNA, Essential Arch, Pragmatic, ML Systems
# Exit: 0 = PASS, 1 = FAIL, 2 = PRECONDITION FAIL

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Native Windows path for python invocations: MSYS auto-conversion of /c/...
# args is inconsistent across shells (produces C:\c\Users\...), so always
# pass an explicit C:/... path to native python.
SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"

# Canonical hash (BAGIAN 16.2): normalize CRLF->LF before checksumming
canonical_md5() {
    tr -d '\r' < "$1" | md5sum | awk '{print $1}'
}

# Enumerate ACTIVE skill SKILL.md files only: skip archives/backups and
# root-level stray files (a real skill lives in a sub-directory of a catalog).
ACTIVE_SKILLS() {
    local root="$1"
    find "$root" -name 'SKILL.md' -type f ! -type l \
      | while IFS= read -r f; do
            case "$f" in
                */backup/*|*/archive/*|*/.archive/*|*/Archives/*) continue ;;
            esac
            [ "$(basename "$(dirname "$f")")" != "$(basename "$root")" ] || continue
            printf '%s\n' "$f"
        done
}

if [ "$#" -eq 0 ]; then
    ROOTS=("C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog")
else
    ROOTS=("$@")
fi
AUDIT_LOG="${HARD_GATE_LOG:-${TMPDIR:-/tmp}/hard-gate-audit.log}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# --- Precondition: Schema validation (DDIA Ch4, ML Systems Ch2) ---
validate_skill_schema() {
    local file="$1"
    # Parse ONLY the YAML frontmatter block — body text can contain example
    # "name:" lines and would otherwise produce false mismatches.
    local fm
    fm=$(awk '/^---[[:space:]]*$/{c++; next} c==1{print}' "$file")
    [ -n "$fm" ] || { echo "❌ Schema validation FAIL: no frontmatter in $file"; return 1; }

    local required=("name" "description")
    for key in "${required[@]}"; do
        printf '%s\n' "$fm" | grep -q "^${key}:" \
            || { echo "❌ Schema validation FAIL: missing '$key' in $file"; return 1; }
    done

    local folder name
    folder=$(basename "$(dirname "$file")")
    name=$(printf '%s\n' "$fm" | sed -n 's/^name:[[:space:]]*//p' | head -1 | sed 's/[[:space:]]*$//' | tr -d '\r')
    if [ "$name" != "$folder" ]; then
        echo "❌ Schema validation FAIL: name '$name' ≠ folder '$folder' ($file)"
        return 1
    fi
    return 0
}

echo "=== HARD GATE #10 Verification ($TIMESTAMP) ===" | tee -a "$AUDIT_LOG"
for r in "${ROOTS[@]}"; do echo "Root: $r" | tee -a "$AUDIT_LOG"; done

# Collect metrics across all roots (multi-root = real 4-catalog layout)
DIRS=0; FILES=0; SYMLINKS=0; PAIRS=""
for ROOT in "${ROOTS[@]}"; do
    [ -d "$ROOT" ] || { echo "❌ Root not found: $ROOT"; exit 2; }
    DIRS=$((DIRS + $(find "$ROOT" -mindepth 1 -maxdepth 1 -type d ! -type l | wc -l)))
    FILES=$((FILES + $(ACTIVE_SKILLS "$ROOT" | wc -l)))
    SYMLINKS=$((SYMLINKS + $(find "$ROOT" -type l | wc -l)))
    PAIR_LINES=""
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        h=$(canonical_md5 "$f")
        fn=$(basename "$(dirname "$f")")
        PAIR_LINES+="$fn $h"$'\n'
    done < <(ACTIVE_SKILLS "$ROOT")
    PAIRS+=$'\n'"$PAIR_LINES"

    # Windows junctions/reparse points are invisible to MSYS `find -type l`.
    # Recursive PowerShell scan is slow on large catalogs (>150s on 650 dirs),
    # so it is OPT-IN: HARD_GATE_REPARSE=1. Default = symlink check only.
    REPARSE=0
    if [ "${HARD_GATE_REPARSE:-0}" = "1" ] && command -v powershell.exe >/dev/null 2>&1; then
        REPARSE=$(powershell.exe -NoProfile -Command "(Get-ChildItem -LiteralPath '$(cygpath -w "$ROOT" 2>/dev/null || echo "$ROOT")' -Recurse -Force -Directory -Attributes ReparsePoint -ErrorAction SilentlyContinue | Measure-Object).Count" 2>/dev/null | tr -d '\r\n ' || echo 0)
    fi
    case "$REPARSE" in ''|*[!0-9]*) REPARSE=0 ;; esac
    SYMLINKS=$((SYMLINKS + REPARSE))
done

# Catalog count: with explicit multi-root args, each root IS a catalog;
# with a single root, count its immediate subdirectories.
[ "${#ROOTS[@]}" -gt 1 ] && DIRS=${#ROOTS[@]} || true
SCHEMA_OK=1
for ROOT in "${ROOTS[@]}"; do
    ALL_FILES=$(ACTIVE_SKILLS "$ROOT")
    TOTAL_F=$(printf '%s\n' "$ALL_FILES" | awk 'NF' | wc -l)
    SCHEMA_OUT=0
    if [ "$TOTAL_F" -gt 0 ]; then
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            folder="$(basename "$(dirname "$f")")"
            name="$(awk '/^---/{c++;next} c==1{print}' "$f" | sed -n 's/^name:[[:space:]]*//p' | head -1 | tr -d '\r' | sed 's/[[:space:]]*$//')"
            if [ -n "$name" ] && [ "$name" = "$folder" ] && grep -q "^description:" "$f" 2>/dev/null; then
                SCHEMA_OUT=$((SCHEMA_OUT + 1))
            fi
        done <<< "$ALL_FILES"
    fi
    if [ "$SCHEMA_OUT" -lt "$TOTAL_F" ]; then
        SCHEMA_OK=0
        echo "❌ Schema validation FAIL: missing name/description in some SKILL.md files ($SCHEMA_OUT/$TOTAL_F)"
    fi
done

# Allowlist governance (BAGIAN 15 / Rego Rule 6+7)
ALLOWLIST_OK=1
if command -v jq >/dev/null 2>&1; then
    for ROOT in "${ROOTS[@]}"; do
        ALW="$ROOT/hard-gate-allowlist.json"
        [ -f "$ALW" ] || continue
        if ! jq -e . "$ALW" >/dev/null 2>&1; then
            echo "❌ Allowlist FAIL: invalid JSON in $ALW"; ALLOWLIST_OK=0
        fi
        NOW=$(date -u +%s)
        while IFS= read -r EXP; do
            [ -z "$EXP" ] && continue
            EXPTS=$(date -u -d "$EXP" +%s 2>/dev/null || date -u -jf %FT%TZ "$EXP" +%s 2>/dev/null || echo 0)
            if [ "$EXPTS" -le "$NOW" ]; then
                echo "❌ Allowlist FAIL: expired entry $EXP ($ALW)"; ALLOWLIST_OK=0
            fi
        done < <(jq -r '.allowed_drifts[]?.expires_at // empty' "$ALW" 2>/dev/null)
    done
fi

# Checksum consistency (DDIA Ch2, Ch5: end-to-end checksum + quorum)
# Per-skill: every replica of the SAME skill must share one hash. Distinct skills
# may differ — comparing all SKILL.md globally would false-FAIL multi-skill catalogs.
PAIRS=$(echo "$PAIRS" | awk 'NF' | sort -u)
SKILLS=$(echo "$PAIRS" | awk 'NF{print $1}' | sort -u | wc -l)
PAIRCOUNT=$(echo "$PAIRS" | awk 'NF' | wc -l)
CHECKSUMS_OK=1
[ "$SKILLS" -eq 0 ] && CHECKSUMS_OK=0
[ "$PAIRCOUNT" -ne "$SKILLS" ] && CHECKSUMS_OK=0
FIRST_HASH=$(echo "$PAIRS" | awk 'NF{print $2; exit}')

echo "Physical catalogs: $DIRS (need ≥2)" | tee -a "$AUDIT_LOG"
echo "Physical SKILL.md files: $FILES (need ≥4)" | tee -a "$AUDIT_LOG"
echo "Symlinks/junctions: $SYMLINKS (must be 0)" | tee -a "$AUDIT_LOG"
echo "Skills / distinct replica hashes: $SKILLS / $PAIRCOUNT (must be equal)" | tee -a "$AUDIT_LOG"
echo "Schema validation: $([ $SCHEMA_OK -eq 1 ] && echo PASS || echo FAIL)" | tee -a "$AUDIT_LOG"
echo "Allowlist governance: $([ $ALLOWLIST_OK -eq 1 ] && echo PASS || echo FAIL)" | tee -a "$AUDIT_LOG"
echo "Reference checksum: $FIRST_HASH" | tee -a "$AUDIT_LOG"

# Manifest baseline verification (§15.1/§16.2) — opt-in via
# <root>/.hard-gate-meta/<skill>.manifest.sha256 files.
MANIFEST_OK=1
# Never let the python verifier write __pycache__ into the tree it audits.
export PYTHONDONTWRITEBYTECODE=1
find_python() {
    local cand
    for cand in "${PYTHON:-}" python3 python py; do
        [ -n "$cand" ] || continue
        if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "import hashlib" >/dev/null 2>&1; then
            printf '%s' "$cand"
            return 0
        fi
    done
    return 1
}
PY_BIN=$(find_python) || true
if [ -n "$PY_BIN" ]; then
    for ROOT in "${ROOTS[@]}"; do
        MDIR="$ROOT/.hard-gate-meta"
        [ -d "$MDIR" ] || continue
        for BL in "$MDIR"/*.manifest.sha256; do
            [ -f "$BL" ] || continue
            SKILL=$(basename "$BL" .manifest.sha256)
            SKDIR="$ROOT/$SKILL"
            if ! "$PY_BIN" "$SCRIPT_W/verify_skill_replicas.py" --root "$SKDIR" --manifest "$BL" >/dev/null 2>&1; then
                echo "❌ Manifest FAIL: $SKILL does not match its baseline" | tee -a "$AUDIT_LOG"
                MANIFEST_OK=0
            fi
        done
    done
fi

echo "Manifest governance: $([ $MANIFEST_OK -eq 1 ] && echo PASS || echo FAIL)" | tee -a "$AUDIT_LOG"

# Verdict (Pragmatic Tip 44: Assertive Programming)
if [ "$DIRS" -ge 2 ] && [ "$FILES" -ge 4 ] && [ "$SYMLINKS" -eq 0 ] && [ "$CHECKSUMS_OK" -eq 1 ] && [ "$SCHEMA_OK" -eq 1 ] && [ "$ALLOWLIST_OK" -eq 1 ] && [ "$MANIFEST_OK" -eq 1 ]; then
    echo "✅ HARD GATE #10 PASSED" | tee -a "$AUDIT_LOG"
    STATUS="PASS"
    EXIT_CODE=0
else
    echo "❌ HARD GATE #10 FAILED" | tee -a "$AUDIT_LOG"
    STATUS="FAIL"
    EXIT_CODE=1
fi

# Structured JSON log for dashboards (DDIA Ch7, TSNA Ch11)
if command -v jq >/dev/null 2>&1; then
    jq -n --arg ts "$TIMESTAMP" --arg root "$(IFS=';'; echo "${ROOTS[*]}")" --argjson dirs "$DIRS" --argjson files "$FILES" \
          --argjson symlinks "$SYMLINKS" --argjson skills "$SKILLS" --argjson pairs "$PAIRCOUNT" \
          --arg hash "$FIRST_HASH" --arg status "$STATUS" --argjson allowlist "$ALLOWLIST_OK" \
        '{timestamp: $ts, root: $root, catalogs: $dirs, files: $files, symlinks: $symlinks,
          skills: $skills, replica_hashes: $pairs, reference_hash: $hash, allowlist: $allowlist, status: $status}' \
        >> "${AUDIT_LOG}.json"
fi
exit $EXIT_CODE
