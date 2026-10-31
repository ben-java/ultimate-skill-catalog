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

# P8-M#2: optional config snippet (single knob). Auto-source skill-root gate.conf,
# or the file named by HARD_GATE_RC (if set). Only exports env vars; must run
# before root resolution so HARD_GATE_ROOTS can be set here.
_GATE_RC="${HARD_GATE_RC:-$SCRIPT_DIR/../gate.conf}"
if [ -f "$_GATE_RC" ]; then
    # shellcheck disable=SC1090
    source "$_GATE_RC"
fi

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
                */backup/*|*/archive/*|*/.archive/*|*/Archives/*|*/quarantine/*|*/.hard-gate-meta/*) continue ;;
            esac
            [ "$(basename "$(dirname "$f")")" != "$(basename "$root")" ] || continue
            printf '%s\n' "$f"
        done
}

if [ "$#" -ge 1 ]; then
    ROOTS=("$@")
elif [ -n "${HARD_GATE_ROOTS:-}" ]; then
    # newline-separated explicit roots (Windows drive colons are safe)
    mapfile -t ROOTS <<< "$HARD_GATE_ROOTS"
elif [ -n "${HARD_GATE_CONF:-}" ] && [ -f "$HARD_GATE_CONF" ]; then
    # one root per non-comment non-empty line
    mapfile -t ROOTS < <(grep -v '^[[:space:]]*#' "$HARD_GATE_CONF" | grep -v '^[[:space:]]*$')
else
    ROOTS=("C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog")
fi
[ "${#ROOTS[@]}" -ge 1 ] || { echo "❌ no roots configured"; exit 2; }
# P5 A2: canonical hermetic root (blind-spot coverage) — opt-in via HARD_GATE_CANONICAL
if [ -n "${HARD_GATE_CANONICAL:-}" ]; then
    ROOTS+=("$HARD_GATE_CANONICAL")
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
START_NS=$(date +%s%N)
STATUS_PRE=""

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

        # D2: optional Ed25519 allowlist signature (P5). Active only when a public
        # key is configured AND a .sig sidecar exists. If configured but the sig
        # is missing or INVALID -> FAIL loudly (no silent skip when operator expects it).
        if [ -n "${HARD_GATE_ALLOWLIST_PUB:-}" ] && [ -f "$ALW.sig" ]; then
            PY_D2="${PY_BIN:-${PYTHON:-python3}}"
            if ! "$PY_D2" "$SCRIPT_W/allowlist.py" --root "$ROOT" validatesig --pub "$HARD_GATE_ALLOWLIST_PUB" >/dev/null 2>&1; then
                echo "❌ Allowlist FAIL: signature INVALID for $ALW"; ALLOWLIST_OK=0
            fi
        fi

        # P7-H#3: optional W3C VC verification of allowlist. Active only when a
        # public key is configured AND a .vc.json sidecar exists (vc-allowlist.py).
        VC_FILE="$ROOT/$(basename "$ROOT").vc.json"
        if [ -n "${HARD_GATE_VC_PUB:-}" ] && [ -f "$VC_FILE" ]; then
            PY_VC="${PY_BIN:-${PYTHON:-python3}}"
            if ! "$PY_VC" "$SCRIPT_W/vc-allowlist.py" --root "$ROOT" verify --pub "$HARD_GATE_VC_PUB" >/dev/null 2>&1; then
                echo "❌ Allowlist FAIL: VC INVALID for $VC_FILE"; ALLOWLIST_OK=0
            fi
        fi
    done
fi

# P7-H#2: optional SBOM predicate (CycloneDX). Active only when HARD_GATE_SBOM_REQ=1.
# For each root's meta dir, require at least one *.sbom.json that parses as CycloneDX.
if [ -n "${HARD_GATE_SBOM_REQ:-}" ] && [ "${HARD_GATE_SBOM_REQ}" = "1" ]; then
    SBOM_OK=1
    for ROOT in "${ROOTS[@]}"; do
        MDIR="$ROOT/.hard-gate-meta"
        [ -d "$MDIR" ] || { echo "❌ SBOM FAIL: no meta dir in $ROOT"; SBOM_OK=0; continue; }
        SB=$(find "$MDIR" -maxdepth 1 -name '*.sbom.json' 2>/dev/null | head -1)
        if [ -z "$SB" ]; then
            echo "❌ SBOM FAIL: no *.sbom.json in $MDIR"; SBOM_OK=0; continue
        fi
        PY_SB="${PY_BIN:-${PYTHON:-python3}}"
        if ! "$PY_SB" -c "import json,sys; d=json.load(open(sys.argv[1],encoding='utf-8')); assert d.get('bomFormat')=='CycloneDX' and d.get('specVersion')" "$(cygpath -w "$SB")" >/dev/null 2>&1; then
            echo "❌ SBOM FAIL: invalid CycloneDX in $SB"; SBOM_OK=0
        fi
    done
else
    SBOM_OK=1
fi

# P7-I#6: optional model-asset signing predicate (G7). Active only when
# HARD_GATE_MODEL_SIGNED=1 and <meta>/model-hashes.json exists.
MODEL_OK=1
if [ -n "${HARD_GATE_MODEL_SIGNED:-}" ] && [ "${HARD_GATE_MODEL_SIGNED}" = "1" ]; then
    PY_M="${PY_BIN:-${PYTHON:-python3}}"
    for ROOT in "${ROOTS[@]}"; do
        if [ ! -f "$ROOT/.hard-gate-meta/model-hashes.json" ]; then
            continue
        fi
        if ! "$PY_M" "$SCRIPT_W/check-model-signed.py" "$ROOT" >/dev/null 2>&1; then
            echo "❌ MODEL FAIL: model asset signing check failed for $ROOT"; MODEL_OK=0
        fi
    done
fi

# P16-A1: OPA Rego enforcement (allowlist rule6). Active when
# HARD_GATE_OPA_ENFORCE=1 (default). Honest skip if opa binary absent.
OPA_OK=1
if [ "${HARD_GATE_OPA_ENFORCE:-1}" = "1" ]; then
    PY_O="${PY_BIN:-${PYTHON:-python3}}"
    if "$PY_O" "$SCRIPT_W/opa-policy-check.py" >/dev/null 2>&1; then
        :
    else
        echo "❌ OPA FAIL: Rego allowlist policy rejected"; OPA_OK=0
    fi
fi

# P8-O#5: optional budget hard-stop. When HARD_GATE_BUDGET is set, sum recent
# token_proxy from gate-cost.jsonl per root; over budget => FAIL.
BUDGET_OK=1
if [ -n "${HARD_GATE_BUDGET:-}" ]; then
    PY_B="${PY_BIN:-${PYTHON:-python3}}"
    WINDOW="${HARD_GATE_BUDGET_WINDOW:-7}"
    for ROOT in "${ROOTS[@]}"; do
        COST="$ROOT/.hard-gate-meta/gate-cost.jsonl"
        [ -f "$COST" ] || continue
        TOT=$("$PY_B" -c "import json,sys; f=sys.argv[1]; w=int(sys.argv[2]);
rows=[json.loads(l) for l in open(f,encoding='utf-8') if l.strip()];
rows=rows[-w:] if len(rows)>w else rows;
print(sum(r.get('token_proxy',0) for r in rows))" "$(cygpath -w "$COST")" "$WINDOW" 2>/dev/null)
        if [ -n "$TOT" ] && [ "$TOT" -gt "${HARD_GATE_BUDGET}" ]; then
            echo "❌ BUDGET FAIL: last-$WINDOW token_proxy=$TOT > ${HARD_GATE_BUDGET} ($ROOT)"; BUDGET_OK=0
        fi
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
export PYTHONIOENCODING=utf-8
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

# P5 A2: canonical drift check (blind-spot) — FAIL when canonical != project replica
if [ -n "${HARD_GATE_CANONICAL:-}" ] && [ -d "$HARD_GATE_CANONICAL" ] && [ -n "$PY_BIN" ]; then
    CANREP="${ROOTS[0]}/ben-mode"
    if [ -d "$CANREP" ] && ! "$PY_BIN" "$SCRIPT_W/verify_skill_replicas.py" \
        --root "$HARD_GATE_CANONICAL" --replica "$CANREP" >/dev/null 2>&1; then
        echo "❌ Canonical drift: canonical ≠ project replica" | tee -a "$AUDIT_LOG"
        MANIFEST_OK=0
        echo "Canonical governance: FAIL" | tee -a "$AUDIT_LOG"
    else
        echo "Canonical governance: PASS" | tee -a "$AUDIT_LOG"
    fi
fi

echo "OPA Rego governance: $([ $OPA_OK -eq 1 ] && echo PASS || echo FAIL)" | tee -a "$AUDIT_LOG"

# Verdict (Pragmatic Tip 44: Assertive Programming)
if [ "$DIRS" -ge 2 ] && [ "$FILES" -ge 4 ] && [ "$SYMLINKS" -eq 0 ] && [ "$CHECKSUMS_OK" -eq 1 ] && [ "$SCHEMA_OK" -eq 1 ] && [ "$ALLOWLIST_OK" -eq 1 ] && [ "$MANIFEST_OK" -eq 1 ] && [ "$SBOM_OK" -eq 1 ] && [ "$MODEL_OK" -eq 1 ] && [ "$BUDGET_OK" -eq 1 ] && [ "$OPA_OK" -eq 1 ]; then
    echo "✅ HARD GATE #10 PASSED" | tee -a "$AUDIT_LOG"
    STATUS="PASS"
    EXIT_CODE=0
else
    echo "❌ HARD GATE #10 FAILED" | tee -a "$AUDIT_LOG"
    STATUS="FAIL"
    EXIT_CODE=1
fi

# P5 C1: record run duration + status (after verdict) — no heredoc (CRLF-safe)
END_NS=$(date +%s%N)
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
# E2: include corpus size (catalogs/files/skills) so duration correlates with scale
if [ -n "$PY_BIN" ]; then
  "$PY_BIN" -c "import json,os,sys; m=os.path.join(sys.argv[1],'.hard-gate-meta'); os.makedirs(m,exist_ok=True); open(os.path.join(m,'gate-time.jsonl'),'a',encoding='utf-8').write(json.dumps({'ts_ms':int(sys.argv[2]),'status':sys.argv[3],'catalogs':int(sys.argv[4]),'files':int(sys.argv[5]),'skills':int(sys.argv[6])})+chr(10))" "$ROOT" "$ELAPSED_MS" "$STATUS" "$DIRS" "$FILES" "$SKILLS"
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
