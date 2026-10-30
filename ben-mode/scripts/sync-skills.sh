#!/usr/bin/env bash
# sync-skills.sh — Atomic skill sync (copy → verify → rollback) for HARD GATE #10
# Usage: ./sync-skills.sh <source_skill_dir> <catalog1> <catalog2> [catalog3 ...]
#   Each catalog holds <skill-name>/SKILL.md replicas. Minimum 2 catalogs.
# Exit: 0 = PASS, 1 = verification FAIL (rolled back), 2 = precondition FAIL

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY_SCRIPT="$SCRIPT_DIR/verify-hard-gate.sh"

[ -f "$VERIFY_SCRIPT" ] || { echo "❌ verify-hard-gate.sh not found at $VERIFY_SCRIPT"; exit 2; }

SOURCE="${1:?Source skill directory required}"
shift
TARGETS=("$@")
[ "${#TARGETS[@]}" -ge 2 ] || { echo "❌ Need ≥2 target catalogs (HARD GATE #10)"; exit 2; }

SKILL_NAME=$(basename "$SOURCE")

echo "=== Syncing skill: $SKILL_NAME ==="
echo "Source: $SOURCE"
echo "Targets: ${TARGETS[*]}"

# Precondition: source has SKILL.md with valid schema
[ -f "$SOURCE/SKILL.md" ] || { echo "❌ Source missing SKILL.md"; exit 2; }

# Validate source schema before sync (DDIA Ch4: schema evolution)
if ! grep -q "^name:" "$SOURCE/SKILL.md" || ! grep -q "^description:" "$SOURCE/SKILL.md"; then
    echo "❌ Source SKILL.md missing required frontmatter (name, description)"
    exit 2
fi

# Verify name matches folder
SRC_NAME=$(grep "^name:" "$SOURCE/SKILL.md" | cut -d' ' -f2-)
if [ "$SRC_NAME" != "$SKILL_NAME" ]; then
    echo "❌ Source SKILL.md name '$SRC_NAME' ≠ folder '$SKILL_NAME'"
    exit 2
fi

# Copy helper: rsync if present, else rm+cp (Windows MSYS often lacks rsync)
copy_tree() {
    local src="$1" dst="$2"
    mkdir -p "$dst"
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete "$src/" "$dst/"
    else
        rm -rf "$dst"
        mkdir -p "$dst"
        cp -a "$src/." "$dst/"
    fi
}

# Atomic sync (TSNA Ch5: idempotent automation) with per-catalog rollback snapshot
declare -a DEST PREV
for t in "${TARGETS[@]}"; do
    dest="$t/$SKILL_NAME"; prev="$t/.prev/$SKILL_NAME"
    rm -rf "$prev"; mkdir -p "$t/.prev"
    [ -d "$dest" ] && cp -a "$dest" "$prev"
    echo "=== Copying to $dest ==="
    copy_tree "$SOURCE" "$dest"
    DEST+=("$dest"); PREV+=("$prev")
done

# Verify immediately (DDIA: linearizable check) on the catalogs' common parent
VERIFY_ROOT=$(cd "${TARGETS[0]}" && cd .. && pwd)
echo "=== Running HARD GATE #10 verification on $VERIFY_ROOT ==="
if "$VERIFY_SCRIPT" "$VERIFY_ROOT"; then
    for t in "${TARGETS[@]}"; do rm -rf "$t/.prev"; done
    echo "✅ Sync + Verify COMPLETE for $SKILL_NAME"
    exit 0
fi

echo "❌ Sync FAILED verification — rolling back $SKILL_NAME"
for i in "${!DEST[@]}"; do
    if [ -n "$(ls -A "${PREV[$i]}" 2>/dev/null)" ]; then
        echo "Restoring ${DEST[$i]}"
        copy_tree "${PREV[$i]}" "${DEST[$i]}"
    else
        echo "Removing ${DEST[$i]} (no prior version)"
        rm -rf "${DEST[$i]}"
    fi
done
for t in "${TARGETS[@]}"; do rm -rf "$t/.prev"; done
exit 1