#!/usr/bin/env bash
# install-precommit-hook.sh — install a git pre-commit hook that runs the
# HARD GATE #10 verifier whenever a staged change touches a skill directory.
#
# Usage: install-precommit-hook.sh [root]
#   root default: C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog
# Skips gracefully when <root> is not a git repository.
set -euo pipefail

ROOT="${1:-C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$ROOT/.git" ]; then
    echo "⚠️  $ROOT is not a git repository — pre-commit hook skipped."
    echo "   (hooks template kept at $SCRIPT_DIR/hooks/pre-commit.ben-mode)"
    mkdir -p "$SCRIPT_DIR/hooks"
    cat > "$SCRIPT_DIR/hooks/pre-commit.ben-mode" <<'EOF'
#!/usr/bin/env bash
# HARD GATE #10 pre-commit hook (template).
# Copy to <root>/.git/hooks/pre-commit and chmod +x.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
# Only run when staged files touch a skill tree.
if git diff --cached --name-only | grep -qE '/(SKILL\.md|references/|scripts/)'; then
    "$(dirname "$0")/../.." 2>/dev/null || true
    cd "$ROOT"
    bash "C:/Users/AMMAR/AppData/Local/hermes/skills/dsh-imported/ben-mode/scripts/verify-hard-gate.sh" "$ROOT"
fi
EOF
    exit 0
fi

HOOK="$ROOT/.git/hooks/pre-commit"
mkdir -p "$ROOT/.git/hooks"
cat > "$HOOK" <<EOF
#!/usr/bin/env bash
# HARD GATE #10 pre-commit hook (installed by ben-mode P2.1).
set -euo pipefail
ROOT="\$(git rev-parse --show-toplevel)"
if git diff --cached --name-only | grep -qE '/(SKILL\.md|references/|scripts/)'; then
    cd "\$ROOT"
    bash "$SCRIPT_DIR/verify-hard-gate.sh" "\$ROOT"
fi
EOF
chmod +x "$HOOK"
echo "✅ pre-commit hook installed: $HOOK"
