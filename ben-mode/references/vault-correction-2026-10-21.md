---
name: Vault Correction & Folder Merge Reference (2026-10-21)
source: session work on obsidian-mind-install + ultimate-skill-catalog merge
dependencies: ben-mode v0.1.0 (formerly ultimate-combined; trigger phrase ben), ultimate-skill v3.4
---

# Rules learned from session

1. Verify vault path with `ls` before editing — multi-copy environments common (`Projects/` vs root).
2. User may use `memories/` (not `brain/`) — confirm with `memory-template.md` / `.claude/` if ambiguous.
3. When merging vault copies: `cp -n`, merge unique, delete wrong folder, keep main.
4. When merging catalog folders with identical core files (SKILL.md) but different README:
   - new folder = combined
   - keep one SKILL.md
   - preserve both README originals
   - new README = combined note
   - delete old folders after verification
5. Hindsight sync file (`Hindsight-Sync-*.md`) goes to `memories/` (user's folder), update `brain/Memories.md` for link.
6. `.env` may stay old (dilindungi) — report open, don't force edit.
7. Not mineru v4.0 — use ultimate-skill v3.4 per version-identification.md.

# Additional pitfalls (2026-10-21 session extension)
8. Folder moves: `mv` can silently fail for large folders — always `ls` after; prefer `cp -r` to `/tmp/` then `mv` from `/tmp/`, verify with `ls` each step.
9. Empty-folder search: exclude `.git/objects/`, `.venv/`, and `vendor/` from cleanup targets — they are repo internals, not user's empty folders.
10. Memory folder convention: confirm with `.claude/memory-template.md` / `.claude/` before assuming `brain/` vs `memories/`; user may prefer `memories/`.
11. User preference: direct action over long explanation — when instructions are explicit, execute and report briefly (rtk/caveman style), not replay process.
