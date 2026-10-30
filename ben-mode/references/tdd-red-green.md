# TDD RED → GREEN — Verification Pattern

Used with HARD GATE #10 and `ben-mode` execution (formerly `ultimate-combined`; trigger phrase `ben`).

Pattern: Measure RED (before fix) → fix → measure GREEN (after fix). Both measurements recorded with direct `ls`/`find`.

Example (from this session's verified run):
- RED: 1 catalog dir + 1 SKILL.md (344 bytes) + 0 symlink — FAIL
- GREEN: 2 catalog dirs + 4 SKILL.md @ 344 bytes + 0 symlink — PASS

Rule: Never declare GREEN without RED proof already recorded. If RED is missing, re-measure before fix.
