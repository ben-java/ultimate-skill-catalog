---
name: version-identification
purpose: Distinguish ultimate-skill family versions; avoid mineru/mineral confusion
rule: When user says 'gunakan ultimate-skill', default is ultimate-skill (v3.4, dsh-imported). The intermediate skill written 3.7 is ultimate-skill-verification — NOT mineru v4.0 and NOT v4.0. Verify its skill directory before claiming version.
verification_command: list the `ultimate-skill-verification` skill directory before claiming its version.
version_map:
  ben-mode wrapper: v0.1.0; legacy trigger phrase: ben
  legacy slug: ultimate-combined (renamed to ben-mode); short trigger phrase: ben
  ultimate-skills / ultimate-skill: v3.4
  ultimate-skill-verification: v3.7 (between the two; combined with v3.4 when user requests 'gabungkan ketiga')
  routing: LangGraph PRIMARY (LOCKED); CrewAI / PyAutoGen only if explicitly requested (per memory 20 Oct 2026)
  mineru: v4.0.10 (separate; do NOT confuse with ultimate-skill family)
pitfall: User explicitly corrected this session ('bukan mineru yang v4.0 tapi... tulisannya 3.7'). Never assume v4.0 belongs to ben family (formerly ultimate-combined).
hard_gate_10: 2 physical catalogs + 4 physical SKILL.md copies + 0 junction; verify each copy directly, never assume from memory.
status: ben-mode (formerly ultimate-combined) is user-owned (created_by=None); curator adoption (hermes curator adopt ben-mode) required before autonomous patch.
---

ben-mode v0.2.0 (rilis P3/P4):
  - frontmatter: version: 0.2.0 (sebelumnya v0.1.0 tanpa field version).
  - scripts baru: sync-all-roots.sh, tdd-red-green.sh, gate-stats.sh,
    runtime-monitor.sh, bmc_concurrency.py, allowlist.py, manifest-sign.sh,
    verify-manifest-sig.sh, cost-report.py, agentlog2trace.py.
  - references baru: windows-execution.md, runtime-trace-validation.md,
    bibliography-articles.md.
  - gate kini multi-root quorum (4 pohon fisik) + manifest terpadu; negative
    suite 13 uji; OPA opsional.
