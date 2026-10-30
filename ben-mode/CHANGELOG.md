# Changelog — ben-mode / HARD GATE #10

## v0.2.0 (2026-10-31) — P3: multi-root consistency & observability
- `sync-all-roots.sh`: sync canonical ke 3 replika fisik + verifikasi quorum full-tree (4/4).
- `cron-hard-gate-monitor.sh`: cakupan diperluas — gate root + quorum canonical-vs-replika (blind-spot); webhook FAIL tetap.
- `agentlog2trace.py` + runtime-gate-scan: adaptasi log Hermes nyata ke trace JSONL; demonstasi P_rt_sessions.
- Git repo + pre-commit hook terpasang di project catalog.
- Meta audit dibersihkan (hapus duplikat .0–.3.jsonl; hanya aggregated).
- Bibliografi 213 artikel dipisah ke `references/bibliography-articles.md`.

## v0.1.0 (2026-10-30) — P0–P2: gate hijau & klaim terverifikasi
- Unifikasi mekanisme manifest; refresh-baseline.sh; bootstrap-deps.sh (z3).
- Negative tests 11 (junction fail-loudly, BOM, hidden-instruction, CRLF canonicalization).
- quorum-check.py, report-drift.py, aggregate-audit.py, opa-policy-check.py.
- Perbaikan path native MSYS (C:\c\Users\...).
