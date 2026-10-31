# Ben-Mode / HARD GATE #10 — Quickstart

## Prasyarat
- Git-Bash (`C:\Program Files\Git\bin\bash.exe`).
- Python (Hermes tools atau venv) dengan `hashlib`; z3 untuk BMC via `bootstrap-deps.sh`.

## Alur harian
```bash
# 1. Sinkronkan canonical ke semua replika fisik + quorum 4-root
PYTHON=<python> bash <ben-mode>/scripts/sync-all-roots.sh

# 2. Regenerate baseline setelah edit (WAJIB setelah edit skill)
PYTHON=<python> bash <ben-mode>/scripts/refresh-baseline.sh <root> ben-mode

# 3. Verifikasi penuh
PYTHON=<python> bash <ben-mode>/scripts/verify-hard-gate.sh <root>

# 4. (Opsional) self-repair otomatis saat drift
REPAIR_FLAG=1 PYTHON=<python> bash <ben-mode>/scripts/cron-hard-gate-monitor.sh <root>
```

## Tes
```bash
bash <ben-mode>/scripts/test-hard-gate-negative.sh     # 13 uji adversarial
bash <ben-mode>/scripts/tdd-red-green.sh              # RED→GREEN executable
<tools-python> <ben-mode>/scripts/bmc_replica_state.py # deadlock-free (UNSAT)
<tools-python> <ben-mode>/scripts/bmc_concurrency.py   # S1 hazard / S2 lock-safe
<tools-python> <ben-mode>/scripts/opa-policy-check.py  # Rego rule6 (opsional)
```

## Pemeriksaan drift
```bash
<python> <ben-mode>/scripts/report-drift.py <root> ben-mode   # CLEAN / DRIFT
<python> <ben-mode>/scripts/quorum-check.py <canonical> <rep1> <rep2> <rep3>
<python> <ben-mode>/scripts/cost-report.py <root>/.hard-gate-meta --budget 500000
```

## Troubleshooting ringkas
| Gejala | Penyebab / Perbaikan |
|---|---|
| Gate FAIL "Manifest FAIL" | baseline basi → `refresh-baseline.sh` setelah edit |
| Python "can't open file C:\c\..." | argumen MSYS → pakai `cygpath -w` + `SCRIPT_W` |
| Junction tak terdeteksi | `GetFileAttributesW & 0x400` (sudah di verifier) |
| Runtime trace selalu FAIL sessions | konversi harus suntik event `verify` per sesi |
| z3 ImportError | `bootstrap-deps.sh` |
