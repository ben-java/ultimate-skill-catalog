# ADR — ben-mode / HARD GATE #10 (P4 F1)

Format: ADR-N — title (status).

## ADR-1 — Unifikasi manifest (diterima, P0)
Gate sebelumnya memiliki dua mekanisme baseline: `check_signed_manifest`
(`.hardgate_manifest.sha256`) dan `verify-hard-gate.sh`
(`.hard-gate-meta/<skill>.manifest.sha256`). Dipilih satu: deterministic tree
signature (CRLF-normalized) dari `generate_manifest.py`, disimpan **di luar**
pohon skill. `gate_predicates.py` kini memakai file yang sama.

## ADR-2 — Deteksi junction via ctypes (diterima, P1)
`os.path.islink` mengembalikan False untuk junction Windows. Deteksi reparse
point dengan `GetFileAttributesW(p) & 0x400` di `verify_skill_replicas.py`
dan `gate_predicates.py`. Pembuatan fixture junction memakai PowerShell
`New-Item -ItemType Junction` (bukan `cmd //c mklink /J` yang membuka cmd
interaktif).

## ADR-3 — Argumen native untuk eksekutabel native (diterima, P1)
MSYS auto-conversion `/c/...` tidak konsisten antar-shell, menghasilkan
`C:\c\Users\...` yang membuat python gagal membuka file. Konvensi:
`SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"` → `"$SCRIPT_W/script.py"`; semua
argumen berkas juga dilewatkan `cygpath -w`.

## ADR-4 — Suntikan event verify sintetis saat konversi trace (diterima, P3/P4)
`runtime_gate.py` P_rt_sessions mensyaratkan minimal satu event `verify` per
sesi. Trace turunan dari log teks tidak menghasilkan event itu → suntikkan di
`agentlog2trace.py` SEBELUM loop penulisan (mutasi sebelum write; append
setelah write tidak terserialisasi).

## ADR-5 — Manifest signature opsional (diterima, P4)
Baseline default adalah hash (bukan tanda tangan). `manifest-sign.sh` +
`verify-manifest-sig.sh` menyediakan Ed25519 opsional via openssl; gate utama
tetap hash (default off), signing dipakai untuk verifikasi suppy-chain penuh.

## ADR-6 — Self-repair monitor (diterima, P4)
`cron-hard-gate-monitor.sh` mendukung `REPAIR_FLAG=1`: saat drift terdeteksi,
jalankan `sync-all-roots.sh` → `refresh-baseline.sh` → verify. Wajib guard
`|| true` pada pipeline yang exit-nya non-zero agar `set -euo pipefail` tidak
menghentikan cabang repair sebelum sempat dieksekusi.
