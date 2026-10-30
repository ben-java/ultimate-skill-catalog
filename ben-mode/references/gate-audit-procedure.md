# Prosedur Audit Total Klaim HARD GATE #10 / Ben-Mode

Gunakan saat diminta review/audit total ben-mode atau hard-gate-10.md, atau sebelum mempercayai status "Implemented & runtime-verified". Prinsip inti: klaim diverifikasi dengan eksekusi, bukan dengan membaca dokumen.

## Langkah
1. **Jalankan gate penuh dulu**: `verify-hard-gate.sh` dari root proyek (12 katalog & 10 SKILL.md di `C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog`). Catat EXIT CODE sebenarnya — jangan ambil `$?` setelah `tail`/pipe (itu exit tail, bukan gate).
2. **Jalankan negative suite**: `test-hard-gate-negative.sh`. Hitung berapa test yang BENAR-BENAR dieksekusi (bukan jumlah yang dicetak) — uji yang skip kondisional bukan bukti.
3. **Eksekusi tiap artefak berklaim**: untuk setiap marker "runtime-verified":
   - jalankan skripnya langsung (mis. `bmc_replica_state.py`, `runtime_gate.py` pada `scripts/fixtures/*.jsonl`);
   - buktikan dependensi importable di env yang SAMA dengan cron gate; set `PYTHONDONTWRITEBYTECODE=1` agar artefak tak mencemari pohon yang diaudit;
   - buktikan binary eksternal ada (mis. `which opa`) bila klaim menyebut engine eksternal.
4. **Klasifikasi klaim**: real (berjalan & hasil sesuai) / overstated (file ada tapi tidak dieksekusi engine mana pun) / broken (crash). Catat klasifikasi per §.
5. **Susun plan**: P0 perbaikan utang integritas (regenerasi baseline, satukan mekanisme, koreksi klaim) → P1 resilience (provisioning dependensi, fail-loudly, launcher tahan upgrade) → P2 nilai tambah. Letakkan plan di bawah proyek (`.../ultimate-skill-catalog/`), bukan di scratch.

## Temuan awal audit (re-verify tiap kali; jangan diasumsikan)
- `bmc_replica_state.py` (BMC deadlock, §14.1) crash tanpa `z3`; tidak ada provisioning dependensi (belum ada requirements.txt/bootstrap).
- Rego Rule 6 (§15.1) murni dokumentasi; tidak ada binary `opa`/`rego` → klaim "enforced" overstated.
- Negative Test 2 (symlink) di Windows/MSYS silent-skip bila `ln -s` gagal (butuh admin) — hanya 6/7 yang benar-benar dicek.
- Dua mekanisme manifest: `check_signed_manifest` (.hardgate_manifest.sha256) vs `verify-hard-gate.sh` (<skill>.manifest.sha256). Baseline basi = gate RED walau predicate lain PASS; regenerasi via `generate_manifest.py --baseline <file-di-luar-pohon>` (anti self-invalidation), lalu verify ulang.

## Utilities
- Bash gate: `C:/Program Files/Git/bin/bash.exe` (bukan `bash` telanjang → WSL).
- Python gate: resolve dari `run_daily_monitor.cmd` (launcher cron) — interpreter yang dipin cron adalah env yang harus dipakai untuk uji runtime-verified.
