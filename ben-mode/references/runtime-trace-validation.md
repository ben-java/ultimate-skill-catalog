# Menvalidasi runtime trace (agent.log → runtime_gate)

Resep untuk memindai jejak eksekusi nyata Hermes dengan `scripts/runtime_gate.py` (P_runtime / P_rt_sessions zero-trust). Diverifikasi pada slice `agent.log` (788 event → PASS).

## Pipeline
1. Ambil slice log (path native untuk python — lihat windows-execution.md §1):
   ```bash
   tail -n 3000 /c/Users/AMMAR/AppData/Local/hermes/logs/agent.log > /tmp/agent_slice.log
   TAILW=$(cygpath -w /tmp/agent_slice.log); OUTW=$(cygpath -w /tmp/agent_trace.jsonl)
   PY scripts/agentlog2trace.py "$TAILW" --out "$OUTW"
   ```
2. Pindai: `bash scripts/runtime-gate-scan.sh "$OUTW"` — exit 0 = semua predicate PASS.

## Mapping (agentlog2trace.py)
- Format baris `YYYY-MM-DD HH:MM:SS,mmm INFO [<session>] <logger>: <msg>`.
- `tools.terminal_tool`/`tools.terminal` → `action`, category=`terminal`, `cmd`=token pertama; perintah destruktif (rm/del/format/…) diberi `approved=false`.
- `agent.tool_executor` → `action`, category=`tool`.
- Sisanya (dengan session id) → `output`.

## Aturan wajib
- **Suntikan event `verify` per sesi** saat konversi (bukan di runtime gate). `P_rt_sessions` membutuhkan minimal satu event `verify` per sesi; tanpa itu seluruh trace FAIL walau aman. `agentlog2trace.py` melakukan ini otomatis.
- **Mutasi daftar event sebelum loop penulisan.** Append setelah write tidak terserialisasi (jumlah print ≠ jumlah baris file). Gejala: parse ulang tidak menemukan event yang baru ditambahkan. Koreksi urutan, jangan ubah format.
- Path untuk python selalu native (`cygpath -w`) — argumen `/tmp/...` gagal dibuka oleh python Windows.
- P_rt_output_structure hanya aktif bila event punya `expected_schema`; trace konversi tanpa schema tidak terpengaruh.
