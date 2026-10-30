---
name: pstack-verify
description: "Evidence-generating verification protocol for autonomous agents. Requires physical execution artifacts before marking tasks complete."
---

# pstack-verify

Protokol verifikasi berbasis bukti fisik untuk agen otonom. Mengeliminasi *hallucinated completion* dengan mewajibkan artefak bukti nyata sebelum penyelesaian tugas dilaporkan.

## Prinsip Operasional
1. **Bukti Fisik Mutlak**: Setiap tugas refactoring, coding, atau audit wajib menyertakan bukti nyata (screenshot, log eksekusi, hash berkas, atau status exit code biner).
2. **Determinisme**: Tidak menerima asumsi bahwa suatu perintah berhasil tanpa verifikasi output sesungguhnya di lingkungan terminal.
3. **Penyimpanan Artefak**: Catat seluruh log verifikasi ke dalam berkas audit terstruktur sebelum menyelesaikan sesi.
