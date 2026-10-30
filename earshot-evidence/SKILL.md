---
name: earshot-evidence
description: "Audio evidence extraction and spectrogram analysis. Converts sound into machine-verifiable timestamps, loudness, and event sheets."
---

# earshot-evidence

Modul ekstraksi bukti audio dan analisis spektrum gelombang suara (pola Earshot oleh Leon Lin).

## Prinsip Operasional
1. **Audio as Evidence**: Ubah berkas audio rekaman atau hasil sintesis menjadi tabel bukti fisik terverifikasi (event waktu, desibel/loudness, spektrogram).
2. **Deterministic Verification**: Verifikasi sinkronisasi audio-visual (misalnya jeda ketukan 80ms) secara matematis melalui data numerik tanpa asumsi subjektif.
3. **Optimasi Runtime**: Jalankan ekstraksi via CLI atau server MCP terisolasi dengan dependensi Python 3.10+ dan ffmpeg.
