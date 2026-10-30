---
name: context-compressor
description: "Output interceptor and token compressor. Filters verbose CLI tool outputs, JSON schemas, and logs before entering LLM context."
---

# context-compressor

Kompresor token dan interceptor luaran alat (terinspirasi dari arsitektur Headroom dan mcptoon).

## Prinsip Operasional
1. **Pre-LLM Filtering**: Intersep luaran perintah terminal, log eksekusi, dan skema JSON yang melebihi batas nominal sebelum disuntikkan ke memori percakapan.
2. **Deterministic Pruning**: Buang stack trace redundan, format ulang tabel panjang menjadi ringkasan baris-kunci, dan pertahankan hanya status eksekusi atau pesan galat esensial.
3. **Ekstraksi Terarah**: Bila luaran melebihi 100 baris, simpan seluruh luaran ke berkas scratch lokal (`TMPDIR`) dan kirimkan ringkasan 10 baris pertama/terakhir beserta path berkas lengkap.
