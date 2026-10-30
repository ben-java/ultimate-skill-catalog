---
name: code-mode-runtime
description: "Programmatic multi-tool execution mode (Cloudflare Code Mode + CodeModo + Git Trajectory Memory). Replaces multiple JSON tool calls with isolated TypeScript/Python scripts, cutting tokens by 75-98%."
---

# code-mode-runtime

Runtime eksekusi multi-tool terprogram berbasis pola Cloudflare Code Mode (`@cloudflare/codemode`), CodeModo (`Connorbelez/codeMode`), dan Git Trajectory Memory (`smithclay/codemode-git`).

## 1. Prinsip Operasional & Efisiensi Token
- **Satu Eksekusi vs Banyak Round-Trip**: Mengganti pemanggilan tool serial via JSON function-calling (yang memicu round-trip LLM berulang) dengan satu blok program TypeScript atau Python.
- **Filtering di Sandbox**: Seluruh perulangan (loop), percabangan kondisi (if-else), dan pemrosesan data dilakukan di dalam runtime eksekusi. Hanya hasil akhir teragregasi yang dikembalikan ke konteks model, memangkas konsumsi token hingga 75–98%.
- **Progressive Interface Loading**: Definisi interface tools dimuat berdasarkan kebutuhan impor program, tanpa membanjiri system prompt dengan seluruh skema JSON.

## 2. Git Trajectory Memory (Pola smithclay/codemode-git)
- Setiap trajektori eksekusi skrip dan luaran validasinya dicatat ke repositori lokal `C:\Users\AMMAR\Hermes Agents\Projects\code-mode-trajectories`.
- Commit git berfungsi sebagai rekaman jejak audit fisik non-volatile (mendukung kepatuhan `pstack-verify` dan `hard-gate-10.md`).

## 3. Alur Penggunaan
1. Tulis kode orkestrasi di runner terisolasi (`execute_code` atau script Node.js).
2. Panggil API/alat target secara terprogram dari dalam kode.
3. Rekam jejak eksekusi ke git trajectory repository bila mencapai status terminal (`completed`/`error`).
