---
name: pi-bolt
description: "Operate and delegate coding tasks to Pi-Bolt (AOT-compiled native Pi coding agent CLI). Fast non-interactive subagent execution with minimal RAM/CPU footprint."
---

# pi-bolt

Skill orkestrasi dan pendelegasian tugas coding ke **Pi-Bolt** (AOT-compiled native binary dari engine Pi coding agent).

## 1. Karakteristik & Efisiensi Token
- **Startup Cepat & Hemat Sumber Daya**: Eksekusi AOT (Ahead-of-Time) tanpa Node/Bun startup overhead. Siap mengetik dalam ~38 ms dengan konsumsi memori ~24–101 MB.
- **Isolasi Tugas**: Cocok untuk pendelegasian tugas coding lokal mandiri (refactoring, generating boilerplate, linting/fixing) tanpa membanjiri konteks percakapan utama Hermes.
- **Biner Terpasang**: `pi-bolt` (win32-x64 native executable).

## 2. Pola Orkestrasi Hermes

### Mode 1: Non-Interactive Print (`-p`) — Jalur Utama
Gunakan perintah satu kali jalan (*one-shot task*) untuk mengeksekusi instruksi coding spesifik:
```bash
pi-bolt -p "Instruksi coding di sini" --tools read,edit,write,bash
```

### Mode 2: Pembatasan Tool untuk Audit / Keamanan
Batasi akses tool agar aman dan terprediksi:
```bash
# Read-only audit
pi-bolt --tools read,grep,find,ls -p "Audit struktur kode di src/"
```

### Mode 3: Format Luaran JSON
Untuk integrasi scripting pipeline terprogram:
```bash
pi-bolt --mode json -p "Tugas"
```

## 3. Konfigurasi Provider & Kredensial
Pi-Bolt menggunakan konfigurasi global di `~/.pi/agent/`. Konfigurasikan provider via:
- Flag CLI: `--provider <name> --model <pattern> --api-key <key>`
- Environment variable: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `GEMINI_API_KEY`, dll.
