---
name: agent-reach
description: "Universal multi-platform intelligence gathering (YouTube, Reddit, X, GitHub) via CLI tools and zero-cost scrapers."
---

# Agent-Reach

Perkakas pengumpulan intelijen dan ekstraksi konten multi-platform tanpa biaya token API berbayar, mengintegrasikan `yt-dlp`, browser session scrapers, dan REST proxies.

## Kebijakan Kredensial & Keamanan (Wajib Dipatuhi)
- "Cookie itu akses login penuh: pakai akun cadangan, jangan akun utama, karena akun bisa dibatasi sampai diblokir."
- "Cek juga aturan tiap platform (aturan X ngelarang scraping tanpa izin tertulis)."
- "Pasang cuma dari repo resminya, mereka nggak punya token kripto apa pun."

## Alur Kerja Operasional
1. **YouTube**: Gunakan utilitas `yt-dlp` untuk mengekstrak metadata video, transkrip subtitle (.vtt/.srt), atau deskripsi postingan secara langsung.
2. **Reddit / X / GitHub**: Gunakan antarmuka CLI yang membaca endpoint publik atau RSS feed secara efisien tanpa membanjiri konteks.
3. **Isolasi Output**: Kompresi teks panjang atau JSON sebelum masuk ke memori agen untuk menjaga efisiensi token.
