---
name: pinchtab-browser
description: "Lightweight browser interaction via accessibility trees and DOM diffs, cutting token usage down to ~800 tokens per action."
---

# pinchtab-browser

Antarmuka otomasi peramban web hemat token berbasis representasi pohon aksesibilitas (Accessibility Tree) dan DOM diffing (pola Pinchtab).

## Prinsip Operasional
1. **Accessibility Tree Over Pixels**: Hindari tangkapan layar penuh (screenshot) berbasis gambar jika halaman dapat dievaluasi melalui node aksesibilitas terstruktur.
2. **DOM Diffing**: Evaluasi hanya elemen interaktif yang mengalami mutasi state setelah suatu aksi klik atau ketik, memangkas konsumsi token hingga 10-15x lipat.
3. **Session Persistence**: Jaga state autentikasi dan cookie dalam sesi profil terisolasi tanpa membanjiri riwayat percakapan.
