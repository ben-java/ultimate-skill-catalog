# Konten Eksternal → Skill Hermes (workflow kelas)

Alur mengubah konten web/sosial/kurasi menjadi skill Hermes yang sah, jujur, dan terverifikasi. Berlaku untuk postingan link, artikel, video, dsb.

## Urutan langkah

1. **Tentukan ketersediaan isi secara jujur.** Coba ambil isi (web_extract / browser). Jika sumber di balik anti-bot (mis. Cloudflare challenge/403): **jangan memaksakan berkali-kali dan jangan fabrikasi**. Gunakan hanya konten yang benar-benar tersedia di konteks/lampiran (mis. caption). Lanjut ke langkah 2.
2. **Buat tabel provenance** di SKILL.md: kolom `Sumber | Isi | Status`. Status hanya dua nilai: `✅ diverifikasi` (konten benar-benar diperoleh) atau `⚠️ UNVERIFIED` (tidak diperoleh — jangan dipakai sebagai isi, tandai pending).
3. **Suling prinsip**, bukan tempel mentah. Isi = prinsip/aturan yang bisa dipakai; jangan salin caption utuh. Untuk isi yang tak terverifikasi, jangan membuat prinsip darinya.
4. **Tentukan penempatan** dalam hirarki routing:
   - Kanon/data referensi → buat skill berisi prinsip + provenance, daftarkan sebagai **subordinat** otoritas kluster (mis. konten desain di bawah `design-master`).
   - Koordinator → skill yang memilih/memuat specialist (lihat `design-master`).
5. **Daftarkan di routing** (`skill-routing-v3-7/SKILL.md`): tambah entri, lalu sinkronkan salinan routing ke semua katalog aktif.
6. **Replikasi fisik** ke ≥2 katalog (canonical `dsh-imported` → `dsh-skill-wrappers` & `.dsh/skills`), tanpa symlink/junction.
7. **Verifikasi GREEN**: seluruh pohon identik byte-for-byte di semua katalog + schema `name==folder` + symlink=0. Lihat HARD GATE #10.
8. **Renaming/arsip skill lama**: pindahkan folder lama ke direktori arsip (jangan biarkan salinan mati menyisa), perbarui semua dokumen yang merujuknya, hapus salinan arsip hanya atas permintaan eksplisit.

## Pitfall

- **Scraper anti-bot (403/Cloudflare) ≠ kegagalan yang harus dipaksa.** Jika challenge interaktif tidak bisa dilewati, berhenti dan andalkan konten yang benar-benar tersedia; tandai sumber yang tak diperoleh UNVERIFIED. Menyatakan isi yang tak pernah diperoleh sebagai fakta = fabrikasi.
- **Jangan membuat skill dari konten yang tak terverifikasi** hanya untuk meramaikan katalog; simpan sebagai baris pending di tabel provenance.
- **Satu sumber yang tak terambil tidak boleh menahan pengiriman** sisanya — serahkan yang verified, tandai yang pending.
- **Update routing dan sinkronisasi harus satu paket** dengan pembuatan skill; skill yang tidak terdaftar tidak akan dipilih router.

## Terkait
- HARD GATE #10 (`references/hard-gate-10.md`) untuk predicate/verifikasi; `skill-routing-v3-7` untuk pendaftaran; `design-master` contoh koordinator kluster.
