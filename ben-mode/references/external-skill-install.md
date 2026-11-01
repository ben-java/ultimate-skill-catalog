# Instal Skill dari Repo GitHub (workflow kelas)

Alur memasang skill siap pakai yang di-clone dari repo GitHub ke katalog Hermes, memverifikasinya terhadap HARD GATE #10. Berlaku untuk repo yang sudah berisi folder skill (`SKILL.md` + references/scripts).

## Urutan langkah

1. **Clone repo** ke folder eval sementara (`<project>/repo-eval/<repo>`), jangan langsung ke katalog.
2. **Identifikasi folder skill** di dalam repo (sering ada di subfolder, bukan root). Cek `name:` frontmatter cocok dengan nama folder itu.
3. **Salin folder skill** (bukan seluruh repo) ke setiap root katalog aktif:
   - canonical `dsh-imported`
   - `Tools/dsh-skill-wrappers`
   - `.dsh/skills`
   Gunakan `cp -r`/`shutil.copytree` (tanpa symlink/junction).
4. **Verifikasi tertarget cepat** (sebelum gate penuh):
   - checksum md5 per file lintas root — tiap file harus 1 hash identik di semua root
   - BOM = 0 pada SKILL.md
   - schema `name==folder`
5. **Jalankan validator bawaan repo** jika ada (`scripts/validate_*.py`) terhadap folder yang terinstall — exit 0 = struktur valid.
6. **Jalankan gate penuh** `verify-hard-gate.sh` (bisa lambat; jalankan di background).

## Pitfall

- **`sync-all-roots.sh` HANYA menyinkronkan tree ben-mode** — bukan installer skill generik. Untuk skill baru, salin folder skill secara manual ke tiap root; jangan mengandalkan sync-all-roots.
- **Gate penuh (`verify-hard-gate.sh` / `verify_skill_replicas.py`) sangat lambat** pada katalog besar (300+ skill × 3 root, >120–180s). Jangan pakai ini sebagai cek cepat per-skill; lakukan verifikasi tertarget (md5 lintas root + BOM + schema) dulu, lalu jalankan gate penuh di background.
- **Salin folder skill, bukan root repo** — menyalin seluruh repo menaruh README/LICENSE/ci di dalam folder skill dan mengacaukan quorum hash.
- **Periksa apakah repo punya validator sendiri** sebelum menulis cek baru; validator bawaan memberi sinyal struktur yang lebih andal daripada cek ad-hoc.

## Terkait
- HARD GATE #10 (`references/hard-gate-10.md`) untuk predicate/verifikasi; `content-to-skill.md` untuk alur konten web→skill (bukan repo siap pakai).
