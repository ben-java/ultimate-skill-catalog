# Menambah Mekanisme / Predicate Baru ke HARD GATE #10

Resep end-to-end untuk menambah satu mekanisme verifikasi baru ke gate ben-mode (dipakai oleh perluasan P1–P12, N1–N12, dan R1–R54/O1–O21). Ikuti urutan ini; jangan lewati fase verifikasi.

## 1. Fungsi mekanisme — `scripts/hard_gate_enhancements.py`
- Tulis fungsi-fungsi modul-level **SEBELUM `def main():`**. Fungsi yang diletakkan setelah baris pemanggilan `main()` (di bawah `if __name__ == "__main__":`) belum terdefinisi saat main berjalan → NameError runtime padahal kode tampak valid.
- Jaga fungsi berdiri sendiri, stdlib-only bila memungkinkan. Beri nama berprefiks `O<N>` / `N<n>` / `T<n>` / `W<n>` agar mudah dipetakan ke spec.
- **Sisipkan blok fungsi dengan TEPAT SATU metode** (append di akhir file ATAU `str.replace(anchor, block+anchor)`, bukan keduanya dalam satu langkah). Kombinasi append + replace menghasilkan blok duplikat; lalu menyelaraskan duplikat dengan slicing antara dua marker bisa menghapus `main()` (beserta seluruh branch selftest) yang berada di antaranya. Setelah insert, verifikasi `txt.count(marker)==1` DAN `ast.parse` sebelum menyimpan.
- **Recovery file terlanjur rusak**: salin dari replika yang masih utuh (byte-identik — hasil `sync-all-roots.sh` sebelumnya) ke canonical, lalu ulangi penyisipan dengan satu metode. Jangan menulis ulang `main()` dari ingatan.
- Tambahkan branch `selftest_<x>` di dalam `main()` yang memanggil setiap fungsi dengan fixture baik & buruk dan `print` hasilnya — ini bukti runtime sebelum di-claim verified.
- Setelah menulis, wajib `ast.parse` pada path file (bukan sekadar mengandalkan string sumber), lalu jalankan `python ... selftest_<x>`.

## 2. Wire predicate — `scripts/gate_predicates.py`
- Tambah fungsi `check_<x>()` yang memuat modul via `_load_enhancements()` dan mengonfirmasi fungsi ada (`getattr(mod, name)` callable).
- Tambahkan nama `"check_<x>"` ke daftar predicate statis.
- Tambahkan marker komentar `# P_N<n>_<name>` / `# P_O<n>_<name>` di dekat fungsi — ini yang dibaca status-matrix untuk surfacing.

**Pitfall — insert ke list literal Python via string replace:** saat menyisipkan entri ke daftar multi-baris dengan mengganti baris anchor yang sudah berujung koma, hasilnya bisa `"check_o21",,` (double comma → SyntaxError). Selalu jalankan `ast.parse` setelah write; koma ganda ketahuan di sana.

## 3. Surfacing di status-matrix
- Regex `predicates()` di `status-matrix.py` harus mencakup set karakter token: `[A-Za-z0-9_]+` (bukan `[a-z_]+`). Token yang memuat huruf kapital/digit (mis. `P_N1_...`, `P_O1_...`) akan diam-diam dijatuhkan oleh regex lowercase → kapabilitas baru tak pernah muncul di dashboard walau gate PASS.
- Verifikasi `P_N*/P_O*` muncul: `python status-matrix.py --root <project> | grep P_N`.

## 4. Dokumentasi spec — `references/hard-gate-10.md`
- Tambah **BAGIAN** baru (tabel: ID, mekanisme, fungsi, basis riset). Mekanisme gate baru wajib di badan spec, bukan sekadar bump header — grep istilah implementasi di doc harus positif setelah rilis.
- Update Quick Reference Index bila jumlah test/predicate bertambah.

## 5. Fase verifikasi (wajib, urut)
1. `scripts/sync-all-roots.sh` → quorum 4/4 (sync ke 4 replika fisik).
2. `scripts/refresh-baseline.sh <project> ben-mode` → regenerate baseline manifest (hanya SETELAH edit terakhir).
3. `scripts/verify-hard-gate.sh <project>` → harus PASS.
4. `python scripts/status-matrix.py --root <project>` → `spec_version_consistent=true`, `negative_pass_consistent=true`, `last_gate_status=PASS`, predikat baru muncul.
5. Jalankan `scripts/test-hard-gate-negative.sh` + `selftest_<x>` untuk buktikan tak ada regresi.

Urutan bukti: sync → refresh baseline → verify → status-matrix. Skip salah satu = gate bisa PASS padahal quorum/versi tidak terbukti.
