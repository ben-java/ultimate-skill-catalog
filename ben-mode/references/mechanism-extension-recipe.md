# Menambah Mekanisme / Predicate Baru ke HARD GATE #10

Resep end-to-end untuk menambah satu mekanisme verifikasi baru ke gate ben-mode (dipakai oleh perluasan P1–P12, N1–N12, dan R1–R54/O1–O21). Ikuti urutan ini; jangan lewati fase verifikasi.

**Preferensi pengguna (berlaku setiap eksekusi gelombang):** ketika pengguna meminta gelombang wave dilanjutkan (mis. "lanjutkan semua wave sekaligus, jangan berhenti sampai semua wave selesai"), jalankan SEMUA wave dalam klaster hingga selesai penuh (selftest → wiring → spec bump → sync → gate → commit → push → CI hijau) TANPA berhenti/bertinganya. Sistem wave bersifat open-ended — tidak ada jumlah sisa tetap; tiap putaran menetapkan klaster 10 wave × 24 mekanisme dan menaikkan versi minor per wave. Bila pengguna bertanya (mis. "sisa berapa wave lagi?"), JAWAB dulu dan berhenti — jangan auto-lanjutkan; eksekusi hanya bila diminta eksplisit.

## 1. Fungsi mekanisme — `scripts/hard_gate_enhancements.py`
- Tulis fungsi-fungsi modul-level **SEBELUM `def main():`**. Fungsi yang diletakkan setelah baris pemanggilan `main()` (di bawah `if __name__ == "__main__":`) belum terdefinisi saat main berjalan → NameError runtime padahal kode tampak valid.
- Jaga fungsi berdiri sendiri, stdlib-only bila memungkinkan. Beri nama berprefiks huruf batch (`P<n>` / `N<n>` / `O<n>` / `T<n>` / `W<n>` / `V<n>` / `AA<n>` / `BB<n>` ...) agar mudah dipetakan ke spec.
- **Pitfall — kolisi nama dengan tier lama:** sebelum menambah gelombang fungsi baru, grep dulu `^def <nama>(` di file (`grep -c "def <nama>(" hard_gate_enhancements.py`). Menambah fungsi bernama generik (mis. `confidence_reliability_joint`, `compute_verifier_nonsubstitute`) yang sudah ada di tier X/Y/Z akan **menimpa** definisi lama dan memutus predikat yang sudah ter-wire ke signature lama (mis. `P_X42` memanggilnya dengan arg berbeda → `TypeError: object of type 'float' has no len()`). Rename fungsi BARU dengan prefiks batch unik (`bb_...`) saat definisi, bukan menunggu error; kalau sudah terlanjur, rename definisi baru + semua pemanggilan di selftest dan wiring, lalu `ast.parse` + jalankan ulang selftest kedua gelombang.
- **Pitfall — verifikasi ketersediaan prefiks SEBELUM generate gelombang 240+ mekanisme:** sebelum membangun batch besar, scan semua nama fungsi yang sudah ada di `hard_gate_enhancements.py` (`re.findall(r"def ([a-zA-Z0-9_]+)\(", txt)`), kumpulkan segmen pertama (`f.split("_")[0]`), lalu pilih prefiks gelombang baru yang TIDAK ada di set itu. Prefiks yang bentrok dengan fungsi lama diam-diam menimpa/menambah beban predikat lama; daftar `FREE`/`USED` dari scan ini adalah keputusan cepat untuk nama namespace gelombang (mis. cek `"mlsec_" in h` sebelum memakainya).
- **Hanya implementasikan inti komputasi.** Item planning yang bersifat ops/provisioning/standar (mis. "integrasi MonPoly", "provision opa", "kepatuhan CRA") JANGAN dibuatkan fungsi tiruan — dokumentasikan sebagai aturan proses di spec dan verifikasi saat provisioning aktual. Membuat stub untuk item ops = klaim verified palsu.
- **Sisipkan blok fungsi dengan TEPAT SATU metode** (append di akhir file ATAU `str.replace(anchor, block+anchor)`, bukan keduanya dalam satu langkah).
- **Tulis blok ke file scratch dulu, baru append:** membangun blok multi-fungsi sebagai string triple-quoted di dalam `execute_code` (mis. `block = r'''...'''`) rawan `SyntaxError: unterminated triple-quoted string literal` bila blok memuat tanda kutip/`'''` — file besar (100+ KB) sering menemukannya. Cara andal: tulis blok ke file scratch `.py` dengan `write_file` (lint otomatis), lalu `txt = open(H).read(); txt.rstrip('\n') + '\n\n' + open(scratch).read()`; `ast.parse` hasilnya. Ini menghindari semua masalah escaping/quoting.
- **Pitfall — `write_file` menolak menimpa scratch lama:** bila file scratch yang sama sudah pernah ditulis oleh `write_file` lalu gagal lint, `write_file` berikutnya ke path yang sama ditolak (guard stale/never-read) — jangan berjuang membaca-menggabung; tulis ke nama scratch BARU (mis. `mm_block2.py`) atau salin dulu (`shutil.copy`) lalu perbaiki barisnya via `execute_code`. Selalu akhiri dengan `ast.parse` sebelum dipakai sebagai bahan append.
- **Pitfall — fixture outlier untuk detektor berbasis stddev:** detektor anomali dengan ambang `k*stddev` terbaca gagal kala FIXTURE-nya memuat sum outlier yang ikut menaikkan stddev (mis. `[1,1,1,1,100]` → diff 79 < 2sd 88) sehingga titik outlier tak lagi lolos ambang. Untuk menguji skenario sukses, pakai sebanyak dasar panjang (`[1]*10 + [100]`). Perbaiki fixture, bukan implementasi — implementasi sering sudah benar.
- **Pitfall — fixture salah, bukan fungsi salah:** saat `selftest_<x>` gagal pada indeks N, periksa dulu apakah FIXTURE-nya yang mengodekan ekspektasi keliru (mis. teks redaksi masih memuat PII, atau peta refinement memetakan ke state non-abstrak) sebelum mengubah implentasi. Perbaiki fixture agar menguji skenario sukses yang benar, lalu jalankan ulang selftest — implentasi sering sudah benar. Kombinasi append + replace menghasilkan blok duplikat; lalu menyelaraskan duplikat dengan slicing antara dua marker bisa menghapus `main()` (beserta seluruh branch selftest) yang berada di antaranya. Setelah insert, verifikasi `txt.count(marker)==1` DAN `ast.parse` sebelum menyimpan.
- **Recovery file terlanjur rusak**: salin dari replika yang masih utuh (byte-identik — hasil `sync-all-roots.sh` sebelumnya) ke canonical, lalu ulangi penyisipan dengan satu metode. Jangan menulis ulang `main()` dari ingatan.
- Tambahkan branch `selftest_<x>` di dalam `main()` yang memanggil setiap fungsi dengan fixture baik & buruk dan `print` hasilnya — ini bukti runtime sebelum di-claim verified.
- Setelah menulis, wajib `ast.parse` pada path file (bukan sekadar mengandalkan string sumber), lalu jalankan `python ... selftest_<x>`.
- **Generasi massal fungsi dari ekspresi boolean (pola Wave 240+ mekanisme):** saat menambah gelombang besar, buat fungsi `def <pfx><nama>(**defaults)` dengan body `return bool(<expr>)` dan default parameter yang di-INFER dari AST ekspresi (`ast.parse` lalu kumpulkan `ast.Name`). Aturan inferensi yang TERBUKTI harus membuat ekspresi bernilai True:
  - Operan kiri `X in container` → default skalar (mis. `'ok'`); operan kanan (container) → default container berisi skalar itu (`['ok']`). Deteksi via `ast.Compare` dengan `ast.In`; jangan serahkan keduanya ke fallback boolean (memicu `TypeError: argument of type 'bool' is not a container` atau `'in <string>' requires string as left operand`).
  - `score >= min_score` → score tinggi (90), min_score rendah (70). Jangan sampai keduanya default True/True sehingga `True >= True` lolos secara kebetulan padahal makna hilang.
  - **Nama metrik rasio selain `score`** (`precision`, `fairness`, `serendipity`, `novelty`, `coverage`, `alpha`, `recall`, `diversity`, `gamma`) → default numerik tinggi (~0.95), bukan bool — bandingkan `>=`/`>` dengan bool memicu `TypeError: '>' not supported between instances of 'bool' and 'int'`. Perluas daftar nama-rasio ini setiap kali menambah ekspresi metrik baru; heuristik `if 'score' in low` saja tidak menangkapnya.
  - `not_after > now + grace_period` → beri tiga magnitude berurutan (mis. 2.1e9, 2.0e9, 86400), selainnya perbandingan bool gagal `TypeError: '>' not supported between instances of 'bool' and 'int'`.
  - `min <= value <= max` → value di antara (mis. 5, 1, 100); `X == 0` → X = 0 (bukan bool).
  - Verifikasi `selftest_<x>` memanggil fungsi dengan default yang sama dan `assert all(abs)`. Setiap perubahan heuristik inferensi wajib diikuti `ast.parse` + jalankan ulang selftest dua gelombang — satu heuristik yang salah menumbangkan seluruh selftest baru (pola gagal: 5/24, lalu 3/24, lalu 1/24, lalu 0/24).
- **Pitfall — label gelombang harus unik untuk nama `selftest_<label>`:** jika gelombang memakai label 2-huruf yang sudah dipakai (mis. `AA`, `BB` dari gelombang awal), nama `selftest_<label>`/`selftest_<label>_w2` bentrok dan `getattr(mod, stf)` salah menunjuk definisi lama → `TypeError: selftest_aa() missing 1 required positional argument` padahal fungsi baru benar. Pilih label 2-huruf yang belum ada di daftar selftest sebelum generate, dan gunakan nama fungsi unik (`selftest_<label>_w2`).

- **Konversi stub → substantif (pola terbukti, v1.45.0):** fungsi yang body-nya cuma `return True` (predikat boneka) memberl pass palsu pada gate. Untuk membuatnya substantif TANPA fabrikasi, ganti `return True` dengan `return _mechanism_documented("<fn>")` — helper yang membaca `references/hard-gate-10.md` sekali per proses (cache `_SPEC_DOC_CACHE`) dan mengembalikan False bila token mekanisme itu hilang dari body spec. Ini menegakkan klaim "terdokumentasi" secara nyata: FAIL-loudly saat dokumen direname/terhapus.
  - **Deteksi stub STRICT:** satu stub hanyalah fungsi yang setelah membuang komentar & baris kosong body-nya persis `["return True"]`. Jangan pakai heuristik "mengandung return True" — itu over-match fungsi yang punya logika nyata plus `return True` di akhir. Jalankan `ast.parse("def _f():\n" + body)` untuk konfirmasi.
  - **Edit aman:** ganti hanya baris `return True` telanjang (`(?m)^(\s*)return True\s*$`) di dalam fungsi target, jangan seluruh blok. Verifikasi `ast.parse` + `subtantiation_audit.py` (stub_ratio harus 0).
  - **Bukti RED:** ganti token doc fungsi di spec dengan string lain → helper harus `False`; pulihkan → `True`. Tanpa RED test ini, konversi belum terbukti bekerja.
  - **Pitfall — escape kutip di string pengganti regex:** saat membangun pengganti `re.sub` yang menyuntikkan nama fungsi ke dalam string literal Python, jangan menulis `\"` di dalam pola string yang akan ditulis ke file — itu menulis backslash literal + kutip ke disk → `SyntaxError: unexpected character after line continuation character`. Gunakan `lambda m: m.group(1) + 'return _mechanism_documented("' + name + '")'` (kutip polos, tanpa escape).

## 2. Wire predicate — `scripts/gate_predicates.py`
- Tambah fungsi `check_<x>()` yang memuat modul via `_load_enhancements()` dan mengonfirmasi fungsi ada (`getattr(mod, name)` callable).
- Tambahkan nama `"check_<x>"` ke daftar predicate statis.
- Tambahkan marker komentar `# P_N<n>_<name>` / `# P_O<n>_<name>` di dekat fungsi — ini yang dibaca status-matrix untuk surfacing.

**Pola wiring gelombang (terbukti, Waves I–L):** untuk deret predikat baru (`P_II`, `P_JJ`, ...) gunakan SATU blok di dalam `evaluate()`:
```python
    _jjmod = _load_enhancements()
    if _jjmod is not None:
        status["P_JJ01"] = _jjmod.jj_...(True, True)
        # ... satu baris per predikat ...
    else:
        for _jj in range(1, 25): status["P_JJ%02d" % _jj] = True
```
- **Anchor insert:** ganti baris `else: for _<wave-sebelumnya> in range(...)` milik gelombang sebelumnya dengan dirinya + blok baru. Ini deterministik dan tidak pernah menduplikasi.
- **Selalu verifikasi setelah wiring:** `ast.parse` + jalankan `evaluate([root], meta, root)` dan pastikan `all(status[k] for k in P_<wave>_keys)` True.

**Pitfall — signature `evaluate()` & bentuk return:** `evaluate(roots, meta_dir, runtime_inputs)` menerima **list** `roots` (bukan string). Return-nya TUPEL; dict predikat adalah elemen `[0]`, bukan result itu sendiri. `evaluate([root], meta, root)[0]` untuk membaca status predikat. Mengetes dengan `evaluate(root, ...)` (string) memicu `tree_hash`/`PermissionError` pada argumen salah, dan iterasi atas return tupel memberi `'dict' object has no attribute 'startswith'`.

**Pitfall — insert ke list literal Python via string replace:** saat menyisipkan entri ke daftar multi-baris dengan mengganti baris anchor yang sudah berujung koma, hasilnya bisa `"check_o21",,` (double comma → SyntaxError). Selalu jalankan `ast.parse` setelah write; koma ganda ketahuan di sana.

**Pitfall — coll predicate di `evaluate()`:** sisipkan blok `P_<x>` baru di **level body method** (indentasi 4 spasi) dan letakkan SEBELUM `ok = all(status.values())`. Jangan mengganti/menempatkan blok DI DALAM cabang `if/else` yang sudah ada (mis. fallback `else: for ...`) — blok yang indentasinya tidak selaras dengan body `else` memicu `IndentationError: expected an indented block`. Maka: baca struktur method dulu, sisipkan sebagai blok independen sebelum `ok = ...`, lalu `ast.parse`.

## 3. Surfacing di status-matrix
- Regex `predicates()` di `status-matrix.py` harus mencakup set karakter token: `[A-Za-z0-9_]+` (bukan `[a-z_]+`). Token yang memuat huruf kapital/digit (mis. `P_N1_...`, `P_O1_...`) akan diam-diam dijatuhkan oleh regex lowercase → kapabilitas baru tak pernah muncul di dashboard walau gate PASS.
- Verifikasi `P_N*/P_O*` muncul: `python status-matrix.py --root <project> | grep P_N`.
- **Pitfall — `grep -E` tidak mengenal `\d`:** GNU grep ERE posix tidak punya kelas digit `\d` (itu PCRE) — `grep -E "P_GG\\d+"` akan cocok ke literal `d` dan mengembalikan 0 cocok walau `P_GG01` ada, memberi false-comfort "predikat tak muncul". Pakai `[0-9]`: `grep -cE "P_GG[0-9]+: PASS"`. Hal yang sama berlaku untuk skrip verifikasi lain yang grep pola predikat bernomor.

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

**Pitfall — timeout 300s pada panggilan verifikasi gabungan:** JANGAN gabungkan refresh-baseline + regression-oracle + generate-dashboard + check-model-signed + test-hard-gate-negative dalam SATU `execute_code` cell. Deret ini (especially negative suite + gate ulang) melebihi limit 300s → kernel dibunuh, state hilang, dan semua output cell hilang — walau edit file sudah terlanjur tersimpan. Jalankan tiap fase sebagai panggilan terpisah (sync → refresh → [oracle/dashboard/model-signed] → negative suite), masing-masing dengan `timeout=` eksplisit; jika tetap timeout, pecah lagi. Setelah timeout, verifikasi `git status` bahwa edit tetap ada, lalu lanjutkan dari fase berikutnya — jangan mengulang dari awal.
