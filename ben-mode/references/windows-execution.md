# Menjalankan toolchain HARD GATE #10 di Windows / Git-Bash

Resep terverifikasi untuk menjalankan script gate/verifier di host Windows dengan bash (Git-Bash/MSYS). Semua aturan di bawah muncul dari kegagalan nyata saat eksekusi P0–P2.

## 1. Konversi path native untuk eksekutabel native (PITFALL UTAMA)

MSYS auto-conversion argumen `/c/...` ke path Windows TIDAK konsisten antar-shell: kadang jadi `C:\Users\...` (benar), kadang jadi `C:\c\Users\...` (prefix drive + komponen `c` dipertahankan) → python/pip/opa gagal membuka berkas dan gate melaporkan FAIL **palsu** (manifest).

Aturan:
- Definisikan sekali: `SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"`.
- Panggil python selalu dengan `"$SCRIPT_W/script.py"` — jangan `"$SCRIPT_DIR/script.py"`.
- Argumen berkas lain (requirements.txt, input JSON OPA, root/replica) juga lewati `cygpath -w`:
  - `--root "$(cygpath -w "$ROOT")"`
  - `pip install -r "$(cygpath -w "$SCRIPT_DIR/requirements.txt")"`
- Catatan: `write_file`/`execute_code`-python juga menolak overwrite setelah `read_file` terpaginasi — gunakan `execute_code` dengan `open(path,'w')` untuk overwrite penuh file yang pernah dibaca parsial.

## 2. Pembuatan & deteksi junction Windows

- `cmd //c mklink /J` dari Git-Bash sering membuka cmd interaktif (banner Microsoft Windows) tanpa mengeksekusi. Pakai PowerShell:
  ```bash
  L=$(cygpath -w "$TMP/link"); T=$(cygpath -w "$TMP/target")
  powershell -NoProfile -Command "New-Item -ItemType Junction -Path '$L' -Target '$T' | Out-Null"
  ```
- `os.path.islink` mengembalikan **False** untuk junction. Deteksi reparse point:
  ```python
  import ctypes
  def is_reparse(p):
      a = ctypes.windll.kernel32.GetFileAttributesW(p)
      return bool(a != -1 and (a & 0x400))
  ```
  Gunakan di `count_symlinks` bersama `os.path.islink`. `os.walk(root, followlinks=False)` tetap mencantumkan dir junction di `dn` sehingga terhitung.
- Negative test yang tidak bisa membangun fixture junction/symlink harus **FAIL (exit 1)**, bukan skip diam-diam.

## 3. OPA (Rego) enforcement opsional

- Download pin (`opa_windows_amd64.exe`) dari GitHub releases ke `tools/opa/opa.exe`; nonaktif bila offline (checker menampilkan SKIPPED).
- `opa eval --input <X>` memperlakukan `<X>` sebagai **path berkas**, bukan JSON inline — tulis input ke tempfile dulu.
- Rego v1: builtin `time.parse_rfc3339_ns` (bukan `time.parse_rfc3339`); bandingkan dengan `time.now_ns()`.
- Pastikan `--data` policy path native (lihat §1).

## 4. generate_manifest.py

- `--baseline` **return** setelah menulis signature, sehingga `--out` diabaikan bila keduanya diberikan. Untuk menghasilkan baseline + manifest JSON lengkap, panggil dua kali:
  ```bash
  python generate_manifest.py "$SK" --baseline "$SIG"
  python generate_manifest.py "$SK" --out "$MAN"
  ```
- Signature baseline = deterministik, CRLF-normalized, dan harus disimpan DI LUAR pohon skill (`.hard-gate-meta/`).

## 5. Konstrain schema untuk fixture test

- Verifier mensyaratkan `name:` di frontmatter == basename folder skill. Fixture uji yang membandingkan dua pohon harus memakai folder bernama sama dengan skill-nya (mis. `a/skill` vs `b/skill`), bukan `a` vs `b` — kalau tidak, schema FAIL walaupun isi identik.

## 6. Urutan aman setelah edit skill

1. Sinkronkan seluruh replika fisik (`cp -r` dari canonical; verifikasi md5 identik).
2. Regenerate baseline (refresh-baseline.sh).
3. Verifikasi gate — cek `GATE_EXIT` dari script, bukan dari `echo $?` setelah pipe `tail` (tail menutupi exit code).
