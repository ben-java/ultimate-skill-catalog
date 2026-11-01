# Browser Context Automation — Metode 1 (CDP / Playwright)

Referensi eksekusi Metode 1 yang digunakan saat pengguna meminta akses browser penuh ke akun Threads (atau layanan serupa) melalui sesi browser yang sudah diautentikasi secara manual oleh pengguna.

## Kapan digunakan
Saat trigger `ben` atau `ben-mode` memicu eksekusi yang melibatkan akses browser otomatis (mis. `agentbrowser`, akses Threads/Instagram melalui profil browser lokal). Tidak menggantikan `hard-gate-10.md`; hanya pelengkap teknis.

## Prosedur (urutan wajib)

1. **Muat `references/hard-gate-10.md`** sebelum menyentuh apa pun.
2. **Verifikasi lingkungan secara fisik** (tidak asumsi):
   - Periksa executable browser (`msedge.exe`, `chrome.exe`, `firefox.exe`, `Helium.exe`) di path standar dan alternatif (`AppData`, per-user, portable).
   - Periksa direktori profil/user data (`User Data`, `Profiles`).
   - Periksa apakah proses browser sedang berjalan (`tasklist`).
   - Periksa apakah `playwright` (atau `websocket-client` untuk CDP mentah) dapat di-import.
3. **Buat artefak script** (`method1_cdp_script_*.py`) — lihat bagian CDP di bawah.
4. **Eksekusi pembukaan browser** menggunakan `subprocess.Popen` (tidak blocking) dengan PID tercatat.
5. **Buat audit JSON** (`audit-*.json`) dengan `execution_timestamp`, `*_found`, `connection_ok`, `action`, `honesty_flag`, `integrity_notes`.
6. **Verifikasi port CDP** (`curl http://localhost:9222/json/version`) SEBELUM klaim koneksi.
7. **Jika lingkungan tidak siap**: laporkan jujur; jangan klaim akses berhasil.

## Aturan CDP pada browser dengan sesi login (yang sudah terverifikasi)

### 1. Remote debugging DITOLAK pada direktori profil DEFAULT
Chromium/Edge menolak `--remote-debugging-port` bila `--user-data-dir` menunjuk direktori profil default (mis. `AppData\Local\Microsoft\Edge\User Data`). stderr-nya eksplisit:
```
DevTools remote debugging requires a non-default data directory. Specify this using --user-data-dir.
```
Jadi jalur `User Data` tidak akan pernah membuka port 9222. Solusi: **salin profil ke direktori non-default** lalu launch di situ:
```bash
# salin Local State + folder profil (mis. Default) ke direktori baru
cp "<User Data>/Local State" "<DST>/Local State"
robocopy "<User Data>/Default" "<DST>/Default" /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NC /NS /NP
```
Lalu launch: `msedge.exe --remote-debugging-port=9222 --remote-allow-origins=* --user-data-dir="<DST>"`.

### 2. Websocket CDP ditolak kecuali `--remote-allow-origins`
Handshake websocket ke `webSocketDebuggerUrl` gagal 403 dengan: _"Rejected an incoming WebSocket connection from the http://localhost:9222 origin"_. Tambahkan `--remote-allow-origins=*` (atau origin eksplisit) pada baris launch.

### 3. Launch ke profil yang sedang dipakai = "attach", flag diabaikan
Memanggil `msedge.exe --user-data-dir=<profil aktif>` saat instance profil itu sudah berjalan hanya meneruskan ke sesi ada (output: _"Opening in existing browser session."_) — semua flag debug diabaikan, port tidak terbuka. **Bunuh SEMUA instance dulu.** Di Windows, `taskkill //F //IM msedge.exe` bisa diam-diam tidak menurunkan jumlah proses; `powershell -NoProfile -Command "Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force"` terbukti andal. Verifikasi `tasklist | grep -ci msedge` = 0 sebelum launch ulang.

### 4. Profil tersalin TIDAK otomatis membawa sesi login server
Menyalin `Default` + `Local State` mempertahankan data lokal, tetapi **tidak menjamin sesi login server (mis. Threads) ikut terbawa** — cookies sesi bisa tidak valid/terikat. Setelah koneksi, deteksi login-wall di DOM (mis. teks "Log in to see more"); jika muncul, minta pengguna login sekali di profil CDP baru itu, lalu rerun ekstraksi. Jangan mengklaim akses repost sebelum login terkonfirmasi.

### 5. Klien CDP alternatif (tanpa playwright)
Jika `playwright` tidak terpasang, pakai `websocket-client` (`pip install websocket-client`) + endpoint HTTP `/json/list`:
```python
import json, urllib.request, websocket, time
pages = [t for t in json.load(urllib.request.urlopen("http://localhost:9222/json/list")) if t.get("type")=="page"]
ws = websocket.create_connection(pages[0]["webSocketDebuggerUrl"], timeout=45)
# kirim {"id":N,"method":...}; jawab dengan id yang sama
# Page.navigate -> tunggu 10-14s (SPA) -> Runtime.evaluate (returnByValue=True)
```
Gunakan `Runtime.evaluate` dengan `returnByValue: true` dan ekspresi yang mengembalikan `JSON.stringify({url, title, loginWall, articles, pressables, sample})` untuk bukti jujur.

## Mengekstrak konten yang dirender via animasi/ketik (SPA generated output)
Beberapa situs tool (mis. generator prompt client-side) menampilkan hasil dengan efek mengetik: teks bertambah karakter demi karakter dan **berhenti di tengah** saat dibaca cepat. `innerText`/`textContent` hanya mengembalikan prefiks terketik — membaca ulang tidak akan pernah memberi teks penuh, dan polling panjang (mis. 10–60s) juga bisa macet di panjang parsial.

Solusi andal: **tidak membaca DOM**, melainkan menangkap string yang disalin. Tombol "Copy" pada tool semacam itu menyalin teks penuh via Clipboard API:
```javascript
// Patch handler sebelum klik tombol Copy
(() => {
  const orig = navigator.clipboard.writeText.bind(navigator.clipboard);
  window.__copied = null;
  navigator.clipboard.writeText = async function(t){ window.__copied = t; return orig(t); };
})()
// lalu klik tombol Copy, dan baca window.__copied
```
Catatan: `navigator.clipboard.readText()` gagal dengan `NotAllowedError: Document is not focused` di sesi browser yang tidak fokus — jangan pakai readText; pakai patch writeText di atas (tidak butuh fokus).

Jika konten yang disalin masih terpotong di panjang sama, periksa apakah hasilnya memang satu template dengan blok `PERSYARATAN SPESIALIS`/role yang berubah per tool, bukan 888 prompt unik — verifikasi nyata jumlah template inti sebelum melaporkan jumlah "tool".

## Integritas (wajib untuk setiap eksekusi)
- **Tidak ada klaim akses berhasil tanpa audit file fisik** (`audit-*.json` dengan `honesty_flag`).
- **Tidak ada injeksi kredensial otomatis** — pengguna memasukkan username dan password secara manual. Ini batas integritas untuk akses akun sosial.
- **Tidak menyembunyikan kegagalan lingkungan** — laporkan jelas, berikan perintah perbaikan.
- **Audit log disimpan di luar pohon verifikasi** (mis. `C:\Users\AMMAR\Hermes Agents\threads-method1-cdp\`) agar tidak merusak hash replika.

## Pitfall utama
- **Jangan menyatakan "tidak bisa dieksekusi" tanpa memeriksa terlebih dahulu** (`os.path.isfile`, `subprocess.run`, `tasklist`, `import`).
- **Jangan mengasumsikan path browser** — periksa beberapa kandidat.
- **Jangan menulis `echo "PASS"` tanpa `echo:;` yang eksplisit** — di bash Windows/MSYS, output kosong/format salah bisa disalahartikan parser audit.
- **Jangan menjalankan `bash` telanjang** dari Python di Windows — pakai `sys.executable` / `C:\Program Files\Git\bin\bash.exe`.
- **Verifikasi port (`curl /json/version`) sebelum koneksi** — jika kosong, jangan lanjut ke ekstraksi.

## Perintah referensi cepat
```python
import os, subprocess
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
# Bunuh semua instance sebelum launch
subprocess.run(["powershell","-NoProfile","-Command",
  "Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force"])
# Launch profil NON-DEFAULT dengan CDP
subprocess.Popen([EDGE, "--remote-debugging-port=9222", "--remote-allow-origins=*",
                  f"--user-data-dir={NON_DEFAULT_PROFILE}", "--no-first-run", "about:blank"],
                 creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
# Verifikasi sebelum ekstraksi
# curl -s http://localhost:9222/json/version
```
