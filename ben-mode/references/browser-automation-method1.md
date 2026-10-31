# Browser Context Automation — Metode 1 (CDP / Playwright)

Referensi eksekusi Metode 1 yang digunakan saat pengguna meminta akses browser penuh ke akun Threads (atau layanan serupa) melalui sesi browser yang sudah diautentikasi secara manual oleh pengguna.

## Kapan digunakan
Saat trigger `ben` atau `ben-mode` memicu eksekusi yang melibatkan akses browser otomatis (mis. `agentbrowser`, akses Threads/Instagram melalui profil browser lokal). Tidak menggantikan `hard-gate-10.md`; hanya pelengkap teknis.

## Prosedur (urutan wajib)

1. **Muat `references/hard-gate-10.md`** sebelum menyentuh apa pun.
2. **Verifikasi lingkungan secara fisik** (tidak asumsi):
   - Periksa executable browser (`Helium.exe`, `chrome.exe`, `msedge.exe`, `firefox.exe`) di path standar dan alternatif (`AppData`, per-user, portable).
   - Periksa direktori profil/user data (`User Data`, `Profiles`).
   - Periksa apakah proses browser sedang berjalan (`tasklist`).
   - Periksa apakah `playwright` dapat di-import (`python -c "import playwright"` atau `pip list`).
3. **Buat artefak script** (`method1_cdp_script_*.py`) dengan:
   - Definisi `HELIUM_BIN`, `PROFILE_DIR`, `DEBUG_PORT`.
   - Perintah peluncuran: `"<BIN>" --remote-debugging-port=9222 --user-data-dir="<PROFILE>" --start-maximized <URL>`
   - Koneksi `playwright.connect_over_cdp("http://localhost:9222")`.
   - Catatan eksplisit: **tidak memasukkan username/password secara otomatis**; pengguna memasukkannya manual.
4. **Eksekusi pembukaan browser** menggunakan `subprocess.Popen` (tidak blocking) dengan PID tercatat.
5. **Buat audit JSON** (`audit-*.json`) dengan:
   - `execution_timestamp`
   - Status eksistensi executable (`*_found`)
   - Status Playwright (`playwright_available`)
   - `action` (perintah yang dijalankan)
   - `honesty_flag`: eksplisit menyatakan tidak ada akses berhasil dieksekusi oleh agen, hanya pembukaan browser.
   - `integrity_notes`: ringkasan bahwa pengguna akan memasukkan kredensial manual.
6. **Verifikasi proses** (`tasklist /FI "PID eq <PID>"`) untuk membuktikan browser benar-benar berjalan.
7. **Jika lingkungan tidak siap** (missing executable, missing Playwright): laporkan jujur, berikan perintah perbaikan (`pip install playwright`), dan **jangan klaim akses berhasil**.

## Konfigurasi per browser (contoh dari verifikasi nyata)

- **Edge (`msedge.exe`)** — terbukti ada di `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`; proses dapat diluncurkan; profil default di `AppData\Local\Microsoft\Edge\User Data`.
- **Chrome (`chrome.exe`)** — proses `chrome.exe` dapat berjalan meskipun file `.exe` tidak berada di `Program Files` (kemungkinan instalasi per-user/portable); periksa dengan `where chrome /r` atau `dir /s`.
- **Helium (`Helium.exe`)** — tidak tersedia dalam verifikasi ini (`C:\Program Files\Helium`, `AppData`); jika pengguna mengklaim sudah login di Helium, berarti Helium berjalan di host/machine lain atau profil berbeda; sesuaikan `HELIUM_BIN` dan `PROFILE_DIR` secara eksplisit.
- **Firefox** — tidak ditemukan dalam verifikasi ini.

## Integritas (wajib untuk setiap eksekusi)
- **Tidak ada klaim akses berhasil tanpa audit file fisik** (`audit-*.json` dengan `honesty_flag`).
- **Tidak ada injeksi kredensial otomatis** — pengguna memasukkan username dan password secara manual. Ini bukan sekadar preferensi; ini adalah batas integritas untuk akses akun sosial.
- **Tidak menyembunyikan kegagalan lingkungan** — jika `playwright` belum terinstal atau executable tidak ditemukan, laporkan dengan jelas dan berikan perintah perbaikan (`pip install playwright && playwright install chromium`).
- **Audit log disimpan di luar pohon verifikasi** (misalnya `C:\Users\AMMAR\Hermes Agents\threads-method1-cdp\`) agar tidak merusak hash replika.

## Pitfall utama
- **Jangan menyatakan "tidak bisa dieksekusi" tanpa memeriksa terlebih dahulu** (`os.path.isfile`, `subprocess.run`, `tasklist`, `import playwright`). Klaim infeasible yang tidak diperiksa akan mengunci pekerjaan secara permanen (`hard-gate-10.md` §Pitfalls).
- **Jangan mengasumsikan path browser** — selalu periksa beberapa kandidat sebelum menyimpulkan browser tidak tersedia.
- **Jangan menulis `echo "PASS"` tanpa `echo:;` yang eksplisit** — dalam konteks bash di Windows/MSYS, output kosong atau format salah dapat disalahartikan sebagai kegagalan oleh parser audit.
- **Jangan menjalankan `bash` telanjang** dari Python di Windows — gunakan `sys.executable` untuk Python dan `C:\Program Files\Git\bin\bash.exe` secara eksplisit untuk bash.

## Perintah referensi cepat
```python
# Verifikasi executable
os.path.isfile(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")

# Verifikasi Playwright
import importlib.util
spec = importlib.util.find_spec("playwright")

# Peluncuran browser dengan remote debugging (tidak blocking)
subprocess.Popen([EDGE_BIN, "--remote-debugging-port=9222",
                  "--start-maximized", "https://www.threads.net/"])

# Koneksi Playwright (setelah browser terbuka)
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    browser = p.chromium.connect_over_cdp("http://localhost:9222")
    contexts = browser.contexts  # mempertahankan sesi login pengguna
```