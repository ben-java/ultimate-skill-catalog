# Device Cleanup via ADB (Android phone/tablet storage)

Recipe membersihkan sampah storage HP Android dari host Windows via adb shell. Bukan pengganti hard-gate-10.md; hanya prosedur teknis. Berlaku untuk task class bersihkan HP.

## Prasyarat
1. Muat references/hard-gate-10.md (wajib tiap kali ben-mode aktif).
2. adb tersedia: cek command -v adb, lalu fallback path umum: ~/Downloads/platform-tools/platform-tools/adb, ~/AppData/Local/Android/Sdk/platform-tools/adb.exe.
3. Device terhubung dan authorized: adb devices -l harus state device (bukan unauthorized/offline). Kalau belum, minta user menghubungkan dan mengizinkan USB debugging — jangan hapus apa pun sebelum itu.
4. Identifikasi model: adb shell getprop ro.product.vendor.model dan ro.product.device (contoh POCO F3 = alioth / M2012K11AG).
5. Test hak tulis sebelum eksekusi: adb shell touch /sdcard/rmtest lalu rm, dan uji yang sama di Android/data/<pkg>/cache (grup ext_data_rw membuatnya mungkin di Android 11+).

## Alur eksekusi
1. Snapshot: adb shell df -h /sdcard, simpan sebagai df_before.txt.
2. Inventarisasi per top-level (JANGAN find /sdcard sekali jalan — sering kembali 0 baris):
   - adb shell ls /sdcard (daftar entry)
   - adb shell du -sm /sdcard/* (ukuran per entry)
   - adb shell ls -laSh /sdcard/<dir> (file terbesar)
   - adb shell du -sk /sdcard/Android/data/* (ukuran per paket)
3. Klasifikasi (tarik inventory size|path per entry via execute_code untuk analisis duplikat/ekstensi):
   - Auto-delete (sampah teknis, regenerable): .thumbnails, cache Glide Pictures/.gs*, direktori cache/ app, .tmp/.partial/.crdownload, log debug MIUI/BugReportCache dan debug_log, media auto-download app (contoh Movies/Twitter), partial downloader (1DMP/.adblocker_1dm), file hash-acak tanpa judul, APK installer yang sudah ter-install.
   - Konfirmasi user dulu (konten pribadi): video/film berjudul, APK mod terunduh yang belum ter-install, game data Android/data/<game>, dokumen/ebook.
   - Jangan sentuh: proteksi setara .dsh, VM images, OS-managed files.
4. Delete berfase: Fase 1 sampah teknis, Fase 2 sampah media. Untuk setiap target: du -sk dulu, rm -rf, lalu verifikasi [ -e ] menjadi GONE/EXISTS. Rekap total via awk (bukan bc).
5. Verifikasi sesudah: df -h /sdcard harus menunjukkan reclaim nyata; re-inventarisasi per top-level untuk statistik akhir.
6. Audit: tulis cleanup_audit.json di project folder user berisi serial/model, timestamp UTC, honesty_flag, storage before/after, GB reclaimed per fase, daftar kategori yang sengaja TIDAK dihapus beserta alasan.

## Pitfall terverifikasi
- bc tidak ada di Git-Bash/MSYS dan sort -h tidak ada di toybox Android — arithmetic pakai awk, sort pakai sort -rn.
- find /sdcard -type f -printf bisa output 0 baris; chunk per entry dan redirect ke file lokal.
- Cache app di Android/data/<pkg>/cache sering ~0 MB (cache pindah ke /data); ukur files/ (contoh gallery_disk_cache, unduhan app) untuk dapat GB nyata.
- Cek installer APK terhadap pm list packages sebelum hapus — APK yang package-nya belum ter-install adalah installer aktif, bukan sampah.
- Nama file dengan spasi/kutip: selalu quote di adb shell rm -rf; loop baca dari adb shell ls perlu tr -d CR (adb output CRLF).
- Setelah hapus direktori besar, media scanner Android bisa tampak lag — beri jeda; tidak perlu restart HP.
