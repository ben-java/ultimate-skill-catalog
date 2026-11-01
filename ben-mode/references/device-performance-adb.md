# Device Performance & Battery Tuning via ADB (Android)

Recipe mengukur dan men-tuning performa/baterai HP Android dari host Windows via adb shell, berbasis bukti: baseline read-only dulu, ubah berfase, verifikasi read-back. Bukan pengganti hard-gate-10.md; hanya prosedur teknis untuk task class "optimasi HP".

## Urutan wajib
1. **Baseline read-only dulu** — jangan ubah apa pun sebelum angka ada; rencana tanpa baseline adalah karangan.
2. **Bedakan 3 penyebab**: (a) software/background load, (b) degradasi baterai fisik, (c) thermal throttling. Kalau (b), tuning software sia-sia → rekomendasi ganti baterai, bukan patch software.
3. **Ubah berfase & reversible**; setiap fase dilaporkan sebelum/sesudah dengan nilai konkret.
4. **Terapkan persis nilai yang user minta**; kalau user menyebut angka target, jangan substitusi dengan angka "rekomendasi" sendiri.

## Baseline probe (read-only, satu blok execute_code)
```
dumpsys battery                    # level, temperature, voltage, health code
dumpsys batterystats | grep -i capacity   # "Estimated battery capacity" vs design spec
dumpsys power | grep -i "Wake Locks" -A3
dumpsys alarm | grep -oE 'u0a[0-9]+' | sort | uniq -c | sort -rn | head
dumpsys jobscheduler | grep -E 'SyncManagerJob|periodMillis' | head
dumpsys deviceidle | head -30
dumpsys cpuinfo | head -12
dumpsys meminfo | grep -E 'Total RAM|Free RAM|Used RAM|ZRAM'
dumpsys activity activities | grep -E 'mResumedActivity' | head -3
settings list system | grep -i refresh ; settings list secure | grep -i refresh
pm list packages | wc -l
for z in /sys/class/thermal/thermal_zone*/temp; do echo -n "$z "; cat $z; done | sort -k2 -rn | head
```
Interpretasi:
- **Baterai sehat?** `health: 2` = good (status, bukan kapasitas). Kapasitas efektif = `Estimated battery capacity` di batterystats; cross-check `charge_counter / (level/100)`. Bandingkan dengan design spec model (POCO F3 = 4520 mAh). >90% retained = baterai masih baik.
- **Tekanan RAM?** Used RAM tinggi + `ZRAM: ... physical used for ... in swap` besar = app sering di-kill lmk → terasa lemot walau RAM besar. Solusi: kurangi package/bloatware, BUKAN restrict background lebih agresif.
- **Alarm berulang?** Pola `+tmpwhitelist=...:<pkg>.ALARM` berulang di batterystats = app bangun device periodik; kandidat restrict.
- **Thermal?** Zone >45-50 °C saat charging wajar; throttle saat dipakai berat.

## Tuning reversible (perubahan settings)
```
# animasi (nilai 0 = mati total, 0.5 = cepat, 1.0 = default)
settings put global window_animation_scale <v>
settings put global transition_animation_scale <v>
settings put global animator_duration_scale <v>
# hemat wake radio
settings put global wifi_scan_always_enabled 0
settings put global ble_scan_always_enabled 0
# background per-app (kandidat dari baseline, bukan blanket)
cmd appops set <pkg> RUN_IN_BACKGROUND ignore
cmd appops set <pkg> RUN_ANY_IN_BACKGROUND ignore
am set-standby-bucket <pkg> restricted
# bloatware aman (bukan uninstall; bisa di-enable lagi)
pm disable-user <pkg>
```

## Verifikasi & rollback
- Setiap `settings put` WAJIB dibaca balik: `settings get global <key>` harus sama dengan target; laporkan PASS/FAIL per key.
- Catat nilai before untuk setiap key dan sertakan baris rollback di laporan.
- Sanity pasca-ubah: `adb devices` masih terhubung, WiFi/koneksi utama tidak mati.

## Pitfall terverifikasi
- **Cek nilai SAAT INI sebelum apply "quick win"** — setting yang sudah non-default bisa jadi pilihan sengaja user; kalau sudah optimal, laporkan sebagai no-op, jangan timpa. Quick win yang direncanakan dari spek bisa jadi basi saat dieksekusi.
- **Refresh rate di MIUI**: `peak_refresh_rate`/`min_refresh_rate` gaya AOSP sering `null`; kunci nyata `user_refresh_rate` di `system`/`secure`. Selalu grep `settings list ... | grep -i refresh`, jangan tebak nama key.
- **Kapasitas baterai via sysfs** (`/sys/class/power_supply/bms/charge_full_design`) sering N/A tanpa root; pakai batterystats + charge_counter.
- **Jangan blanket-restrict background di MIUI** — lmk sudah agresif; restrict berlebih membuat notifikasi chat/e-wallet telat. Restrict hanya app yang baseline tunjukkan leaky.
- **Akun Google ganda**: SyncManagerJob periodik berlipat per akun; hapus akun butuh keputusan + login ulang user, jangan dieksekusi sepihak.
- `sort -h` tidak ada di toybox Android dan `bc` tidak ada di MSYS — pakai `sort -rn` + `awk`.
- Kunci `settings` global vs system vs secure berbeda namespace; cek di namespace yang benar sebelum menyimpulkan "belum di-set".
