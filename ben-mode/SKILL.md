---
name: ben-mode
version: 0.25.0
description: "Ben-mode integrity and routing workflow; trigger: ben or ben-mode. WAJIB muat references/hard-gate-10.md via skill_view setiap kali skill terpicu."
---
# Ben Mode (Token-First & Integrity Spine)

> **⚠️ WAJIB SEBELUM EKSEKUSI** — Muat dulu `references/hard-gate-10.md` via `skill_view(name="dsh-imported\ben-mode", file_path="references/hard-gate-10.md")`. Dokumen itu memuat spesifikasi HARD GATE #10 yang mengikat tiap eksekusi; jangan lewati, jangan jalankan mode apa pun tanpa membacanya lebih dulu.

Skill ini mewajibkan agen menerapkan efisiensi token secara otomatis dan berkelanjutan (first-principle) tanpa menunggu instruksi manual per-subskill:

## 1. Otomasi Efisiensi Token (Phase B - Token-First Enforced)
Agen wajib menerapkan aturan efisiensi berikut secara instan dan otomatis:
- **`ponytail` Otomatis**: Aktif pada SEMUA tugas coding, skrip, dan modifikasi konfigurasi. Terapkan prinsip YAGNI ekstrem, gunakan library standar/fitur bawaan platform, diff kode sesingkat mungkin, tolak abstraksi/boilerplate tak diminta.
- **`caveman` Otomatis**: Bahasa tanggapan padat dan langsung ke poin teknis (*fluff gone, facts kept*). Hapus basa-basi pembuka/penutup, ceremony, kata pengisi (*just/basically/actually*). Jawab langsung inti solusi teknis.
- **`code-mode-runtime` Otomatis**: Untuk alur kerja yang melibatkan 3+ pemanggilan tool berturut-turut atau perulangan/filtering data, wajib alihkan dari pemanggilan tool JSON serial ke eksekusi satu blok program terisolasi (TypeScript/Python via `execute_code`). Mereduksi token 75–98% dan merekam jejak audit ke repositori trajektori git lokal.
- **`RTK` / Output Compression**: Wajib gunakan binary `rtk` (~/bin/rtk-bin/rtk.exe) atau filter baris saat memanggil CLI command yang menghasilkan output besar (git status, log, diff, directory listing) agar terminal output tidak membanjiri konteks.
- **Web research**: Untuk riset multi-sudut, route ke `parallel-web` bila tersedia; gunakan `web_search`/`web_extract` dalam batch terbatas bila tidak. Pilih `research-lookup` untuk paket bukti akademik dan `last30days` untuk diskusi publik terbaru. Sintesis dengan sumber dan perbedaan temuan; laporkan jumlah URL berhasil, gagal, dan tidak diambil. Jangan duplikasi skill riset yang ada atau mengasumsikan tool khusus OpenCode.
  - Jangan anggap klaim upstream tentang 100 URL paralel sebagai jaminan: skill sumber menginstruksikan 10–20 fetch paralel, tanpa uji/kontrak batas konkuren.
- **Dokumen & Konteks**:
  - Teks panjang/log/wiki: kompresi via `llm-text-compressor` dan `context-compressor` (interseptor output CLI/JSON/stack-trace).
  - Dokumen <10 hal: `docling` / stdlib regex.
  - Dokumen >10 hal / tabel kompleks: `mineru`.
  - Codebase: Graphify per-repo knowledge graph atau codebase-memory-mcp traversal; hindari recursive grep besar.

## 2. Router & Integritas (Phase A - Integrity Spine & Functional Routing)
- **4 Layer Integritas**:
  1. Artifact honesty (Purpose test, R-17 sampai R-38).
  2. Evidence (Proof over flags, disclosure kewajiban mutlak, zero unverified claims).
  3. Process inspectability (Konfigurasi deterministik, anti black-box, fail-loudly).
  4. Settled truth (Settlement ladder: run execution over plausibility).

### Matriks Routing Fungsional (300+ Skills Terpetakan):
Routing tugas secara deterministik ke kluster fungsional yang tepat, cegah pemborosan token dan platform mismatch:

1. **Token-First & Integrity Spine** (Otomasi, Audit, Tata Kelola):
   - `ben-mode` (formerly `ultimate-combined`; trigger phrase: `ben`), `ultimate-skill`, `ultimate-skills`, `delivery-gate`, `evidence-settlement`, `memory-fallback-routing`, `skill-routing-v3.7`, `ultimate-skill-verification`, `pstack-verify`, `context-compressor`, `code-mode-runtime`, `ponytail`, `caveman`, `antislop`, `anti-slop`, `no-ai-slop`, `skill-routing-v3-7`, `model-routing`.
2. **Autonomous AI Agents & Multi-Agent Orchestration**:
   - `hermes-agent`, `claude-code`, `codex`, `opencode`, `computer-use`, `agentbrowser`, `sandbase-harness`, `nanobot`, `strix`, `webbrain`, `task-observer`, `agent-reach`, `pinchtab-browser`, `pi-bolt`.
3. **Software Development, Testing & Systems Engineering**:
   - `codebase-inspection`, `dogfood`, `evidence-based-script-review`, `github`, `hermes-agent-skill-authoring`, `inspecting-hermes-desktop-dom`, `integration-trigger-verification`, `node-inspect-debugger`, `requesting-code-review`, `simplify-code`, `spike`, `systematic-debugging`, `test-driven-development`, `third-party-ruleset-adoption`, `windows-config-repair`, `sdlc-review`, `architecture-decision-records`, `superpowers`, `agent-skills`, `agent-experience`, `plannotator`, `cordis-plugin-development`, `cordis-composition-reference`, `editing-cordis-compositions`, `engineer-skills`, `dirsearch`, `tldr`.
4. **Knowledge Graph, Codebase Intelligence & Memory**:
   - `graphify` (AST structural + semantic knowledge graphs), `codebase-memory` (graph traversal & symbols), `obsidian` / `dsh-imported/obsidian-mind`, `llm-wiki`, `open-notebook`.
5. **Productivity, Office Deliverables & Workspace**:
   - `airtable`, `box`, `document-compliance-audit`, `document-to-action-items`, `docx`, `google-workspace`, `maps`, `meeting-action-items`, `notion`, `pdf`, `powerpoint`, `ppt-master` (otoritas utama deck presentasi visual), `product-price-monitor`, `report-documents-from-source-notes`, `weekly-review-planning`, `xlsx`, `document-format-replication`, `himalaya`, `email-inbox-triage`, `workspace-cleanup`.
6. **Document Processing, OCR & Context Compression**:
   - `mineru` (PDF >10 hal, layout/tabel kompleks), `docling` (dokumen ringan/konversi), `convert-documents-to-markdown`, `llm-text-compressor`, `context-compressor`, `post-extract`, `reel-transcript`, `social-video-transcript`.
7. **Creative Design, UI/UX & Media**:
   - `design-master` (otoritas utama UI/UX terpadu), `design-md`, `design-taste-skill`, `design-ui-ux-pro-max`, `design-hallmark`, `design-impeccable`, `claude-design`, `popular-web-designs`, `architecture-diagram`, `diagram-design`, `infographics`, `baoyu-infographic`, `scientific-schematics`, `oil-ui`, `ryux`, `ascii-video`, `manim-video`, `p5js`, `songwriting-and-ai-music`, `gif-search`, `songsee`, `youtube-content`, `earshot-evidence`, `design-uiux-canon`.
8. **Research, Academic Intelligence & Scientific Literature**:
   - `arxiv`, `competitor-news-monitor`, `grounded-citations`, `literature-review`, `literature-search`, `paper-lookup`, `paperclip`, `paperzilla`, `research-lookup`, `scholar-evaluation`, `scientific-brainstorming`, `scientific-critical-thinking`, `scientific-writing`, `last30days`.
9. **Academic Deliverables, Practicum & Education**:
   - `laporan-praktikum`, `practicum-audit`, `eli5`, `bantulokal-website`, `repo-link-via-ultimate-skill`.
10. **Scientific Computing & Domain-Specific Packages (200+ Imported Modules)**:
    - *Bioinformatika & Genomik*: `biopython`, `scanpy`, `anndata`, `scvelo`, `scvi-tools`, `bulk-rnaseq`, `pysam`, `primer-design`, `pathway-enrichment`.
    - *Kimia Komputasi & Farmasi*: `rdkit`, `chemistry-rdkit`, `datamol`, `deepchem`, `diffdock`, `medchem`, `molfeat`, `pyopenms`.
    - *Kuantum & Fisika*: `qiskit`, `cirq`, `pennylane`, `qutip`, `astropy`, `cantera`, `fluidsim`.
    - *Matematika, Graf & Pemodelan Data*: `networkx`, `torch-geometric`, `transformers`, `pytorch-lightning`, `scikit-learn`, `polars`, `dask`, `vaex`, `sympy`, `pymc`, `statsmodels`.

## 3. Verifikasi & Sinkronisasi (Phase C - HARD GATE #10 & TDD)

- TDD RED → GREEN Proof: Ukur kondisi RED sebelum manipulasi file/katalog. Lihat `references/tdd-red-green.md`.
- Eksekusi perbaikan tanpa link simbolik / junction (`find -type l` = 0).
- Verifikasi GREEN: Sinkronkan salinan fisik yang memang aktif; pastikan salinan pendukung lengkap dan konsisten.
- Menambah rujukan eksternal (mis. dari awesome-agent-harness) ke arsitektur gate: verifikasi repo nyata & klaim cocok via `web_extract` sebelum mengutip; petakan tiap entri ke seksi gate yang diperkuatnya (mis. §10/15/16); lalu sinkronkan **seluruh pohon** skill (bukan hanya SKILL.md) ke 4 replika dan verifikasi md5 identik + jumlah file penuh.
- Untuk rename/sinkronisasi skill, inventarisasi dulu root katalog aktif, duplikasi nama, referensi pemicu, dan arsip. Pilih slug unik valid; `name:` harus sama dengan nama folder. Perbarui trigger phrase dan referensi lintas-skill, lalu salin seluruh skill dari satu sumber canonical ke root aktif yang dimaksud. Tandai snapshot lama sebagai arsip, jangan menimpa atau menghapusnya tanpa kebutuhan.
- Verifikasi dengan parser YAML yang sudah tersedia, `skill_view` dan daftar skill Hermes; bandingkan hash semua file di salinan aktif, serta pastikan BOM/link/junction nol. Jangan memasang dependensi hanya untuk validasi frontmatter.

### HARD GATE #10 Enforcement (dari `references/hard-gate-10.md`)

Setiap sinkronisasi skill **wajib** lolos verifikasi otomatis:

1. **Jalankan verifikasi** setelah copy: `./scripts/verify-hard-gate.sh`
2. **Schema validation** frontmatter SKILL.md (name, description, name=folder)
3. **Per-skill replica checksum** — setiap skill punya 1 hash konsisten di semua katalog (md5sum)
4. **Zero symlinks/junctions** — `find -type l` harus 0
5. **Minimal 2 katalog fisik** + **4 file SKILL.md fisik**
6. **Exit code 0** = PASS, 1 = FAIL — tidak ada "manual override"

**Scripts terintegrasi** (di `scripts/`):
- `benctl.sh` — satu perintah orkestrasi penuh (`sync-all-roots` → `refresh-baseline` → `verify-hard-gate` → `quorum-check` → `dashboard` → `status-matrix`) dengan flag `--redgreen`.
- `verify-hard-gate.sh` — verifikasi lengkap + JSON audit log + schema check + auto-source `gate.conf`
- `verify_skill_replicas.py` — PHP verifikasi setara (pure stdlib) utk host tempat `bash` tak me-resolve ke Git-Bash (mis. me-resolve ke WSL tanpa /bin/bash). Dipanggil: `python scripts/verify_skill_replicas.py --root <canonical> --replica <target> ...`. Cek seluruh pohon file, bukan hanya SKILL.md.
- `test-hard-gate-negative.sh` — adversarial test (symlink, partial copy, drift, hard budget ceiling; 35/35 tests) buktikan gate menangkap fault
- `sync-skills.sh` — atomic rsync + verify + rollback on fail (change management workflow)

**Workflow Phase C**:
1. RED: jalankan `verify-hard-gate.sh` sebelum sync (catat baseline)
2. Copy skill ke 4 lokasi fisik via `sync-skills.sh` (atau manual + verify)
3. GREEN: jalankan `verify-hard-gate.sh` lagi — harus PASS
4. Log ke `hard-gate-audit.log` + `hard-gate-audit.log.json` (structured)
5. Jika FAIL → rollback otomatis via `sync-skills.sh` atau manual, re-run, never skip

**Pitfalls** (dari buku kanonikal):
- Symlink/junction = technical debt (DDIA Ch3, Essential Arch) — gunakan `cp -r`/`rsync -a`/`robocopy /MIR`
- Checksum drift = artifact drift (ML Systems Ch8) — verifikasi per-sync, cron harian untuk drift detection
- Schema mismatch = breaking change (DDIA Ch4) — validasi frontmatter sebelum gate
- Manual verification = unverified claim (Pragmatic Tip 44, TSNA Ch18) — selalu script, never manual check
- Setelah sync, verifikasi **seluruh pohon** replika (setiap file), bukan hanya `SKILL.md` — salinan parsial lolos cek hash SKILL.md namun tetap gagal quorum saat file referensi/script hilang. Bandingkan set key + hash tiap file.
- Saat membandingkan replika, kunci hash dengan **path root**, bukan basename folder — dua root berbeda bisa berbagi basename yang sama, memicu KeyError/banding salah.
- Simpan baseline/manifest hash dan log audit **di luar pohon** yang diverifikasi — jika ditulis ke dalam pohon, penulisan itu mengubah hash yang sedang dihitung (self-invalidation) dan membuat cek reproduksibilitas/`P_reproducible` gagal. Letakkan di direktori meta terpisah, bukan di dalam root skill.
- Scanner pola statis (injeksi/malware) **self-incriminate**: polanya sering muncul di dokumen yang mendeskripsikan teknik itu atau di kode sumber tool itu sendiri → false positive. Arahkan scanner hanya ke direktori input runtime yang ditunjuk (`--runtime-inputs`); jangan pindai prosa/referensi/dokumentasi.
- Large file write over pagination/tools: Hindari `write_file` parsial setelah `read_file` terpaginasi (tool menolak overwrite bila state pembacaan parsial/stale). Gunakan `execute_code` Python dengan raw multiline string (`r"""..."""`) untuk mencegah kegagalan unicode escape (`\U...`/`\u...`) atau shell quoting truncation saat memperbarui dokumen spesifikasi besar (>15KB).
- Multi-edit batch pada dokumen spesifikasi besar (>15KB): ikuti prosedur assertion-guarded batched replacement di `references/large-document-editing.md` — daftar (old, new, expected_count), anchor unik pendek (bukan blok multiline), lalu verifikasi ulang dengan cek audit yang sama.
- Jangan menyatakan sebuah mekanisme "tidak bisa dieksekusi" karena "tooling eksternal hilang" tanpa memeriksa ketersediaannya lebih dulu (import / shutil.which / ls). Klaim infeasible yang tidak diperiksa mengeraskan diri jadi penolakan yang mengunci pekerjaan; cek dulu baru putuskan.
- Edit yang memperkenalkan sekuens backslash-escape ke dalam kode sumber (byte literal, regex) via `patch`/`write_file`: tool dapat menerjemahkan escape menjadi karakter kontrol hidup di dalam string literal → syntax error "unterminated string". Untuk edit semacam itu, rekonstruksi baris presisi via `execute_code` (baca baris, ganti, tulis ulang), bukan `patch`.
- Menjalankan script `.sh` gate dari `execute_code`/subprocess: jangan panggil `bash` telanjang (di host ini me-resolve ke WSL tanpa /bin/bash). Panggil jalur absolut Git-Bash: `C:\Program Files\Git\bin\bash.exe`. Verifier `.py` berjalan dengan `sys.executable`.
- Marker status "Implemented & runtime-verified" di `hard-gate-10.md` adalah klaim, bukan fakta — jalankan artefaknya sebelum mempercayainya. Jalankan dengan interpreter/env yang SAMA dengan cron gate (`run_daily_monitor.cmd`), dan buktikan dependensi importable (mis. `import z3`) / binary eksternal ada (mis. `which opa`) bila skrip mengaku runtime-verified — file yang ada tapi dependensinya tak termuat tetap gagal saat dieksekusi. Contoh ditemukan: verifier replika canonical menyimpan syntax error lama sehingga tak pernah ter-compile; baru terungkap saat benar-benar dieksekusi.
- Jalankan gate/verifier secara **bebas-efek samping** terhadap pohon yang diperiksa: script Python membuat `__pycache__/*.pyc` (set `PYTHONDONTWRITEBYTECODE=1`) dan default jalur audit yang relatif/tak-absolut menulis JSONL ke dalam `scripts/` — keduanya memutus identitas replika pada verifikasi berikutnya sendiri. Arahkan audit log ke absolut `tempfile.gettempdir()`, jangan pernah relatif atau ke-dalam-pohon.
- Generate baseline/manifest signature **hanya setelah edit terakhir**, lalu verifikasi dalam satu landasan — baseline yang direkam sebelum edit lanjutan langsung basi, sehingga pohon bersih pun gagal verifikasi. Urutan aman: sinkronkan replika → regenerate baseline → verifikasi.
- Gate pemindai katalog harus menghitung **hanya skill aktif**: lewati path arsip/`backup/*`, file nyasar tingkat-root, serta artefak self-healing `*/.hard-gate-meta/*` dan `*/quarantine/*` (skill asli hidup di sub-direktori katalog). Reparasi/karantina otomatis menulis salinan skill di dalam root proyek; jika ikut terhitung, ia menambah satu SKILL.md dengan hash divergen → gate FAIL palsu (10 skill/11 hash) walau quorum 4/4 bersih. SKILL.md lama/arsip yang ikut terhitung juga gagal schema dan memerah seluruh gate.
- Negative test yang menyerah diam-diam saat tak bisa membangun fixture-nya memberi keyakinan palsu: di Windows/MSYS `ln -s` gagal tanpa privilege admin, sehingga uji symlink ber-pola `if [ -L ... ]; then ... fi` menjadi no-op dan terhitung "PASS" tanpa pernah memverifikasi apa pun. Buat kegagalan setup menjadi FAIL (exit 1) — verifikasi fixture benar-benar tercipta sebelum menyatakan test PASS.
- Gate memakai DUA mekanisme manifest berbeda: `check_signed_manifest` (`gate_predicates.py` → `.hardgate_manifest.sha256`) dan `verify-hard-gate.sh` (→ `.hard-gate-meta/<skill>.manifest.sha256`). Edit skill → regenerasi baseline via `generate_manifest.py --baseline <file-di-luar-pohon>` lalu jalankan ulang verify; baseline yang basi membuat gate RED walau semua predicate lain PASS.
- Panggil eksekutabel native (python, pip, opa) dari Git-Bash hanya dengan path native hasil `cygpath -w`: argumen `/c/...` sering termutilasi menjadi `C:\c\Users\...` (prefix drive + komponen pertama dipertahankan) oleh auto-conversion MSYS yang tidak konsisten antar-shell — python gagal membuka script/berkas dan gate melaporkan FAIL palsu (mis. manifest). Definisikan `SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"` sekali, lalu pakai `$SCRIPT_W/...` di semua pemanggilan python; lakukan sama untuk tiap argumen berkas (requirements.txt, input OPA).
- Deteksi/ciptakan junction Windows: `os.path.islink` mengembalikan False untuk junction — deteksi via ctypes `GetFileAttributesW(p) & 0x400`. Buat junction dengan PowerShell `New-Item -ItemType Junction -Path <L> -Target <T>`; jangan `cmd //c mklink /J` (di Git-Bash bisa membuka cmd interaktif dan tidak mengeksekusi). Recipe lengkap di `references/windows-execution.md`.
- Generator/konverter trace (mis. `agentlog2trace.py`) yang menulis JSONL: mutasi daftar event — termasuk menyuntikkan marker baru — wajib terjadi SEBELUM loop penulisan. Append setelah write tidak akan terserialisasi; print bisa sudah menghitungnya sehingga jumlah print ≠ jumlah baris file. Jika parse ulang tidak menemukan event baru, cek posisi append terhadap write, bukan format file.
- `runtime_gate.py` (P_rt_sessions / zero-trust): setiap sesi wajib punya minimal satu event `verify`. Trace turunan dari log teks yang tidak menghasilkan event verify akan selalu FAIL pada predicate ini walau aman. Suntikkan satu event `verify` sintetis per sesi saat konversi (bukan di runtime gate).
- Metrik/stats kustom harus meniru filter ACTIVE gate (lewati `.git`, `backup/*`, `archive/*`, dan file nyasar root) supaya angkanya konsisten dengan laporan `verify-hard-gate.sh`; kalau tidak, hitungan membengkak (mis. direktori `.git` ikut terhitung sebagai katalog).

- Script bash dengan `set -euo pipefail`: pipeline yang sengaja gagal di cabang error (mis. `verify-hard-gate.sh ... | tee -a log`) tetap menghentikan seluruh script SEBELUM blok recovery/repair sempat jalan. Guard setiap panggilan verifikasi/quorum non-zero dengan `|| true` bila masih ada logika lanjutan setelahnya.
- Gate `verify-hard-gate.sh` hanya memindai root yang diberikan (project); drift canonical vs replika TIDAK terlihat oleh gate (bisa gate PASS padahal quorum 3/4). Setelah edit canonical, urutan bukti: `sync-all-roots.sh` → `refresh-baseline.sh` → `verify-hard-gate.sh`, lalu buktikan `quorum-check.py --root <canonical> <replicas...>` = 4/4 (atau cukup jalankan `benctl.sh --redgreen`).
- Wrapper bash scripts yang memanggil sub-skrip (.sh vs .py): jangan mendispatch skrip bash via `$PY_BIN` (`python` akan gagal syntax error pada statement shell seperti `export`); pisahkan variabel `$BASH_BIN` (menunjuk `bash.exe` Git-Bash) dan `$PY_BIN` secara eksplisit.
- Path literal Windows di script generator/pembantu: gunakan forward-slash (`/`) atau `os.path.abspath` untuk menghindari Python syntax/unicode error `\U...` escape truncation. Pastikan direktori metadata (`.hard-gate-meta/`) hanya dibuat di root repositori/proyek, jangan pernah dibuat di dalam subfolder skill pohon replika (hindari self-invalidation).
- Menambah entri versi baru di `CHANGELOG.md`: jangan sisipkan setelah newline pertama, karena bila baris pertama file sudah berupa heading `## v...`, entri baru akan mendarat DI BAWAH-nya dan `status-matrix` melaporkan VERSION MISMATCH (SKILL.md vs CHANGELOG). Anchor pada heading `## v` PERTAMA (bawa blok baru ke atasnya), bukan pada newline pertama; setelah dipindah, verifikasi `versions_consistent()` sebelum mem-bump.
- Dokumen spesifikasi yang mengklaim selaras dengan versi kode harus punya header versi sendiri dan divalidasi silang oleh matriks status (`spec_version_consistent`) — tanpa itu, klaim "versi konsisten" di dokumen diam-diam basi saat versi kode naik.
- Sandbox hermetic `env -i` (verify-hard-gate-sandbox.sh) hanya mewarisi PATH/TMPDIR/HARD_GATE_LOG/HOME — validator yang memanggil subprocess python (SBOM/VC) akan gagal dengan FAIL palsu (mis. "invalid CycloneDX") walau file valid, karena interpreter tidak resolvable di MIN_PATH. Resolve satu python SEBELUM `env -i` dan ekspor `PY_BIN` (plus tambah direktorinya ke PATH) di dalam pemanggilan `env -i`.
- Saat membangun string old/new untuk patch bash via `execute_code` Python: baris yang diakhiri backslash-kontinuasi (`\` di akhir baris) harus ditulis `\\` + newline eksplisit — dalam string Python biasa, `\` diikuti newline nyata termakan sebagai line-continuation sehingga anchor kehilangan backslash dan newline (tidak pernah match, count=0). Gunakan `\\\n` atau raw string, dan verifikasi `s.count(anchor)==1` sebelum replace.
- Panggil `verify-fresh-machine.sh` dengan canonical skill dir, bukan root proyek — jika diberi project root, ia menyalin seluruh tree sehingga muncul `ben-mode/ben-mode` bersarang dan schema FAIL (name≠folder). Buat arg-wrapper di orkestrator meneruskan `$(cd "$SCRIPT_DIR/.." && pwd)`.
- Kapabilitas verifikasi yang di-gate per-run (`HARD_GATE_FRESH`, dsb.) harus **default ON** di `gate.conf` dan diverifikasi muncul di output deep `benctl --redgreen` — flag default-off membuat deep run diam-diam melewatkan cek dan laporan "verified" jadi tidak lengkap tanpa ada yang sadar.
- Probe binary eksternal (opa/cosign/wasmtime) pakai `shutil.which` PLUS fallback eksplisit (`~/bin/*.exe`, env override `OPA_BIN`) — PATH subprocess tidak selalu memuat direktori user bin; `which` yang gagal melaporkan false padahal biner ada.
- Berkas Python bernama hyphen (`transparency-log.py`) tidak bisa di-`import` sebagai modul standar (`from transparency_log import` → ModuleNotFoundError). Muat via `importlib.util.spec_from_file_location` + `exec_module` saat importer lintas-skrip perlu memakainya.
- Saat satu mode CLI hanya butuh sebagian arg (mis. `--ai-rmf`), jangan tandai `--root`/`--meta-dir` sebagai `required=True` — buat default `""` + guard manual `parser.error(...)` agar mode parsial tetap jalan tanpa wajib menyuplai arg mode lain.
- Checker artefak (sbom_present di status-matrix) jangan menebak lokasi relatif ke skill dir; terima root proyek sebagai arg/param dan cek multi-kandidat (`<skill-meta>/...`, `<project>/.hard-gate-meta/...`) — artefak gate hidup di meta proyek, bukan di samping skill.
- Saat me-wire checker eksternal opsional (mis. opa-policy-check) ke gate: default-kan ON via `${HARD_GATE_OPA_ENFORCE:-1}`, perlakukan `exit 0` saat biner absent sbg honest-skip (bukan FAIL), bedakan skip(0)/deny(1)/eval-fail(2), dan gabungkan flagnya ke boolean verdict akhir — jangan hanya menyisipkan panggilan tanpa memasukkannya ke kondisional PASS/FAIL.
- Suite adversarial sebaiknya mendeklarasikan konstanta `TOTAL_TESTS=N` di header, lalu status-matrix membandingkan declared vs present (`Test N PASS` timbul) dan menandai drift bila tak sama. Hitung semua field turunan SEBELUM membangun dict literal — statement assignment tidak bisa hidup di dalam literal dict (SyntaxError `':' expected`).
- Predicate parity yang membandingkan jumlah uji yang dideklarasikan di doc vs aktual harus **membaca `actual` dari skrip pengujian itu sendiri** (regex `TOTAL_TESTS=`), bukan konstanta keras — konstanta keras menciptakan titik sinkronisasi kedua yang diam-diam basi tiap kali suite bertambah.
- Integrasikan suite adversarial + pemeriksaan kesehatan (routing, coverage) sebagai **fase di dalam orkestrator** (`benctl --redgreen`) sehingga satu perintah membuktikan seluruh gerbang, bukan menjalankannya terpisah.
- Validasi integrasi scheduled task: jangan cukup grep launcher `.cmd` — jalankan task-nya (`schtasks /Run /TN …`), lalu poll `schtasks /Query /FO CSV /V` sampai status `Ready` (bukan berhenti di `Running`), dan periksa `Last Result = 0` + tail log alert. Kode `0x41301` = SCHED_S_TASK_RUNNING (tugas sedang berjalan), bukan error — jangan salah simpulkan. Launcher bisa route melalui skrip lain (mis. `.cmd` → cron → `benctl --quick`), dan bisa jatuh ke full pipeline (tree berubah) sehingga berjalan ~60s+; isi aktual hanya terlihat saat task benar-benar tuntas. Recipe lengkap: `references/windows-execution.md` §9.
- Predicate dormant (mis. `P_model_signed`) baru live setelah manifest pemicunya (`model-hashes.json`) ada; untuk mengaktifkan + menguji, buat manifest contoh yang menunjuk artefak nyata dengan hash benar (berlaku), dan pastikan daftar `assets` kosong/di-h sistem ditolak (exit non-zero → FAIL), bukan diam-diam lolos.
- Manifest yang self-referencing artefak yang diregenerasi (mis. `model-hashes.json` → `dashboard.html` dari `generate-dashboard.py`) bisa basi diam-diam. Resolusi yang benar: jadikan **generator ikut memperbarui manifest secara atomik** (`os.replace` setelah menulis), dan hitung digest dari **byte file aktual yang ditulis** (`open(out,'rb').read()`), bukan dari string di memori — mode text-write Windows memperluas `\n`→`\r\n`, sehingga `sha256(doc.encode())` ≠ hash on-disk dan setiap run FAIL palsu.
- Predicate yang memverifikasi artefak yang diregenerasi (`P_model_signed` → dashboard) harus menunjuk **artefak yang dimiliki generator** (mis. `.hard-gate-meta/dashboard.html`), bukan salinan turunan yang diter-bitkan belakangan (`docs/dashboard.html`) — jika verify berjalan sebelum publish, manifest (yang diperbarui oleh ekor run sebelumnya) selalu mendahului file di disk → FAIL palsu berulang. Publikasikan salinan identik setelah verify bila diperlukan deploy.
- Pipeline gate yang meregenerasi baseline/SBOM tidak boleh berjalan konkuren: dua run paralel race pada penulisan baseline/artefak dan menimbulkan FAIL palsu/state robek. Serialisasi dengan lockfile atomik `mkdir` (`trap 'rmdir ...' EXIT`); run kedua skip dengan pesan, bukan merusak state.
- Setiap kapabilitas gate baru wajib disurfacing **serentak di semua permukaan observability**: field `status-matrix.py`, anchor `traceability.py`, baris `weekly-summary.py`, dan kartu dashboard — kalau tidak, satu permukaan melaporkan kelengkapan basi dan mengerdilkan keputusan.
- Saat matriks status perlu mencerminkan verdict checker lain (mis. traceability, coverage): jalankan checker itu via `subprocess` dan parse stdout-nya — jangan meng-ulang logikanya inline, atau dua salinan logika drift diam-diam.
- Log audit append-only (JSONL/log) tumbuh tanpa batas; tambahkan langkah rotasi/retensi (arsip ke `meta/archive/<ts>/` lalu truncate live) di monitor terjadwal, bukan hanya saat disk penuh.
- Label/hitungan statik pada output orkestrasi (mis. `benctl` "negative adversarial suite (29/29)") langsung basi saat jumlah suite bertambah; turunkan dari sumber tunggal yang sama (`TOTAL_TESTS`) atau perbarui serentak dengan bump hitungan, kalau tidak laporan menampilkan angka lebih rendah daripada suite yang benar-benar dieksekusi.
- Pre-commit `git diff --cached --check` gagal pada artefak provenans biner (`.sig`, `.bin`) dan blank-line-EOF YAML → jangan bypass `--no-verify`; kunci exklusi via pathspec pada perintah check itu sendiri: `git diff --cached --check -- . ':(exclude)*.sig' ':(exclude)*.bin'`. Ini menyimpan guard whitespace untuk file teks, melewatkan biner, dan membuat commit normal tetap tertahan tanpa bypass. Bila tetap harus `--no-verify`, batasi hanya untuk file tak tersentuh dan catat jujur.
- Subprocess `git commit` via execute_code wajib set `GIT_AUTHOR_NAME`/`GIT_AUTHOR_EMAIL` (+ COMMITTER) eksplisit — tanpa itu gagal "Author identity unknown". Decode output subprocess dgn `errors="replace"` karena pre-commit hook dapat memuntahkan byte non-UTF8 yang menghentikan decode ketat.
- `git add -A -- ':(exclude)…'` hanya mengecualikan file belum-di-tracking; artefak self-healing yang sudah ter-tracking tetap ikut ter-stage — bila ingin dikeluarkan, unstage setelah add atau terima melacaknya.
- Mekanisme gate baru wajib didokumentasikan di BADAN spec (BAGIAN), bukan sekadar bump header versi — grep istilah implementasi di doc harus positif setelah rilis; header saja membuat klaim "selaras" menipu.
- Rego (OPA) memakai `x and y` / `every k, v in ... { }` / ref kata kunci baru → wajib `import future.keywords.and` / `import future.keywords.every` di header policy; tanpa itu OPA gagal parse "unexpected identifier token" (hint: `import future.keywords.and`).
- OPA `eval --input -` (stdin) tidak konsisten — tulis input ke temp file lalu teruskan path-nya; dan output `--format json` untuk deny adalah `"value": false` (dengan spasi), bukan `"false"` — skrip grep/skema harus mencocokkan `"value": false`.
- Cabang "skip" di suite adversarial jangan men-echo `Test N PASS` (mis. saat tool absent) — `status-matrix.py` menghitung kemunculan `Test \d+ PASS` dan membandingkannya dengan `TOTAL_TESTS`; dup match membuat `negative_pass_consistent=false` walau suite lolos. Pakai kata `SKIPPED` untuk skip jujur.
- Hook pre-commit menjalankan `verify-hard-gate.sh` pada tiap commit yang menyentuh SKILL.md, references, atau scripts — jadi baseline manifest WALIB terkini pada saat commit: edit apa pun (termasuk perbaikan trailing whitespace atau bump label) harus diikuti `refresh-baseline.sh` + `sync-all-roots.sh` SEBELUM commit, atau hook gagal "Manifest FAIL" dan menolak commit (bukan bypass `--no-verify`).
- Scanner self-BOM (`status-matrix.py` `missing_bom`) memindai setiap baris yang diawali `- ` di SKILL.md dan mengekstrak path `(references|scripts)/...` — prosa dalam bullet yang secara literal memuat frasa `references` dirangkai slash diikuti sub-path (mis. `references` dirangkai `scripts`) memicu `SELF-BOM FAIL` palsu walau tak ada referensi hilang. Jauhkan literal mirip-path dari prosa bullet; reword (mis. `references dan scripts`) atau jangan tulis frasa itu di baris bullet.

- Workflow GitHub Actions hanya berjalan pada event yang didaftarkan di `on:`. Ingin memicu via push → tambah `push: branches: [main]`; tanpa itu push tidak menjalankan apa pun dan run lama tetap tampil sebagai "terbaru" (menyesatkan poll).
- Referensi `needs:` di workflow harus menunjuk nama job yang nyata; salah nama membuat seluruh run gagal dengan pesan samar "workflow file issue" tanpa detail job — verifikasi nama job terhadap blok `jobs:` sebelum push.
- Attestation GitHub (`attest-build-provenance`/keyless) tidak tersedia untuk repo privat milik user — jangan klaim keyless verified pada repo privat; skip job tersebut secara jujur atau publikasikan repo dahulu.
- Baseline manifest gate bersifat host-spesifik (baris baru/file ekstra) — pada fresh clone CI ia melenceng dan memicu "Manifest FAIL" padahal lokal PASS. Regenerasi baseline di dalam CI sebelum verify (`refresh-baseline.sh . ben-mode`) dan tegakkan canonical LF via `.gitattributes` + `git add --renormalize` agar hash konsisten lintas-host.
- `git push` bisa menggantung saat credential helper meminta interaksi — panggil dengan helper dinonaktifkan dan token disematkan: `git -c credential.helper= push https://x-access-token:$GH_TOKEN@github.com/<owner>/<repo>.git main` (hindari prompt interaktif).
- Validator Python yang mencetak karakter non-ASCII (mis. `≥`/`≤`/em-dash) di Windows/CI runner meledak `UnicodeEncodeError` (codec default cp1252) SETELAH logika lolos — test tampak FAIL padahal predikat PASS. Di header tiap CLI tool yang mencetak simbol: `sys.stdout.reconfigure(encoding="utf-8", errors="replace")` (± stderr), atau ganti simbol jadi ASCII (`>=`) di seluruh pesan.
- Resolusi eksekutabel opsional di bash jangan memakai rantai fallback `|| echo path` — fallback membuat variabel NON-kosong walau biner absent (tilde literal `~/bin/x` tidak ter-ekspansi dan gagal `[ -x ]`), sehingga guard `[ -n ]` masuk cabang jalankan dan FAIL. Guard dengan `[ -x "${TOOL:-}" ]` dan resolve path nyata via `$HOME`/env override.
- Provisioning binary dalam job CI harus diletakkan SEBELUM langkah yang mengonsumsinya (suite/test), bukan sesudahnya — test yang menuntut biner gagal jika langkah fetch-nya terlambat. Saat test LOLOS lokal tapi FAIL hanya di hosted runner, tambahkan diagnostik (cetak output verifier) sebelum menganggap bug logika — akar sering beda env (encoding/order) bukan logika.

## References:
-
 references/github-actions-ci.md — deployment HARD GATE #10 ke GitHub Actions: trigger, validasi needs, keterbatasan attestation repo privat, parity baseline LF.
- references/cose-scitt-receipt.md — resep COSE_Sign1 (python-cose) untuk receipt SCITT/attestation.
- references/version-identification.md
- references/vault-correction-2026-10-21.md
- references/hard-gate-10.md  # ⚠️ WAJIB DIBACA setiap kali skill aktif (gate inti)
- references/tdd-red-green.md
- references/large-document-editing.md
- references/article-evidence.md
- references/pdf-corpus-regeneration.md
- references/content-to-skill.md — alur mengubah konten eksternal/web menjadi skill (provenance, routing, sinkronisasi).
- references/gate-audit-procedure.md — prosedur audit total klaim gate: jalankan artefak dengan env cron, klasifikasi klaim (real/overstated/broken), susun plan P0/P1/P2.
- references/release-verification-routine.md — urutan verifikasi/rilis penuh pasca-edit canonical (sync→deep→suite→oracle→dashboard→bump) + pitfall khusus rutin.
- references/windows-execution.md — resep menjalankan toolchain gate di Windows/Git-Bash: konversi path native, pembuatan/deteksi junction, OPA, generate_manifest, konstrain schema nama-folder untuk fixture test.
- references/runtime-trace-validation.md — resep mengubah agent.log Hermes menjadi trace JSONL untuk `runtime_gate` (mapping, suntikan event verify per sesi, pemindaian).
- scripts/tdd-red-green.sh — uji executable RED→GREEN: flip satu byte di replika → verifier harus FAIL; pulihkan → harus PASS.
- scripts/generate-sbom.py — P6-D: CycloneDX v1.5 JSON SBOM (komponen ter-hash + deps).
- scripts/vc-allowlist.py — P6-C: representasi allowlist sbg W3C VC v2.0 + EdDSA + Bitstring Status List revocation.
- scripts/status-matrix.py — P7-J: sumber tunggal status predicate + self-BOM check referensi SKILL.md.
- scripts/check-model-signed.py — P7-I#6: P_model_signed opsional (verifikasi hash aset model).
- scripts/verify-fresh-machine.sh — P6-E: push-button artifact reproducibility (dua sandbox bersih bit-identik).
- scripts/verify-incremental.sh — P5 E1: gate inkremental (tree signature CRLF-normalized; tree tidak berubah → quick PASS, berubah → verify penuh + simpan sig).
- scripts/gate-stats.sh — catat metrik observability per run (katalog/skill/symlink/tree_bytes + token_proxy) ke `.hard-gate-meta/gate-cost.jsonl`.
- scripts/allowlist.py — lifecycle `hard-gate-allowlist.json` (init/add/remove/validate).
- scripts/manifest-sign.sh + verify-manifest-sig.sh — tanda tangan Ed25519 opsional atas baseline manifest (openssl pkeyutl; default off).
- scripts/runtime-monitor.sh — slice agent.log → trace → scan runtime + audit `runtime-audit.jsonl` (status + since_clean).
- scripts/bmc_concurrency.py — BMC konkurensi read/write: S1 no-lock SAT (hazard), S2 lock UNSAT (aman).
- scripts/cost-report.py — ringkasan `gate-cost.jsonl` + budget alert.
- scripts/benctl.sh — P8-M#1: satu-perintah orkestrasi HARD GATE #10 (sync -> refresh -> verify -> quorum -> dashboard -> status-matrix).
- scripts/generate-dashboard.py — P8-O#6: generator dashboard HTML observability offline tanpa dependency runtime.
- gate.conf — P8-M#2: file konfigurasi terpusat auto-source oleh verify-hard-gate.sh.
- Reference harness implementations (mendukung klaim HARD GATE #10 §§10,15,16); dikurasi dari awesome-agent-harness (Picrew), diverifikasi 2026-10-29:
  - `google/ax` (Apache-2.0) — Agent Executor: event-log snapshots, isolated actors, audit & policy → §10 audit trail & §16 execution deterministik. https://github.com/google/ax
  - `block/buzz` (Apache-2.0) — signed Nostr event log; audit trail identik utk manusia & agen → §15 crypto attestation/append-only log. https://github.com/block/buzz
  - `Kocoro-lab/Shannon` (MIT) — WASI sandboxing, OPA policies, token budgets, temporal debugging → §16.1 hermetic sandbox & §13 governance. https://github.com/Kocoro-lab/Shannon
  - `KodekaTeam/superior-skills` (MIT) — portable skill-package design: satu canonical `skills/` tree melayani banyak format agen (Claude/Codex/Cursor/Gemini/Kimi), routing by work-type, progressive disclosure via `references/` → memvalidasi pendekatan multi-replika ben-mode (katalog fisik + tree canonical). https://github.com/KodekaTeam/superior-skills
  - `roedyrustam/vibes-plug` (MIT) — swarm plugin dgn P1–P7 engine (SMT invariant verifier→§14.1; WASM sandbox→§16.1; CycloneDX SBOM→§15.1; adversarial fuzzing→§13.1). ⚠️ Klaim performa (potong 75–90% biaya, 10x TTFT) adalah marketing tak-terverifikasi; rujukan untuk POLA desain saja. https://github.com/roedyrustam/vibes-plug

---

### 4. Browser Context Automation — Metode 1 (CDP / Playwright)
Alur eksekusi saat tugas melibatkan akses browser (mis. `agentbrowser`, akses akun sosial melalui sesi browser yang sudah diautentikasi oleh pengguna). Ini bukan pengganti `hard-gate-10.md`; hanya prosedur teknis.

**Urutan wajib (tidak bisa dilewati):**
1. Muat `references/hard-gate-10.md`.
2. Verifikasi lingkungan fisik: `os.path.isfile` untuk executable (`Helium.exe`, `chrome.exe`, `msedge.exe`, `firefox.exe`); periksa direktori profil (`User Data`, `Profiles`); `tasklist` untuk proses berjalan; `import playwright` atau `pip list`.
3. Tulis script (`method1_cdp_script_*.py`) dengan `HELIUM_BIN`, `PROFILE_DIR`, `DEBUG_PORT = 9222`, dan perintah `subprocess.Popen` untuk membuka browser dengan `--remote-debugging-port=9222 --user-data-dir=...`.
4. **Tidak memasukkan username/password secara otomatis** — pengguna memasukkannya manual.
5. Buat audit JSON (`audit-*.json`) dengan `execution_timestamp`, `honesty_flag`: "Tidak ada akses berhasil dieksekusi oleh agen; hanya pembukaan browser yang diverifikasi.", `action`: perintah yang dijalankan, status executable (`*_found`), status Playwright (`playwright_available`), dan `integrity_notes`.
6. Verifikasi proses (`tasklist /FI "PID eq ..."`) untuk membuktikan browser berjalan.
7. Jika lingkungan tidak siap (missing executable, missing Playwright), laporkan jujur, berikan perintah perbaikan (`pip install playwright && playwright install chromium`), dan **jangan klaim akses berhasil**.

**Pitfall (aturan tetap):** Jangan menyatakan "tidak bisa dieksekusi" tanpa memeriksa terlebih dahulu (`import`, `os.path.isfile`, `tasklist`). Jangan mengklaim akses berhasil tanpa audit file fisik (`honesty_flag`). Jangan menyuntikkan kredensial secara otomatis — akses akun sosial memerlukan otorisasi manual pengguna. Lihat `references/browser-automation-method1.md` untuk detail perintah dan template audit.

Lihat juga: `references/browser-automation-method1.md`.
