# ADR — ben-mode / HARD GATE #10 (P4 F1)

Format: ADR-N — title (status).

## ADR-1 — Unifikasi manifest (diterima, P0)
Gate sebelumnya memiliki dua mekanisme baseline: `check_signed_manifest`
(`.hardgate_manifest.sha256`) dan `verify-hard-gate.sh`
(`.hard-gate-meta/<skill>.manifest.sha256`). Dipilih satu: deterministic tree
signature (CRLF-normalized) dari `generate_manifest.py`, disimpan **di luar**
pohon skill. `gate_predicates.py` kini memakai file yang sama.

## ADR-2 — Deteksi junction via ctypes (diterima, P1)
`os.path.islink` mengembalikan False untuk junction Windows. Deteksi reparse
point dengan `GetFileAttributesW(p) & 0x400` di `verify_skill_replicas.py`
dan `gate_predicates.py`. Pembuatan fixture junction memakai PowerShell
`New-Item -ItemType Junction` (bukan `cmd //c mklink /J` yang membuka cmd
interaktif).

## ADR-3 — Argumen native untuk eksekutabel native (diterima, P1)
MSYS auto-conversion `/c/...` tidak konsisten antar-shell, menghasilkan
`C:\c\Users\...` yang membuat python gagal membuka file. Konvensi:
`SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"` → `"$SCRIPT_W/script.py"`; semua
argumen berkas juga dilewatkan `cygpath -w`.

## ADR-4 — Suntikan event verify sintetis saat konversi trace (diterima, P3/P4)
`runtime_gate.py` P_rt_sessions mensyaratkan minimal satu event `verify` per
sesi. Trace turunan dari log teks tidak menghasilkan event itu → suntikkan di
`agentlog2trace.py` SEBELUM loop penulisan (mutasi sebelum write; append
setelah write tidak terserialisasi).

## ADR-5 — Manifest signature opsional (diterima, P4)
Baseline default adalah hash (bukan tanda tangan). `manifest-sign.sh` +
`verify-manifest-sig.sh` menyediakan Ed25519 opsional via openssl; gate utama
tetap hash (default off), signing dipakai untuk verifikasi suppy-chain penuh.

## ADR-6 — Self-repair monitor (diterima, P4)
`cron-hard-gate-monitor.sh` mendukung `REPAIR_FLAG=1`: saat drift terdeteksi,
jalankan `sync-all-roots.sh` → `refresh-baseline.sh` → verify. Wajib guard
`|| true` pada pipeline yang exit-nya non-zero agar `set -euo pipefail` tidak
menghentikan cabang repair sebelum sempat dieksekusi.

## ADR-7 — Allowlist signing Ed25519 (diterima, P5 D1/D2)
`allowlist.py` menyediakan subcommand `sign` (openssl pkeyutl -sign, rawin) dan
`validatesig` (verify, auto-extract pub dari private key). Gate
`verify-hard-gate.sh` memverifikasi signature allowlist secara OPSIONAL: aktif
hanya jika `HARD_GATE_ALLOWLIST_PUB` diset DAN `hard-gate-allowlist.json.sig`
ada. Verifikasi gagal -> FAIL keras (bukan silent skip). Default off agar
deployment existing tidak berubah.

## ADR-8 — Observability & incremental (diterima, P5 C1/E1/E2)
C1: `gate-time.jsonl` merekam durasi per run (E2: + cakupan katalog/berkas/
skill utk korelasi durasi vs skala). C2/C3: `weekly-summary.py` agregat
cost/time/runtime/audit JSONL + histogram drift dari alerts log (tanggal dibawa
dari header seksi). E1: `verify-incremental.sh` — tree signature (CRLF-
normalized SHA-256 atas SKILL.md+scripts/references) disimpan di
`.hard-gate-meta/last-tree.sig`; tidak berubah -> quick PASS, berubah -> verify
penuh + simpan sig baru.

## ADR-9 — P6 Hardening (diterima, P6)
- **P6-G**: `PYTHONDONTWRITEBYTECODE=1` di semua script .sh pencegah .pyc drift.
  `z3` solver diprovision via `bootstrap-deps.sh` (BMC kembali verified nyata).
  CI workflow diperluas (incremental smoke, telemetri assert, full-tree verifier).
  `verify-hard-gate.sh` mendukung parameterisasi ROOT via file config
  (`HARD_GATE_CONF`) dan env newline-separated (`HARD_GATE_ROOTS`).
- **P6-A**: Adversarial suite diperluas 16 test (Test 14: RAG pollution, Test 15:
  system-override jailbreak, Test 16: stale session freshness).
  `runtime-monitor.sh` menghitung `since_clean` nyata (durasi sejak PASS terakhir).
- **P6-B**: Sigstore/cosign keyless OIDC dicatat sebagai *blocked (external
  tooling absent)* per kejujuran artefak (cosign/gh absent di host ini).
- **P6-C**: `vc-allowlist.py` — representasi allowlist sbg W3C Verifiable
  Credential Data Model v2.0 (EdDSA proof via openssl) + Bitstring Status List
  revocation.
- **P6-D**: `generate-sbom.py` — CycloneDX v1.5 JSON SBOM (55 komponen
  ter-hash + external library purl).
- **P6-E**: `verify-fresh-machine.sh` — simulasi runner bersih (dua sandbox
  independen) membuktikan determinisme P_reproducible bit-for-bit.
- **P6-F**: `runtime_gate.py` memperkuat `P_rt_sessions` dengan jendela
  freshness (`HARD_GATE_SESSION_FRESHNESS`, default 3600s) — aksi setelah verify
  yang stale akan FAIL keras.

## ADR-10 — P7 Hardening (diterima, P7)
- Unit-test otomatis toolchain (allowlist/VC/SBOM) ditambahkan di
  `scripts/tests/test_toolchain.py`; 6/6 PASS.
- Predicate opsional baru di gate: SBOM (`HARD_GATE_SBOM_REQ=1`), VC
  (`HARD_GATE_VC_PUB`), model-signed (`HARD_GATE_MODEL_SIGNED=1`) — semuanya
  default off agar tidak mengubah perilaku deployment existing.
- Task Scheduler `Hermes-HardGate-Daily-Monitor` diverifikasi terjadwal (Daily
  02:00). RED→REPAIR terbukti: ketika baseline basi, monitor mendeteksi drift,
  self-repair sync, gate GREEN.
- End-to-end runtime: agentlog2trace.py→runtime_gate.py pada agent.log asli
  menghasilkan PASS; setiap sesi mendapat event verify.
- `status-matrix.py` menjadi sumber tunggal status (predicate/jumlah test/deps)
  yang diturunkan dari kode, mencegah drift angka antara spec dan implementasi.
- Self-BOM check: seluruh referensi SKILL.md (references/ scripts/) diverifikasi
  ada di disk.
- Perbaikan integrasi cron (P7-H#4): run terjadwal gagal rc 1 karena stdout
  python tools 3.14.x memakai cp1252 dan `quorum-check.py` mencetak `≥`
  (U+2265) -> UnicodeEncodeError -> REPAIR gagal. Fix: `PYTHONIOENCODING=utf-8`
  di launcher + script gate + `sys.stdout.reconfigure(errors='replace')` di
  quorum-check.py. Task diverifikasi kembali Last Result 0.

## ADR-11: Phase 8 Operator Ergonomics, Version Anti-Drift, Hard Budget Ceiling (2026-10-31)
- **Context**: Operator was required to invoke 4 distinct bash/python commands manually. Configuration flags were dispersed across ad-hoc environment variables. Gate cost tracking was purely passive with no hard enforcement mechanism.
- **Decision**:
  1. Introduce `benctl.sh` wrapping the standard pipeline with deterministic return codes.
  2. Implement `gate.conf` auto-sourcing in `verify-hard-gate.sh` to centralize optional feature toggles.
  3. Enforce version equality between `SKILL.md` frontmatter and `CHANGELOG.md` in `status-matrix.py`.
  4. Integrate hard budget ceiling predicate `HARD_GATE_BUDGET` gating over-budget execution (Negative Test 17).
  5. Provide `generate-dashboard.py` rendering self-contained `dashboard.html` for offline observability.
  6. Add CI step for `verify-fresh-machine.sh` in `.github/workflows/hard-gate.yml`.
- **Consequences**: Zero manual steps for verification, strict version drift prevention, verifiable financial limit enforcement, and honest reporting on unprovisioned external binaries.

## ADR-12: Phase 9 External Tooling Provisioning & Operator Enforcement (2026-10-31)
- **Context**: P8-P deferred OPA/Cosign/WASI due to missing host tooling; budget predicate was off-by-default; dashboard refreshed only manually; routing matrix untested; no cross-run regression oracle.
- **Decision**:
  1. Provision real OPA (v1.22.0) to `C:\Users\AMMAR\bin\opa.exe`; wire `opa-policy-check.py` to evaluate Rule 6 via the binary (deny proven on expired allowlist). Cosign/gh absent → keyless OIDC documented as blocked, not faked.
  2. Make budget predicate windowed and default-on (`HARD_GATE_BUDGET=1000000`, WINDOW=7).
  3. Add `cron-watchdog.sh` + secondary Scheduled Task as failover for the primary daily monitor.
  4. Add `routing-health.py` (171/171 matrix skills resolve) and `regression-oracle.py` (metric drift alert).
  5. Keep `model-tier.py` optional (HARD_GATE_MODEL_ROUTING=1), default off.
- **Consequences**: Real (not mocked) OPA enforcement; dual cron coverage; verifiable routing integrity; baseline snapshot regression detection.


## ADR-13: P10 Continuous Governance, Sigstore Keyless, and Cross-Platform CI (2026-10-31)
- **Context**: Post-P9 review revealed lingering blocked status for Cosign keyless attestation, default-optional SBOM, unverified cron cross-consistency, missing Linux runner in CI, and duplicate section headers in `hard-gate-10.md`.
- **Decision**:
  1. Provision `cosign.exe` in `~/bin/`, implement `sigstore-verify.py` with dual-mode (selfcheck default, keyless verify-blob when invoked), add Test 19 to negative suite.
  2. Mandate CycloneDX SBOM by default (`HARD_GATE_SBOM_REQ=1` in `gate.conf`).
  3. Wire routing-health, regression-oracle, OPA policy check, and SBOM into GitHub Actions CI; add a parallel `fresh-linux` runner job for cross-OS reproducibility.
  4. Augment `cron-watchdog.sh` with primary-monitor cross-consistency checks and wire drift detection into `cron-hard-gate-monitor.sh`.
  5. Dedup `hard-gate-10.md` BAGIAN 18 (survey renamed BAGIAN 20).
  6. Surface `unit_test_count` in `status-matrix.py`.
- **Status**: Accepted. Version bumped to v0.7.0.


## ADR-14: P11 Deep Verification Pipeline + Runtime Adversarial Suite (2026-10-31)
- **Context**: Post-P10, the orchestrator (`benctl.sh`) did not exercise §16.1 hermetic sandbox / §14.1 BMC daily; negative suite lacked runtime/behavioral injection coverage (G4).
- **Decision**:
  1. Fold hermetic sandbox + BMC into `benctl.sh` as an opt-out deep-test stage (default ON).
  2. Fix sandbox hermetic env to resolve python and pass `PY_BIN` so SBOM/VC validators run in `env -i` (previously invalid CycloneDX false-failure).
  3. Extend negative suite to 21 tests: prompt-injection and multi-injection via `runtime_gate.py`.
  4. Add daily `P_runtime` self-check to the cron monitor PASS path.
  5. Route cron REPAIR through `benctl.sh`.
- **Status**: Accepted. v0.8.0. Verified: benctl rc 0, negative 21/21, sandbox PASS, BMC UNSAT.

## ADR-15: Phase 12 — Continuous Runtime Watcher, WASI Sandbox Execution, Ed25519 Manifest Attestation & High-Risk HITL Negative Gates (v0.9.0)

- **Status**: Accepted (2026-10-31)
- **Context**: Post-P11 verification left four architectural gaps: (1) runtime gate only ran in batch mode, lacking a continuous incremental watcher; (2) WASI runtime sandbox was simulated purely by `env -i` shell isolation; (3) manifest signing was optional without an executable offline attestation pipeline; (4) adversarial suite lacked explicit negative tests for HITL credential approval and system prompt override attacks.
- **Decisions**:
  1. Built `scripts/runtime-gate-watch.py` supporting byte-offset incremental tracking, periodic heartbeat auditing, and immediate injection rejection.
  2. Hardened failover watchdog scheduled task (`Hermes-HardGate-Watchdog-Failover`) with robust file-mtime detection, achieving verified Last Result 0.
  3. Provisioned `wasmtime` engine and introduced `wasi-sandbox-check.py` to exercise true WebAssembly bytecode sandboxed execution within `benctl.sh` deep tests.
  4. Implemented `sigstore-pipeline.sh` executing deterministic Ed25519 signing + verification over the canonical manifest (with Cosign provisioned for keyless blob checks).
  5. Expanded adversarial suite to 23 tests with Test 22 (high-risk credential execution rejected without HITL approval) and Test 23 (system prompt override rejected via runtime gate).
  6. Scheduled `Hermes-HardGate-Weekly-Summary` weekly task and enriched `dashboard.html` with real-time gate execution and oracle status cards.
- **Consequences**:
  - Full P12 implementation delivered without external network dependencies.
  - Test suite coverage stands at 23/23 negative tests, 6/6 unit tests, and 171/171 routing matrix checks.

## ADR-16: Phase 13 — VSA, Transparency Merkle, Zero-Trust PEP, Auto-Repair & Traceability (v0.10.0)

- **Status**: Accepted (2026-10-31)
- **Context**: Post-P12 review (G1–G12) prioritized: runtime enforcement maturity, tamper-evident local log, offline attestation metadata, and spec→code traceability.
- **Decisions**:
  1. VSA (`vsa-attestation.py`) + Ed25519 signing/verification (`check-vsa.py`), integrated into `benctl.sh` deep test.
  2. Append-only Merkle transparency (`transparency-log.py`) over audit events; tamper → FAIL (Test 26).
  3. Keyless OIDC probe (`keyless-check.py`) reports availability honestly (CI vs local).
  4. Zero-Trust PEP (`zero-trust-pep.py`) wraps `runtime_gate` per-session allow/deny.
  5. Negative suite expanded to 26/26 (Tests 24–26) with secrets & output-structure fixtures.
  6. Auto-Repair (`auto-repair.sh`) isolates drifted replica to quarantine, re-syncs, re-verifies; wired into cron REPAIR.
  7. EU CRA conformity mapping added as BAGIAN 21.
  8. Traceability matrix (`traceability.py`) covering 11 spec anchors.
  9. Dashboard trend + publish to `docs/` + CI deploy job; weekly task fired.
- **Consequences**: full offline determinism preserved; keyless honestly gated on CI; negative suite 26/26.

## ADR-17: Phase 14 — Merkle-VSA binding, daily anchors, model/VC enforcement defaults & 12-record settlement (v0.11.0)

- **Status**: Accepted (2026-10-31)
- **Context**: P13 meninggalkan: root Merkle belum terikat ke VSA; `P_model_signed`/VC hanya opsional; 12 record UNVERIFIED belum diselesaikan; keyless hanya probe.
- **Decisions**:
  1. VSA membawa digest Merkle root; `P_transparency` = (recompute root == stored == VSA subject).
  2. Anchor harian root tertanda (`daily-root-anchor.sh`) + alert drift antar-hari di cron.
  3. `HARD_GATE_MODEL_SIGNED=1` default; Test 27 (mismatch ditolak).
  4. VC revocation end-to-end diuji (Test 28).
  5. BAGIAN 22 (AI RMF + justifikasi SBOM) ditambahkan.
  6. 12 UNVERIFIED di-re-settle dari `merged_records.json` (settle-unverified.py); spec 18.3 kini 213 VERIFIED.
  7. Keyless OIDC + `gh attestation verify` di-wire di CI (job `keyless-attest`); lokal tetap Ed25519.
- **Consequences**: negative suite 28/28; seluruh 12 record kini boleh disitasi; keyless jujur gated dan.

## ADR-18: Phase 15 — status-matrix detection fixes, benctl --quick, fresh-machine wiring & AI RMF predicate (v0.12.0)

- **Status**: Accepted (2026-10-31)
- **Context**: P14 meninggalkan SBOM/opa terdeteksi false, tanpa quick gate untuk cron, fresh-machine tidak ter-wire, dan BAGIAN 22 hanya dokumentasi.
- **Decisions**:
  1. `status-matrix.py`: `sbom_present` cek meta dir + project-root; `opa` fallback `~/bin/opa.exe`/OPA_BIN (dengan versi); tambah `P_transparency` ke static predicates.
  2. `benctl.sh --quick`: incremental tree-sig (verify-incremental.sh) → skip deep bila tidak berubah; fallback full bila berubah.
  3. `verify-fresh-machine.sh` di-wire ke deep (guard `HARD_GATE_FRESH=1`), arg = canonical skill dir; verified.
  4. Cron harian pakai `benctl.sh --quick --no-report`.
  5. `traceability.py` MAP diperluas 11→15 anchor.
  6. `P_ai_rmf` (NIST AI RMF) ditambahkan ke gate_predicates.py + deep benctl.
- **Consequences**: debug drastis pada cron (50s→15s); status-matrix konsisten (sbom/opa true); BAGIAN 22 kini ber-predicate.

## ADR-19: Phase 16 — OPA enforcement, launcher validation, model-hashes live & negative telemetry (v0.13.0)

- **Status**: Accepted (2026-10-31)
- **Context**: OPA terprovision tapi tidak dieksekusi di gate; launcher task tidak tervalidasi; `P_model_signed` dormant; `negative_test_count` hanya regex statis.
- **Decisions**:
  1. `verify-hard-gate.sh`: jalankan `opa-policy-check.py` default ON (`${HARD_GATE_OPA_ENFORCE:-1}`); skip(0)/deny(1)/fail(2) → `OPA_OK` masuk verdict.
  2. `verify-incremental.sh`: `tree_sig` diperluas ke fixtures/tests/policies/gate.conf.
  3. Launcher harian divalidasi via `schtasks /Run` → chain `.cmd`→cron→`benctl --quick` (Last Result 0).
  4. `status-matrix.py`: `negative_declared` (dari `TOTAL_TESTS`) vs `present`; exit 1 bila inkonsisten.
  5. Sample `model-hashes.json` (→ `docs/dashboard.html`) mengaktifkan `P_model_signed`; Test 29 menolak assets kosong.
  6. Dashboard + kartu `OPA Enforce`/`Model-hashes`.
- **Consequences**: gate kini menegakkan Rego; quick gate sensitif thd perubahan fixture; predikat model live; telemetri negatif mendeteksi drift; suite 29/29.

## ADR-20: Phase 17 Live Runtime Audit, SBOM Orchestration & Telemetry (2026-10-31)
- **Status**: Accepted
- **Context**: Spesifikasi gate sebelumnya hanya memindai fixture statis pada alur harian dan SBOM tidak diregenerasi otomatis saat dependensi bertambah. Peringatan budget hanya berbentuk hard stop tanpa threshold proaktif.
- **Decision**:
  1. Cron harian memanggil `runtime-monitor.sh` untuk memindai `agent.log` nyata.
  2. `benctl.sh` mengintegrasikan regenerasi CycloneDX SBOM otomatis via `generate-sbom.py`.
  3. Scheduled task mingguan mengeksekusi deep test penuh dan `cost-report.py` dengan alert threshold 80%.
  4. Perluasan traceability matrix menjadi 20 spec anchors terverifikasi 100%.
  5. Status keyless attestation CI dicatat `BLOCKED-BY-REMOTE` sesuai layer Settlement Ladder.
- **Consequences**: Seluruh siklus audit kini mencakup log runtime nyata, dependensi selalu sinkron dalam SBOM, dan pengawasan biaya lebih adaptif.
## ADR-21: Phase 18 Spec Parity, Concurrency Guard & Atomic Manifest (2026-10-31)
- **Status**: Accepted
- **Decision**:
  1. Predicate `P_spec_parity` menolak spesifikasi/klaim jumlah uji yang basi.
  2. `benctl.sh` di-lock single-flight (atomic mkdir) untuk mencegah race baseline/SBOM.
  3. `generate-dashboard.py` memperbarui manifest self-referencing secara atomik dengan hash file riil (CRLF-correct).
  4. `runtime_audit_latest` diekspos di status-matrix.
- **Consequences**: Dokumentasi spesifikasi selalu sinkron dengan suite aktual; eksekusi gate aman dijalankan paralel/terjadwal; hash manifest tidak basi siluman.
## ADR-22: Phase 19 Integrated Negative/Health Suite, Daily Cost Alert, Spec Version & Routing Coverage (2026-10-31)
- **Status**: Accepted
- **Decision**:
  1. `benctl --redgreen` mengintegrasikan negative suite + routing-health di fase report.
  2. `P_spec_parity` dinamis terhadap `TOTAL_TESTS`.
  3. Cron harian menjalankan alert budget threshold 80%.
  4. Spec diberi header versi; status-matrix memvalidasi `spec_version_consistent`.
  5. routing-health menghitung coverage dan dashboard menampilkan Spec v & Routing cov.
- **Consequences**: Satu perintah membuktikan seluruh gerbang; drift biaya & versi spec terdeteksi harian/otomatis.
## ADR-23: Phase 20 Full-Suite Orchestration & Matrix Telemetry (2026-10-31)
- **Status**: Accepted
- **Decision**: 1) unit test diintegrasikan ke `benctl --redgreen`; 2) status-matrix mengekspos `routing_coverage`; 3) traceability diperluas ke 27 anchors; 4) dashboard menampilkan Budget usage %.
- **Consequences**: Satu perintah membuktikan seluruh gerbang (deep/adversarial/routing/unit); telemetri matriks & dashboard lebih lengkap.
## ADR-24: Phase 21 Matrix Traceability & Audit Rotation (2026-10-31)
- **Status**: Accepted
- **Decision**: 1) status-matrix mengagregasi traceability; 2) weekly-summary menyertakan coverage & spec version; 3) audit log dirotasi (threshold 512KB → archive) di cron harian.
- **Consequences**: Dashboard-of-record & ringkasan mingguan lengkap; audit log tidak tumbuh tanpa batas, riwayat tervalidasi di archive.
## ADR-25: Phase 22 Scheduled-Task Evidence & Traceability 28 (2026-10-31)
- **Status**: Accepted
- **Decision**: 1) traceability diperluas ke 28 anchors; 2) verifikasi scheduled task pakai `schtasks /FO CSV /V` (parser robust), daily run dibuktikan Last Result 0; 3) rotasi audit log juga dijalankan mingguan.
- **Consequences**: Status penjadwalan runtime terkonfirmasi (bukan hanya grep launcher); retensi log konsisten harian+mingguan.

## ADR-26: Phase 23 Fresh Default, Actionable Coverage & Gate Verdict (2026-10-31)
- **Status**: Accepted
- **Decision**:
  1. Default-kan `HARD_GATE_FRESH=1` di `gate.conf` dan `benctl.sh` agar fresh-machine reproducibility aktif otomatis pada deep verification.
  2. Perluas `routing-health.py` untuk menyertakan daftar `unresolved` pada sidecar `.hard-gate-meta/routing-coverage.json`.
  3. Tambahkan pembacaan audit log ke `status-matrix.py` untuk mengekspos `last_gate_status` dan `last_gate_ts`.
  4. Perluas `traceability.py` ke 31 spec anchors (100% resolve) dan tambahkan kartu `Gate Verdict` pada dashboard.
  5. Catat job CI keyless attestation tetap `BLOCKED-BY-REMOTE` secara transparan.
- **Consequences**: Deep verification selalu membuktikan fresh reproducibility; status riil gate terekam di matrix; coverage routing dapat ditindaklanjuti secara presisi.

## ADR-27: Phase 24 Spec Parity, Git Baseline & Fresh-Guard Negative Test (2026-10-31)
- **Status**: Accepted
- **Decision**: 1) Dokumen P23 (fresh default, gate verdict, unresolved sidecar) ke BAGIAN 19.3 spec; 2) commit baseline git (eksklusi meta via info/exclude); 3) Test 30 untuk guard fresh default-ON + warning OFF jujur (TOTAL_TESTS=30).
- **Consequences**: Spec selaras dengan implementasi; riwayat drift dapat dilacak via git; fresh reproducibility tak bisa di-silence tanpa catatan.

## ADR-28: Phase 25 Hook Hardening & Weekly Gate-Verdict Telemetry (2026-10-31)
- **Status**: Accepted
- **Decision**: 1) pre-commit hook mengecualikan .sig/.bin dari whitespace --check (commit normal tanpa --no-verify); 2) weekly-summary.py menampilkan last gate verdict; 3) CI keyless tetap BLOCKED-BY-REMOTE.
- **Consequences**: Guard commit pulih (tanpa bypass); paritas observability lengkap di matrix/dashboard/weekly.

## ADR-29: Phase 26 Agent-Runtime Hardening (2026-10-31)
- **Status**: Accepted
- **Decision**: Tambah P_rt_ifc, P_rt_plan_drift, P_rt_tool_schema di runtime_gate.py; OPA Rule 7 tool-policy; Test 31/32 (TOTAL_TESTS=32).
- **Consequences**: Runtime gate menolak cross-boundary trust flow, urutan tool drift, dan param tool invalid; OPA menegakkan allowlist tool.

## ADR-30: Phase 26 lanjutan — Throttle/Msg-Auth/Token-Scope/AIBOM/Redteam (2026-10-31)
- **Status**: Accepted
- **Decision**: Tambah P_rt_throttle, P_rt_msg_auth, validasi token scoped di P_rt_secrets, P_ai_bom; mode benctl --redteam; Test 33/34 (TOTAL_TESTS=34).
- **Consequences**: Blast-radius dibatasi; anti-spoofing antar-agent; model manifest AIBOM diverifikasi; red-team dapat dijalankan tanpa menyentuh prod.
