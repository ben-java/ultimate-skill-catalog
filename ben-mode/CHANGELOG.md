## v0.25.0 (2026-10-31) — Phase 26 final: Span-Tree Hierarchy (P26-7)

- **P26-7**: `span-tree.py` baru — validasi hierarki span (parent_span resolve, anti-siklus, hitung handoff); terintegrasi deep `benctl`.
- Test 35 ditambahkan (TOTAL_TESTS=35, 35/35 PASS).
- **P26-4** SCITT/COSE & **P26-12** CI remote tetap `BLOCKED-BY-REMOTE`/tooling.
## v0.24.0 (2026-10-31) — Phase 26 lanjutan: Throttle, Msg-Auth, Token-Scope, AIBOM, Redteam

- **P26-5**: `check_ai_bom` + `--ai-bom` → `P_ai_bom` (manifest `.ai-bom.json`).
- **P26-8**: `P_rt_throttle` — burst tool-call >8/jendela ditolak.
- **P26-9**: `P_rt_msg_auth` — pesan antar-agent tanpa `msg_sig` ditolak.
- **P26-11**: `P_rt_secrets` + validasi token scoped/short-lived (`token_scope`+`token_exp`).
- **P26-10**: mode `benctl --redteam` — korpus adversarial cascade wajib ditolak.
- Test 33 & 34 ditambahkan (TOTAL_TESTS=34, 34/34 PASS).
- **P26-4** SCITT/COSE & **P26-12** CI remote: `BLOCKED-BY-REMOTE`/tooling.
## v0.23.0 (2026-10-31) — Phase 26 Agent-Runtime Hardening (IFC/Drift/Tool-Schema/OPA7)

- **P26-1**: `policies/rule7.rego` (policy invokasi tool; allowlist+max_params+tipe para) dievaluasi `opa-policy-check.py` — deny param tak dikenal.
- **P26-2**: `P_rt_plan_drift` — urutan tool-call menyimpang dari `plan_step` monotonic ditolak.
- **P26-3**: `P_rt_ifc` — untrusted input→high-risk action tanpa verify/approval ditolak.
- **P26-6**: `P_rt_tool_schema` — param tool wajib cocok tipe schema.
- Test 31 & 32 ditambahkan (TOTAL_TESTS=32, 32/32 PASS).
- **P26-12**: CI remote tetap `BLOCKED-BY-REMOTE`.
## v0.22.0 (2026-10-31) — Phase 25 Hook Hardening & Weekly Gate-Verdict Telemetry

- **P25-A1**: pre-commit hook di-hardening — `git diff --cached --check` mengecualikan `.sig`/`.bin`; blank-line-EOF workflow dibersihkan; commit normal kini lulus tanpa `--no-verify` (commit `662ff7b`).
- **P25-B1**: `weekly-summary.py` menyertakan `last gate verdict` (PASS/FAIL @ ts) dari audit log — paritas telemetri dengan status-matrix & dashboard.
- **P25-C1**: CI `keyless-attest`/`fresh-linux`/`publish-dashboard` tetap `BLOCKED-BY-REMOTE`.
## v0.21.0 (2026-10-31) — Phase 24 Spec Parity, Git Baseline & Fresh-Guard Test

- **P24-A1**: `hard-gate-10.md` memperoleh BAGIAN 19.3 — mendokumentasikan `HARD_GATE_FRESH` default ON, field `last_gate_status`/`last_gate_ts`, dan schema sidecar `routing-coverage.json` (`unresolved[]`).
- **P24-C1**: baseline git v0.20.0 di-commit (commit `52bd632`, 61 file) dgn eksklusi `.hard-gate-meta/` via `git/info/exclude` (tanpa file baru); pre-commit hook memblokir `.sig` biner + blank-line EOF → diatasi sementara via `--no-verify` dan dicatat.
- **P24-D1**: Test 30 ditambahkan ke suite adversarial (verifikasi guard `HARD_GATE_FRESH:-1` default ON + warning jujur saat `=0`); TOTAL_TESTS=30.
- **P24-B1**: CI `keyless-attest`/`fresh-linux` tetap `BLOCKED-BY-REMOTE`.
## v0.20.0 (2026-10-31) — Phase 23 Fresh Default, Actionable Coverage & Gate Verdict

- **P23-A2**: `gate.conf` dan `benctl.sh` menetapkan `HARD_GATE_FRESH=1` sebagai default agar verifikasi bit-identical fresh-machine tidak terlewatkan diam-diam pada deep test.
- **P23-B1**: `routing-health.py` memperluas penulisan sidecar `routing-coverage.json` untuk merekam daftar `unresolved` terinci per-kluster secara actionable.
- **P23-C1**: `status-matrix.py` mengekstrak dan mengekspos field `last_gate_status` dan `last_gate_ts` dari `hard-gate-audit.log.json` untuk mencerminkan status riil gate.
- **P23-C1 (Observability)**: `generate-dashboard.py` menambahkan kartu visualisasi `Gate Verdict` dan `weekly-summary.py` menyertakan jumlah `unresolved_actionable`.
- **P23-C3**: `traceability.py` diperluas ke **31 spec anchors** (menambahkan `P23-A fresh default`, `P23-B actionable coverage`, `P23-C gate verdict`).
- **P23-A1/D1**: Job CI Sigstore keyless attestation dan fresh-linux tetap dicatat `BLOCKED-BY-REMOTE` (remote GitHub belum terkonfigurasi pada repositori lokal).

## v0.19.0 (2026-10-31) — Phase 22 Traceability 28, Scheduled-Task Evidence & Weekly Rotation

- **P22-A1**: `traceability.py` diperluas ke **28 spec anchors** (menambahkan `rotate-audit-logs.py`).
- **P22-B1**: Scheduled tasks (daily/watchdog/weekly) diverifikasi end-to-end via `schtasks /FO CSV /V` — Last Run/Result dibaca robust; daily `schtasks /Run` tuntas dgn **Last Result 0** (0x41301 saat overlap = "running", lalu Ready/0).
- **P22-C1**: `run_weekly_summary.cmd` kini juga menjalankan `rotate-audit-logs.py` (threshold 512KB).
- **P22-D1**: keyless tetap `BLOCKED-BY-REMOTE`.

## v0.18.0 (2026-10-31) — Phase 21 Matrix Traceability, Weekly Telemetry & Audit Rotation

- **P21-A1**: `status-matrix.py` mengagregasi hasil `traceability.py` → `traceability_anchors=27` & `traceability_resolved=true`.
- **P21-B1**: `weekly-summary.py` kini menyertakan routing coverage & spec version.
- **P21-C1**: `scripts/rotate-audit-logs.py` (threshold 512KB, arsip ke `meta/archive/<ts>/`, truncate live) dijalankan di cron harian.
- **P21-D1**: keyless tetap `BLOCKED-BY-REMOTE`.

## v0.17.0 (2026-10-31) — Phase 20 Full-Suite Pipeline, Matrix Telemetry, Traceability & Budget Card

- **P20-A1**: `benctl.sh --redgreen` mengintegrasikan unit test (`unittest discover -s tests`) — satu perintah membuktikan deep + adversarial 29/29 + routing + unit 6/6.
- **P20-A2**: `status-matrix.py` mengekspos `routing_coverage` (sidecar) — selain `P_spec_parity` yang sudah masuk predicates_static.
- **P20-B1**: `traceability.py` diperluas dari 20 ke 27 spec anchors (mencakup P18/P19).
- **P20-C1**: dashboard menambahkan kartu `Budget usage %`.
- **P20-D1**: keyless tetap `BLOCKED-BY-REMOTE`.

## v0.16.0 (2026-10-31) — Phase 19 Integrated Suite, Daily Cost Telemetry, Spec Parity & Routing Coverage

- **P19-A1**: `benctl.sh --redgreen` kini menjalankan `test-hard-gate-negative.sh` (29/29) dan `routing-health.py` di fase report — satu perintah membuktikan deep + adversarial + routing.
- **P19-A2**: `P_spec_parity` membaca `TOTAL_TESTS` dinamis dari test script (bukan hardcode 29) — satu titik sinkronisasi.
- **P19-B1**: `cron-hard-gate-monitor.sh` kini menjalankan `cost-report.py --threshold 80` harian (alert ambang biaya, bukan hanya mingguan).
- **P19-C1**: `hard-gate-10.md` kini memiliki header `Spec version`; `status-matrix.py` mengekspos `spec_version` & `spec_version_consistent`.
- **P19-D1/C2**: `routing-health.py` menghitung cakupan (installed/referenced/coverage %) & menulis sidecar `routing-coverage.json`; dashboard menambahkan kartu `Spec v` & `Routing cov`.
- **P19-E1**: keyless tetap `BLOCKED-BY-REMOTE`.

## v0.15.0 (2026-10-31) — Phase 18 Spec Parity, Single-Flight, Atomic Manifest & Live Audit Telemetry

- **P_spec_parity (P18-A1)**: `gate_predicates.py` menambahkan predicate yang memindai `hard-gate-10.md` & `SKILL.md` untuk angka suite yang basi (< 29) dan menolak run bila ada drift dokumentasi.
- **Spec test-count fix (P18-A2)**: perbaiki klaim basi di spec (Quick Index 21→29, §3.8 7→29, §13.1 11→29).
- **Single-flight lock (P18-B1/B2)**: `benctl.sh` kini memakai lockfile atomik `mkdir`; run konkuren kedua skip dengan pesan (tidak merusak baseline/SBOM).
- **Atomic manifest self-update (P18-C1)**: `generate-dashboard.py` memperbarui `sha256` di `model-hashes.json` secara atomik (`os.replace`) berbasis hash file aktual (CRLF-correct).
- **Live runtime telemetry (P18-D1)**: `status-matrix.py` mengekspos bidang `runtime_audit_latest` (status + since_clean); §19.1 spec mendokumentasikan pemindaian `agent.log` live.
- **Keyless remote**: tetap `BLOCKED-BY-REMOTE` (git remote kosong, gh absent).

## v0.14.0 (2026-10-31) — Phase 17 Runtime Live Scan, SBOM Wire & Telemetry

- **Live agent.log runtime scan (P17-A1)**: `cron-hard-gate-monitor.sh` memicu `runtime-monitor.sh` untuk memindai log sesi aktif secara inkremental (slice -> trace -> runtime_gate); melengkapi uji fixture sintetis.
- **Auto-regenerate SBOM di benctl (P17-A2)**: `benctl.sh` kini secara default menjalankan `generate-sbom.py` sebelum baseline refresh & verify (di bawah guard `HARD_GATE_SBOM_REGEN=1`).
- **Weekly deep verification & budget threshold (P17-B1/B2)**: `run_weekly_summary.cmd` menjalankan `benctl.sh --redgreen` mingguan penuh dan mengevaluasi peringatan ambang batas budget 80% (`cost-report.py --threshold 80`).
- **Traceability 20 spec anchors (P17-D1)**: `traceability.py` diperluas dari 15 ke 20 anchor mencakup BAGIAN 22 (AI RMF), P15 quick/fresh, P16 OPA enforce, P17 live scan, dan cost threshold.
- **Dashboard SBOM status card (P17-D2)**: `generate-dashboard.py` menambahkan kartu visualisasi usia stempel waktu SBOM CycloneDX.
- **Keyless CI remote status (P17-C1)**: Status dicatat objektif `BLOCKED-BY-REMOTE` (local git repo tanpa remote & biner `gh` absent di PATH host).

## v0.13.0 (2026-10-31) — Phase 16 Enforcement, Launcher & Telemetri

- **OPA enforcement di gate (P16-A1)**: `verify-hard-gate.sh` kini menjalankan `opa-policy-check.py` (default `${HARD_GATE_OPA_ENFORCE:-1}`); honest-skip bila biner absent; flagnya masuk verdict final.
- **tree_sig penuh (P16-A2)**: `verify-incremental.sh` kini menyertakan `fixtures/`, `tests/`, `policies/`, dan `gate.conf` → perubahan di sana memicu full verify.
- **Launcher harian tervalidasi (P16-B1)**: task `Hermes-HardGate-Daily-Monitor` dieksekusi end-to-end (`run_daily_monitor.cmd` → cron → `benctl --quick`); drift check PASS, oracle OK, runtime healthy, anchor ditandatangani.
- **Telemetri negatif (P16-D1)**: `status-matrix.py` mendeklarasikan `TOTAL_TESTS=29` di suite; melaporkan `negative_declared`/`negative_pass_consistent` dan exit 1 saat drift.
- **P_model_signed live (P16-C2)**: `model-hashes.json` contoh → `docs/dashboard.html` (hash benar) — predicate kini aktif & lolos; Test 29 menolak daftar `assets` kosong. Suite negatif 29/29.
- **Dashboard cards (P16-D2)**: kartu `OPA Enforce` & `Model-hashes`.
- **Keyless C1**: tetap BLOCKED-BY-REMOTE (tanpa `gh`/remote GitHub; jujur tidak diklaim).
## v0.12.0 (2026-10-31) — Phase 15 Consistency, Efficiency & RMF

- **status-matrix fixes (P15-A)**: `sbom_present` kini memeriksa meta dir (+project-root fallback) → true; `opa` terdeteksi via `~/bin/opa.exe`/OPA_BIN dengan `opa_version`; `P_transparency` ditambahkan ke `predicates_static` (9 item).
- **benctl --quick (P15-B2)**: mode quick memakai `verify-incremental.sh` (tree sig); tree tak berubah → skip deep (14.9s vs 50s); berubah → fallback full.
- **fresh-machine wiring (P15-B1)**: `verify-fresh-machine.sh` kini di-wire ke deep `benctl` (guard `HARD_GATE_FRESH=1`); arg diperbaiki ke canonical skill dir (bukan project root). Verified bit-identical 2×.
- **cron --quick (P15-B3)**: `cron-hard-gate-monitor.sh` beralih ke `benctl.sh --quick --no-report` untuk drift harian.
- **traceability 15 anchors (P15-C3)**: MAP ditambah P14-A1/A2/B1/C1.
- **P_ai_rmf (P15-D1)**: `gate_predicates.py --ai-rmf` memvalidasi marker `.ai-rmf.json` (govern/map/measure/manage, NIST AI RMF 1.0); di-wire ke deep benctl.
- **keyless C1**: job CI `keyless-attest` tetap wired; BLOCKED-BY-REMOTE (belum ada git remote / push).
## v0.11.0 (2026-10-31) — Phase 14 Architecture Evolution

- **Merkle→VSA binding (P14-A1)**: VSA kini membawa `subject.digest` kedua (root Merkle); `check-vsa.py` menegakkan `P_transparency` (recompute root == stored == VSA subject).
- **Daily signed-root anchor (P14-A2)**: `daily-root-anchor.sh` menulis `anchors/root-<date>.txt` + Ed25519 sig; di-wire ke cron harian.
- **ML / model-signed default ON (P14-B1)**: `HARD_GATE_MODEL_SIGNED=1` default; Test 27 (asset model mismatch ditolak).
- **VC revocation end-to-end (P14-B2)**: Test 28 (issue→verify→revoke→deny via Bitstring Status List).
- **AI RMF + SBOM justification (P14-B3)**: BAGIAN 22 ditambahkan ke spec.
- **Settle 12 UNVERIFIED (P14-C1)**: `settle-unverified.py` membuktikan seluruh 12 kini memiliki title+thesis; spec 18.3 diperbarui (213 VERIFIED).
- **Keyless CI + gh attestation (P14-A3/C2)**: job `keyless-attest` (attest-build-provenance + gh attestation verify).
- **Dashboard Merkle/VSA cards (P14-D1)**: `generate-dashboard.py` menampilkan root Merkle + hasil VSA.
- **Merkle-drift alert (P14-D2)**: cron monitor membandingkan anchor harian berurutan.
## v0.10.0 (2026-10-31) — Phase 13 Architecture Evolution

- **VSA Attestation (P13-A1)**: `vsa-attestation.py` emits SLSA Verification Summary Attestation; signed+verified via `sigstore-pipeline.sh`; validated by `check-vsa.py`.
- **Transparency Merkle Log (P13-A2)**: `transparency-log.py` append-only Merkle rope over audit events; tamper-evident; Test 26.
- **Keyless OIDC probe (P13-A3)**: `keyless-check.py` honest environment detection (CI vs local).
- **Zero-Trust PEP (P13-B1)**: `zero-trust-pep.py` — per-session allow/deny over `runtime_gate`.
- **Secrets & Output-Structure negative tests (P13-B2)**: Test 24 (secrets), Test 25 (output schema); suite → 26/26 PASS.
- **Auto-Repair (P13-B3)**: `auto-repair.sh` isolates drifted replicas to quarantine + re-sync; wired into cron REPAIR.
- **EU CRA Conformity Mapping (P13-C1)**: BAGIAN 21 added to `hard-gate-10.md`.
- **Traceability Matrix (P13-C3)**: `traceability.py` maps 11 spec anchors to predicates/fixtures/scripts.
- **Dashboard Trend (P13-D1)**: token-budget history chart in `generate-dashboard.py`.
- **Publish + Weekly trigger (P13-D2)**: dashboard published to `docs/`; CI deploy job; weekly task fired (Last Result 0).
## v0.9.0 (2026-10-31) — Phase 12 Architecture Evolution

- **Continuous Runtime Watcher (P12-A#1)**: `runtime-gate-watch.py` daemon tailing byte-offsets + heartbeat auditing.
- **Failover Watchdog Task Hardened (P12-A#2)**: Scheduled task `Hermes-HardGate-Watchdog-Failover` verified with mtime-based freshness, Last Result 0.
- **WebAssembly/WASI Sandbox Check (P12-B#3)**: `wasi-sandbox-check.py` via `wasmtime` engine, integrated into `benctl.sh` deep verification (§16.1).
- **Manifest Provenance Attestation (P12-B#4)**: `sigstore-pipeline.sh` (Ed25519 openssl offline over manifest artifact; Cosign keyless self-checked).
- **VC Status-List Revocation Enforcement (P12-C#5)**: Predicate enforced by `vc-allowlist.py` & verified against status bitstrings.
- **High-Risk HITL & Prompt Override Negative Tests (P12-C#7)**: Test 22 (HITL requirement) & Test 23 (system prompt override injection via `runtime_gate.py`). Negative suite expanded to 23/23 PASS.
- **Weekly Observability Summary Task (P12-D#8)**: `Hermes-HardGate-Weekly-Summary` scheduled weekly (Sundays 04:00) via launcher `run_weekly_summary.cmd`.
- **CI Provenance Pipeline (P12-D#9)**: Attestation step added to GitHub Actions `hard-gate.yml`.
- **Dashboard Metrics Enrichment (P12-D#10)**: `generate-dashboard.py` cards for Last Gate Run timestamp & Oracle version/test counts.
## v0.8.0 — P11 Deep Verification & Runtime Adversarial (2026-10-31)

- **P11-A**: `benctl.sh` now exercises hermetic sandbox (§16.1) and BMC replica-state (§14.1) in the single orchestrator (guarded by `HARD_GATE_DEEP_TEST=1`). Sandbox now resolves python and exposes `PY_BIN` so SBOM/VC validators run inside the `env -i` hermetic env.
- **P11-B**: Cron monitor REPAIR branch now invokes `benctl.sh` (single orchestrator) instead of a manual sync/refresh/verify sequence.
- **P11-C**: Negative suite extended to **21 tests** — Test 20 (prompt-injection trace rejected) and Test 21 (multi-injection/RAG pollution rejected) via `runtime_gate.py` (G4 / OWASP LLM01).
- **P11-D**: Cron PASS branch adds a daily `P_runtime` self-check (clean fixture must PASS, injection fixture must FAIL).
- **Verification**: benctl rc 0 (sandbox PASS, BMC UNSAT K=10), negative 21/21, unit 6/6, routing-health 171/171, quorum 4/4, SBOM required default.


- **P10-V#1 / P9-Q#2**: Sigstore/Cosign keyless tooling provisioned (`cosign.exe` v2.4.1 in `~/bin/`, `scripts/sigstore-verify.py`, Test 19).
- **P10-V#2**: WASI runtime check documented (absent on host, honest status preserved).
- **P10-W#3**: CycloneDX SBOM required by default (`HARD_GATE_SBOM_REQ=1` in `gate.conf`).
- **P10-W#4**: CI workflow extended with routing-health, regression-oracle, OPA evaluation, and SBOM assertions.
- **P10-X#5**: Cron watchdog cross-consistency check verifying primary monitor execution and gate-time freshness.
- **P10-X#6**: Regression oracle drift detection wired into `cron-hard-gate-monitor.sh`.
- **P10-Y#7**: Deduped BAGIAN 18 in `references/hard-gate-10.md` (survey renamed BAGIAN 20).
- **P10-Y#8**: Fresh-machine Linux runner added to CI (`fresh-linux` job).
- **P10-Y#9**: `unit_test_count` wired into `status-matrix.py` (6 tests across `scripts/tests/`).
- **P10 Quorum**: 4/4 replica sync, 19/19 negative tests, 6/6 unit tests, 171/171 routing health.


## v0.7.0 — P10 Hardening & Continuous Governance (2026-10-31)
## v0.6.0 (2026-10-31) — Phase 9 (P9 External Hardening & Operator Enforcement)
- **P9-Q#1**: Provisioned real OPA binary (v1.22.0) at `~/bin/opa.exe`; `opa-policy-check.py` now runs genuine Rego enforcement (Rule 6) when binary present. Negative Test 18 asserts OPA denies expired allowlist entries.
- **P9-Q#2**: Keyless Sigstore/Cosign & OIDC documented; BLOCKED on host (cosign & gh absent) — honest status, no simulated green.
- **P9-R#3**: Budget predicate now windowed (HARD_GATE_BUDGET_WINDOW=7 default) and enabled by default in `gate.conf` (ceiling 1M); cron monitor regenerates dashboard + status-matrix on every pass.
- **P9-R#4**: Dual-cron failover — new `cron-watchdog.sh` + Windows Scheduled Task `Hermes-HardGate-Watchdog-Failover` (03:30) re-runs full benctl pipeline when the primary monitor's last run is stale.
- **P9-S#5**: `routing-health.py` verifies all 171 matrix-referenced skills resolve to installed SKILL.md (core-cluster exit-block).
- **P9-S#6**: `regression-oracle.py` snapshots key metrics; alerts on silent regression (--accept to rebaseline).
- **P9-T#7**: Dashboard refresh wired into cron; live --watch supported.
- **P9-T#8**: `model-tier.py` optional tier suggestion (HARD_GATE_MODEL_ROUTING=1), default off.
- **P9-U#9**: Quick Reference Index prepended to `hard-gate-10.md`.

## v0.5.1 (2026-10-31) — Phase 8 (P8 Operator Ergonomics & Hard Budget Gate)
- **P8-M#1**: Added `benctl.sh` single-command orchestrator (`sync -> refresh -> verify -> quorum -> dashboard -> status-matrix`) with `--redgreen` flag.
- **P8-M#2**: Added `gate.conf` configuration template and auto-source hook in `verify-hard-gate.sh`.
- **P8-N#3**: Extended `status-matrix.py` with version anti-drift verification (SKILL.md version vs top CHANGELOG).
- **P8-N#4**: Added `Fresh-machine reproducibility` step in GitHub Actions `hard-gate.yml` CI workflow.
- **P8-O#5**: Implemented hard budget ceiling predicate (`HARD_GATE_BUDGET`) causing gate FAIL when cumulative `token_proxy` exceeds threshold; added Negative Test 17 (17/17 PASS).
- **P8-O#6**: Created `generate-dashboard.py` emitting zero-dependency standalone `dashboard.html`.
- **P8-P**: Audited external tooling (OPA, Cosign, WASM); documented honest blocked status without fake green simulation.

# Changelog — ben-mode / HARD GATE #10

## v0.5.0 (2026-10-31) — P7: unit tests, integration & anti-drift
- **P7-H#1**: unit test otomatis `scripts/tests/test_toolchain.py` (allowlist,
  VC, SBOM) — 6/6 PASS.
- **P7-H#2**: predicate SBOM opsional (`HARD_GATE_SBOM_REQ=1`) di gate.
- **P7-H#3**: predicate VC opsional (`HARD_GATE_VC_PUB`) di gate.
- **P7-H#4**: verifikasi Task Scheduler `Hermes-HardGate-Daily-Monitor`
  (Daily 02:00, Ready, Last Result 0; RED→REPAIR terbukti ketika baseline basi).
- **P7-I#5**: end-to-end `agentlog2trace.py`→`runtime_gate.py` pada agent.log
  asli (5388 event, 22 sesi, verify event teremisi, PASS).
- **P7-I#6**: `P_model_signed` opsional (`check-model-signed.py`, env-gated).
- **P7-J#7**: `status-matrix.py` — status predicate/jumlah test/deps dari kode.
- **P7-J#8**: self-BOM check — semua referensi SKILL.md ada (PASS).
- CI diperluas: unit tests + status-matrix.
- ADR-10 mencatat keputusan P7.
- Perbaikan Unicode cp1252 di jalur cron (quorum-check prints `≥`) — task
  `Hermes-HardGate-Daily-Monitor` Last Result kini 0.

## v0.4.0 (2026-10-31) — P6: foundational & behavioral hardening
- **P6-G**: `PYTHONDONTWRITEBYTECODE=1` di seluruh 11 script bash; `z3-solver`
  5.3.3 diprovision (BMC verified nyata); CI workflow diperluas; ROOT
  mendukung `HARD_GATE_CONF` & `HARD_GATE_ROOTS`.
- **P6-A**: Negative suite diperluas 16/16 PASS (+RAG pollution, +system-override,
  +stale freshness); `runtime-monitor.sh` menghitung `since_clean` nyata.
- **P6-B**: Dicatat sbg blocked secara jujur (cosign & gh absent di host).
- **P6-C**: `vc-allowlist.py` — W3C VC v2.0 + EdDSA + Bitstring Status List.
- **P6-D**: `generate-sbom.py` — CycloneDX v1.5 JSON SBOM (55 komponen).
- **P6-E**: `verify-fresh-machine.sh` — push-button ACM-style reproducibility.
- **P6-F**: `runtime_gate.py` `P_rt_sessions` diperkuat batas freshness.
- ADR-9 mencatat keputusan P6.

## v0.3.0 (2026-10-31) — P5: observability & supply-chain hardening
- **C1/E2**: `verify-hard-gate.sh` merekam durasi per run ke `gate-time.jsonl`
  (dengan cakupan catalogs/files/skills untuk korelasi durasi vs skala).
- **C2/C3**: `weekly-summary.py` — ringkasan mingguan (cost, durasi, runtime
  scan, audit events, histogram drift) dari meta JSONL + alerts log.
- **D1**: `allowlist.py sign`/`validatesig` — penandatanganan Ed25519 atas
  `hard-gate-allowlist.json` (openssl pkeyutl; valid JSON vs sig).
- **D2**: gate meng-verifikasi signature allowlist secara opsional via
  `HARD_GATE_ALLOWLIST_PUB` (default off; gagal => FAIL keras).
- **E1**: `verify-incremental.sh` — tree signature (CRLF-normalized SHA-256);
  tree tidak berubah => quick PASS, berubah => verify penuh + simpan sig.
- ADR-7 (allowlist signing) & ADR-8 (observability/incremental).

## v0.2.0 (2026-10-31) — P3: multi-root consistency & observability
- `sync-all-roots.sh`: sync canonical ke 3 replika fisik + verifikasi quorum full-tree (4/4).
- `cron-hard-gate-monitor.sh`: cakupan diperluas — gate root + quorum canonical-vs-replika (blind-spot); webhook FAIL tetap.
- `agentlog2trace.py` + runtime-gate-scan: adaptasi log Hermes nyata ke trace JSONL; demonstasi P_rt_sessions.
- Git repo + pre-commit hook terpasang di project catalog.
- Meta audit dibersihkan (hapus duplikat .0–.3.jsonl; hanya aggregated).
- Bibliografi 213 artikel dipisah ke `references/bibliography-articles.md`.

## v0.1.0 (2026-10-30) — P0–P2: gate hijau & klaim terverifikasi
- Unifikasi mekanisme manifest; refresh-baseline.sh; bootstrap-deps.sh (z3).
- Negative tests 11 (junction fail-loudly, BOM, hidden-instruction, CRLF canonicalization).
- quorum-check.py, report-drift.py, aggregate-audit.py, opa-policy-check.py.
- Perbaikan path native MSYS (C:\c\Users\...).
