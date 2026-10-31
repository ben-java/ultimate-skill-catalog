# Deploying HARD GATE #10 to GitHub Actions

Resep memasang workflow `hard-gate.yml` pada remote GitHub dan membuat CI benar-benar berjalan. Berlaku untuk job `gate`, `fresh-linux`, `publish-dashboard`, `keyless-attest`.

## Kickoff: repo remote + CLI
- `gh` CLI: unduh zip rilis langsung (`gh_<ver>_windows_amd64.zip`) ke `~/bin`, ekstrak → `~/bin/gh-cli/bin/gh.exe` (winget bisa timeout).
- Token OAuth tersimpan di `~/.github_token_env` (`export GH_TOKEN=...`); set `GH_TOKEN` sebagai env setiap memanggil `gh`. Scopes yang dibutuhkan: `repo`, `gist`, `workflow`. (Scope `read:org` tidak wajib dan absent — jangan diblokir karenanya.)
- `gh repo create <owner>/<name> --private --source <path> --push --remote origin` membuat repo + remote + push awal.

## Trigger (paling sering terlewat)
Workflow hanya berjalan pada event yang didaftarkan di `on:`. Default hanya `pull_request` + `workflow_dispatch` → push ke `main` TIDAK memicu apa pun; `gh run list` terus menampilkan run lama.
```yaml
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:
```

## Validasi `needs:`
`needs:` harus menunjuk nama job yang ADA persis (mis. `needs: gate`). Rujukan ke job yang tidak ada (mis. `gate-check`) membuat SELURUH run gagal dengan pesan samar ".workflow file issue" tanpa daftar job — tidak ada log per-job untuk didiagnosis. Verifikasi nama terhadap blok `jobs:` sebelum push.

## Attestation pada repo privat
`actions/attest-build-provenance` (keyless-basedIDC) TIDAK tersedia untuk repo privat milik user; run gagal: _Feature not available for user-owned private repositories_. Keputusan: publikasikan repo, atau skip job tersebut secara jujur (jangan klaim keyless verified pada repo privat).

## Parity baseline manifest di fresh clone
Baseline manifest pada `.hard-gate-meta/ben-mode.manifest.sha256` dihasilkan dari tree host lokal (baris baru CRLF, file ekstra). Pada clone CI yang bersih, tree-hash melenceng → `verify-hard-gate.sh` gagal "Manifest FAIL" padahal lokal PASS.
- Regenerasi baseline DI DALAM CI sebelum verify, agar self-consistent: `bash ben-mode/scripts/refresh-baseline.sh . ben-mode` mendahului `verify-hard-gate.sh`.
- Tegakkan canonical LF agar hash lintas-host stabil: berkas `.gitattributes` `* text=auto` + `git add --renormalize .` sekali, lalu commit; checkout CI menghasilkan LF yang cocok dengan baseline yang dihasilkan ulang.
- Meta (`.hard-gate-meta/`) yang dibutuhkan CI (manifest, sbom, gate-time, model-hashes) harus ikut di-commit — `git add -f` bila baris `.gitignore`/`info/exclude` mengecualikannya. Jangan commit kunci privat sigstore/.

## `git push` yang menggantung
`git push origin main` bisa menggantung tak berujung saat credential helper (GCM) membuka prompt interaktif. Nonaktifkan helper + sematkan token pada URL, dalam satu perintah:
```
git -c credential.helper= push https://x-access-token:$GH_TOKEN@github.com/<owner>/<repo>.git main
```
(`GIT_TERMINAL_PROMPT=0` saja tidak cukup bila GCM tetap aktif.)
