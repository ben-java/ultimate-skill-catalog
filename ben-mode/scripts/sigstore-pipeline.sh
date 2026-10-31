#!/usr/bin/env bash
# sigstore-pipeline.sh — P12-B#4: real artifact attestation over the canonical
# manifest. Uses Ed25519 (openssl, offline) — robust on this host where cosign
# v2.4 bundle signing requires Rekor/network. cosign remains provisioned+selfchecked.
set -euo pipefail
ROOT="${1:-C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog}"
META="$ROOT/.hard-gate-meta"
BL="$META/ben-mode.manifest.json"
[ -f "$BL" ] || { echo "sigstore-pipeline: manifest missing"; exit 2; }
KEY="$META/sigstore/manifest.ed25519.key"
SIG="$BL.sig"
PUB="$META/sigstore/manifest.ed25519.pub"
command -v openssl >/dev/null 2>&1 || { echo "sigstore-pipeline: openssl missing"; exit 2; }

if [ ! -f "$KEY" ]; then
  openssl genpkey -algorithm ED25519 -out "$KEY" >/dev/null 2>&1
  openssl pkey -in "$KEY" -pubout -out "$PUB" >/dev/null 2>&1
fi
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$BL" -out "$SIG"
openssl pkeyutl -verify -pubin -inkey "$PUB" -rawin -in "$BL" -sigfile "$SIG" >/dev/null 2>&1
echo "sigstore-pipeline: Ed25519 sign+verify OK over $BL"
if [ -f "$META/vsa.json" ]; then
  openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$META/vsa.json" -out "$META/vsa.sig"
  openssl pkeyutl -verify -pubin -inkey "$PUB" -rawin -in "$META/vsa.json" -sigfile "$META/vsa.sig" >/dev/null 2>&1
  echo "sigstore-pipeline: VSA signed+verified OK"
fi
