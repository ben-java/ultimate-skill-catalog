#!/usr/bin/env bash
# daily-root-anchor.sh — P14-A2: daily signed-root snapshot.
# Writes <meta>/anchors/root-<date>.txt (hex root) + Ed25519 signature, then
# verifies the latest existing anchor. Exit 0 PASS, 1 FAIL, 2 missing deps.
set -euo pipefail
ROOT="${1:-C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog}"
META="$ROOT/.hard-gate-meta"
PY="${PYTHON:-python3}"
ANCH="$META/anchors"
KEY="$META/sigstore/manifest.ed25519.key"
PUB="$META/sigstore/manifest.ed25519.pub"
mkdir -p "$ANCH"
[ -f "$KEY" ] && [ -f "$PUB" ] || { echo "anchor: keypair missing"; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "anchor: openssl missing"; exit 2; }
TL="$META/transparency.merkle.json"
[ -f "$TL" ] || { echo "anchor: transparency log missing"; exit 2; }

# current root
ROOT_HEX=$("$PY" -c "import json,sys; print(json.load(open(sys.argv[1],encoding='utf-8'))['root'])" "$TL")
DATE=$(date +%Y%m%d)
TXTF="$ANCH/root-$DATE.txt"
SIGF="$ANCH/root-$DATE.sig"
printf '%s\n' "$ROOT_HEX" > "$TXTF"
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$TXTF" -out "$SIGF"
openssl pkeyutl -verify -pubin -inkey "$PUB" -rawin -in "$TXTF" -sigfile "$SIGF" >/dev/null 2>&1
echo "anchor: signed root for $DATE ($ROOT_HEX)"
# verify most recent anchor
LATEST=$(ls -1 "$ANCH"/root-*.txt 2>/dev/null | tail -1)
if [ -n "$LATEST" ] && [ -f "${LATEST%.txt}.sig" ]; then
  openssl pkeyutl -verify -pubin -inkey "$PUB" -rawin -in "$LATEST" -sigfile "${LATEST%.txt}.sig" >/dev/null 2>&1
  echo "anchor: OK (latest $(basename "$LATEST"))"
  exit 0
fi
echo "anchor: no anchor to verify"; exit 1
