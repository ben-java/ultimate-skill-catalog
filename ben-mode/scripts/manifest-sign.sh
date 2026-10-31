#!/usr/bin/env bash
# manifest-sign.sh — optional Ed25519 signature over a manifest baseline (P4 A2).
# Default OFF in gate; this gives real supply-chain attestation (§15) on demand.
# Usage: manifest-sign.sh <baseline-file> [key-file]
#   key-file default: <baseline>.sign.key.pem (created if missing)
# Writes <baseline>.sig (raw Ed25519 signature via openssl pkeyutl -rawin).
set -euo pipefail

BL="${1:?usage: manifest-sign.sh <baseline-file> [key-file]}"
[ -f "$BL" ] || { echo "❌ baseline not found: $BL"; exit 2; }
KEY="${2:-$BL.sign.key.pem}"

if [ ! -f "$KEY" ]; then
    openssl genpkey -algorithm ED25519 -out "$KEY" >/dev/null 2>&1
    echo "key generated: $KEY"
fi
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$BL" -out "$BL.sig"
echo "✅ signed $BL -> $BL.sig"
