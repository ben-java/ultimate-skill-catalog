#!/usr/bin/env bash
# verify-manifest-sig.sh — verify an Ed25519 signature over a manifest baseline.
# Usage: verify-manifest-sig.sh <baseline-file> <sig-file> <pubkey-or-key>
# Exit 0 = signature valid; 1 = invalid; 2 = usage/error.
set -euo pipefail

BL="${1:?usage: verify-manifest-sig.sh <baseline> <sig> <pubkey>}"
SG="${2:?sig file required}"
KEY="${3:?pubkey (or private key) required}"
[ -f "$BL" ] && [ -f "$SG" ] && [ -f "$KEY" ] || { echo "❌ missing file"; exit 2; }

PUB="$KEY"
# derive pubkey from private key if a public key is not passed
if grep -q "PRIVATE KEY" "$KEY" 2>/dev/null; then
    PUB="$(mktemp).pub"
    trap 'rm -f "$PUB"' EXIT
    openssl pkey -in "$KEY" -pubout -out "$PUB" >/dev/null 2>&1
fi

if openssl pkeyutl -verify -pubin -inkey "$PUB" -rawin -in "$BL" -sigfile "$SG" >/dev/null 2>&1; then
    echo "✅ signature VALID"
    exit 0
else
    echo "❌ signature INVALID"
    exit 1
fi
