#!/usr/bin/env python3
"""vc-allowlist.py — P6-C: represent `hard-gate-allowlist.json` as a W3C
Verifiable Credential (Data Model v2.0) with EdDSA proof and Bitstring
Status List revocation. Pure stdlib + openssl (Ed25519), same raw-sign scheme
as allowlist.py.

Envelope semantics (minimal but spec-shaped):
  {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "id": "urn:uuid:<id>",
    "type": ["VerifiableCredential", "HardGateAllowlistCredential"],
    "issuer": "<issuer>",
    "issuanceDate": "ISO-8601",
    "credentialSubject": { "id": "urn:hardgate:allowlist", "payload": <allowlist JSON> },
    "credentialStatus": { "id": "urn:hardgate:statuslist", "type": "BitstringStatusListEntry", "statusListIndex": N, "statusPurpose": "revocation" },
    "proof": { "type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022",
                "created": "...", "verificationMethod": "did:key:<b64>",
                "proofValue": "<b64 signature>" }
  }

Revocation: .status-list.json holds a base64 bitstring; bit i set = revoked.
Exit: 0 ok, 1 verify/revoke-state failure, 2 precondition.
"""
import argparse, base64, hashlib, json, os, subprocess, sys, uuid
from datetime import datetime, timezone
from pathlib import Path

CRED_CTX = "https://www.w3.org/ns/credentials/v2"
STATUS_FILE_SUFFIX = ".status-list.json"
VC_SUFFIX = ".vc.json"


def canonical(s):
    # deterministic byte string for signing: compact JSON with sorted keys
    return json.dumps(s, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def openssl(args, stdin_bytes=None):
    r = subprocess.run(["openssl"] + args, input=stdin_bytes, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError("openssl " + " ".join(args) + " -> " + str(r.stderr[-300:]))
    return r.stdout


def load_allowlist(root):
    p = Path(root) / "hard-gate-allowlist.json"
    if not p.is_file():
        sys.stderr.write("no allowlist\n"); sys.exit(2)
    d = json.loads(p.read_text(encoding="utf-8"))
    d.setdefault("allowed_drifts", [])
    return d, p.parent


def issuer_did(keypath):
    # did:key from the Ed25519 public key (raw bytes, base64)
    pub = openssl(["pkey", "-in", keypath, "-pubout", "-outform", "DER"])
    return "did:key:z" + base64.urlsafe_b64encode(pub).rstrip(b"=").decode("ascii")


def status_index(d):
    return d.get("credentialStatus", {}).get("statusListIndex", 0)


def vc_envelope(payload, issuer, idx):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "@context": [CRED_CTX],
        "id": "urn:uuid:" + str(uuid.uuid4()),
        "type": ["VerifiableCredential", "HardGateAllowlistCredential"],
        "issuer": issuer,
        "issuanceDate": now,
        "credentialSubject": {"id": "urn:hardgate:allowlist", "payload": payload},
        "credentialStatus": {
            "id": "urn:hardgate:statuslist",
            "type": "BitstringStatusListEntry",
            "statusListIndex": idx,
            "statusPurpose": "revocation",
        },
    }


def cmd_sign(args):
    payload, base = load_allowlist(args.root)
    idx = int(args.index)
    issuer = issuer_did(args.key)
    env = vc_envelope(payload, issuer, idx)
    # proof over canonical envelope (without proof); -rawin needs a file, not stdin
    env_tmp = base / "._env.tmp"
    sig_tmp = base / "._sig.tmp"
    env_tmp.write_bytes(canonical(env))
    openssl(["pkeyutl", "-sign", "-inkey", args.key, "-rawin",
             "-in", str(env_tmp), "-out", str(sig_tmp)])
    sig = sig_tmp.read_bytes()
    env_tmp.unlink(missing_ok=True); sig_tmp.unlink(missing_ok=True)
    proof = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-rdfc-2022",
        "created": env["issuanceDate"],
        "verificationMethod": issuer,
        "proofValue": base64.b64encode(sig).decode(),
    }
    env["proof"] = proof
    out = base / (base.name + VC_SUFFIX)
    out.write_text(json.dumps(env, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # init status list bitmap (0 = not revoked) if absent
    sl = base / (base.name + STATUS_FILE_SUFFIX)
    if not sl.exists():
        bits = bytearray((idx // 8) + 1)
    else:
        bits = bytearray(base64.b64decode(json.loads(sl.read_text(encoding="utf-8"))["bitstring"]))
    if idx // 8 >= len(bits):
        bits += bytearray((idx // 8) - len(bits) + 1)
    sl.write_text(json.dumps({"bitstring": base64.b64encode(bits).decode()},
                             indent=2) + "\n", encoding="utf-8")
    print("signed VC:", out)
    print("status list:", sl)


def cmd_verify(args):
    payload, base = load_allowlist(args.root)
    vc_path = base / (base.name + VC_SUFFIX)
    if not vc_path.is_file():
        sys.stderr.write("no VC\n"); sys.exit(1)
    env = json.loads(vc_path.read_text(encoding="utf-8"))
    proof = env.pop("proof")
    expect = canonical(env)
    env["proof"] = proof
    # verify Ed25519 proof over the canonical envelope (openssl raw verify)
    env_tmp = base / "._env.tmp"
    sig_tmp = base / "._sig.tmp"
    env_tmp.write_bytes(expect)
    sig_tmp.write_bytes(base64.b64decode(proof["proofValue"]))
    try:
        checker = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                                   "-inkey", args.pub, "-rawin",
                                   "-in", str(env_tmp), "-sigfile", str(sig_tmp)],
                                  capture_output=True)
        ok = checker.returncode == 0
    finally:
        env_tmp.unlink(missing_ok=True); sig_tmp.unlink(missing_ok=True)
    if not ok:
        sys.stderr.write("VC proof INVALID\n"); sys.exit(1)
    if canonical(env["credentialSubject"]["payload"]) != canonical(payload):
        sys.stderr.write("VC payload != current allowlist\n"); sys.exit(1)
    sl_path = base / (base.name + STATUS_FILE_SUFFIX)
    idx = status_index(env)
    if sl_path.exists():
        bits = bytearray(base64.b64decode(json.loads(sl_path.read_text(encoding="utf-8"))["bitstring"]))
        if idx < len(bits) * 8 and (bits[idx // 8] >> (idx % 8)) & 1:
            sys.stderr.write("VC revoked (status list bit set)\n"); sys.exit(1)
    print("VC VALID (proof ok, payload current, not revoked)")

def cmd_revoke(args):
    payload, base = load_allowlist(args.root)
    sl_path = base / (base.name + STATUS_FILE_SUFFIX)
    if not sl_path.exists():
        sys.stderr.write("no status list\n"); sys.exit(2)
    bits = bytearray(base64.b64decode(json.loads(sl_path.read_text(encoding="utf-8"))["bitstring"]))
    idx = int(args.index)
    if idx // 8 >= len(bits):
        bits += bytearray((idx // 8) - len(bits) + 1)
    bits[idx // 8] |= (1 << (idx % 8))
    sl_path.write_text(json.dumps({"bitstring": base64.b64encode(bits).decode()},
                                   indent=2) + "\n", encoding="utf-8")
    print("revoked index", idx)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sign"); s.add_argument("--key", required=True); s.add_argument("--index", default="0")
    v = sub.add_parser("verify"); v.add_argument("--pub", required=True)
    r = sub.add_parser("revoke"); r.add_argument("--index", required=True)
    args = ap.parse_args()
    if args.cmd == "sign": cmd_sign(args)
    elif args.cmd == "verify": cmd_verify(args)
    elif args.cmd == "revoke": cmd_revoke(args)


if __name__ == "__main__":
    main()
