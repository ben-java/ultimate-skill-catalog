#!/usr/bin/env python3
"""scitt-receipt.py — P26-4: SCITT-style execution receipt via COSE_Sign1 (EdDSA).

Signs an execution statement (JSON) into a COSE_Sign1 receipt encoded as CBOR,
and verifies it against a public key. Mirrors IETF SCITT AI-Agent-Execution profile
(signed statement + tamper-evident) with COSE instead of bare Ed25519.

Usage:
  scitt-receipt.py sign --statement st.json --priv priv.pem --out receipt.cbor
  scitt-receipt.py verify --receipt receipt.cbor --pub pub.pem
Exit: 0 sign/ok, 1 verify-fail, 2 usage/input error.
"""
import argparse, json, os, sys
import cbor2
from cose.messages import Sign1Message
from cose.keys import OKPKey
from cose.algorithms import EdDSA
from cose.keys.keytype import KtyOKP
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
from cryptography.hazmat.primitives import serialization

def _load_ed25519(pem_path, private=True):
    with open(pem_path, "rb") as f:
        data = f.read()
    if private:
        k = serialization.load_pem_private_key(data, password=None)
        raw = k.private_bytes(serialization.Encoding.Raw,
                              serialization.PrivateFormat.Raw,
                              serialization.NoEncryption())
        pub = k.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw)
        return raw, pub
    k = serialization.load_pem_public_key(data)
    return None, k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def _cose_key(d, x):
    k = OKPKey(crv=6, d=d, x=x) if d is not None else OKPKey(crv=6, x=x)
    k.alg = EdDSA
    return k

def sign(statement, priv, out):
    d, x = _load_ed25519(priv, True)
    payload = cbor2.dumps(statement)
    msg = Sign1Message(
        phdr={"alg": -8},
        uhdr={},
        payload=payload,
        key=_cose_key(d, x))
    with open(out, "wb") as f:
        f.write(msg.encode())
    return len(msg.encode())

def verify(receipt, pub):
    _, x = _load_ed25519(pub, False)
    with open(receipt, "rb") as f:
        raw = f.read()
    try:
        obj = cbor2.loads(raw)
        tup = obj.value if isinstance(obj, cbor2.CBORTag) else obj
        protected_b, _u_b, payload_b, sig_b = tup
        sig_structure = cbor2.dumps(["Signature1", protected_b, b"", payload_b])
        pubk = ed25519.Ed25519PublicKey.from_public_bytes(x)
        pubk.verify(sig_b, sig_structure)
        return True
    except Exception as e:
        print("  verify error:", e); return False

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sign"); s.add_argument("--statement", required=True); s.add_argument("--priv", required=True); s.add_argument("--out", required=True)
    v = sub.add_parser("verify"); v.add_argument("--receipt", required=True); v.add_argument("--pub", required=True)
    args = ap.parse_args()
    if args.cmd == "sign":
        if not os.path.isfile(args.statement) or not os.path.isfile(args.priv):
            print("scitt: statement/priv missing"); return 2
        st = json.load(open(args.statement, encoding="utf-8"))
        n = sign(st, args.priv, args.out)
        print("SCITT RECEIPT SIGNED: bytes=%d" % n)
        return 0
    ok = verify(args.receipt, args.pub)
    print("SCITT RECEIPT VERIFY: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
