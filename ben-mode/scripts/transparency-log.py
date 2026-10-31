#!/usr/bin/env python3
"""transparency-log.py — P13-A2: append-only local transparency (Merkle rope).

Maintains meta/transparency.merkle.json: each gate run appends one leaf whose
hash = sha256(JSON bytes of the audit event). A binary Merkle root is recomputed
each append and stored, giving local tamper-evidence without network.

Modes:
  append [meta-dir]   read latest audit event, append leaf, recompute root
  verify [meta-dir]   recompute leaves+root, compare to stored; exit 0/1
  root   [meta-dir]   print current root hash
"""
import hashlib, json, os, sys


def _h(b):
    return hashlib.sha256(b).hexdigest()


def _merkle_root(hash_list):
    if not hash_list:
        return _h(b"")
    level = list(hash_list)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i + 1] if i + 1 < len(level) else a
            nxt.append(_h((a + b).encode("ascii")))
        level = nxt
    return level[0]


def _meta_file(d):
    return os.path.join(d, "transparency.merkle.json")


def _latest_audit(d):
    candidates = [
        os.path.join(d, "hard-gate-audit.jsonl"),
        os.path.join(d, "gate-time.jsonl"),
        os.path.join(d, "gate-audit-aggregated.jsonl"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            lines = [l for l in open(c, encoding="utf-8", errors="replace").read().splitlines() if l.strip()]
            if lines:
                return lines[-1], os.path.basename(c)
    return None, None


def _load(d):
    f = _meta_file(d)
    if os.path.isfile(f):
        return json.load(open(f, encoding="utf-8"))
    return {"version": 1, "leaves": [], "root": _h(b"")}


def _save(d, doc):
    json.dump(doc, open(_meta_file(d), "w", encoding="utf-8"), indent=2, ensure_ascii=False)


def cmd_append(d):
    line, src = _latest_audit(d)
    if line is None:
        print("transparency-log: no audit source found in", d); return 1
    doc = _load(d)
    leaves = doc["leaves"]
    ev = {"ts": None}
    try:
        parsed = json.loads(line); ev = {"kind": src, "data": parsed}
    except Exception:
        ev = {"kind": src, "data": line}
    leaf_hash = _h((json.dumps(ev, ensure_ascii=False, sort_keys=True)).encode("utf-8"))
    if leaves and leaves[-1]["hash"] == leaf_hash:
        print("transparency-log: duplicate event, no append (idempotent)")
    else:
        leaves.append({"hash": leaf_hash, "event": ev, "ts": parsed.get("ts") if isinstance(parsed, dict) else None})
    doc["root"] = _merkle_root([l["hash"] for l in leaves])
    _save(d, doc)
    print("transparency-log: appended %d leaves, root %s" % (len(leaves), doc["root"]))
    return 0


def cmd_verify(d):
    doc = _load(d)
    leaves = doc["leaves"]
    if not leaves:
        print("transparency-log: no leaves (meta empty)"); return 1
    for i, l in enumerate(leaves):
        data = json.dumps(l["event"], ensure_ascii=False, sort_keys=True).encode("utf-8")
        if _h(data) != l["hash"]:
            print("transparency-log: TAMPER at leaf %d (event hash mismatch)" % i); return 1
    root = _merkle_root([l["hash"] for l in leaves])
    if root != doc["root"]:
        print("transparency-log: ROOT MISMATCH stored=%s recomputed=%s" % (doc["root"], root)); return 1
    print("transparency-log: OK (%d leaves, root %s)" % (len(leaves), root))
    return 0


def cmd_root(d):
    print(_load(d)["root"]); return 0


def main():
    if len(sys.argv) < 3:
        print(__doc__); return 2
    mode, d = sys.argv[1], sys.argv[2]
    return {"append": cmd_append, "verify": cmd_verify, "root": cmd_root}[mode](d)


if __name__ == "__main__":
    sys.exit(main())
