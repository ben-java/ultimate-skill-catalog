#!/usr/bin/env python3
"""quorum-check.py — §15.2 majority quorum across PHYSICAL roots of the same skill.

Prints the deterministic tree signature of each root and decides by majority:
    agree = count of roots sharing the most common signature
    threshold = floor(N/2) + 1
Exit 0 if agree >= threshold and all roots are schema-valid & link-free; else 1.

Usage:
    python quorum-check.py <root1> <root2> [root3 ...]
"""
import argparse, hashlib, os, re, sys
from collections import Counter


def tree_signature(root):
    lines = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            data = open(p, "rb").read().replace(b"\r\n", b"\n")
            lines.append(f"{rel} {hashlib.sha256(data).hexdigest()}")
    return hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()


def schema_ok(folder):
    sm = os.path.join(folder, "SKILL.md")
    if not os.path.isfile(sm):
        return False
    txt = open(sm, encoding="utf-8-sig").read()
    m = re.search(r"^name:\s*(.+)$", txt, re.M)
    d = re.search(r"^description:\s*(.+)$", txt, re.M)
    return bool(m and d) and m.group(1).strip() == os.path.basename(os.path.normpath(folder))


def count_links(root):
    n = 0
    for dp, dn, fn in os.walk(root, followlinks=False):
        for name in dn + fn:
            p = os.path.join(dp, name)
            if os.path.islink(p):
                n += 1
                continue
            try:
                import ctypes
                a = ctypes.windll.kernel32.GetFileAttributesW(p)
                if a != -1 and (a & 0x400):
                    n += 1
            except Exception:
                pass
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("roots", nargs="+")
    args = ap.parse_args()
    if len(args.roots) < 2:
        print("quorum: need >=2 roots")
        sys.exit(2)

    sigs, fails = {}, []
    for r in args.roots:
        if not os.path.isdir(r):
            fails.append(f"root not found: {r}"); continue
        if not schema_ok(r):
            fails.append(f"schema FAIL: {r}")
        if count_links(r) != 0:
            fails.append(f"links FAIL: {r}")
        sigs[r] = tree_signature(r)

    counts = Counter(sigs.values())
    best, agree = counts.most_common(1)[0]
    n = len(args.roots)
    threshold = n // 2 + 1
    for r, s in sigs.items():
        print(f"  {r}  {s[:16]}…")
    print(f"quorum = {agree}/{n} roots agree (threshold ≥{threshold})")
    if agree < threshold:
        fails.append(f"quorum FAIL: {agree}/{n} (need ≥{threshold})")

    if fails:
        print("status = FAIL")
        for f in fails:
            print("  -", f)
        sys.exit(1)
    print("status = PASS")
    sys.exit(0)


if __name__ == "__main__":
    main()
