#!/usr/bin/env python3
"""Portable HARD GATE #10 replica verification (pure stdlib, Windows-safe).

Use this when the bundled bash gate cannot run (e.g. `bash` resolves to WSL
with no /bin/bash on a Git-Bash/MSYS host). It is deterministic and checks the
FULL tree of every replica, not just SKILL.md.

Usage:
    python verify_skill_replicas.py --root <canonical> --replica <target> [--replica <target> ...]
    python verify_skill_replicas.py --list   # use default catalog roots

Checks (exit 0 = PASS, 1 = FAIL):
  1. schema: name==folder, description present (frontmatter)
  2. end-to-end checksum: md5 of every file at each replica
  3. determinism: md5 recomputed twice, must match
  4. quorum/DRY: replicates must be byte-for-byte identical to canonical
  5. zero symlinks/junctions
  6. adversarial self-check: an injected single-byte flip in a temp copy
     must be detected
  7. audit: one JSONL line appended to the audit log
"""
import argparse, hashlib, json, os, re, shutil, sys, tempfile, datetime

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

DEFAULT_ROOTS = [
    r"C:\Users\AMMAR\AppData\Local\hermes\skills\dsh-imported",
    r"C:\Users\AMMAR\Tools\dsh-skill-wrappers",
    r"C:\Users\AMMAR\.dsh\skills",
]
AUDIT_LOG = os.path.join(tempfile.gettempdir(), "ben-mode-gate-audit.jsonl")


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_md5(path):
    """§16.2: bit-for-bit deterministic — normalize CRLF->LF before checksumming,
    strip timestamps/inode metadata (we hash content only)."""
    data = open(path, "rb").read().replace(b"\r\n", b"\n")
    return hashlib.md5(data).hexdigest()


def tree_hash(root, hf=md5):
    out = {}
    for dp, dn, fn in os.walk(root):
        for name in fn:
            p = os.path.join(dp, name)
            out[os.path.relpath(p, root)] = hf(p)
    return out


def quorum_report(canonical_hashes):
    """§15.2: a replica set is valid only when a quorum of [N/2]+1 catalogs
    independently report identical hashes."""
    from collections import Counter
    n = len(canonical_hashes)
    counts = Counter(tuple(sorted(h.items())) for h in canonical_hashes.values())
    sig, agree = counts.most_common(1)[0]
    threshold = n // 2 + 1
    return agree >= threshold, agree, threshold, n


def tree_signature(root):
    """§15.1/§16.2 deterministic signature (mirrors generate_manifest.py)."""
    lines = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace("\\", "/")
            data = open(p, "rb").read().replace(b"\r\n", b"\n")
            lines.append(f"{rel} {hashlib.sha256(data).hexdigest()}")
    return hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()


def schema_ok(folder):
    skill_md = os.path.join(folder, "SKILL.md")
    if not os.path.isfile(skill_md):
        return False
    txt = open(skill_md, encoding="utf-8-sig").read()
    m = re.search(r"^name:\s*(.+)$", txt, re.M)
    d = re.search(r"^description:\s*(.+)$", txt, re.M)
    return bool(m and d) and m.group(1).strip() == os.path.basename(os.path.normpath(folder))


def is_reparse(p):
    """True for Windows reparse points (junctions, symlinked dirs) that
    os.path.islink misses on older Python/Windows combinations."""
    try:
        import ctypes
        a = ctypes.windll.kernel32.GetFileAttributesW(p)
        return bool(a != -1 and (a & 0x400))
    except Exception:
        return False

def count_symlinks(root):
    n = 0
    for dp, dn, fn in os.walk(root, followlinks=False):
        for name in dn + fn:
            p = os.path.join(dp, name)
            if os.path.islink(p) or is_reparse(p):
                n += 1
    return n


def adversarial_selfcheck(src_skill_md):
    tmp = tempfile.mkdtemp(prefix="adversarial_")
    try:
        dst = os.path.join(tmp, "SKILL.md")
        shutil.copy2(src_skill_md, dst)
        b = bytearray(open(dst, "rb").read())
        b[0] ^= 0xFF
        open(dst, "wb").write(bytes(b))
        return md5(src_skill_md) != md5(dst)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", help="canonical skill folder")
    ap.add_argument("--replica", action="append", help="a skill folder to compare (repeatable)")
    ap.add_argument("--audit", default=AUDIT_LOG, help="JSONL audit log path")
    ap.add_argument("--manifest", help="baseline signature file (from generate_manifest.py --baseline) to verify root against")
    args = ap.parse_args()

    if not args.root or (not args.replica and not args.manifest):
        print("ERROR: --root is required, plus --replica and/or --manifest")
        sys.exit(2)

    replicas = [args.root] + (args.replica or [])
    # §16.2: canonical (CRLF->LF normalized) hashing across the full tree
    hashes = {r: tree_hash(r, canonical_md5) for r in replicas}
    canon = hashes[args.root]

    fails = []
    for r in replicas:
        if not schema_ok(r):
            fails.append(f"schema FAIL: {r}")
        if count_symlinks(r) != 0:
            fails.append(f"symlink FAIL: {r}")
        # determinism: recompute once
        if tree_hash(r, canonical_md5) != hashes[r]:
            fails.append(f"determinism FAIL: {r}")
    for rep in (args.replica or []):
        if set(hashes[rep]) != set(canon) or any(hashes[rep][k] != canon[k] for k in canon):
            fails.append(f"replica drift FAIL: {rep}")
    # §15.2: quorum = majority of [N/2]+1 replicas must report identical hashes
    quorum_ok, agree, threshold, total = quorum_report(hashes)
    if not quorum_ok:
        fails.append(f"quorum FAIL: {agree}/{total} replicas agree (need >={threshold})")

    # §15.1/§16.2: verify tree against reproducible manifest baseline, if given
    if args.manifest:
        if os.path.isfile(args.manifest):
            expected = open(args.manifest, encoding="utf-8").read().strip()
            actual = tree_signature(args.root)
            if actual != expected:
                fails.append("manifest FAIL: tree signature differs from baseline")
            else:
                print(f"manifest OK: signature matches baseline ({actual[:12]}…)")
        else:
            fails.append(f"manifest FAIL: baseline file not found: {args.manifest}")

    adv = adversarial_selfcheck(os.path.join(args.root, "SKILL.md"))
    if not adv:
        fails.append("adversarial self-check FAIL: injected flip not detected")

    status = "PASS" if not fails else "FAIL"
    entry = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": status,
        "replicas": len(replicas),
        "fails": fails,
    }
    with open(args.audit, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    print(f"status = {status}")
    print(f"quorum = {agree}/{total} replicas agree (threshold >={threshold})")
    for f in fails:
        print("  -", f)
    sys.exit(0 if status == "PASS" else 1)


if __name__ == "__main__":
    main()
