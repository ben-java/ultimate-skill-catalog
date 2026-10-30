#!/usr/bin/env python3
"""§15.1 — SBOM / in-toto-style manifest generation for a skill tree.

Every artifact is bound to its canonical source by a SHA-256 attestation over
the normalized (CRLF->LF) content, so a manifest is reproducible across
platforms and git line-ending settings.

Usage:
    python generate_manifest.py <skill_dir> [--out manifest.json] [--algorithm sha256]
Exit: 0 on success, 1 on error.
"""
import argparse, hashlib, json, os, sys, datetime


def canonical_sha256(path):
    data = open(path, "rb").read().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def build_manifest(skill_dir, algorithm="sha256"):
    root = os.path.abspath(skill_dir)
    name = os.path.basename(os.path.normpath(root))
    files = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace("\\", "/")
            files.append({
                "path": rel,
                "size": os.path.getsize(p),
                "sha256": canonical_sha256(p),  # §16.2 normalized hash
            })
    return {
        "schema": "agent-skill-manifest/v1",
        "skill": name,
        "algorithm": algorithm,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "file_count": len(files),
        "files": files,
    }


def tree_signature(skill_dir):
    """Deterministic §16.2-canonical signature: sha256 over sorted
    'relpath canonical_sha256' lines. Reproducible across platforms
    (no timestamps; CRLF normalized).
    """
    root = os.path.abspath(skill_dir)
    lines = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace("\\", "/")
            lines.append(f"{rel} {canonical_sha256(p)}")
    return hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("skill_dir")
    ap.add_argument("--out", default="-")
    ap.add_argument("--algorithm", default="sha256")
    ap.add_argument("--baseline", help="write deterministic tree signature to this file (outside the tree)")
    args = ap.parse_args()

    if not os.path.isfile(os.path.join(args.skill_dir, "SKILL.md")):
        print(f"ERROR: no SKILL.md in {args.skill_dir}", file=sys.stderr)
        sys.exit(1)

    if args.baseline:
        sig = tree_signature(args.skill_dir)
        with open(args.baseline, "w", encoding="utf-8") as f:
            f.write(sig + "\n")
        print(f"baseline written: {args.baseline} ({sig})")
        return

    manifest = build_manifest(args.skill_dir, args.algorithm)
    text = json.dumps(manifest, indent=2, ensure_ascii=False)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"manifest written: {args.out} ({manifest['file_count']} files)")


if __name__ == "__main__":
    main()
