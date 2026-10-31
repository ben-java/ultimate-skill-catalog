#!/usr/bin/env python3
"""generate-sbom.py — P6-D: CycloneDX v1.5 JSON Software Bill of Materials.
Pure stdlib. Scans the skill tree, emits metadata + component list (SKILL.md,
scripts, references) with SHA-256 hashes, licenses, and external requirements.
Usage: generate-sbom.py [skill_dir] [--out out.json]
Exit: 0 ok.
"""
import argparse, hashlib, json, os, sys, uuid
from datetime import datetime, timezone

SPEC_VER = "1.5"


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("skill_dir", default=".", nargs="?")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    root = os.path.abspath(args.skill_dir)
    skill_name = os.path.basename(root)

    components = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", ".hard-gate-meta", "__pycache__", "backup", "archive")]
        for f in sorted(files):
            fp = os.path.join(base, f)
            rel = os.path.relpath(fp, root).replace("\\", "/")
            ctype = "file"
            if f == "SKILL.md":
                ctype = "application"
            elif f.endswith(".py") or f.endswith(".sh"):
                ctype = "framework"
            elif f.endswith(".md"):
                ctype = "documentation"
            components.append({
                "type": ctype,
                "name": rel,
                "version": "1.0",
                "hashes": [{"alg": "SHA-256", "content": sha256_file(fp)}],
            })

    # external deps (from requirements.txt if present)
    req = os.path.join(root, "scripts", "requirements.txt")
    if os.path.isfile(req):
        for line in open(req, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#"):
                name = line.split(">=")[0].split("==")[0].strip()
                components.append({
                    "type": "library",
                    "name": name,
                    "version": line[len(name):].lstrip("=>="),
                    "purl": f"pkg:pypi/{name}",
                })

    sbom = {
        "$schema": f"http://cyclonedx.org/schema/bom-{SPEC_VER}.json",
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VER,
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "application",
                "name": skill_name,
                "version": "0.3.0",
                "description": "ben-mode agent skill tree",
            },
        },
        "components": components,
    }

    out_s = json.dumps(sbom, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        open(args.out, "w", encoding="utf-8").write(out_s)
        print("wrote SBOM to", args.out, f"({len(components)} components)")
    else:
        print(out_s)


if __name__ == "__main__":
    main()
