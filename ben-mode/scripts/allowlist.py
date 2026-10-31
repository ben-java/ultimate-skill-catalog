#!/usr/bin/env python3
"""allowlist.py — lifecycle management for hard-gate-allowlist.json (P4 A3).

Commands:
  init                create a valid empty allowlist (or validate existing)
  add --skill S --hash H --reason R --approved-by A [--expires ISO]
                      append an approved drift entry (dedupe by skill+hash)
  remove --skill S --hash H
                      delete a matching entry
  list                print all entries
  validate            exit 0 if schema-valid; 1 otherwise

Schema (gate Rule 6/7 compatible):
  {"allowed_drifts":[{"skill","reason","approved_hashes":[...],
                     "approved_by","expires_at"}]}
Pure stdlib. Exit 0 ok, 1 invalid, 2 usage.
"""
import argparse, datetime, json, os, sys

REQUIRED = ("skill", "reason", "approved_hashes", "approved_by", "expires_at")


def load(root):
    path = os.path.join(root, "hard-gate-allowlist.json")
    if not os.path.isfile(path):
        return {"allowed_drifts": []}, path
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception as e:
        print(f"FATAL: invalid JSON: {e}")
        sys.exit(1)
    return data, path


def validate(data):
    errors = []
    if not isinstance(data, dict) or "allowed_drifts" not in data:
        return ["missing allowed_drifts"]
    allw = data["allowed_drifts"]
    if not isinstance(allw, list):
        return ["allowed_drifts not a list"]
    for i, e in enumerate(allw):
        for k in REQUIRED:
            if k not in e:
                errors.append(f"entry[{i}] missing {k}")
                continue
            if k == "approved_hashes" and not isinstance(e[k], list):
                errors.append(f"entry[{i}] approved_hashes must be list")
            if k == "expires_at":
                try:
                    datetime.datetime.fromisoformat(e[k].replace("Z", "+00:00"))
                except Exception:
                    errors.append(f"entry[{i}] bad expires_at {e[k]!r}")
    return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".",
                    help="catalog root (allowlist lives here)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("list")
    ap2 = sub.add_parser("add")
    for k in ("skill", "hash", "reason", "approved-by"):
        ap2.add_argument(f"--{k}", required=True)
    ap2.add_argument("--expires", default="2099-12-31T23:59:59Z")
    ap3 = sub.add_parser("remove")
    ap3.add_argument("--skill", required=True)
    ap3.add_argument("--hash", required=True)
    sub.add_parser("validate")
    args = ap.parse_args()

    data, path = load(args.root)
    if args.cmd == "init":
        errs = validate(data)
        if errs:
            print("existing invalid:", errs)
            sys.exit(1)
        if not data["allowed_drifts"]:
            open(path, "w", encoding="utf-8").write(
                json.dumps({"allowed_drifts": []}, indent=2) + "\n")
            print("allowlist initialized:", path)
        else:
            print("allowlist already valid:", path)
        sys.exit(0)

    if args.cmd == "list":
        for e in data["allowed_drifts"]:
            print(e)
        sys.exit(0)

    if args.cmd == "validate":
        errs = validate(data)
        if errs:
            print("INVALID")
            for e in errs:
                print("  -", e)
            sys.exit(1)
        print("VALID")
        sys.exit(0)

    if args.cmd == "add":
        entry = {
            "skill": args.skill,
            "reason": args.reason,
            "approved_hashes": [args.hash],
            "approved_by": args.approved_by,
            "expires_at": args.expires,
        }
        data["allowed_drifts"] = [
            e for e in data["allowed_drifts"]
            if not (e.get("skill") == args.skill and args.hash in e.get("approved_hashes", []))
        ]
        data["allowed_drifts"].append(entry)
        open(path, "w", encoding="utf-8").write(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        print("added:", entry)
        sys.exit(0)

    if args.cmd == "remove":
        before = len(data["allowed_drifts"])
        data["allowed_drifts"] = [
            e for e in data["allowed_drifts"]
            if not (e.get("skill") == args.skill and args.hash in e.get("approved_hashes", []))
        ]
        if len(data["allowed_drifts"]) == before:
            print("no matching entry found")
            sys.exit(1)
        open(path, "w", encoding="utf-8").write(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        print("removed")
        sys.exit(0)


if __name__ == "__main__":
    main()
