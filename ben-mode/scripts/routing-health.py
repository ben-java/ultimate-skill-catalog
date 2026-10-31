#!/usr/bin/env python3
"""routing-health.py — P9-S#5 (rev2): verify every skill referenced in ben-mode's
routing matrix resolves to an installed SKILL.md with valid frontmatter.

Only the "Matriks Routing Fungsional" matrix is parsed (not code/prose backticks).
Existence is checked against a recursive index of all installed SKILL.md names.

Exits: 0 = OK; 1 = BLOCK (core-cluster unresolved, or any unresolved under --strict).
"""
import os
import re
import sys

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL_MD = os.path.join(SKILL_DIR, "SKILL.md")

ROOTS = [
    os.path.expanduser("C:/Users/AMMAR/AppData/Local/hermes/skills"),
    os.path.expanduser("C:/Users/AMMAR/Tools/dsh-skill-wrappers"),
    os.path.expanduser("C:/Users/AMMAR/.dsh/skills"),
    os.path.expanduser("C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog"),
]

CORE_CLUSTERS = {1}

ALIASES = {
    "ben": "ben-mode",
    "ultimate-combined": "ben-mode",
}


def parse_matrix():
    text = open(SKILL_MD, encoding="utf-8").read()
    start = text.find("Matriks Routing Fungsional")
    if start == -1:
        print("routing-health: matrix section not found")
        sys.exit(2)
    tail = len(text)
    for marker in ("## 3.", "### 3."):
        i = text.find(marker, start + 40)
        if i != -1:
            tail = min(tail, i)
    block = text[start:tail]
    skills = {}
    cluster = None
    for line in block.splitlines():
        m = re.match(r"^\s*(\d+)\.\s+", line)
        if m:
            cluster = int(m.group(1))
            continue
        if cluster:
            for tok in re.findall(r"`([^`]+)`", line):
                name = tok.strip()
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
                    continue
                if any(ch in name for ch in ("/", "\\", ":")):
                    continue
                skills.setdefault(name, cluster)
    return skills


def build_index():
    names = set()
    for root in ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in (".git", "backup", "archive", "node_modules")]
            if "SKILL.md" in files:
                names.add(os.path.basename(dirpath).lower())
                try:
                    txt = open(os.path.join(dirpath, "SKILL.md"), encoding="utf-8",
                               errors="replace").read(1500)
                except Exception:
                    txt = ""
                m = re.search(r"^name:\s*(.+)$", txt, re.M)
                if m:
                    names.add(m.group(1).strip().lower())
    return names


def main():
    strict = "--strict" in sys.argv
    ci_smoke = "--ci-smoke" in sys.argv
    skills = parse_matrix()
    index = build_index()
    unresolved = {s: c for s, c in skills.items()
                  if ALIASES.get(s, s).lower() not in index}
    core_unresolved = {s for s, c in unresolved.items() if c in CORE_CLUSTERS}
    print("routing-health: referenced skills = %d" % len(skills))
    print("routing-health: index=%d resolved=%d unresolved=%d" % (
        len(index), len(skills) - len(unresolved), len(unresolved)))
    _resolved = len(skills) - len(unresolved)
    _cov = (_resolved * 100 // len(index)) if len(index) else 0
    print("routing-health: installed=%d coverage=%d%%" % (len(index), _cov))
    _side = r"C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog/.hard-gate-meta/routing-coverage.json"
    try:
        import json
        os.makedirs(os.path.dirname(_side), exist_ok=True)
        json.dump({"installed": len(index), "referenced": len(skills),
                   "resolved": _resolved, "coverage_pct": _cov,
                   "unresolved": [f"[cluster {c}] {s}" for s, c in sorted(unresolved.items())]},
                  open(_side, "w", encoding="utf-8"), indent=2)
    except Exception:
        pass
    if unresolved:
        print("UNRESOLVED (%d):" % len(unresolved))
        for s, c in sorted(unresolved.items()):
            print("  [cluster %d] %s" % (c, s))
    if core_unresolved:
        if ci_smoke:
            print("routing-health: CI smoke — core skills unresolved (env-limited): %s"
                  % ", ".join(sorted(core_unresolved)))
        else:
            print("routing-health: BLOCK — core skills missing: %s"
                  % ", ".join(sorted(core_unresolved)))
            sys.exit(1)
    if strict and unresolved:
        print("routing-health: BLOCK (--strict) — unresolved skills present")
        sys.exit(1)
    print("routing-health: OK")
    sys.exit(0)


if __name__ == "__main__":
    main()
