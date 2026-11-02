# substantiation_audit.py - HARD GATE #10 substantiation layer
# Closes the hollow-getattr gap: wired predicates previously fell back to
# `lambda *a, **k: True` when a mechanism function was missing, so a hidden
# or renamed function silently passed as True. This audit:
#   1. Parses gate_predicates.py for every getattr(<mod>, "<fn>", ...) call.
#   2. Verifies every referenced fn EXISTS in hard_gate_enhancements.py.
#   3. Classifies wired mechanism bodies as substantive vs stub.
#   4. Writes JSON evidence to the OS temp dir, exits 0/1.
import sys, re, json, os, tempfile, ast

FUNCS = "hard_gate_enhancements.py"
PREDS = "gate_predicates.py"

def find_file(root, name):
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirpath.split(os.sep):
            continue
        if name in filenames:
            return os.path.join(dirpath, name)
    return None

def stuby(body):
    # wrap in a function so indented return/ast parses
    try:
        tree = ast.parse("def _f():\n" + body)
    except SyntaxError:
        return False
    ret = [n for n in ast.walk(tree) if isinstance(n, ast.Return)]
    if not ret:
        return False
    for r in ret:
        v = r.value
        if isinstance(v, ast.Constant) and v.value is True:
            return True
        if isinstance(v, ast.BoolOp) and all(
            isinstance(x, ast.Constant) and x.value is True for x in v.values):
            return True
    return False

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    p = find_file(root, PREDS)
    f = find_file(root, FUNCS)
    if not p or not f:
        print(json.dumps({"error": "gate_predicates.py or hard_gate_enhancements.py not found",
                           "root": root}))
        return 1
    pred_src = open(p, encoding="utf-8").read()
    func_src = open(f, encoding="utf-8").read()
    defined = set(re.findall(r"def ([a-zA-Z0-9_]+)\(", func_src))
    # getattr(<mod>, "<fn>", lambda ...)
    calls = re.findall(r'getattr\([^,]+,\s*"([a-zA-Z0-9_]+)"', pred_src)
    wired = set(calls)
    missing = sorted(wired - defined)
    present = sorted(wired & defined)
    func_bodies = {}
    for m in re.finditer(r"def ([a-zA-Z0-9_]+)\(.*?\):\n(.*?)(?=\ndef |\Z)", func_src, re.S):
        func_bodies[m.group(1)] = m.group(2)
    stubs, substantive = [], []
    for fn in present:
        if stuby(func_bodies.get(fn, "")):
            stubs.append(fn)
        else:
            substantive.append(fn)
    report = {
        "root": root,
        "wired_count": len(wired),
        "present_count": len(present),
        "missing_count": len(missing),
        "missing": missing,
        "stub_count": len(stubs),
        "substantive_count": len(substantive),
        "stub_ratio": round(len(stubs)/len(present), 4) if present else 0.0,
        "substantive_ratio": round(len(substantive)/len(present), 4) if present else 0.0,
    }
    out = os.path.join(tempfile.gettempdir(), "ben_substantiation_audit.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if missing else 0

if __name__ == "__main__":
    sys.exit(main())
