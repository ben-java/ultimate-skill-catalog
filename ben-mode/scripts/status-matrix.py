#!/usr/bin/env python3
"""status-matrix.py — P7-J#7+#8: single-source-of-truth status + self-BOM check.

#7: derives gate/behavioral status from CODE (not from prose in hard-gate-10.md):
  - active scripts count, negative-test count (from test-hard-gate-negative.sh)
  - dependency availability (z3 importable? opa binary? openssl?)
  - predicates implemented (P_* identifiers from gate_predicates.py / runtime_gate.py)
#8: P_bom self-check — every path referenced by SKILL.md (references/ scripts/)
  must exist on disk.
Exit: 0 if self-BOM is clean; 1 if any referenced file is missing.
"""
import json, os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)          # ben-mode skill root
SKILL_MD = os.path.join(SKILL_DIR, "SKILL.md")
SCRIPTS = HERE
META = os.path.join(SKILL_DIR, ".hard-gate-meta")


def missing_bom():
    missing = []
    for line in open(SKILL_MD, encoding="utf-8"):
        line = line.strip()
        if not line.startswith("- "):
            continue
        seg = line[2:]
        m = re.search(r"(references|scripts)/[\w./-]+", seg)
        if not m:
            continue
        rel = m.group(0)
        full = os.path.join(SKILL_DIR, rel)
        if not os.path.exists(full):
            missing.append(rel)
    return missing


def neg_test_count():
    t = os.path.join(SCRIPTS, "test-hard-gate-negative.sh")
    if not os.path.isfile(t):
        return 0, None, True
    txt = open(t, encoding="utf-8", errors="ignore").read()
    m = re.search(r"TOTAL_TESTS=(\d+)", txt)
    declared = int(m.group(1)) if m else None
    present = len(re.findall(r"Test \d+ PASS", txt))
    consistent = (declared is None) or (declared == present)
    return present, declared, consistent


def unit_test_count():
    """P10-Y#9: count test methods in scripts/tests/*.py."""
    d = os.path.join(SCRIPTS, "tests")
    if not os.path.isdir(d):
        return 0
    n = 0
    for f in sorted(os.listdir(d)):
        if f.endswith(".py"):
            n += len(re.findall(r"def (?:test|runTest)\w*\(\w*\)",
                               open(os.path.join(d, f), encoding="utf-8",
                                    errors="ignore").read()))
    return n


def predicates(script):
    p = os.path.join(SCRIPTS, script)
    if not os.path.isfile(p):
        return []
    txt = open(p, encoding="utf-8", errors="ignore").read()
    return sorted(set(re.findall(r"\bP_[a-z_]+", txt)))


def versions_consistent():
    """P8-N#3: SKILL.md version must equal the top CHANGELOG version."""
    import re
    sk = open(SKILL_MD, encoding="utf-8").read()
    m = re.search(r"^version:\s*(\S+)", sk, re.M)
    skill_ver = m.group(1) if m else None
    cl = os.path.join(SKILL_DIR, "CHANGELOG.md")
    cl_ver = None
    if os.path.isfile(cl):
        cm = re.search(r"^## v(\S+)", open(cl, encoding="utf-8").read(), re.M)
        if cm:
            cl_ver = "v" + cm.group(1) if not cm.group(1).startswith("v") else cm.group(1)
    return skill_ver, cl_ver


def find_python():
    for c in (os.environ.get("PYTHON"), "python3", "python", "py"):
        if c and shutil.which(c):
            return c
    return None


def main():
    PY = find_python() or sys.executable
    _opa = shutil.which("opa") or os.path.expanduser("~/bin/opa.exe")
    _opa_env = os.environ.get("OPA_BIN")
    if _opa_env and os.path.isfile(_opa_env):
        _opa = _opa_env
    _opa_ok = bool(_opa) and os.path.isfile(_opa)
    deps = {
        "z3": False, "openssl": bool(shutil.which("openssl")),
        "opa": _opa_ok,
    }
    if _opa_ok:
        try:
            rv = subprocess.run([_opa, "version"], capture_output=True, text=True, timeout=20)
            if rv.returncode == 0:
                import re as _re
                m = _re.search(r"Version:\s*(\S+)", rv.stdout)
                if m:
                    deps["opa_version"] = m.group(1)
        except Exception:
            pass
    if PY:
        try:
            r = subprocess.run([PY, "-c", "import z3; print(z3.get_version_string())"],
                               capture_output=True, text=True, timeout=30)
            deps["z3"] = r.returncode == 0
        except Exception:
            deps["z3"] = False

    root_arg = sys.argv[1] if len(sys.argv) > 1 else None
    _proj_meta = os.path.abspath("C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog/.hard-gate-meta")
    _sbom_candidates = [os.path.join(META, "ben-mode.sbom.json"),
                        os.path.join(SKILL_DIR, ".hard-gate-meta", "ben-mode.sbom.json"),
                        os.path.join(_proj_meta, "ben-mode.sbom.json")]
    if root_arg:
        _sbom_candidates.append(os.path.join(root_arg, ".hard-gate-meta", "ben-mode.sbom.json"))
        _sbom_candidates.append(os.path.join(root_arg, "ben-mode.sbom.json"))
    _sbom_present = any(os.path.isfile(c) for c in _sbom_candidates)
    # P18-D1: latest live runtime audit (P17-A1)
    _runtime_audit = "n/a"
    _ra_candidates = [os.path.join(META, "runtime-audit.jsonl"),
                       os.path.join(SKILL_DIR, ".hard-gate-meta", "runtime-audit.jsonl"),
                       os.path.join(_proj_meta, "runtime-audit.jsonl")]
    for _rc in _ra_candidates:
        if os.path.isfile(_rc):
            try:
                _ra_lines = [l for l in open(_rc, encoding="utf-8").read().splitlines() if l.strip()]
                if _ra_lines:
                    _last = json.loads(_ra_lines[-1])
                    _runtime_audit = "%s since_clean=%s" % (_last.get("status", "?"), _last.get("since_clean"))
            except Exception:
                pass
            break
    # P23-C1: last real gate verdict from audit log (filtered to project root)
    import tempfile as _tf
    _gate_status = "n/a"; _gate_ts = "n/a"
    _proj_root = "C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog"
    _ga = os.path.join(_tf.gettempdir(), "hard-gate-audit.log.json")
    if os.path.isfile(_ga):
        try:
            _txt = open(_ga, encoding="utf-8", errors="ignore").read()
            _dec = json.JSONDecoder(); _i = 0
            while _i < len(_txt):
                while _i < len(_txt) and _txt[_i] in " \t\r\n": _i += 1
                if _i >= len(_txt): break
                if _txt[_i] != "{": _i += 1; continue
                try:
                    _obj, _end = _dec.raw_decode(_txt, _i)
                except Exception:
                    _i += 1; continue
                if _proj_root in _obj.get("root", "") and _obj.get("status") in ("PASS", "FAIL"):
                    _gate_status = _obj.get("status")
                    _gate_ts = _obj.get("timestamp", _obj.get("ts", ""))
                _i = _end
        except Exception:
            pass
    _neg_present, _neg_declared, _neg_consistent = neg_test_count()
    _routing_cov = "n/a"
    _rc_path = os.path.join(_proj_meta, "routing-coverage.json")
    if os.path.isfile(_rc_path):
        try:
            _rc = json.load(open(_rc_path, encoding="utf-8"))
            _routing_cov = "%d%%" % _rc.get("coverage_pct", 0)
        except Exception:
            pass
    skill_ver, cl_ver = versions_consistent()
    _tr_anchors, _tr_resolved = 0, False
    try:
        import subprocess as _sp
        _tr = _sp.run([sys.executable, os.path.join(SKILL_DIR, "scripts", "traceability.py")],
                      capture_output=True, text=True, timeout=60)
        _ml = re.search(r"(\d+) spec anchors mapped", _tr.stdout)
        if _ml:
            _tr_anchors = int(_ml.group(1))
        _tr_resolved = ("UNRESOLVED" not in _tr.stdout)
    except Exception:
        pass
    _spec_ver = ""
    _spec_path = os.path.join(SKILL_DIR, "references", "hard-gate-10.md")
    if os.path.isfile(_spec_path):
        _sm = re.search(r"Spec version.*?(\d+\.\d+\.\d+)", open(_spec_path, encoding="utf-8", errors="ignore").read())
        if _sm:
            _spec_ver = _sm.group(1)
    _norm = lambda x: (x or "").lstrip("v")
    skill_ver = _norm(skill_ver); cl_ver = _norm(cl_ver)
    matrix = {
        "skill": os.path.basename(SKILL_DIR),
        "version": skill_ver,
        "changelog_version": cl_ver,
        "version_consistent": bool(skill_ver and skill_ver == cl_ver),
        "spec_version": _spec_ver,
        "spec_version_consistent": bool(_spec_ver and _spec_ver == skill_ver),
        "scripts": sorted(os.listdir(SCRIPTS)),
        "script_count": len([f for f in os.listdir(SCRIPTS) if os.path.isfile(os.path.join(SCRIPTS, f))]),
        "negative_test_count": _neg_present,
        "negative_declared": _neg_declared,
        "negative_pass_consistent": _neg_consistent,
    "unit_test_count": unit_test_count(),
        "dependencies": deps,
        "predicates_static": sorted(set(predicates("gate_predicates.py")) | set(predicates("check-vsa.py"))),
        "predicates_runtime": predicates("runtime_gate.py"),
        "bom_missing": missing_bom(),
        "sbom_present": _sbom_present,
        "runtime_audit_latest": _runtime_audit,
        "routing_coverage": _routing_cov,
        "traceability_anchors": _tr_anchors,
        "traceability_resolved": _tr_resolved,
        "last_gate_status": _gate_status,
        "last_gate_ts": _gate_ts,
    }
    print(json.dumps(matrix, indent=2, ensure_ascii=False))
    code = 0
    if matrix["bom_missing"]:
        sys.stderr.write("SELF-BOM FAIL: %s\n" % ", ".join(matrix["bom_missing"]))
        code = 1
    if not matrix["version_consistent"]:
        sys.stderr.write("VERSION MISMATCH: SKILL.md=%s vs CHANGELOG=%s\n"
                         % (matrix["version"], matrix["changelog_version"]))
        code = 1
    if not matrix["negative_pass_consistent"]:
        sys.stderr.write("NEGATIVE PASS INCONSISTENT: declared=%s present=%s\n"
                         % (matrix["negative_declared"], matrix["negative_test_count"]))
        code = 1
    if code:
        sys.exit(code)
    sys.stderr.write("SELF-BOM OK: all SKILL.md references exist; version consistent.\n")


if __name__ == "__main__":
    main()
