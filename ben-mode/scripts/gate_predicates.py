"""Hard Gate predicates (pure stdlib) - implements G1-G12 sub-predicates.
Usage: python gate_predicates.py --root <canonical> --replica <target1> [--replica ...] \
       --meta-dir <dir> [--runtime-inputs <dir>]
Baseline & audit log disimpan di --meta-dir (DI LUAR pohon skill).
Exit: 0 PASS, 1 FAIL, 2 PRECONDITION.
"""
import sys, os, hashlib, json, datetime, re, argparse

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()

def tree_hash(root):
    items = {}
    for dp, dn, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            items[rel] = sha256_file(p)
    agg = hashlib.sha256()
    for k in sorted(items):
        agg.update(k.encode()); agg.update(b"\0"); agg.update(items[k].encode())
    return items, agg.hexdigest()

def tree_signature(root):
    """§15.1/§16.2 canonical deterministic signature — SAME algorithm and SAME
    baseline file (<meta-dir>/<skill>.manifest.sha256) as verify-hard-gate.sh /
    verify_skill_replicas.py. Removes the old dual-manifest mechanism."""
    lines = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            data = open(p, "rb").read().replace(b"\r\n", b"\n")
            lines.append(f"{rel} {hashlib.sha256(data).hexdigest()}")
    return hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()


def check_spec_parity(spec_files):
    """P18-A1/P19-A2: scan spec/SKILL for declared suite-size counts that are
    STALE (< actual TOTAL_TESTS). Actual is read dynamically from the negative
    test script so adding suite tests needs no second sync point."""
    actual = 29
    _base = os.path.dirname(os.path.abspath(__file__))
    _neg = os.path.join(_base, "test-hard-gate-negative.sh")
    if os.path.isfile(_neg):
        _m = re.search(r"TOTAL_TESTS=(\d+)", open(_neg, encoding="utf-8", errors="ignore").read())
        if _m:
            actual = int(_m.group(1))
    stale = []
    pat = re.compile(r"\b(\d+)\s+(?:(?:adversarial|synthetic)\s+)?(?:tests?|fault\s+injections?|corruption\s+patterns?)\b")
    for f in spec_files:
        if not os.path.isfile(f):
            continue
        txt = open(f, encoding="utf-8", errors="ignore").read()
        for m in pat.finditer(txt):
            n = int(m.group(1))
            if 0 < n < actual:
                ctx = txt[max(0,m.start()-40):m.end()+20].replace("\n"," ")
                stale.append((os.path.basename(f), n, ctx.strip()))
    return stale

def check_schema(root):
    txt = open(os.path.join(root, "SKILL.md"), encoding="utf-8-sig").read()
    nm = re.search(r'^name:\s*(.+)$', txt, re.M)
    return bool(nm) and nm.group(1).strip() == os.path.basename(root)

def check_ai_rmf(meta_dir):
    """P_ai_rmf (BAGIAN 22): RMF marker .ai-rmf.json must declare all four
    functions (govern/map/measure/manage) from NIST AI RMF 1.0."""
    p = os.path.join(meta_dir, ".ai-rmf.json")
    if not os.path.isfile(p):
        return False
    try:
        d = json.load(open(p, encoding="utf-8"))
    except Exception:
        return False
    return all(bool(d.get(k)) for k in ("govern", "map", "measure", "manage"))


def check_bom_inventory(root):
    txt = open(os.path.join(root, "SKILL.md"), encoding="utf-8-sig").read()
    missing = []
    for m in re.finditer(r'^\s*-\s+references/([\w./-]+)', txt, re.M):
        rel = m.group(1); p = os.path.join(root, "references", rel)
        if not os.path.isfile(p) or os.path.getsize(p) == 0:
            missing.append("references/" + rel)
    for m in re.finditer(r'^\s*-\s+scripts/([\w./-]+)', txt, re.M):
        rel = m.group(1); p = os.path.join(root, "scripts", rel)
        if not os.path.isfile(p) or os.path.getsize(p) == 0:
            missing.append("scripts/" + rel)
    return missing

def check_signed_manifest(root, meta_dir):
    baseline = os.path.join(meta_dir,
                           os.path.basename(os.path.normpath(root)) + ".manifest.sha256")
    agg = tree_signature(root)
    if not os.path.exists(baseline):
        with open(baseline, "w") as f:
            f.write(agg + "\n")
        return True, f"baseline dibuat (baru): {agg[:12]}..."
    stored = open(baseline).read().strip()
    return stored == agg, f"{agg[:12]}... vs stored {stored[:12]}..."

def check_runtime_static(runtime_inputs):
    """G1/G4: hanya scan input runtime aktual (bukan prosa/self-doc)."""
    if not runtime_inputs or not os.path.isdir(runtime_inputs):
        return []
    patterns = [r"ignore.{0,50}instruction", r"disregard.{0,50}rule",
                r"override.{0,50}system", r"</?system>", r"<script", r"javascript:"]
    hits = []
    for dp, dn, fn in os.walk(runtime_inputs):
        for f in fn:
            p = os.path.join(dp, f)
            try:
                txt = open(p, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            for pat in patterns:
                if re.search(pat, txt, re.IGNORECASE):
                    hits.append(f"{os.path.relpath(p, runtime_inputs)}::{pat}")
                    break
    return hits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="")
    ap.add_argument("--replica", action="append", default=[])
    ap.add_argument("--meta-dir", default="")
    ap.add_argument("--runtime-inputs", default="")
    ap.add_argument("--ai-rmf", default="")
    args = ap.parse_args()
    if not (args.ai_rmf or args.root):
        ap.error("--root (or --ai-rmf) required")
    if args.ai_rmf:
        ok = check_ai_rmf(args.ai_rmf)
        print("P_ai_rmf: %s" % ("PASS" if ok else "FAIL"))
        sys.exit(0 if ok else 1)
    roots = [args.root] + args.replica
    os.makedirs(args.meta_dir, exist_ok=True)
    log_path = os.path.join(args.meta_dir, "hard-gate-audit.jsonl")

    # P_quorum
    hashes = {r: tree_hash(r)[1] for r in roots}
    base = hashes[args.root]
    quorum_ok = all(hashes[r] == base for r in args.replica)

    # P_reproducible: hitung ULANG SEBELUM baseline ditulis
    repro_ok = (tree_hash(args.root)[1] == base)

    status = {"P_quorum": quorum_ok, "P_schema": all(check_schema(r) for r in roots)}
    def _reparse(p):
        try:
            import ctypes
            a = ctypes.windll.kernel32.GetFileAttributesW(p)
            return bool(a != -1 and (a & 0x400))
        except Exception:
            return False
    links = sum(1 for r in roots for dp, dn, fn in os.walk(r)
                for n in dn + fn
                if os.path.islink(os.path.join(dp, n)) or _reparse(os.path.join(dp, n)))
    status["P_zero_links"] = links == 0
    bom = {r: check_bom_inventory(r) for r in roots}
    status["P_bom"] = all(not v for v in bom.values())
    m_ok, m_msg = check_signed_manifest(args.root, args.meta_dir)
    status["P_signed_manifest"] = m_ok
    static = check_runtime_static(args.runtime_inputs)
    status["P_runtime_static"] = len(static) == 0
    _spec_parity = check_spec_parity([
        os.path.join(SCRIPT_DIR, "..", "SKILL.md"),
        os.path.join(SCRIPT_DIR, "..", "references", "hard-gate-10.md")])
    status["P_spec_parity"] = len(_spec_parity) == 0

    ok = all(status.values())
    status["ok"] = ok
    entry = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
             "predicates": {k: v for k, v in status.items() if k != "ok"},
             "status": "PASS" if ok else "FAIL"}
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    with open(log_path, encoding="utf-8") as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    att_ok = bool(lines) and json.loads(lines[-1]).get("ts") == entry["ts"]
    status["P_attestation"] = att_ok
    ok = ok and att_ok

    print("PREDICATE REPORT")
    for k, v in status.items():
        if k != "ok":
            print(f"  {k}: {'PASS' if v else 'FAIL'}")
    if bom[args.root]:
        print("  missing refs:", bom[args.root])
    if _spec_parity:
        print("  spec parity stale:", _spec_parity)
    print("  manifest:", m_msg)
    print(f"OVERALL: {'PASS' if ok else 'FAIL'} | exit {0 if ok else 1}")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
