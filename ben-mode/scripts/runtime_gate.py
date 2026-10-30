"""P_runtime live gate - validates an agent action trace (JSONL).
Events: {"session_id","ts","event_type":"action|output|input","actor",
         "payload":... ,"approved":bool,"schema": "optional expected structure"}
Predicates:
  P_rt_injection   - hostile/injection payload entering model context (event=input) flagged
  P_rt_highrisk_hitl - destructive/credential action requires approved==true
  P_rt_output_structure - output with expected_schema must carry required keys
  P_rt_sessions    - zero-trust: tiap session diverifikasi ulang (quorum fresh)
Exit: 0 PASS, 1 FAIL.
"""
import sys, os, json, re, hashlib, datetime

INJ = [re.compile(r"ignore.{0,50}instruction", re.I),
        re.compile(r"disregard.{0,50}rule", re.I),
        re.compile(r"override.{0,50}system", re.I),
        re.compile(r"</?system>", re.I)]

HIGH_RISK = ("destructive", "credential", "exfiltration", "privilege")

def check_trace(path):
    fails = {}
    sessions = set()
    if not os.path.isfile(path):
        return {"trace_missing": True}
    with open(path, encoding="utf-8") as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    for ln in lines:
        ev = json.loads(ln)
        sessions.add(ev.get("session_id"))
        et = ev.get("event_type")
        pl = ev.get("payload") or {}
        # P_rt_injection: konten dari luar (input) mengandung pola injeksi
        if et == "input":
            text = pl if isinstance(pl, str) else json.dumps(pl, ensure_ascii=False)
            if any(p.search(text) for p in INJ) and not ev.get("sanitized"):
                fails.setdefault("P_rt_injection", []).append(text[:60])
        # P_rt_highrisk_hitl
        if et == "action":
            cat = str(pl.get("category", "")).lower()
            if any(h in cat for h in HIGH_RISK) and not ev.get("approved"):
                fails.setdefault("P_rt_highrisk_hitl", []).append(str(pl.get("category")))
        # P_rt_output_structure
        if et == "output" and ev.get("expected_schema"):
            for k in ev["expected_schema"]:
                if k not in (pl if isinstance(pl, dict) else {}):
                    fails.setdefault("P_rt_output_structure", []).append(k)
    # P_rt_sessions: zero-trust - tiap sesi wajib punya minimal verifikasi (quorum) ditandai
    for s in sessions:
        if not any(ev.get("session_id") == s and ev.get("event_type") == "verify"
                   for ev in (json.loads(l) for l in lines)):
            fails.setdefault("P_rt_sessions", []).append(str(s))
    return fails

def main():
    trace = sys.argv[1]
    fails = check_trace(trace)
    ok = not fails
    print("P_RUNTIME REPORT  (%s)" % os.path.basename(trace))
    for k in sorted(fails):
        print(f"  {k}: FAIL {fails[k][:3]}")
    if ok:
        print("  semua predicate runtime PASS")
    print(f"OVERALL: {'PASS' if ok else 'FAIL'} | exit {0 if ok else 1}")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
