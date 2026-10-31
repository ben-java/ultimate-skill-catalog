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
        re.compile(r"</?system>", re.I),
        # multilingual / obfuscated variants (P4 B1)
        re.compile(r"abaikan.{0,50}instruksi", re.I),
        re.compile(r"hiraukan.{0,50}aturan", re.I),
        re.compile(r"langgar.{0,50}aturan", re.I),
        re.compile(r"buka.{0,50}sistem", re.I),
        re.compile(r"n?gore.{0,50}instruction", re.I),
        re.compile(r"oublie.{0,50}instruction", re.I),
        # prompt-delimiter abuse
        re.compile(r"<\|im_start\|>", re.I),
        re.compile(r"<\|im_end\|>", re.I),
        re.compile(r"\[system\]", re.I),
        re.compile(r"developer.{0,20}overlay", re.I)]

HIGH_RISK = ("destructive", "credential", "exfiltration", "privilege")

SECRETS = [re.compile(r"AKIA[0-9A-Z]{16}"),
           re.compile(r"github_pat_[A-Za-z0-9_]+"),
           re.compile(r"ghp_[A-Za-z0-9]{30,40}"),
           re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
           re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
           re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")]

def _luhn_ok(s):
    if not s.isdigit() or len(s) < 13 or len(s) > 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(s)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

def _scan_secrets(text):
    hits = []
    for pat in SECRETS:
        if pat.search(text):
            hits.append(pat.pattern)
    # Luhn card-like sequences (13-19 digits)
    for m in re.finditer(r"\b\d{13,19}\b", text):
        if _luhn_ok(m.group(0)):
            hits.append("luhn-card")
            break
    return hits

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
        # P_rt_secrets: secret material in any payload must be approved
        text = pl if isinstance(pl, str) else json.dumps(pl, ensure_ascii=False)
        sec = _scan_secrets(text)
        if sec and not ev.get("approved"):
            fails.setdefault("P_rt_secrets", []).append(sec[0])
    # P_rt_sessions: zero-trust
    recs = {}
    for ev in (json.loads(l) for l in lines):
        sid = ev.get("session_id")
        et = ev.get("event_type")
        text = json.dumps(ev.get("payload") or {}, ensure_ascii=False)
        flagged = [p.pattern for p in INJ if p.search(text)]
        flagged += _scan_secrets(text)
        if flagged:
            recs.setdefault(sid, set()).update(flagged)
    if recs:
        print("  [recommendations] per-session redaction:")
        for sid, flag in recs.items():
            print(f"    {sid}: redact/approve: {', '.join(sorted(flag))}")
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
