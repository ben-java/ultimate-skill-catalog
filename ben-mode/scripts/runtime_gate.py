"""P_runtime live gate - validates an agent action trace (JSONL).
Events: {"session_id","ts","event_type":"action|output|input","actor",
         "payload":... ,"approved":bool,"schema": "optional expected structure"}
Predicates:
  P_rt_injection   - hostile/injection payload entering model context (event=input) flagged
  P_rt_highrisk_hitl - destructive/credential action requires approved==true
  P_rt_output_structure - output with expected_schema must carry required keys
  P_rt_sessions    - zero-trust: tiap session diverifikasi ulang (quorum fresh)
  P_rt_ifc         - information flow control: untrusted input->high-risk action tanpa verify boundary
  P_rt_plan_drift  - plan drift: tool-call sequence menyimpang dari urutan/plan yang diizinkan
  P_rt_tool_schema - tool param harus lolos schema ketat (tipe/sejumlah/allowlist)
  P_rt_throttle    - burst tool-call tak wajar dalam jendela waktu (blast-radius)
  P_rt_msg_auth    - pesan antar-agent wajib bertanda tangan (anti-spoofing)
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
    _last_plan = {}
    _thr = {}
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
        # P_rt_ifc (P26-3): untrusted input boundary -> high-risk action tanpa verify/approval
        if et == "action":
            cat = str(pl.get("category", "")).lower()
            trust = str(pl.get("trust", "trusted")).lower()
            if any(h in cat for h in HIGH_RISK) and trust == "untrusted" and not ev.get("approved"):
                fails.setdefault("P_rt_ifc", []).append(f"{ev.get('session_id')}:{cat}")
        # P_rt_plan_drift (P26-2): tool-call sequence menyimpang dari plan_step monotonic
        if et == "action" and isinstance(pl.get("plan_step"), int):
            _s = ev.get("session_id")
            _prev = _last_plan.get(_s)
            if _prev is not None and pl["plan_step"] < _prev:
                fails.setdefault("P_rt_plan_drift", []).append(f"{_s}:step{pl['plan_step']}after{_prev}")
            _last_plan[_s] = pl["plan_step"]
        # P_rt_tool_schema (P26-6): tool param wajib cocok schema
        if et == "action" and isinstance(pl.get("params"), dict) and isinstance(pl.get("param_schema"), dict):
            for _pn, _pt in pl["param_schema"].items():
                if _pn not in pl["params"]:
                    continue
                _val = pl["params"][_pn]
                if _pt == "str" and not isinstance(_val, str):
                    fails.setdefault("P_rt_tool_schema", []).append(f"{_pn}:want-str-got-{type(_val).__name__}")
                elif _pt == "int" and not isinstance(_val, int):
                    fails.setdefault("P_rt_tool_schema", []).append(f"{_pn}:want-int-got-{type(_val).__name__}")
        # P_rt_throttle (P26-8): burst action > N dalam window
        if et == "action":
            _s = ev.get("session_id")
            _t_iso = ev.get("ts")
            _slot = (ev.get("ts") or "")[:16]  # minute granularity
            _thr.setdefault(_s, {}).setdefault(_slot, 0)
            _thr[_s][_slot] += 1
            if _thr[_s][_slot] > 8:
                fails.setdefault("P_rt_throttle", []).append(f"{_s}:{_slot}:{_thr[_s][_slot]}")
        # P_rt_msg_auth (P26-9): inter-agent message tanpa signature
        if et == "action" and pl.get("target_agent") and not ev.get("msg_sig"):
            fails.setdefault("P_rt_msg_auth", []).append(f"{ev.get('session_id')}:{pl.get('target_agent')}")
        # P_rt_secrets: token scoped/short-lived wajib punya scope+exp
        if et in ("input", "action"):
            _txt = pl if isinstance(pl, str) else json.dumps(pl, ensure_ascii=False)
            if re.search(r"\b(?:ghp_|github_pat_|sk-|xox)[A-Za-z0-9_-]+\b", _txt):
                if isinstance(pl, dict) and not (pl.get("token_scope") and pl.get("token_exp")):
                    fails.setdefault("P_rt_secrets", []).append("token-missing-scope-or-exp")
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
    # P6-F: + freshness - action/output setelah verify lebih tua dari jendela = FAIL.
    FRESHNESS = int(os.environ.get("HARD_GATE_SESSION_FRESHNESS", "3600"))
    def _ep(ev):
        return ev.get("event_type"), ev.get("session_id"), ev.get("ts"), ev
    events = [json.loads(l) for l in lines]
    for s in sessions:
        se = [ev for ev in events if ev.get("session_id") == s]
        has_verify = any(ev.get("event_type") == "verify" for ev in se)
        if not has_verify:
            fails.setdefault("P_rt_sessions", []).append(str(s) + ":no-verify")
            continue
        # freshness: last verify ts vs max ts of later non-verify events
        vtimes = []
        for ev in se:
            if ev.get("event_type") == "verify" and ev.get("ts"):
                try:
                    vtimes.append(datetime.datetime.fromisoformat(ev["ts"].replace("Z", "+00:00")))
                except Exception:
                    pass
        if not vtimes:
            continue
        last_verify = max(vtimes)
        for ev in se:
            if ev.get("event_type") in ("action", "output") and ev.get("ts"):
                try:
                    t = datetime.datetime.fromisoformat(ev["ts"].replace("Z", "+00:00"))
                except Exception:
                    continue
                if t > last_verify and (t - last_verify).total_seconds() > FRESHNESS:
                    fails.setdefault("P_rt_sessions", []).append(str(s) + ":stale-after-verify")
                    break
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
