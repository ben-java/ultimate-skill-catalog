#!/usr/bin/env python3
"""weekly-summary.py — combined weekly observability summary (P5 C2/C3).

Reads meta-dir artifacts:
  gate-cost.jsonl, gate-time.jsonl, runtime-audit.jsonl, gate-audit-aggregated.jsonl,
  hard-gate-alerts.log (drift FAIL events -> histogram per root/date).

Prints a compact summary; exit 0.
"""
import argparse, json, os, re, sys
from collections import Counter, defaultdict


def load_jsonl(path, skip_missing=True):
    out = []
    if not os.path.isfile(path):
        return out if skip_missing else None
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    except Exception as e:
        print(f"warn: cannot read {path}: {e}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("meta")
    ap.add_argument("--days", type=int, default=7)
    args = ap.parse_args()

    cost = load_jsonl(os.path.join(args.meta, "gate-cost.jsonl"))
    times = load_jsonl(os.path.join(args.meta, "gate-time.jsonl"))
    runtime = load_jsonl(os.path.join(args.meta, "runtime-audit.jsonl"))
    aggr = load_jsonl(os.path.join(args.meta, "gate-audit-aggregated.jsonl"))

    print(f"=== Weekly summary (last {args.days}d) ===")
    if cost:
        toks = sum(r.get("token_proxy", 0) for r in cost[-200:])
        print(f"gate runs: {len(cost)}  total token_proxy: {toks}")
    if times:
        ms = [r.get("ts_ms", 0) for r in times[-200:]]
        print(f"gate duration: avg {sum(ms)//len(ms)}ms  max {max(ms)}ms  (n={len(ms)})")
    if runtime:
        statuses = Counter(r.get("status") for r in runtime[-100:])
        print(f"runtime scan: {dict(statuses)}  last_since_clean={runtime[-1].get('since_clean')}")
    # P21-B1: telemetri mutakhir
    _covp = os.path.join(args.meta, "routing-coverage.json")
    if os.path.isfile(_covp):
        try:
            _c = json.load(open(_covp, encoding="utf-8"))
            _unres = len(_c.get("unresolved", []))
            print(f"routing coverage: {_c.get('coverage_pct')}% (installed={_c.get('installed')}, referenced={_c.get('referenced')}, unresolved_actionable={_unres})")
        except Exception:
            pass
    _sp = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "references", "hard-gate-10.md"))
    if os.path.isfile(_sp):
        mm = re.search(r"Spec version.*?(\d+\.\d+\.\d+)", open(_sp, encoding="utf-8").read())
        if mm:
            print(f"spec version: {mm.group(1)}")

    # P25-B1: last real gate verdict from audit log (mirror status-matrix)
    import tempfile as _tf
    _ga = os.path.join(_tf.gettempdir(), "hard-gate-audit.log.json")
    _gate_status = "n/a"; _gate_ts = "n/a"
    _proj_root = "C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog"
    if os.path.isfile(_ga):
        try:
            _txt = open(_ga, encoding="utf-8", errors="ignore").read()
            _dec = json.JSONDecoder(); _i = 0
            while _i < len(_txt):
                while _i < len(_txt) and _txt[_i] in " \t\r\n": _i += 1
                if _i >= len(_txt): break
                if _txt[_i] != "{": _i += 1; continue
                try: _obj, _end = _dec.raw_decode(_txt, _i)
                except Exception: _i += 1; continue
                if _proj_root in _obj.get("root", "") and _obj.get("status") in ("PASS", "FAIL"):
                    _gate_status = _obj.get("status")
                    _gate_ts = _obj.get("timestamp", _obj.get("ts", ""))
                _i = _end
        except Exception:
            pass
    print(f"last gate verdict: {_gate_status} @ {_gate_ts}")

    if aggr:
        st = Counter(r.get("status") for r in aggr[-200:])
        print(f"audit events: {dict(st)}")

    # drift histogram from alerts log (date on its own section header line, not the FAIL line)
    alerts = os.path.join(args.meta, "..", "hard-gate-alerts.log")
    drifts = []
    if os.path.isfile(alerts):
        cur_date = None
        for line in open(alerts, encoding="utf-8", errors="ignore"):
            if line.startswith("===") and "(" in line:
                seg = line.split("(")[-1][:10]
                if len(seg) == 10 and seg[4] == "-" and seg[7] == "-":
                    cur_date = seg
            if "FAILED" in line or "Drift check FAILED" in line:
                if cur_date:
                    drifts.append(cur_date)
    if drifts:
        hist = Counter(drifts)
        print("drift events by day:", dict(sorted(hist.items())))
    else:
        print("drift events: none in alerts log (clean)")


if __name__ == "__main__":
    main()
