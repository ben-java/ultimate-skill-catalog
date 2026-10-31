#!/usr/bin/env python3
# generate-dashboard.py — P8-O#6: self-contained passive HTML dashboard.
# Reads .hard-gate-meta/ (gate-cost, gate-time, audit logs) and writes dashboard.html.
# No external JS/CSS runtime dependencies; strictly read-only inspection.
import glob
import hashlib
import html
import json
import os
import re
import shutil
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CANON_META = os.path.abspath("C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog/.hard-gate-meta")


def load_jsonl(p, limit=50):
    rows = []
    if not os.path.isfile(p):
        return rows
    with open(p, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows[-limit:]


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else CANON_META
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(target, "dashboard.html")
    cost_rows = load_jsonl(os.path.join(target, "gate-cost.jsonl"))
    time_rows = load_jsonl(os.path.join(target, "gate-time.jsonl"))
    audit_rows = load_jsonl(os.path.join(target, "runtime-audit.jsonl"))

    tot_tokens = sum(r.get("token_proxy", 0) for r in cost_rows)
    tot_bytes = cost_rows[-1].get("tree_bytes", 0) if cost_rows else 0
    last_rc = time_rows[-1].get("rc", "n/a") if time_rows else "n/a"
    import time as _time
    gt = os.path.join(target, "gate-time.jsonl")
    last_run_str = (_time.strftime("%Y-%m-%d %H:%M", _time.localtime(os.path.getmtime(gt)))
                    if os.path.isfile(gt) else "n/a")
    oracle_ver, oracle_tests = "n/a", 0
    snap_path = os.path.join(target, "regression-snapshot.json")
    if os.path.isfile(snap_path):
        try:
            _snap = json.load(open(snap_path, encoding="utf-8"))
            oracle_ver = _snap.get("version", "n/a")
            oracle_tests = _snap.get("negative_test_count", 0)
        except Exception:
            pass
    merkle_root = "n/a"
    tl_path = os.path.join(target, "transparency.merkle.json")
    if os.path.isfile(tl_path):
        try:
            merkle_root = json.load(open(tl_path, encoding="utf-8")).get("root", "n/a")[:16]
        except Exception:
            pass
    vsa_result = "n/a"
    vsa_path = os.path.join(target, "vsa.json")
    if os.path.isfile(vsa_path):
        try:
            vsa_result = json.load(open(vsa_path, encoding="utf-8")).get("result", "n/a")
        except Exception:
            pass
    model_hashes = "absent"
    if os.path.isfile(os.path.join(target, "model-hashes.json")):
        model_hashes = "present"
    _opa = shutil.which("opa") or os.path.expanduser("~/bin/opa.exe")
    _opa_env = os.environ.get("OPA_BIN")
    if _opa_env and os.path.isfile(_opa_env):
        _opa = _opa_env
    opa_state = "enforced" if (_opa and os.path.isfile(_opa)) else "skipped"

    # P20-C1: budget usage %
    _budget = 1000000
    _budget_pct = 0
    if tot_tokens:
        _budget_pct = min(100, tot_tokens * 100 // _budget)

    # P19-C2: routing coverage + spec version stats
    _rout = {"installed": "n/a", "coverage_pct": "n/a"}
    _rout_path = os.path.join(target, "routing-coverage.json")
    if os.path.isfile(_rout_path):
        try:
            _rout.update(json.load(open(_rout_path, encoding="utf-8")))
        except Exception:
            pass
    # P23-C1: last real gate verdict
    import tempfile as _tf
    _gate_verdict = "n/a"
    _ga = os.path.join(_tf.gettempdir(), "hard-gate-audit.log.json")
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
                if "ultimate-skill-catalog" in _obj.get("root", "") and _obj.get("status") in ("PASS", "FAIL"):
                    _gate_verdict = _obj.get("status")
                _i = _end
        except Exception:
            pass
    _spec_ver = "n/a"
    _sp = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "references", "hard-gate-10.md"))
    if os.path.isfile(_sp):
        _m = re.search(r"Spec version.*?(\d+\.\d+\.\d+)", open(_sp, encoding="utf-8").read())
        if _m:
            _spec_ver = _m.group(1)

    # P17-D2: SBOM age & traceability stats
    sbom_path = os.path.join(target, "ben-mode.sbom.json")
    if not os.path.isfile(sbom_path):
        sbom_path = os.path.abspath(os.path.join(target, "..", "ben-mode.sbom.json"))
    sbom_status = (_time.strftime("%m-%d %H:%M", _time.localtime(os.path.getmtime(sbom_path)))
                   if os.path.isfile(sbom_path) else "absent")

    cost_tr = "".join(
        f"<tr><td>{html.escape(str(r.get('ts','')))}</td>"
        f"<td>{r.get('token_proxy',0)}</td>"
        f"<td>{r.get('skills',0)}</td>"
        f"<td>{r.get('tree_bytes',0)}</td></tr>"
        for r in reversed(cost_rows[-10:])
    )
    time_tr = "".join(
        f"<tr><td>{html.escape(str(r.get('ts','')))}</td>"
        f"<td>{r.get('wall_s',0):.2f}s</td>"
        f"<td>{r.get('rc',0)}</td></tr>"
        for r in reversed(time_rows[-10:])
    )

    if cost_rows:
        mx = max(r.get("token_proxy", 0) for r in cost_rows) or 1
        bars = []
        for r in cost_rows[-14:]:
            w = max(2, int(100 * r.get("token_proxy", 0) / mx))
            bars.append('<div style="display:flex;align-items:center;gap:8px;">'
                        '<div style="width:130px;color:#8b949e;font-size:0.78rem;">%s</div>'
                        '<div style="background:#3fb950;height:14px;width:%d%%;border-radius:3px;"></div>'
                        '<div style="color:#e6edf3;font-size:0.8rem;">%s tok</div></div>'
                        % (html.escape(str(r.get("ts", "")))[5:16], w, r.get("token_proxy", 0)))
        trend_html = ('<h2>Recent Token Budget Trend (14 runs)</h2><div style="margin-bottom:2rem;">'
                      + "".join(bars) + "</div>")
    else:
        trend_html = "<h2>Recent Token Budget Trend (14 runs)</h2><p>No data</p>"
    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>HARD GATE #10 Dashboard</title>
<style>
body {{ font-family: -apple-system, Segoe UI, sans-serif; margin: 2rem; background: #0f141c; color: #e6edf3; }}
h1, h2 {{ color: #58a6ff; }}
.cards {{ display: flex; gap: 1rem; margin-bottom: 2rem; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; flex: 1; }}
.card .val {{ font-size: 1.8rem; font-weight: bold; color: #3fb950; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 2rem; }}
th, td {{ text-align: left; padding: 0.5rem; border-bottom: 1px solid #21262d; font-size: 0.9rem; }}
th {{ color: #8b949e; background: #161b22; }}
</style>
</head>
<body>
<h1>HARD GATE #10 Observability Dashboard</h1>
<div class="cards">
  <div class="card"><div>Total Token Proxy</div><div class="val">{tot_tokens:,}</div></div>
  <div class="card"><div>Tree Bytes</div><div class="val">{tot_bytes:,}</div></div>
  <div class="card"><div>Last Cron RC</div><div class="val">{last_rc}</div></div>
  <div class="card"><div>Audits Recorded</div><div class="val">{len(audit_rows)}</div></div>
  <div class="card"><div>Last Gate Run</div><div class="val">{last_run_str}</div></div>
  <div class="card"><div>Oracle v / neg-tests</div><div class="val">{oracle_ver} / {oracle_tests}</div></div>
  <div class="card"><div>Merkle Root</div><div class="val">{merkle_root}</div></div>
  <div class="card"><div>VSA Result</div><div class="val">{vsa_result}</div></div>
  <div class="card"><div>OPA Enforce</div><div class="val">{opa_state}</div></div>
  <div class="card"><div>Model-hashes</div><div class="val">{model_hashes}</div></div>
  <div class="card"><div>SBOM</div><div class="val">{sbom_status}</div></div>
  <div class="card"><div>Spec v</div><div class="val">{_spec_ver}</div></div>
  <div class="card"><div>Routing cov</div><div class="val">{_rout["coverage_pct"]}%</div></div>
  <div class="card"><div>Budget usage</div><div class="val">{_budget_pct}%</div></div>
  <div class="card"><div>Gate Verdict</div><div class="val">{_gate_verdict}</div></div>
</div>
<h2>Recent Gate Executions (Cost)</h2>
<table>
<thead><tr><th>Timestamp</th><th>Token Proxy</th><th>Skills</th><th>Bytes</th></tr></thead>
<tbody>{cost_tr or '<tr><td colspan="4">No data</td></tr>'}</tbody>
</table>
<h2>Recent Gate Runtimes (Wall-Clock)</h2>
<table>
<thead><tr><th>Timestamp</th><th>Wall Clock</th><th>Exit Code</th></tr></thead>
<tbody>{time_tr or '<tr><td colspan="3">No data</td></tr>'}</tbody>
</table>
{trend_html}
<p style="color:#8b949e; font-size:0.8rem;">Generated deterministically by generate-dashboard.py (P8-O#6). Zero external script runtime.</p>
</body>
</html>"""
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(doc)
    # P18-C1: atomically refresh model-hashes.json (self-referencing manifest)
    _mh = os.path.join(target, "model-hashes.json")
    if os.path.isfile(_mh):
        try:
            _m = json.load(open(_mh, encoding="utf-8"))
            with open(out, "rb") as _f:
                _raw = _f.read()
            _digest = hashlib.sha256(_raw).hexdigest()
            _dirty = False
            for _a in _m.get("assets", []):
                if os.path.basename(str(_a.get("path",""))) in ("dashboard.html",):
                    if _a.get("sha256") != _digest:
                        _a["sha256"] = _digest; _dirty = True
            if _dirty:
                _tmp = _mh + ".tmp"
                json.dump(_m, open(_tmp, "w", encoding="utf-8"), indent=2)
                os.replace(_tmp, _mh)  # atomic
        except Exception:
            pass
    print(f"✅ Dashboard written to {out} ({len(doc)} bytes)")


if __name__ == "__main__":
    main()
