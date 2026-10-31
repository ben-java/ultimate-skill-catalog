#!/usr/bin/env python3
"""span-tree.py — P26-7: hierarchical span-tree validation of an agent trace (JSONL).

Each event may carry span_id and optional parent_span (span-per-tick style; AgentOps/
MLflow). A handoff event (payload.target_agent) links spans across agents. This tool:
  - ensures every parent_span reference resolves to an existing span_id,
  - rejects cycles,
  - counts handoff spans.
Exit 0 valid, 1 invalid, 2 input error.
"""
import json, os, sys

def build(path):
    if not os.path.isfile(path):
        return None, "trace missing"
    spans = {}
    children = {}
    handoffs = 0
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l for l in f.read().splitlines() if l.strip()]
        for ln in lines:
            ev = json.loads(ln)
            sid = ev.get("span_id")
            if sid is not None:
                spans[sid] = ev
                parent = ev.get("parent_span")
                if parent is not None:
                    children.setdefault(parent, set()).add(sid)
            if isinstance(ev.get("payload"), dict) and ev["payload"].get("target_agent"):
                handoffs += 1
    except Exception as e:
        return None, "parse error: %s" % e
    # missing parent refs
    missing = [sid for sid, ev in spans.items()
               if ev.get("parent_span") is not None and ev["parent_span"] not in spans]
    # cycles via DFS
    state = {}; cyc = []
    def visit(n, stack):
        if state.get(n) == 2: return
        if state.get(n) == 1:
            cyc.append(n); return
        state[n] = 1
        for ch in sorted(children.get(n, ())):
            visit(ch, stack + [ch])
        state[n] = 2
    for s in spans: visit(s, [s])
    return {"spans": len(spans), "missing_parents": len(missing),
            "cycles": len(cyc), "handoffs": handoffs}, None

def main():
    if len(sys.argv) < 2:
        print("usage: span-tree.py <trace.jsonl>"); return 2
    info, err = build(sys.argv[1])
    if err:
        print("span-tree:", err); return 2
    ok = info["missing_parents"] == 0 and info["cycles"] == 0
    print("SPAN-TREE REPORT: spans=%d handoffs=%d missing_parents=%d cycles=%d"
          % (info["spans"], info["handoffs"], info["missing_parents"], info["cycles"]))
    print("OVERALL: %s | exit %d" % ("PASS" if ok else "FAIL", 0 if ok else 1))
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
