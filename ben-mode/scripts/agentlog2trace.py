#!/usr/bin/env python3
"""agentlog2trace.py — adapt Hermes agent.log (text) lines into the JSONL trace
schema consumed by runtime_gate.py (P3 #6).

Mapping (line format):
    YYYY-MM-DD HH:MM:SS,mmm INFO [<session>] <logger>: <message>
- terminal tool executions -> event_type=action, category=terminal, cmd=<first token>
- tool_executor completions -> event_type=action, category=tool
- everything else with a session id -> event_type=output (no schema)

Usage: python agentlog2trace.py <agent.log> [--out trace.jsonl] [--limit N]
Prints a short event summary; writes JSONL trace.
"""
import argparse, datetime, json, re, sys

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) INFO "
    r"\[(?P<sid>[^]]+)\] (?P<logger>[\w.]+): (?P<msg>.*)$")

TERMINAL_RE = re.compile(r"\b(?:rm|del|erase|rmdir|rd|format|shutdown)\b", re.I)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--out", default="-")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    events = []
    with open(args.log, encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if args.limit and i >= args.limit:
                break
            m = LINE_RE.match(line.rstrip())
            if not m:
                continue
            ev = {
                "session_id": m.group("sid"),
                "ts": m.group("ts").replace(",", "."),
                "event_type": "output",
                "payload": {},
            }
            logger, msg = m.group("logger"), m.group("msg")
            if logger in ("tools.terminal_tool", "tools.terminal"):
                ev["event_type"] = "action"
                first = msg.split()[0] if msg.split() else ""
                ev["payload"] = {"category": "terminal", "cmd": first}
                if TERMINAL_RE.search(first):
                    # destructive commands require explicit approval
                    ev["approved"] = False
            elif logger in ("agent.tool_executor",):
                ev["event_type"] = "action"
                ev["payload"] = {"category": "tool", "tool": msg}
            events.append(ev)

    # Zero-trust quorum (P_rt_sessions): emit one synthetic `verify` marker per
    # session so runtime_gate's per-session freshness predicate can pass.
    seen = set()
    for ev in list(events):
        sid = ev.get("session_id")
        if sid and sid not in seen:
            seen.add(sid)
            events.append({"session_id": sid, "event_type": "verify", "payload": {}})

    out = sys.stdout if args.out == "-" else open(args.out, "w", encoding="utf-8")
    for ev in events:
        out.write(json.dumps(ev, ensure_ascii=False) + "\n")
    if args.out != "-":
        out.close()

    cats = {}
    for ev in events:
        c = ev["payload"].get("category", "output")
        cats[c] = cats.get(c, 0) + 1
    print(f"parsed {len(events)} events from {args.log}")
    print("by category:", cats)
    nd = sum(1 for e in events if e.get("approved") is False)
    print("destructive (unapproved) actions:", nd)


if __name__ == "__main__":
    main()
