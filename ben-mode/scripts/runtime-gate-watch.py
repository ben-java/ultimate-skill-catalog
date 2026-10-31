#!/usr/bin/env python3
"""runtime-gate-watch.py — P12-A#1: continuous incremental runtime gate.

Tails a trace JSONL file and re-evaluates appended events on the fly using
the existing `runtime_gate.py` CLI, writing a heartbeat audit record per poll.

Exit: 0 if the last evaluated batch PASSed; 1 if a violation was detected.
Flags:
  --trace <path>      trace JSONL to watch (required)
  --once              single incremental pass (test-friendly); else loop
  --interval <sec>    poll interval (default 5)
  --out <path>        heartbeat JSONL destination (default: tempdir)
  --state <path>      byte-offset state file (default: <trace>.watch.state)
"""
import argparse, json, os, subprocess, sys, time

def load_state(path):
    try:
        with open(path, encoding="utf-8") as f:
            return int(f.read().strip() or 0)
    except Exception:
        return 0

def save_state(path, pos):
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(pos))

def tail_new(path, pos):
    with open(path, "rb") as f:
        f.seek(pos)
        data = f.read()
    return pos + len(data), data

def eval_trace(runtime_gate, trace_path, out_path, events, status, ts):
    r = subprocess.run([sys.executable, runtime_gate, trace_path],
                       capture_output=True, text=True)
    ok = r.returncode == 0
    rec = {"ts": ts, "events_since_last": events,
           "status": "PASS" if ok else "FAIL",
           "exit_code": r.returncode,
           "detail": (r.stdout + r.stderr).strip()[-300:]}
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return ok

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", required=True)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=int, default=5)
    ap.add_argument("--out")
    ap.add_argument("--state")
    a = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    runtime_gate = os.path.join(here, "runtime_gate.py")
    state_f = a.state or (a.trace + ".watch.state")
    out_f = a.out or os.path.join(tempfile_gettempdir(), "runtime-audit.jsonl")

    pos = load_state(state_f)
    while True:
        npos, data = tail_new(a.trace, pos)
        if data and data.strip():
            # write only the new events into a temp trace slice
            slice_path = a.trace + ".slice.jsonl"
            with open(slice_path, "ab") as f:
                f.write(data)
            n_events = len(data.strip().splitlines())
            ok = eval_trace(runtime_gate, slice_path, out_f, n_events,
                            None, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            # merge accepted events into a running full trace for next eval
            with open(a.trace + ".full.jsonl", "ab") as g:
                g.write(data)
            pos = npos
            save_state(state_f, pos)
            if not ok:
                print("runtime-gate-watch: VIOLATION detected (rc=1)")
                return 1
            print("runtime-gate-watch: batch OK (%d events)" % n_events)
        if a.once:
            break
        time.sleep(max(1, a.interval))
    return 0

def tempfile_gettempdir():
    import tempfile
    return tempfile.gettempdir()

if __name__ == "__main__":
    sys.exit(main())
