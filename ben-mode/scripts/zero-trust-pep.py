#!/usr/bin/env python3
"""zero-trust-pep.py — P13-B1: Zero-Trust Policy Enforcement Point over traces.

Wraps runtime_gate.check_trace as a PEP (NIST SP 800-207): each session is
re-evaluated; allow iff no P_rt predicate fails. Exit 0 = ALLOW, 1 = DENY.
Usage: zero-trust-pep.py <trace.jsonl>
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from runtime_gate import check_trace


def main():
    if len(sys.argv) < 2:
        print("usage: zero-trust-pep.py <trace.jsonl>"); return 2
    fails = check_trace(sys.argv[1])
    denies = {k: v for k, v in fails.items() if v}
    if denies:
        print("PEP: DENY  %s" % ", ".join(sorted(denies)))
        return 1
    print("PEP: ALLOW (all P_rt predicates pass)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
