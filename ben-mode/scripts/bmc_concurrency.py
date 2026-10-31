#!/usr/bin/env python3
"""bmc_concurrency.py — bounded model check of the gate's read/write concurrency
invariant (P4 E2).

Model: two verifier readers (R1,R2) and one syncer writer W mutate the same
skill tree. Safety property: no reader may observe a half-written file, i.e.
any write of file F sets `dirty[F]=1` before writing and clears it after; a
reader reads F only while `dirty[F]=0`; a writer must not start a second write
while a write is in flight (no lost update). We ask z3 for a K-step interleaving
that violates the invariant -> expect UNSAT.

Exit: 0 = UNSAT (invariant holds, bounded), 1 = SAT (violation found),
      2 = z3 unavailable.
"""
import sys
try:
    import z3
except Exception:
    print("bmc_concurrency: z3 unavailable (run bootstrap-deps.sh)")
    sys.exit(2)

K = 8

# per-step: phase of each actor; dirty flag; write-active flag
R1, R2, W = 0, 1, 2
IDLE, READ, WRITE = 0, 1, 2

def T(ph, ph2, dirty, dirty2, wact, wact2, lock=False):
    """Transition relation for one step. lock=True enforces mutual exclusion:
    write may start only while both readers are idle (pe model = serialized sync)."""
    steps = []
    # R1
    steps.append(z3.And(ph[R1] == IDLE, dirty == 0, ph2[R1] == READ, ph2[R2] == ph[R2], ph2[W] == ph[W],
                        dirty2 == dirty, wact2 == wact))
    steps.append(z3.And(ph[R1] == READ, ph2[R1] == IDLE, ph2[R2] == ph[R2], ph2[W] == ph[W],
                        dirty2 == dirty, wact2 == wact))
    # R2
    steps.append(z3.And(ph[R2] == IDLE, dirty == 0, ph2[R2] == READ, ph2[R1] == ph[R1], ph2[W] == ph[W],
                        dirty2 == dirty, wact2 == wact))
    steps.append(z3.And(ph[R2] == READ, ph2[R2] == IDLE, ph2[R1] == ph[R1], ph2[W] == ph[W],
                        dirty2 == dirty, wact2 == wact))
    # W start: require no write in flight AND (if lock) both readers idle
    w_start_guard = wact == 0
    if lock:
        w_start_guard = z3.And(wact == 0, ph[R1] == IDLE, ph[R2] == IDLE)
    steps.append(z3.And(ph[W] == IDLE, w_start_guard, ph2[W] == WRITE,
                        ph2[R1] == ph[R1], ph2[R2] == ph[R2],
                        dirty2 == 1, wact2 == 1))
    steps.append(z3.And(ph[W] == WRITE, ph2[W] == IDLE, ph2[R1] == ph[R1], ph2[R2] == ph[R2],
                        dirty2 == 0, wact2 == 0))
    steps.append(z3.And(ph[R1] == IDLE, ph[R2] == IDLE, ph[W] == IDLE,
                        ph2[R1] == IDLE, ph2[R2] == IDLE, ph2[W] == IDLE,
                        dirty2 == dirty, wact2 == wact))
    return z3.Or(*steps)

def main():
    s = z3.Solver()
    # per-actor phase at each step: r1[i], r2[i], w[i]; plus dirty[i], wact[i]
    r1 = [z3.Int(f"r1_{i}") for i in range(K + 1)]
    r2 = [z3.Int(f"r2_{i}") for i in range(K + 1)]
    w = [z3.Int(f"w_{i}") for i in range(K + 1)]
    d = [z3.Int(f"dirty_{i}") for i in range(K + 1)]
    wa = [z3.Int(f"wact_{i}") for i in range(K + 1)]
    for i in range(K + 1):
        for v in (r1[i], r2[i], w[i], d[i], wa[i]):
            s.add(v >= 0, v <= 2)
    # start: all idle, clean
    for i in range(K + 1):
        pass
    s.add(r1[0] == IDLE, r2[0] == IDLE, w[0] == IDLE)
    s.add(d[0] == 0, wa[0] == 0)
    idx = lambda i: (r1[i], r2[i], w[i])
    # Scenario S1: NO lock (cp + verify run concurrently) -> expect SAT (hazard exists)
    s1 = z3.Solver()
    for i in range(K + 1):
        for v in (r1[i], r2[i], w[i], d[i], wa[i]):
            s1.add(v >= 0, v <= 2)
    s1.add(r1[0] == IDLE, r2[0] == IDLE, w[0] == IDLE)
    s1.add(d[0] == 0, wa[0] == 0)
    for i in range(K):
        s1.add(T(idx(i), idx(i + 1), d[i], d[i + 1], wa[i], wa[i + 1], lock=False))
    v1 = False
    for i in range(K + 1):
        v1 = z3.Or(v1, z3.And(r1[i] == READ, d[i] == 1),
                   z3.And(r2[i] == READ, d[i] == 1))
    s1.add(v1)
    r1res = s1.check()

    # Scenario S2: WITH lock (serialized sync) -> expect UNSAT (invariant holds)
    s2 = z3.Solver()
    for i in range(K + 1):
        for v in (r1[i], r2[i], w[i], d[i], wa[i]):
            s2.add(v >= 0, v <= 2)
    s2.add(r1[0] == IDLE, r2[0] == IDLE, w[0] == IDLE)
    s2.add(d[0] == 0, wa[0] == 0)
    for i in range(K):
        s2.add(T(idx(i), idx(i + 1), d[i], d[i + 1], wa[i], wa[i + 1], lock=True))
    v2 = False
    for i in range(K + 1):
        v2 = z3.Or(v2, z3.And(r1[i] == READ, d[i] == 1),
                   z3.And(r2[i] == READ, d[i] == 1))
    s2.add(v2)
    r2res = s2.check()

    print(f"BMC CONCURRENCY S1 (no lock): {r1res}  -> hazard {'present' if r1res == z3.sat else 'absent'}")
    print(f"BMC CONCURRENCY S2 (lock):    {r2res}  -> invariant {'HOLDS' if r2res == z3.unsat else 'violated'}")
    if r2res == z3.unsat:
        print("=> serialized sync (cp -> verify) prevents read-while-write; concurrency-safe")
        return 0
    print("=> lock discipline required before concurrent verifier runs")
    return 1

if __name__ == "__main__":
    sys.exit(main())
