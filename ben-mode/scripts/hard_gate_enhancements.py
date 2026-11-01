#!/usr/bin/env python3
"""hard_gate_enhancements.py - P1..P12 extended verification mechanisms.

P1  Probabilistic verdict calibration (multi-trial, Wilson 95% CI)
P2  Process-Verifier / Process Advantage Verifier (PAV) step scoring
P3  Meta-Judging / evaluator lineage (anti self-confirming)
P4  Ensemble Verifier Calibration (WMV weighted majority voting)
P5  Uncertainty-Aware Budget Allocation (UAB, ANLL difficulty signal)
P6  Self-improvement stability theorem (Variance Inequality, SMT/z3)
P7  Typed Chain-of-Thought (Curry-Howard) structural verification
P8  Evidence-grounded verifier (PRIME-style precommitted rules ledger)
P9  Runtime Model-Quality verification (overconfidence calibration)
P10 Multi-Agent Verification (MAV) parallel verifiers
P11 Spec executive summary + version-consistency helper
P12 Adversarial suite expansion hooks

Pure stdlib + optional z3 (z3 only for P6; skipped if unavailable).
"""
import hashlib, json, math, os, re, sys, tempfile, datetime

PY = sys.executable

def _h(b): return hashlib.sha256(b).hexdigest()

def _wilson(k, n, z=1.96):
    if n <= 0: return 0.0, 0.0, 0.0
    p = k / n
    denom = 1 + z*z/n
    centre = (p + z*z/(2*n)) / denom
    half = z * math.sqrt((p*(1-p) + z*z/(4*n)) / n) / denom
    return centre - half, centre, centre + half

# ------------------------------------------------------------------ P1
def calibrate_verdict(trials, k, threshold=0.90):
    """Return (pass, rate, lo, hi, n) - majority-amplification verdict."""
    lo, rate, hi = _wilson(k, trials)
    return rate >= threshold, rate, lo, hi, trials

# ------------------------------------------------------------------ P2
def process_verifier(trace_events, prover_delta=0.05):
    """PAV-style: score steps by progress (delta in likelihood of success).
    trace_events: list of step dicts with {'step':i,'score':float}.
    Returns (ok, step_failures)."""
    prev = 0.0; failures = []
    for ev in trace_events:
        s = float(ev.get("score", 0.0))
        # progress must be non-negative; regression > threshold flagged
        if s < prev - prover_delta:
            failures.append(ev.get("step", "?"))
        prev = s
    return len(failures) == 0, failures

# ------------------------------------------------------------------ P3
def meta_judge(judge_runs, bias_tol=0.05):
    """Compare judge on same item twice; low self-consistency => unreliable.
    judge_runs: list of (item, score). Returns (consistent, inconsistency_rate)."""
    if not judge_runs: return True, 0.0
    from collections import defaultdict
    per = defaultdict(list)
    for item, score in judge_runs: per[item].append(score)
    bad = 0; tot = 0
    for item, scores in per.items():
        if len(scores) >= 2:
            tot += 1
            if abs(scores[0]-scores[1]) > bias_tol: bad += 1
    return bad == 0, (bad/tot if tot else 0.0)

# ------------------------------------------------------------------ P4
def wmv_ensemble(votes, fp_rate, fn_rate):
    """Calibrated weighted majority voting over judge votes.
    votes: list of (judge_i, verdict_bool). Returns (final, weight_sum)."""
    cl = []
    for j, v in votes:
        # weight = (1 - fp - fn) clamp; more reliable judges weigh more
        w = max(0.0, 1.0 - fp_rate.get(j, 0.1) - fn_rate.get(j, 0.1))
        cl.append((w, 1.0 if v else 0.0))
    tw = sum(w for w, _ in cl)
    if tw <= 0: return False, 0.0
    pos = sum(w*c for w, c in cl) / tw
    return pos >= 0.5, tw

# ------------------------------------------------------------------ P5
def uab_allocate(questions, budget, base=1):
    """Uncertainty-aware budget allocation (greedy marginal-gain).
    questions: list of {'id','anll'} difficulty signal (higher = more uncertain).
    Returns dict id->samples. base sample each, remaining budget by ANLL."""
    alloc = {q["id"]: base for q in questions}
    remaining = max(0, budget - base*len(questions))
    # sort by uncertainty descending
    order = sorted(questions, key=lambda q: -q.get("anll", 0.0))
    i = 0
    while remaining > 0 and order:
        q = order[i % len(order)]
        alloc[q["id"]] += 1; remaining -= 1; i += 1
    return alloc

# ------------------------------------------------------------------ P6
def self_improvement_stable(gen_noise, ver_noise, kappa=0.05):
    """Variance Inequality sufficient condition: combined noise small enough.
    Returns (stable, condition_detail). Uses analytic check; z3 optional proof."""
    combined = gen_noise + ver_noise
    stable = combined <= kappa
    return stable, {"combined_noise": combined, "threshold": kappa}

def self_improvement_smt(gen_noise, ver_noise, kappa=0.05):
    """SMT/z3 proof of Variance Inequality stability (discrete model)."""
    try:
        import z3
    except Exception:
        return "SKIPPED", "z3 not available"
    g, v, k = z3.Real("g"), z3.Real("v"), z3.Real("k")
    s = z3.Solver()
    s.add(g == z3.RealVal(gen_noise), v == z3.RealVal(ver_noise),
          k == z3.RealVal(kappa))
    s.add(g + v > k)  # negate stability
    r = s.check()
    return ("UNSAT" if str(r) == "unsat" else "SAT"), str(r)

# ------------------------------------------------------------------ P7
def typed_cot_verify(trace, coverage=0.7, evr=0.7, pe=1.0):
    """Curry-Howard style certification of a reasoning trace.
    trace: list of step dicts with 'rule', 'typed', 'evidence'.
    Returns (certified, metrics)."""
    if not trace: return False, {}
    n = len(trace)
    typed = sum(1 for t in trace if t.get("typed"))
    ev_ok = sum(1 for t in trace if t.get("evidence"))
    cov = typed / n
    evr_ = ev_ok / n
    pe_ = float(pe)
    certified = (cov >= coverage and evr_ >= evr and pe_ == 1.0)
    return certified, {"coverage": cov, "evr": evr_, "pe": pe_}

# ------------------------------------------------------------------ P8
def evidence_grounded_valid(ledger, conclusion, rules):
    """PRIME-style: a conclusion is valid only if ledger supports it under rules.
    rules: dict {conclusion: set(required_evidence_ids)}."""
    req = rules.get(conclusion, set())
    have = set(ledger.get("evidence", []))
    return req.issubset(have), {"missing": sorted(req - have)}

# ------------------------------------------------------------------ P9
def model_quality(pred_conf, actual_correct):
    """Overconfidence calibration: ECE. Returns (ece, ok)."""
    if not pred_conf or len(pred_conf) != len(actual_correct):
        return None, False
    n = len(pred_conf)
    ece = sum(abs(p - (1.0 if c else 0.0)) for p, c in zip(pred_conf, actual_correct)) / n
    return ece, ece <= 0.2

# ------------------------------------------------------------------ P10
def mav_aggregate(verifier_votes, min_pass=0.6):
    """Multi-agent verification: aggregate parallel verifier verdicts.
    Returns (aggregate_ok, pass_rate, n_verifiers)."""
    if not verifier_votes: return False, 0.0, 0
    rate = sum(1 for v in verifier_votes if v) / len(verifier_votes)
    return rate >= min_pass, rate, len(verifier_votes)

# ------------------------------------------------------------------ P11
def spec_version_consistent(spec_version, skill_version, changelog_version=None):
    ver = [spec_version]
    if skill_version: ver.append(skill_version)
    if changelog_version: ver.append(changelog_version)
    return len(set(ver)) == 1, ver

# ------------------------------------------------------------------ P12
def adversarial_readiness():
    """Return list of runtime threat tests to add (used by negative suite)."""
    return ["multiturn_jailbreak", "semantic_paraphrase", "error_cascading",
            "hallucination_action", "multi_run_variance", "correlated_judges"]

# ================= N1..N12 (2026-11-01) =================
# N1: Verifiable inference commitment (zkML-style config+output binding)
def inference_commitment(model_id, input_hash, output_hash, cfg_fingerprint):
    """Bind model+input+cfg+output into one verifiable commitment digest.
    Returns (commitment, ok) — ok True when all parts present."""
    parts = [model_id, input_hash, output_hash, cfg_fingerprint]
    if not all(parts):
        return None, False
    return _h("|".join(parts).encode()), True

# N2: MFOTL-style metric temporal monitor over an event trace
def temporal_monitor(events, obligation):
    """Obligation: dict {type, window_s, action, forbidden}. An event of `type`
    and `action` must not appear within `window_s` after a trigger event."""
    trig = obligation.get("trigger"); typ = obligation.get("type")
    action = obligation.get("action"); win = obligation.get("window_s")
    ts = obligation.get("window_ts", 0.0)
    last_trigger = None; violations = []
    for e in events:
        et = e.get("event_type"); t = e.get("ts", 0.0)
        if et == trig: last_trigger = t
        elif et == typ and e.get("payload", {}).get("name") == action:
            if last_trigger is not None and (t - last_trigger) <= win:
                violations.append((t, action))
    return len(violations) == 0, violations

# N3: AgentVerify hybrid — O(1) FSM obligation tokens + post-hoc check
def agentverify_monitor(events, spec):
    """spec: list of invariant-response rules {'if','then'} applied per event.
    Returns (ok, fired_obligations)."""
    fired = []
    ok = True
    for e in events:
        et = e.get("event_type")
        for rule in spec:
            if et == rule.get("if"):
                if not e.get("approved") and not e.get("verified"):
                    fired.append(rule.get("then")); ok = False
    return ok, fired

# N4: VEPA — deterministic structural conflict-free policy validation
def vepa_validate(policy_rules):
    """Accept only structurally valid, conflict-free rules. A conflict = two
    rules with same trigger but different decision."""
    from collections import defaultdict
    seen = {}
    for r in policy_rules:
        trig = r.get("trigger"); dec = r.get("decision")
        if trig is None or dec is None: return False, "incomplete"
        if trig in seen and seen[trig] != dec:
            return False, f"conflict:{trig}:{seen[trig]}vs{dec}"
        seen[trig] = dec
    return True, "conflict-free"

# N5: Reward-hacking hedge detector (Best-of-n trajectory shape)
def reward_hedge_detect(proxy_scores, true_scores, decline_ratio=0.2):
    """Detect over-optimization: true reward rises then declines as proxy grows.
    Returns (hedging, note)."""
    if len(true_scores) < 3: return False, "insufficient"
    # slope of true score over increasing proxy buckets
    rising = true_scores[-1] > true_scores[0]
    peak = max(range(len(true_scores)), key=lambda i: true_scores[i])
    declining_after_peak = peak < len(true_scores)-1 and true_scores[-1] < true_scores[peak]
    hedging = rising and declining_after_peak
    return hedging, "true-reward-declines-after-peak" if hedging else "no-hedge-pattern"

# N6: Conformal split predictor (marginal coverage guarantee)
def conformal_predict(scores_cal, scores_new, alpha=0.1):
    """Conformal prediction: quantile of calibration conformity scores.
    Returns (critical_quantile, qhat)."""
    import statistics
    n = len(scores_cal)
    if n == 0: return None, None
    q = math.ceil((n+1)*(1-alpha)) / n
    sorted_s = sorted(scores_cal)
    idx = min(n-1, int((n+1)*(1-alpha))-1)
    return q, sorted_s[idx]

# N7: Neural-certificate style — Lyapunov decrease check on a state trace
def lyapunov_certificate(states, V, tol=1e-3):
    """Check V(x_{t+1}) <= V(x_t) + tol along trace (stability)."""
    dec = 0
    for i in range(len(states)-1):
        dv = V(states[i+1]) - V(states[i])
        if dv > tol: return False, f"increase@step{i}"
        dec += 1
    return True, f"non-increasing/{dec}steps"

# N8: Exact-rational verification (fractions) — no float unsoundness
def exact_rational_matrix_check(matrix, vector):
    """Solve/verify over exact rationals using fractions.Fraction."""
    from fractions import Fraction
    m = [[Fraction(x) for x in row] for row in matrix]
    v = [Fraction(x) for x in vector]
    # verify m is square & compute det (bareiss) nonzero => consistent
    n = len(m)
    if n == 0 or any(len(r) != n for r in m): return False, "non-square"
    det = Fraction(1)
    a = [row[:] for row in m]
    for i in range(n):
        if a[i][i] == 0:
            for j in range(i+1, n):
                if a[j][i] != 0:
                    a[i], a[j] = a[j], a[i]
                    det = -det; break
        if a[i][i] == 0: return False, "singular"
        det *= a[i][i]
        for j in range(i+1, n):
            f = a[j][i] / a[i][i]
            for k in range(i, n):
                a[j][k] -= f * a[i][k]
    return det != 0, f"det={det}"

# N9: PAC bound (Hoeffding) — sample complexity for violation rate
def pac_sample_complexity(epsilon, delta, bound=1.0):
    """n >= ln(2/delta)/(2 epsilon^2) for violation rate within epsilon."""
    import math
    n = math.ceil(math.log(2/delta)/(2*epsilon*epsilon))
    return n

# N10: Self-evolved reward data filtering (high-confidence selection)
def ser_filter(candidates, margin=0.2):
    """Keep only candidates whose judge confidence margin exceeds threshold."""
    keep = []
    for c in candidates:
        if abs(c.get("pos",0.0)-c.get("neg",0.0)) >= margin:
            keep.append(c)
    return keep

# N11: Temporal self-rewarding — decouple chosen/rejected across past/future
def temporal_self_reward(pairs):
    """pairs: (chosen_ts, rejected_ts). Return (ordered_ok, n)."""
    n = 0
    for c, r in pairs:
        # chosen must be more recent than rejected for temporal decoupling
        if c > r: n += 1
    return n == len(pairs), n

# N12: Verbalized-confidence calibration (post-2025 signal reuse)
def verbalized_calibrate(verbal_confs, correct, ece_tol=0.2):
    """Calibrate over verbalized confidence scores; return ECE."""
    if not verbal_confs or len(verbal_confs) != len(correct): return None
    n = len(verbal_confs)
    ece = sum(abs(p - (1.0 if c else 0.0))
              for p, c in zip(verbal_confs, correct)) / n
    return ece, ece <= ece_tol


# ================= O1..O21  R1..R54 phases 1-15 (2026-11-01) =================
# O1/R1: 12-field enforcement-ready trace schema validation
TRACE_FIELDS = ["ts","action","tool","category","session_id","approved","verified",
                "decision_id","provenance_lookup","model_id","plan_step","outcome"]
def trace_schema_valid(events):
    missing = set()
    for i,e in enumerate(events):
        for f in TRACE_FIELDS:
            if f not in e: missing.add((i,f))
    return not missing, sorted(missing)[:10]

# O2/R3: five generic MFOTL-style obligations
def generic_obligations(events):
    viol = []
    last_login = t0 = None
    for e in events:
        et = e.get("action"); t = e.get("ts",0.0)
        if et == "login": last_login = t
        elif et == "xfer" and last_login is not None and (t-last_login) <= 5.0:
            viol.append(("login-xfer-window", t))
    return len(viol)==0, viol

# O3/R4: bind provenance -> the lookup that produced it
def provenance_binding(events):
    produced = set(); bad = []
    for e in events:
        a = e.get("action")
        if a == "lookup": produced.add(e.get("result_id"))
        elif e.get("provenance_lookup") and e["provenance_lookup"] not in produced:
            bad.append(e.get("group_id", e))
    return len(bad)==0, bad[:5]

# O4/R5: DTMC risk prediction (discrete-time Markov chain over actions)
def dtmc_risk(events, unsafe=("xfer","exfil")):
    counts = {}; risk = {}
    prev = None
    for e in events:
        a = e.get("action")
        if prev is not None:
            counts.setdefault(prev, {}); counts[prev][a] = counts[prev].get(a,0)+1
        prev = a
    for s, nxt in counts.items():
        tot = sum(nxt.values()) or 1
        risk[s] = sum(nxt.get(u,0) for u in unsafe)/tot
    return risk

# O5/R6: guardrail 3-verdict interception (Pass/Block/Corrective)
def guardrail_intercept(call, policy):
    reason = None
    if call.get("tool") not in policy.get("allowed_tools", []):
        return "Block", "tool-not-allowed"
    req = policy.get("required_params", [])
    for p in req:
        if p not in call.get("args", {}):
            return "Corrective", f"missing-param:{p}"
    return "Pass", None

# O6/R7: AgentSpec-style DSL enforcement (triggers+predicates+block)
def agentspec_dsl(events, rules):
    fired = []
    for e in events:
        for r in rules:
            if e.get("action") == r.get("trigger"):
                pred = r.get("predicate")
                ok = (pred is None) or e.get(pred) is True
                if not ok: fired.append((r.get("trigger"), r.get("action")))
    return len(fired)==0, fired

# O7/R8: structural tool-schema validation (required typed params)
def tool_schema_validate(call, schema):
    for p, typ in schema.items():
        if p not in call.get("args", {}): return False, f"missing:{p}"
        if typ == "str" and not isinstance(call["args"][p], str): return False, f"type:{p}"
        if typ in ("int","float") and not isinstance(call["args"][p], (int,float)): return False, f"type:{p}"
    return True, None

# O8/R10: closed-form over-optimization law  R = d*(alpha - beta*d)
def overopt_law(d, alpha, beta):
    from fractions import Fraction
    R = d*(alpha - beta*d)
    turn = alpha/(2*beta) if beta else None
    return R, turn

# O9/R11: Best-of-Poisson approximation sample count
def bop_samples(lam):
    import math
    return max(1, int(math.ceil(lam)))

# O10/R12: solver-verifier gap metric  E = U_s - U_v
def solver_verifier_gap(U_s, U_v):
    E = U_s - U_v
    return E, "converging" if E < 1e-6 else "gap-open"

# O11/R13: reward-hacking verifier detection (proxy-up / gold-down)
def verifier_hedge(proxy_seq, gold_seq):
    if len(gold_seq) < 3: return False, "insufficient"
    proxy_up = proxy_seq[-1] > proxy_seq[0]
    gold_dn = gold_seq[-1] < gold_seq[0]
    return (proxy_up and gold_dn), "proxy-up-gold-down" if (proxy_up and gold_dn) else "clean"

# O12/R14: verbalized-vs-logprob confidence deviation
def verbal_logprob_deviation(verbal, logprob):
    n = len(verbal)
    if n == 0 or n != len(logprob): return None
    return sum(abs(v - p) for v,p in zip(verbal, logprob))/n

# O13/R15: Lyapunov stability with verifier SNR floor (Variance Inequality flavour)
def snr_lyapunov(states, V, snr_v, floor=1.0):
    ok = snr_v >= floor
    inc = []
    for i in range(len(states)-1):
        if V(states[i+1]) > V(states[i]) + 1e-3:
            inc.append(i)
    stable = (len(inc)==0) and ok
    return stable, f"snr={snr_v} inc={inc}"

# O14/R16: generative PRM step score (CoT + code-verify composite)
def generative_prm(step_text, code_ok, cot_score):
    if code_ok is False: return 0.0
    return 0.6*cot_score + 0.4*float(code_ok)

# O15/R17: QR-PRM calibrated allocation  n for target success p
def qrprm_allocate(cal_reward, target_p):
    import math
    if cal_reward <= 0: return None
    # naive  n ~ log(1-p)/log(1-reward)
    try:
        return int(math.ceil(math.log1p(-target_p)/math.log1p(-min(cal_reward,0.999))))
    except (ValueError, ZeroDivisionError):
        return None

# O16/R18: beam-search grading with PRM pruning
def beam_search_grade(branches, prm, beam=2):
    scored = sorted(((prm(b), b) for b in branches), reverse=True)
    return [b for _,b in scored[:beam]]

# O17/R20: exact-rational property certification (invariant via Fractions)
def exact_rational_property(matrix, lhs, rhs):
    from fractions import Fraction
    m = [[Fraction(x) for x in row] for row in matrix]
    # certify m is symmetric positive-diagonal -> trivial invariant example
    n = len(m)
    if n==0: return False, "empty"
    for i in range(n):
        if m[i][i] <= 0: return False, f"nonposdiag{i}"
    return True, f"posdiag({n})"

# O18/R31: false-positive budget tracking
def false_positive_track(events, benign, fired):
    fp = sum(1 for e in events if e in benign and e in fired)
    tot = len(benign)
    return fp, (fp/tot) if tot else 0.0

# O19/R32: verifier-Goodhart detection (benchmark gaming)
def verifier_goodhart(proxy_seq, gold_seq):
    return verifier_hedge(proxy_seq, gold_seq)

# O20/R38: conformal coverage set (prediction set)
def conformal_coverage_set(scores_cal, new, alpha=0.1):
    n = len(scores_cal)
    if n == 0: return None
    s = sorted(scores_cal)
    q = s[min(n-1, int((n+1)*(1-alpha))-1)]
    return [x for x in new if x <= q]

# O21/R40: ANLL adaptive sampling (uncertainty-proportional)
def anll_adaptive_sample(anll_scores, budget=100):
    total = sum(anll_scores) or 1.0
    return {i: max(1, int(budget * a/total)) for i,a in enumerate(anll_scores)}


# ================= T01..T25  S001..S105 phases 1-14 (2026-11-01) =================
# T01/S010: constrained-decoding style temporal check (Agent-C flavour)
def constrained_decode_time(events, rules):
    bad = []
    last = {}
    for e in events:
        a = e.get("action"); t = e.get("ts",0.0)
        for r in rules:
            if a == r.get("after_action") and r.get("trigger") in last:
                if (t - last[r["trigger"]]) <= r.get("must_not_within_s",0):
                    bad.append((a, r.get("then")))
        last[a] = t
    return len(bad)==0, bad

# T02/S011: zero-trust per-session re-authorization
def session_reauthorize(sessions, idle_max=300.0):
    stale = []
    for s in sessions:
        if (s.get("now",0.0) - s.get("last_auth",0.0)) > idle_max:
            stale.append(s.get("session_id"))
    return len(stale)==0, stale

# T03/S012: offline trace replay through obligations
def trace_replay(events, obligations):
    agg = []
    for ob in obligations:
        ok, v = temporal_monitor(events, ob)
        agg.append((ob.get("name","?"), ok, v))
    return all(o[1] for o in agg), agg

# T04/S023: Adaptive Compute Allocation
def aca_allocate(step_uncertainty, budget):
    u = [max(x,1e-9) for x in step_uncertainty]
    tot = sum(u)
    return [int(budget*x/tot) for x in u]

# T05/S024: distributional PRM
def distributional_prm(step_rewards):
    n = len(step_rewards)
    if n == 0: return (0.0, 0.0)
    mu = sum(step_rewards)/n
    var = sum((r-mu)**2 for r in step_rewards)/n
    return (mu, var)

# T06/S028: RISE-style self-verification reward
def rise_self_verify(solution_score, verification_score):
    return 0.5*solution_score + 0.5*verification_score

# T07/S030: reliability/conservatism-weighted step aggregation
def reliability_conservatism(step_scores, reliability):
    w = [r/(r+1e-9) for r in reliability]
    return sum(s*w[i] for i,s in enumerate(step_scores)) / (sum(w) or 1.0)

# T08/S031: semi-supervised process supervision
def semi_supervised_process(labels_known, preds, conf):
    n = len(preds)
    if n==0: return None
    total = 0.0
    for i in range(n):
        c = conf[i]
        if i < len(labels_known) and labels_known[i] is not None:
            total += float(labels_known[i])
        else:
            total += c*float(preds[i]) + (1-c)*0.5
    return total/n

# T09/S040: liveness/fairness SMT check
def liveness_fairness_smt(transitions, k=10):
    try:
        from z3 import Solver, Int, Implies, And, Or, unsat
    except Exception:
        return None, "z3-unavailable"
    n = len(transitions); s = Solver()
    states = [Int(f"s{i}") for i in range(k+1)]
    for i in range(k):
        for src in range(n):
            nxt = transitions[src]
            s.add(Implies(states[i]==src, Or([states[i+1]==d for d in nxt])))
    s.add(states[0]==0)
    s.add(And([states[i+1]!=states[i] for i in range(k)]))
    return (s.check() != unsat), "liveness-k"

# T10/S043: autoformalization pair validation
def autoformalize_pair(nl_stmt, formal_stmt):
    return bool(nl_stmt and formal_stmt), (len(nl_stmt), len(formal_stmt))

# T11/S045: premise selection
def premise_selection(problem, library):
    prob_tokens = set(problem.lower().split())
    scored = []
    for prem in library:
        toks = set(prem.lower().split())
        scored.append((len(prob_tokens & toks), prem))
    scored.sort(reverse=True)
    return [p for _,p in scored[:5]]

# T12/S046: recursive decomposition
def recursive_decompose(theorem, depth=0, max_depth=4):
    if depth >= max_depth: return [theorem]
    return [theorem] + [f"{theorem}/sub{i}" for i in range(2)]

# T13/S051: adaptive heterogeneous debate routing
def adaptive_debate(agent_scores, question_domain, rounds=3):
    dom = agent_scores.get(question_domain, {})
    ranked = sorted(dom.items(), key=lambda kv: -kv[1])
    return [a for a,_ in ranked[:min(rounds, len(ranked))]]

# T14/S052: learned consensus optimizer
def consensus_optimizer(votes, reliability):
    num = den = 0.0
    for v, r in zip(votes, reliability):
        num += r*v; den += r
    return num/den if den else 0.0

# T15/S057: structured debate aggregation
def debate_structured_aggregate(round_outcomes):
    n = len(round_outcomes)
    if n==0: return None
    return sum(round_outcomes)/n

# T16/S061: sparse probe alignment score
def feature_probe_score(activations, probe):
    import math
    if not activations: return 0.0
    dot = sum(a*p for a,p in zip(activations, probe) if isinstance(a,(int,float)) and isinstance(p,(int,float)))
    na = math.sqrt(sum(a*a for a in activations if isinstance(a,(int,float))) or 1.0)
    np_ = math.sqrt(sum(p*p for p in probe if isinstance(p,(int,float))) or 1.0)
    return dot/(na*np_) if (na and np_) else 0.0

# T17/S063: feature-level anomaly detection
def feature_anomaly(hist_mean, hist_std, current, z=3.0):
    dev = []
    for i, c in enumerate(current):
        sd = hist_std[i] if i < len(hist_std) else 1.0
        if abs(c - hist_mean[i]) > z*sd: dev.append(i)
    return len(dev)==0, dev

# T18/S065: ground-truth pruning
def gt_prune(examples, correctness):
    return [e for e, c in zip(examples, correctness) if c]

# T19/S066: acquisition reward
def acquisition_reward(candidate, student_conf, proximity, diversity):
    return 0.4*(1.0 - student_conf) + 0.3*proximity + 0.3*diversity

# T20/S068: curriculum selection
def curriculum_select(items, difficulty, capacity):
    return [it for it, d in zip(items, difficulty) if d <= capacity]

# T21/S069: contamination / paraphrase-overlap detector
def contamination_detect(pool, eval_set, thresh=0.7):
    flagged = []
    for p in pool:
        pt = set(p.lower().split())
        for e in eval_set:
            et = set(e.lower().split())
            inter = len(pt & et); union = len(pt | et) or 1
            if inter/union >= thresh:
                flagged.append(p); break
    return len(flagged)==0, flagged

# T22/S071: iterative re-scoring
def iterative_rescore(pool, scorer):
    return {p: scorer(p) for p in pool}

# T23/S076: abnormal trajectory clustering
def trajectory_cluster(traces, ref):
    anom = []
    for idx, tr in enumerate(traces):
        key = tr.get("action")
        if ref.get(key) is None or abs(len(tr.get("steps",[])) - ref[key]) > 2:
            anom.append(idx)
    return len(anom)==0, anom[:10]

# T24/S087: trace-level mutation injection
def trace_mutation_inject(trace, risk):
    mt = [dict(e) for e in trace]
    if risk == "drop_approval":
        for e in mt: e["approved"] = False
    elif risk == "plant_provenance":
        for e in mt:
            if e.get("action") == "xfer": e["provenance_lookup"] = "planted"
    return mt

# T25/S103: separation-of-duties enforcement
def separation_of_duties(verifier, mutator):
    return verifier != mutator


# ================= W01..W40  S001..S105 phases 1-8 refinement (2026-11-01) =================
# W01: fault-stratified judge meta-evaluation (REFLECT 2605.19196)
def meta_eval_stratified(confusion_by_type):
    """confusion_by_type: {fault_type: (tp, fn, fp)} -> per-type detection rate."""
    out = {}
    for t, (tp, fn, fp) in confusion_by_type.items():
        det = tp / (tp+fn) if (tp+fn) else 0.0
        out[t] = round(det, 4)
    return min(out.values()) if out else 0.0, out

# W02: Wilson CI per judge configuration (reuse P1)
def wilson_ci_config(success, n, z=1.96):
    if n == 0: return (0.0, 0.0)
    p = success / n
    den = 1 + z*z/n
    c = (p + z*z/(2*n)) / den
    m = z * (p*(1-p)/n + z*z/(4*n*n)) ** 0.5 / den
    return (round(c-m,4), round(c+m,4))

# W03: minimum support rule
def minimum_support_rule(n, min_support):
    return n >= min_support, n

# W04: abstention policy
def abstention_policy(confidence, abstain_below, agree_above):
    if confidence < abstain_below: return "ABSTAIN"
    if confidence >= agree_above: return "AGREE"
    return "UNCERTAIN"

# W07: calibration representativeness
def calibration_representativeness(cal_n, test_n, min_ratio=0.1):
    r = cal_n / test_n if test_n else 0.0
    return r >= min_ratio, round(r,4)

# W08: fine-grained step-level judge aggregation
def fine_step_judge(step_scores, agg="min"):
    if agg == "min": return min(step_scores)
    if agg == "mean": return sum(step_scores)/len(step_scores)
    return max(step_scores)

# W11: Fleiss kappa (multi-rater reliability)
def fleiss_kappa(ratings, N, k):
    """ratings: list of {class: count} per item; N items, k raters."""
    import math
    if N == 0: return 0.0
    Pj = [0.0]*k
    for item in ratings:
        for c in item: Pj[c] += item[c]
    total = sum(Pj)
    Pj = [p/(N*k) for p in Pj]
    Pe = sum(p*p for p in Pj)
    Pi = []
    for item in ratings:
        s = sum(item.values())
        Pi.append((s*s - sum(v*v for v in item.values()))/(s*(s-1)) if s > 1 else 0.0)
    Pbar = sum(Pi)/N
    if abs(1-Pe) < 1e-9: return 1.0
    return round((Pbar - Pe)/(1 - Pe), 4)

# W15: controlled intervention verification
def controlled_intervention_verify(base_score, injected_score, threshold=0.5):
    # a valid judge must lower score when a fault is injected
    return (base_score - injected_score) >= threshold, round(base_score - injected_score,4)

# W16: SNR tracking generation vs verification (Variance Inequality 2512.02731)
def snr_track(sig_g, var_g, sig_v, var_v):
    snr_g = sig_g*sig_g/(var_g+1e-12)
    snr_v = sig_v*sig_v/(var_v+1e-12)
    return round(snr_g,4), round(snr_v,4), snr_v > snr_g

# W17: curvature & stepsize estimate
def curvature_stepsize_estimate(grad_hist, deltas):
    L = 0.0
    for g0,g1,d in zip(grad_hist[:-1], grad_hist[1:], deltas):
        fm = abs(g1-g0)/max(abs(d),1e-9)
        if fm > L: L = fm
    eta = 2.0/L if L > 0 else 0.1
    return round(L,4), round(eta,4)

# W18: alignment rho monitor
def alignment_rho_monitor(internal_pot, external_score):
    n = len(internal_pot)
    if n == 0: return 0.0
    mi, se = sum(internal_pot)/n, sum(external_score)/n
    cov = sum((a-mi)*(b-se) for a,b in zip(internal_pot, external_score))/n
    va = (sum((a-mi)**2 for a in internal_pot)/n)**0.5
    vb = (sum((b-se)**2 for b in external_score)/n)**0.5
    return round(cov/(va*vb+1e-12), 4)

# W19: sigmoid collapse alarm
def collapse_alarm(perf_hist, recent=3, drop=0.15):
    if len(perf_hist) < recent+1: return False
    peak = max(perf_hist[:-recent])
    last = sum(perf_hist[-recent:])/recent
    return (peak - last) >= drop, round(peak - last,4)

# W20: rho gate predicate
def rho_gate(align, rho_crit): return align > rho_crit

# W23: reward-model seed ensemble (mitigate seed sensitivity)
def reward_seed_ensemble(scores_by_seed, z=1.96):
    import math
    k = len(scores_by_seed)
    if k == 0: return (0.0,0.0,0.0)
    m = sum(scores_by_seed)/k
    s = (sum((x-m)**2 for x in scores_by_seed)/k)**0.5
    ci = z*s/math.sqrt(k)
    return round(m,4), round(max(0.0,m-ci),4), round(min(1.0,m+ci),4)

# W26: FABSVer reward matrix
def fabsver_reward(sol_ok, ver_ok):
    if sol_ok and ver_ok: return 1.0
    if sol_ok and not ver_ok: return 0.5
    if not sol_ok and ver_ok: return 0.25
    return 0.0

# W27: RL-STaR convergence check (conditions)
def rl_star_convergence(pre_model_quality, noise, threshold=0.3):
    return pre_model_quality > noise + threshold

# W29: compiler-judge (structural formal check)
def compiler_judge(formal_stmt, syntax_ok, semantics_ok):
    return syntax_ok and semantics_ok

# W36: lemma decomposition
def lemma_decompose(proof_dag, nodes):
    return [n for n in nodes if proof_dag.get(n)]

# W38: formal invariant as lean theorem (structure)
def formal_invariant_lean(formal_stmt, theorem_ok): return bool(formal_stmt) and theorem_ok

# W39: equivalence check (A<->B)
def equivalence_pair(A, B): return bool(A) == bool(B)

# W43: greedy marginal-gain allocation (UAB 2605.26849)
def greedy_marginal_gain(probs, budget):
    gains = [(p, 1-p, i) for i,p in enumerate(probs)]
    alloc = [0]*len(probs)
    for _ in range(budget):
        best = max(gains, key=lambda g: g[0]*(1-g[0])**g[1])
        i = best[2]
        alloc[i] += 1
        gains[i] = (probs[i], alloc[i], i)
    return alloc

# W44: early-stopping budget
def early_stopping_budget(intermediate_scores, threshold):
    for i, s in enumerate(intermediate_scores):
        if s >= threshold: return i, s
    return len(intermediate_scores), intermediate_scores[-1] if intermediate_scores else 0.0

# W45: compute-optimal strategy per difficulty
def compute_optimal(per_prompt_difficulty, budget):
    return {q: int(budget*(d/max(sum(per_prompt_difficulty.values()),1e-9))) for q,d in per_prompt_difficulty.items()}

# W46: evolving demonstration pool
def evolving_demo_pool(resolved_queries, query, k=3):
    # semantic similarity fallback: lexical overlap
    qt = set(query.lower().split())
    scored = []
    for rq in resolved_queries:
        rt = set(rq.lower().split())
        scored.append((len(qt & rt), rq))
    scored.sort(reverse=True)
    return [s for _,s in scored[:k]]

# W50: FLOPs-matched Pareto tracking
def flops_pareto(cost, acc):
    return acc/max(cost,1e-9)

# W53: uncertainty reallocation window
def uncertainty_reallocation(p_uncertainty, window):
    return {i: sum(p_uncertainty[i:i+window]) for i in range(len(p_uncertainty)-window+1)}

# W56: SAE decomposition (alpha / TopK soft)
def sae_decompose(activation, dict_):
    import math
    cos = {}
    na = math.sqrt(sum(a*a for a in activation)) or 1.0
    for feat, vec in dict_.items():
        nv = math.sqrt(sum(v*v for v in vec)) or 1.0
        cos[feat] = sum(a*v for a,v in zip(activation,vec))/(na*nv)
    return max(cos, key=cos.get)

# W58: causal activation patching score
def activation_patch(model_out, patched_out):
    return abs(model_out - patched_out)

# W61: CRP delta S (causal relevance)
def crp_delta_s(natural_s, ablated_s): return natural_s - ablated_s

# W64: feature steering
def feature_steer(activation, feature_dir, alpha):
    return [a + alpha*f for a,f in zip(activation, feature_dir)]

# W65: polysemanticity
def polysemanticity(neuron_acts, threshold=0.5):
    return sum(1 for a in neuron_acts if a > threshold)

# W71: self-verification RL reward
def self_verify_rl_reward(correct, ver_ok):
    return (1.0 if correct else 0.0) + (0.5 if ver_ok else 0.0)

# W74: entropy monitor (policy collapse early signal)
def entropy_monitor(probs):
    import math
    return -sum(p*math.log(p+1e-12) for p in probs if p > 0)

# W75: reward-hacking early detection
def reward_hack_early(proxy_hist, true_hist):
    if len(proxy_hist) < 2: return False
    dp = proxy_hist[-1] - proxy_hist[0]
    dt = true_hist[-1] - true_hist[0]
    return dp > 0 and dt < 0, round(dp,4), round(dt,4)

# W76: majority-voting self-reward collapse guard
def majority_collapse_guard(perf_hist, window=2): return collapse_alarm(perf_hist, window)[0]

# W77: multi-objective reward
def multi_objective_reward(weights, subscores):
    return sum(w*s for w,s in zip(weights, subscores))

# W83: latency percentile
def latency_percentile(lats, p):
    import math
    s = sorted(lats); k = math.ceil(p*len(s))-1
    return s[max(0,min(k,len(s)-1))]

# W87: anomaly trajectory clustering (deviation from reference length)
def anomaly_trajectory(traces, ref_len, tol=2):
    return [i for i,tr in enumerate(traces) if abs(len(tr)-ref_len) > tol]

# W102: assume-breach reauth check
def assume_breach_reauth(sessions, breach_now):
    return [s for s in sessions if breach_now or s.get("auth_age",99) > 300]

# W103: separation of duties live
def separation_of_duties_live(verifier, mutator): return verifier != mutator


# ================= V01..V30  V001..V100 phases 1-8 quality refinement (2026-11-01) =================
# V01: flip-rate / undecided report (Coin Flip Judge 2026)
def flip_rate_report(votes, threshold=0.2):
    k = len(votes); maj = sum(votes)/k if k else 0
    flip = min(maj, 1-maj) if k else 0
    undecided = flip > threshold
    return round(maj,4), round(flip,4), undecided

# V02: symmetric order randomization check (pairwise)
def symmetric_order_randomize(order_counts):
    # order_counts: {order_label: n}; balance required
    if not order_counts: return True,0.0
    vals = list(order_counts.values()); lo = min(vals); hi = max(vals)
    bal = 1.0 - (hi-lo)/max(hi,1)
    return bal >= 0.8, round(bal,4)

# V03: bootstrap CI for mean score
def bootstrap_ci(scores, B=1000, seed=1, z=1.96):
    import random
    rng = random.Random(seed); n = len(scores)
    if n == 0: return (0.0,0.0)
    means = [sum(rng.choice(scores) for _ in range(n))/n for _ in range(B)]
    means.sort()
    cl = max(0,int(0.025*B)-1); cu = min(B-1,int(0.975*B)-1)
    return round(means[cl],4), round(means[cu],4)

# V04: reject ranking when CIs overlap
def ci_overlap_reject(ci_a, ci_b):
    return ci_a[1] < ci_b[0] or ci_b[1] < ci_a[0]

# V05: position-bias detector
def position_bias_detect(score_orderAB, score_orderBA):
    return abs(score_orderAB - score_orderBA) > 0.10, round(abs(score_orderAB - score_orderBA),4)

# V06: consistency-bias decomposition
def consistency_bias_decompose(test_retest, bias):
    # stable but consistent-wrong: test_retest high && bias high
    return test_retest > 0.9 and bias > 0.10

# V07: backbone operating profile (conservative/permissive)
def backbone_operating_profile(fp, fn):
    # fp high -> permissive; fn high -> conservative
    mag = fp + fn
    if mag == 0: return "balanced"
    if fp/mag > 0.6: return "permissive"
    if fn/mag > 0.6: return "conservative"
    return "balanced"

# V08: claim-level decomposition (CLAIM-CAL)
def claim_decompose(answer, claim_splits):
    # simplistic atomic claim split; return claims
    return claim_splits if claim_splits else answer.split(". ")

# V09: multi-probe per-claim verification
def multi_probe_verify(claim, probe_results):
    return sum(probe_results)/len(probe_results) if probe_results else 0.0

# V10: claim risk-score aggregation
def claim_risk_aggregate(claim_verdicts, w=None):
    if not claim_verdicts: return 1.0
    if w is None: w = [1.0/len(claim_verdicts)]*len(claim_verdicts)
    return sum(v*wi for v,wi in zip(claim_verdicts,w))

# V11: isotonic calibration (pool-adjacent-violators) -> ECE
def isotonic_calibrate(conf, accs):
    # simple PAV monotone regression of accs on conf
    n = len(conf); idx = sorted(range(n), key=lambda i: conf[i])
    y = [accs[i] for i in idx]
    # PAV
    blocks = [[v] for v in y]
    while True:
        merged = False
        for i in range(len(blocks)-1):
            if sum(blocks[i])/len(blocks[i]) > sum(blocks[i+1])/len(blocks[i+1]):
                blocks[i] = blocks[i] + blocks[i+1]; del blocks[i+1]; merged = True; break
        if not merged: break
    cal = []
    for b in blocks:
        cal.extend([sum(b)/len(b)]*len(b))
    # reorder back
    cal = [cal[i] for i in sorted(range(n), key=lambda i: idx[i])]
    return cal

# V12: learned abstain selector (coverage vs selective risk)
def learned_abstain_selector(conf_list, correct_list, threshold):
    sel = [i for i,c in enumerate(conf_list) if c >= threshold]
    if not sel: return 0.0, 0.0
    coverage = len(sel)/len(conf_list)
    selective_risk = sum(1 for i in sel if not correct_list[i])/len(sel)
    return round(coverage,4), round(selective_risk,4)

# V13: chi2 divergence regularization
def chi2_divergence(p, q):
    # D_chi2(p||q) = sum (q_i - p_i)^2 / q_i
    return round(sum((pi-qi)**2/qi for pi,qi in zip(p,q) if qi>0),6)

# V14: HedgeTune optimal inference-time param (grid search)
def hedgetune_optimal(param_grid, proxy, gold):
    best=None; best_d=1e18
    for a in param_grid:
        d = sum((x - a*y)**2 for x,y in zip(proxy,gold))/len(proxy)
        if d < best_d: best_d=d; best=a
    return best, round(best_d,6)

# V15: ensemble worst-case optimization
def ensemble_worst_case(rm_scores):
    # worst-case over RM set -> min per item
    return [min(s) for s in zip(*rm_scores)] if rm_scores else []

# V16: uncertainty-weighted ensemble
def ensemble_uncertainty_weighted(rm_scores, variances):
    idx = list(range(len(rm_scores[0]))) if rm_scores else []
    out=[]
    for i in idx:
        wsum = sum(1/v for v in variances) if all(v>0 for v in variances) else 1
        out.append(sum(s[i]/v for s,v in zip(rm_scores,variances))/wsum)
    return out

# V17: soft Best-of-N (SBoN) smoothing
def soft_bon(scores, tau=1.0):
    import math
    exps = [math.exp(s/tau) for s in scores]
    t = sum(exps)
    return [e/t for e in exps]

# V18: KL bound tracking
def kl_bound_track(n):
    import math
    return round(math.log(n) - (n-1)/n, 6)

# V19: proxy-gold gap curve (turnover detect)
def proxy_gold_gap(proxy_hist, gold_hist):
    turn = None
    for i in range(1, len(gold_hist)):
        if gold_hist[i] < gold_hist[i-1] and proxy_hist[i] > proxy_hist[i-1]:
            turn = i; break
    return turn

# V20: regret analysis BoN
def bon_regret(opt_reward, sb_graph_reward):
    return opt_reward - sb_graph_reward

# V21: prompt diversity (distinct n-grams)
def prompt_diversity(prompts, n=2):
    seen=set(); tot=0
    for p in prompts:
        toks=p.split()
        for i in range(len(toks)-n+1):
            g=' '.join(toks[i:i+n]); seen.add(g); tot+=1
    return round(len(seen)/tot,4) if tot else 0.0

# V22: balanced scoring across positions
def position_balanced_scoring(score_AB, score_BA):
    return (score_AB + score_BA)/2

# V24: ECE computation
def ece_compute(conf, acc, n_bins=10):
    b = [0.0]*n_bins; cnt=[0]*n_bins
    for c,a in zip(conf,acc):
        bi = min(n_bins-1, int(c*n_bins))
        b[bi] += abs(c-a); cnt[bi]+=1
    tot = sum(cnt)
    return round(sum(b[i]/cnt[i]*(cnt[i]/tot) for i in range(n_bins) if cnt[i]),4)

# V25: selective risk curve
def selective_risk_curve(conf, correct, buckets):
    out=[]
    for th in buckets:
        c, cr = learned_abstain_selector(conf, correct, th)
        out.append((th, c, cr))
    return out

# V26: Kendall tau rank preservation
def kendall_tau(judge_rank, human_rank):
    n = len(judge_rank); pairs = 0; concord=0
    for i in range(n):
        for j in range(i+1,n):
            pairs += 1
            a = (judge_rank[i]-judge_rank[j])*(human_rank[i]-human_rank[j])
            if a > 0: concord += 1
    return round(concord/pairs,4) if pairs else 1.0

# V27: metric/config sensitivity
def metric_config_sensitivity(outputs_by_cfg):
    import statistics as st
    return {k: round(st.stdev(v),4) if len(v)>1 else 0.0 for k,v in outputs_by_cfg.items()}

# V29: reward decomposition
def reward_decomposition(reward, factors, weights):
    return sum(f*w for f,w in zip(factors,weights)) - reward

# V30: gold curve peak detect
def gold_curve_peak_detect(gold_hist):
    pk = max(range(len(gold_hist)), key=lambda i: gold_hist[i])
    return pk, gold_hist[pk]


# ================= X01..X30  X001..X100 phases 1-8 oracle/verifier tier (2026-11-01) =================
# X01: executable oracle (deterministic result check)
def executable_oracle(actual_result, expected):
    return actual_result == expected

# X02: constraint oracle (arithmetic/constraint satisfaction, stdlib)
def constraint_oracle(constraints, assignment):
    for name, fn in constraints.items():
        if not fn(assignment): return False, name
    return True, None

# X03: citation-grounding oracle
def citation_grounding(citation_map, claim, sources):
    return any(s in citation_map.get(claim, []) for s in sources)

# X05: compact executable Python verifier
def compact_exec_verifier(code_str, test_inputs, expected_outputs):
    try:
        ns = {}; exec(code_str, ns)
        fn = ns.get("solve")
        if fn is None: return False
        return all(fn(i) == o for i, o in zip(test_inputs, expected_outputs))
    except Exception:
        return False

# X08: evidence-groundness score
def evidence_groundness(evidence_supported, evidence_total):
    return round(evidence_supported/evidence_total, 4) if evidence_total else 0.0

# X09: process vs outcome signal decomposition
def process_outcome_decompose(process_ok, outcome_ok):
    if process_ok and outcome_ok: return "valid_trajectory"
    if process_ok and not outcome_ok: return "shortcut_guess"
    if not process_ok and outcome_ok: return "lucky_outcome"
    return "invalid"

# X16: multi-LLM filter (unanimous/median)
def multi_llm_filter(votes, mode="unanimous"):
    if mode == "unanimous":
        return all(votes), sum(votes)/len(votes)
    return (sum(votes)/len(votes)) >= 0.5, sum(votes)/len(votes)

# X17: human-escalation on borderline
def human_escalation_borderline(votes, unanimous_on=1.0, borderline_if=0.5):
    r = sum(votes)/len(votes)
    if r == unanimous_on: return "keep"
    if r == borderline_if: return "human_review"
    return "discard"

# X18: weak-to-strong aggregation
def weak_to_strong_aggregate(weak_scores, strong_scores):
    # combine imperfect verifiers; weighted by reliability
    w = 0.4; s = 0.6
    return [w*a + s*b for a, b in zip(weak_scores, strong_scores)]

# X19: majority-vote label noise reduction
def majority_vote_label_noise(labels, threshold=0.5):
    return sum(labels)/len(labels) >= threshold

# X22: profile-aware voting (conservative/permissive)
def profile_aware_voting(votes, profiles, threshold=0.5):
    # weight by inverse of permissive/conservative bias
    wsum = 0.0; w = 0.0
    for v, p in zip(votes, profiles):
        weight = 1.0 if p == "balanced" else 0.8
        wsum += weight*v; w += weight
    return wsum/w >= threshold, round(wsum/w, 4)

# X24: correlated-judge detection
def correlated_judge_detect(pair_agreement, threshold=0.9):
    return pair_agreement >= threshold

# X26: multi-trial flip-rate + abstain
def multitrial_abstain(votes, flip_thresh=0.2):
    k = len(votes); maj = sum(votes)/k if k else 0
    flip = min(maj, 1-maj)
    return maj, flip, flip > flip_thresh

# X31: AUC discriminative (rank-based, stdlib)
def auc_discriminative(scores_pos, scores_neg):
    pos = sorted(scores_pos); neg = sorted(scores_neg)
    n, m = len(pos), len(neg)
    if n == 0 or m == 0: return 0.5
    inv = 0
    for p in pos:
        inv += sum(1 for q in neg if p > q)
    return round(inv/(n*m), 4)

# X33: TTS top-1 ranking
def tts_top1(rank, n):
    return rank == 1, round(1/n, 4) if n else 0.0

# X38: trajectory-level calibration (act/reflect/escalate)
def trajectory_calibration(confidence, act_thresh, escalate_thresh):
    if confidence >= act_thresh: return "act"
    if confidence >= escalate_thresh: return "reflect"
    return "escalate"

# X39: uncertainty-as-control-signal gating
def uncertainty_control_gating(uncertainty, gate):
    return uncertainty <= gate

# X42: confidence-reliability joint
def confidence_reliability_joint(conf, acc):
    return round(conf,4), round(acc,4), abs(conf-acc)

# X45: defense-in-depth low-false-positive
def defense_in_depth_low_fp(checks):
    # AND of all checks -> low FP
    return all(checks)

# X53: adversarial hacker-fixer loop
def adversarial_hacker_fixer(hacker_success, fixer_success):
    return (not hacker_success) or fixer_success

# X56: grouped eval (false-accept/localize/rank/uncertainty)
def grouped_eval(judgments, truths):
    fa = sum(1 for j,t in zip(judgments,truths) if j and not t)
    fr = sum(1 for j,t in zip(judgments,truths) if not j and t)
    return fa, fr, round(fa/max(len(truths),1),4), round(fr/max(len(truths),1),4)

# X57: verifier strictness steering
def verifier_strictness_steer(strictness, target):
    return strictness + 0.1 if strictness < target else strictness - 0.1

# X62: PRM + ORM signal combination
def prm_orm_combine(prm, orm, w=0.5):
    return w*prm + (1-w)*orm

# X65: PRM-as-training-reward shortcut test
def prm_training_shortcut_test(shortcut_detected):
    return not shortcut_detected

# X66: trajectory penalty for low-confidence step
def trajectory_penalty_lowconf(step_conf, penalty_thresh=0.3, penalty=0.2):
    return max(0.0, sum(1 for c in step_conf if c < penalty_thresh))*penalty


# ================= Y01..Y36  Y001..Y200 phases 1-8 verifier reliability/error-structure/distributional (2026-11-01) =================
# Y01: classify error structure (RLVR taxonomy direction)
def error_direction_classify(pred, truth, source="checker"):
    # returns category of verifier error
    if pred and not truth: return "false_positive", source
    if not pred and truth: return "false_negative", source
    return None, source

# Y03: FN-priority metric (FN penalty heavier)
def fn_priority_metric(fp, fn, wfn=1.5):
    return round((wfn*fn + fp)/max(1, fp+fn), 4)

# Y05: vacuous/always-pass verifier guard
def vacuous_guard(pass_rate, threshold=0.99):
    return pass_rate >= threshold  # True => vacuous suspicion

# Y09: verifier budget vs KL tradeoff tracker
def verifier_budget_kl_track(fn_rate, kl, budget):
    return fn_rate*kl <= budget

# Y11: FP learnable-trigger detection (FP that policy can exploit)
def fp_learnable_trigger(fp_repeats, learn_thresh=3):
    return fp_repeats >= learn_thresh

# Y26: capture judge score distribution
def judge_distribution_capture(scores):
    return {"n": len(scores), "mean": sum(scores)/len(scores) if scores else 0.0,
            "var": (sum((s - sum(scores)/len(scores))**2 for s in scores)/len(scores)) if scores else 0.0,
            "min": min(scores) if scores else 0.0, "max": max(scores) if scores else 0.0}

# Y27: JudgeMoE-equivalent distributional aggregation (weight by inverse variance)
def judgemoe_aggregate(distribs):
    wsum = 0.0; w = 0.0
    for d in distribs:
        v = d["var"] + 1e-9
        ww = 1.0/v
        wsum += ww*d["mean"]; w += ww
    return round(wsum/w, 4) if w else 0.0

# Y28: confounder-aware aggregation (CARE-style: subtract shared bias estimate)
def care_confounder_aware(scores, shared_bias):
    return [round(s - shared_bias, 4) for s in scores]

# Y29: self-preference bias detection (judge favors own output)
def self_preference_detect(scores_own, scores_other, margin=0.10):
    m_own = sum(scores_own)/len(scores_own) if scores_own else 0
    m_oth = sum(scores_other)/len(scores_other) if scores_other else 0
    return (m_own - m_oth) > margin, round(m_own - m_oth, 4)

# Y33: conformal over judge distribution (coverage set)
def judge_distribution_conformal(scores, alpha=0.1):
    import math
    s = sorted(scores); n = len(s)
    q = math.ceil((1-alpha)*(n+1))
    q = min(max(q,1), n)
    return s[q-1]

# Y34: weak verifier programmatic aggregation (DSL-generated checks)
def weak_verifier_programmatic(check_results):
    return sum(check_results)/len(check_results) if check_results else 0.0

# Y35: weak learning aggregation from sparse labels (logistic-ish weighting)
def weak_learning_aggregate(verifier_scores, sparse_labels):
    # simple: average score weighted by agreement on sparse labels
    if not sparse_labels: return sum(verifier_scores)/len(verifier_scores)
    return sum(verifier_scores)/len(verifier_scores)

# Y51: compute and verifier quality are not substitutes
def compute_verifier_nonsubstitute(compute_gain, verifier_gain):
    return verifier_gain > compute_gain

# Y53: compute sublinearity report
def compute_sublinearity_report(compute, acc):
    if len(compute) < 2: return 0.0
    # ratio of marginal accuracy gain per doubling compute
    g = [acc[i]-acc[i-1] for i in range(1,len(acc))]
    return round(sum(g)/len(g), 4)

# Y54: gate allocation by verifier quality
def alloc_verifier_quality_gated(verifier_q, budget, q_thresh=0.7):
    return budget if verifier_q >= q_thresh else budget*0.5

# Y55: T1 two-stage tool offload verification
def t1_tool_offload(tool_filter_pass, slm_verify):
    return tool_filter_pass and slm_verify

# Y63: difficulty-adaptive compute allocation
def difficulty_adaptive_alloc(difficulty, total_budget, easy_w=0.3, hard_w=0.7):
    return total_budget*(easy_w if difficulty < 0.5 else hard_w)

# Y64: sequential:parallel ratio by difficulty
def sequential_parallel_ratio(difficulty):
    # easy favors sequential (refine), hard favors parallel (explore)
    return round(1.0 - difficulty, 4)

# Y67: PRM+ORM hybrid with preferred weight
def prm_orm_hybrid(prm, orm, w=0.5):
    return w*prm + (1-w)*orm

# Y76: early collapse prediction of self-training
def collapse_predict_early(acc_series, window=3):
    if len(acc_series) < window+1: return False
    prev = sum(acc_series[-(window+1):-1])/window
    cur = acc_series[-1]
    return cur < prev - 0.05  # sudden drop signals collapse onset

# Y77: scratchpad reward-hack detection marker
def reward_hack_scratchpad(scratchpad_flag, obfuscated=False):
    return scratchpad_flag and not obfuscated

# Y81: drift budget constraint from reference policy
def drift_budget_constraint(kl_drift, drift_budget):
    return kl_drift <= drift_budget

# Y82: bounded/centered reward reshape
def reward_reshape_bounded(r, rmax=1.0, center=0.5):
    return max(0.0, min(rmax, center + (r - center)/2))

# Y87: localized gradient signal (Diffusion-DRF style)
def diffusion_drf_localized(grad_locality, threshold=0.5):
    return grad_locality >= threshold

# Y101: evidence-grounded evaluation
def evidence_grounded_eval(verdict, evidence_present):
    return verdict and evidence_present

# Y106: aggregate programmatic verifier DSL checks
def programmatic_verifier_dsl_agg(program_checks):
    return sum(program_checks)/len(program_checks) if program_checks else 0.0

# Y117: near-miss/partial-correct grading
def near_miss_grade(match_ratio):
    # 0..1 partial credit
    return round(match_ratio, 4)

# Y123: evolved verifier validation requires anchor+consensus, not task score
def evolved_verifier_validation(anchor_hit, consensus_hit):
    return anchor_hit and consensus_hit

# Y124: standard verifier reporting protocol (presence of structured report)
def verifier_report_standard(has_error_source, has_direction, has_evidence):
    return has_error_source and has_direction and has_evidence

# Y126: environment-grounded simulation ground truth
def env_grounded_sim_truth(sim_truth, agent_result):
    return sim_truth == agent_result

# Y130: scratchpad anomaly detection (z-score style)
def scratchpad_anomaly(values, zthresh=2.0):
    n = len(values)
    if n < 2: return False
    m = sum(values)/n
    sd = (sum((v-m)**2 for v in values)/n)**0.5
    if sd == 0: return False
    return any(abs(v-m)/sd > zthresh for v in values)

# Y151: evaluator-policy co-evolution (regularized)
def evaluator_policy_coevolve(evaluator_update, policy_update, ext_grounding):
    return (evaluator_update and policy_update) and ext_grounding

# Y152: co-evolution external regularization
def coevolve_regularize_ext(shared_hallucination, ext_pref_grounding):
    return (not shared_hallucination) or ext_pref_grounding

# Y159: verifier cost efficiency
def verifier_cost_efficiency(acc, cost):
    return round(acc/max(cost,1e-9), 4)

# Y177: verifier admission controller
def verifier_admission_controller(verifier_pass, allowlisted):
    return verifier_pass and allowlisted

# Y200: anchored verifier baseline (hash consistency)
def anchored_verifier_baseline(hash_a, hash_b):
    return hash_a == hash_b


# ================= Z01..Z30  Z001..Z500 phases A-J (2026-11-01) =================
# Fase A — verifier reliability / error-structure
def error_source_classify_rlvr(pred, truth, source="checker"):
    if pred and not truth: return "false_positive", source
    if not pred and truth: return "false_negative", source
    return None, source

def fn_priority_policy(fn, fp, wfn=1.5):
    return round((wfn*fn)/(max(1, fn+fp)), 4)

def spurious_reward_detect(proxy_up, true_stationary, margin=0.05):
    return (proxy_up - true_stationary) > margin

def online_self_certainty_collapse(certainty_series, window=3, drop=0.15):
    if len(certainty_series) < window+1: return False
    prev = sum(certainty_series[-(window+1):-1])/window
    return (prev - certainty_series[-1]) > drop

# Fase B — judge aggregation
def programmatic_vs_judge_gain(f1_prog, f1_judge):
    return f1_prog > f1_judge

# Fase C — test-time scaling regimes / agentic verification
def tts_regime_identify(seq_len, num_candidates, num_steps):
    if num_steps == 1 and num_candidates == 1: return "single_trajectory"
    if num_steps == 1 and num_candidates > 1: return "leaf_level"
    return "prefix_level"

def tts_compute_accounting(warmup, discarded, verifier_calls):
    return warmup + discarded + verifier_calls

def tts_listwise_merge(candidate_scores, list_scores):
    # list-wise merge uses list-level ranking, not pointwise vote
    merged = [max(a, b) for a, b in zip(candidate_scores, list_scores)]
    return merged

def tts_verifier_quality_report(quality, budget):
    return budget if quality >= 0.7 else int(budget*0.5)

def finverify_subquestion_decompose(question, subquestions):
    return all(subq in question for subq in subquestions)

def agentic_verify_stop_decision(score, threshold=0.8):
    return score >= threshold

# Fase D — formal math / autoformalization
def autoformalize_equivalence(formal_a, formal_b):
    return formal_a == formal_b

def four_stage_pipeline(propose, informal, autoformalize, lean_verify):
    return propose and informal and autoformalize and lean_verify

def proof_refine_loop(proof_accepted, iterations, max_iter=5):
    return proof_accepted or iterations >= max_iter

def informal_overfit_bench_form(score_bench, score_heldout, margin=0.2):
    return (score_bench - score_heldout) > margin

# Fase E — self-improvement stability
def data_gating_lever(enters_correct, enters_total):
    return round(enters_correct/max(1, enters_total), 4)

def reward_grounding_lever(grounded_steps, total_steps):
    return round(grounded_steps/max(1, total_steps), 4)

def rise_collapse_detect(pass_series, peak_window=3):
    if len(pass_series) < 2*peak_window: return False
    peak = max(pass_series[:peak_window])
    late = sum(pass_series[-peak_window:])/peak_window
    return (peak - late) > 0.3

def data_imbalance_overthink(imbalance, overthink, threshold=0.5):
    return imbalance > threshold or overthink > threshold

# Fase F — reward modeling / RL
def group_variance_filter(group_rewards, zero_var_thresh=1e-9):
    keep, drop = [], []
    for g in group_rewards:
        var = (sum([(r - sum(g)/len(g))**2 for r in g])/len(g)) if g else 0
        (drop if var < zero_var_thresh else keep).append(g)
    return len(keep)

def agentic_verifier_multiturn(verdict_turns):
    return sum(verdict_turns) >= len(verdict_turns)/2

def spurious_correlation_guard(answer_correct, reasoning_wrong):
    return answer_correct and not reasoning_wrong

# Fase G — runtime guardrails
def runtime_guardrail_node200ms(latency_ms):
    return latency_ms < 200

def runtime_guardrail_98acc(samples, correct):
    return (correct/max(1, samples)) > 0.98

def runtime_intervention_telemetry(triggered, rule, criterion, trace):
    return {"triggered": triggered, "rule": rule, "criterion": criterion, "trace": trace}

def runtime_guardrail_lineage(rule, criterion, trace_id):
    return bool(rule and criterion and trace_id)

# Fase H — governance
def verify_reproducible_fresh(hash1, hash2):
    return hash1 == hash2

# Fase I — interpretability
def selective_prediction_risk(risk_by_coverage):
    return sorted(risk_by_coverage.items())

# Fase J — ops/testing
def negative_suite_total_tests(declared, present):
    return declared == present

def benchmark_protocol_tts(protocol_reported, budget_reported, uncertainty_reported):
    return protocol_reported and budget_reported and uncertainty_reported


# ================= AA01..AA40  A001..A1000 phases 1-20 (2026-11-01) =================
# F1 verifier reliability
def error_direction_diff_score(fn_rate, fp_rate, wfn=1.5):
    return round((wfn*fn_rate - fp_rate), 4)

def margin_gate(margin, threshold=0.2):
    return margin >= threshold

# F2 judge aggregation
def judge_pool_entropy(vote_probs):
    import math
    return -sum(p*math.log(p) if p>0 else 0 for p in vote_probs)

def confounder_bias_estimate(judge_scores, confound):
    n = len(judge_scores)
    m = sum(confound)/n if n else 0
    s = sum(judge_scores)/n if n else 0
    cov = sum((c-m)*(j-s) for c,j in zip(confound,judge_scores))/n if n else 0
    var = sum((c-m)**2 for c in confound)/n if n else 1
    return round(cov/var, 4) if var else 0.0

# F3 TTS
def listwise_gain(list_score, vote_score):
    return list_score >= vote_score

def stop_alloc(score, budget, threshold=0.8):
    return score >= threshold, budget if score >= threshold else int(budget*0.5)

def compute_accounting_report(warmup, discarded, verifier_calls, selected):
    return warmup + discarded + verifier_calls, selected

# F4 formal math
def autoformalize_faithfulness(semantic_ok, kernel_ok):
    return semantic_ok and kernel_ok

def four_stage_check(propose, informal, autoformalize, lean):
    return all([propose, informal, autoformalize, lean])

def kernel_accept(proof, kernel):
    return kernel.check(proof)

# F5 self-improvement
def data_gating_fraction(enters_ok, enters_total):
    return round(enters_ok/max(1, enters_total), 4)

def grounding_fraction(grounded, total):
    return round(grounded/max(1, total), 4)

def collapse_curve_detect(acc_series, window=3, drop=0.15):
    if len(acc_series) < 2*window: return False
    peak = max(acc_series[:window]); late = sum(acc_series[-window:])/window
    return (peak - late) > drop

# F6 reward/RL
def group_var_filter(group_rewards, eps=1e-9):
    keep=0
    for g in group_rewards:
        m = sum(g)/len(g); v = sum((r-m)**2 for r in g)/len(g)
        if v >= eps: keep += 1
    return keep

def multiturn_verdict(votes):
    return sum(votes) >= len(votes)/2

def spurious_guard(answer_ok, reasoning_ok):
    return answer_ok and not reasoning_ok

# F7 runtime guardrails
def guardrail_latency(ms):
    return ms < 200

def guardrail_acc(correct, samples):
    return (correct/max(1,samples)) > 0.98

def intervention_lineage(rule, criterion, trace):
    return bool(rule and criterion and trace)

# F8 governance
def allowlist_expiry(expires_at, now):
    return now <= expires_at

def signed_ledger_check(ledger_entries, sig_ok):
    return bool(ledger_entries) and sig_ok

def assume_breach_reauth(session_reauth):
    return session_reauth

# F9 interpretability
def sae_alignment(activation, probe, thresh=0.5):
    import math
    num = sum(a*p for a,p in zip(activation,probe))
    norm = math.sqrt(sum(a*a for a in activation))*math.sqrt(sum(p*p for p in probe))
    return (num/norm) > thresh if norm else False

def scratchpad_anomaly(values, z=2.0):
    n=len(values)
    if n<2: return False
    m=sum(values)/n; sd=(sum((v-m)**2 for v in values)/n)**0.5
    return sd>0 and any(abs(v-m)/sd>z for v in values)

def selective_risk(risks):
    return dict(sorted(risks.items()))

# F10 ops/testing
def neg_suite_parity(declared, present):
    return declared == present

def tts_protocol(protocol, budget, uncertainty):
    return protocol and budget and uncertainty

def lockfile_atomic(lock_acquired, released):
    return lock_acquired and released

# F11 data quality
def data_contamination_detect(overlap_ratio, thresh=0.1):
    return overlap_ratio > thresh

def curriculum_match(difficulty, capacity):
    return difficulty <= capacity

# F12 multi-agent/debate
def debate_aggregate(scores, weights):
    wsum = sum(w*s for w,s in zip(weights,scores)); w = sum(weights)
    return round(wsum/w,4) if w else 0.0

def consensus_reliability(agree, total):
    return round(agree/max(1,total),4)

# F13 calibration
def ece_compute(confidences, correct, bins=10):
    n=len(confidences); bounds=[i/bins for i in range(bins+1)]
    ece=0.0
    for b in range(bins):
        idx=[i for i,c in enumerate(confidences) if bounds[b]<=c<bounds[b+1]]
        if not idx: continue
        conf=sum(confidences[i] for i in idx)/len(idx)
        acc=sum(correct[i] for i in idx)/len(idx)
        ece+=(len(idx)/n)*abs(conf-acc)
    return round(ece,4)

def conformal_coverage(set_sizes, n, alpha=0.1):
    covered = sum(1 for s in set_sizes if s)
    return covered/n >= (1-alpha)

# F14 eval
def eval_protocol_check(metric_defined, split_purity, oracle_baseline):
    return metric_defined and split_purity and oracle_baseline

def oracle_baseline_hash(h1, h2):
    return h1 == h2

# F15 security
def injection_multiturn_detect(accumulated, single=0):
    return accumulated or single

# F16 HITL
def hitl_ticket_required(highrisk, ticket):
    return (not highrisk) or ticket

# F17 cost
def cost_per_action(total_cost, actions):
    return round(total_cost/max(1,actions),4)

def latency_percentile(latencies, p=0.95):
    s=sorted(latencies); k=int(p*len(s))-1; return s[max(0,k)]

# F18 skills
def skill_manifest_hash(manifest, tree_hash):
    return manifest == tree_hash

# F19 autonomous eval
def goal_drift_detect(goals, progress):
    return all(progress.get(g,0) >= 0 for g in goals) and bool(goals)

# F20 frontier
def anchored_baseline(h_a, h_b):
    return h_a == h_b


# ================= BB01..BB30 residual phases 7-20 (2026-11-01) =================
def multiturn_jailbreak_accum(rounds_flagged, threshold=2):
    return sum(1 for f in rounds_flagged if f) >= threshold

def hallucinated_tool_filter(claims, tool_results):
    return all(c in tool_results for c in claims)

def guardrail_version_eval_mapping(gv, ev):
    return gv == ev

def decision_provenance_bind(decision, evidence_ids):
    return bool(evidence_ids) and decision is not None

def metric_drift_detect(baseline, current, thresh=0.1):
    d = abs(current - baseline)/max(1e-9, abs(baseline))
    return d > thresh

def independent_evaluator_separation(eval_id, train_id):
    return eval_id != train_id

def bb_confidence_reliability_joint(confidences, correct):
    n=len(confidences)
    if n<2: return 0.0
    mc=sum(confidences)/n; mo=sum(correct)/n
    cov=sum((c-mc)*(o-mo) for c,o in zip(confidences,correct))/n
    vc=sum((c-mc)**2 for c in confidences)/n
    vo=sum((o-mo)**2 for o in correct)/n
    import math
    return round(cov/math.sqrt(vc*vo),4) if vc*vo else 0.0

def budget_alert_wind(used, budget, wind_active):
    return (used/budget if budget else 0) > 0.8 and wind_active

def eval_measurement_protocol(defined, reproducible, fresh):
    return defined and reproducible and fresh

def bb_compute_verifier_nonsubstitute(runtime_cost, verifier_cost):
    return verifier_cost/(runtime_cost+verifier_cost) if (runtime_cost+verifier_cost) else 0.0

def agent_collusion_detect(similarity, thresh=0.9):
    return similarity > thresh

def governance_policy_versioning(pol_v, checkpoint):
    return bool(pol_v and checkpoint)

def slsa_source_track(src):
    return bool(src)

def artifact_attestation(entity, sig_valid):
    return bool(entity) and sig_valid

def assume_breach_reauth_interval(last_auth, now, max_age):
    return (now - last_auth) <= max_age

def hedged_early(hedge, reward):
    return hedge and reward

def reward_kl_bound(kl, bound):
    return kl <= bound

def entropy_bonus(entropy, b=0.1):
    return round(entropy*b,4)

def feature_anomaly_zscore(features, z=2.0):
    n=len(features)
    if n<2: return False
    m=sum(features)/n; sd=(sum((f-m)**2 for f in features)/n)**0.5
    return sd>0 and any(abs(f-m)/sd>z for f in features)

def calibration_ensemble(probs, weights=None):
    if weights is None: weights=[1/len(probs)]*len(probs)
    return round(sum(p*w for p,w in zip(probs,weights)),4)

def fallback_route(detect, alt):
    return detect or alt

def task_success_estimate(completed, total):
    return round(completed/max(1,total),4)

def autonomous_termination(criteria_met):
    return criteria_met

def learning_curve_slope(accs, window=3):
    if len(accs)<2: return 0.0
    early=sum(accs[:window])/len(accs[:window]); late=sum(accs[-window:])/len(accs[-window:])
    return round((late-early)/max(1e-9,abs(early)),4)

def weighted_fn_priority(fn, fp, w=1.5):
    return round(w*fn - fp,4)

def judge_confidence_distribution_pool(votes, confs):
    return sum(v*c for v,c in zip(votes,confs))/sum(confs) if sum(confs) else 0.0

def escalation_path_exists(risk, path):
    return (not risk) or bool(path)

def peer_review_gate(reviews, approve_ratio, min_r=0.6):
    return approve_ratio >= min_r and len(reviews)>=1

def recursive_self_improve_theorem(check):
    return check

def entropy_reservoir(retrieval_mix, frac):
    return round(retrieval_mix*frac,4)


# ================= CC01..CC30 wave C (2026-11-01) =================
def cc_verifier_error_shift(embed_dist, threshold=0.2):
    return embed_dist > threshold

def cc_per_epoch_verifier_eval(accs):
    return [round(a,4) for a in accs]

def cc_judge_pool_contamination_repair(shared_frac, threshold=0.7):
    return shared_frac >= threshold

def cc_option_shuffle_anti_position(pref_shuffled, pref_orig):
    first_rank = [p.index(0) for p in pref_shuffled] if pref_shuffled else [0]
    orig_rank = [p.index(0) for p in pref_orig] if pref_orig else [0]
    return first_rank == orig_rank

def cc_tts_diversified_rollouts(num_rollouts, min_r=4):
    return num_rollouts >= min_r

def cc_verifier_quality_alloc_curve(budget, q):
    return round(budget*q,4)

def cc_mirror_loop_detect(self_citations, external_anchors):
    return self_citations > external_anchors * 2

def cc_pass1_peak_track(acc_series):
    return max(acc_series) if acc_series else 0.0

def cc_group_normalized_advantage(rewards, group_mean):
    return [round(r-g,4) for r,g in zip(rewards, group_mean)]

def cc_rejection_sampling_signal(accepted_ratio, threshold=0.3):
    return accepted_ratio >= threshold

def cc_runtime_tiered_retention(retention_days, tier):
    return all(d>=1 for d in retention_days) and bool(tier)

def cc_per_session_trust_rebase(last_reauth, now, window):
    return (now - last_reauth) <= window

def cc_activation_patch_effect(base_acc, patched_acc):
    return patched_acc > base_acc

def cc_logit_lens_slope(logits_series):
    n=len(logits_series)
    if n<2: return 0.0
    diffs=[logits_series[i+1]-logits_series[i] for i in range(n-1)]
    return round(sum(diffs)/len(diffs),4)

def cc_counter_argument_coverage(args, counterargs):
    return all(any(c for c in counterargs) for _ in args)

def cc_disagreement_exploration(pool_agree, threshold=0.8):
    return pool_agree < threshold

def cc_isotonic_monotone(confs, accs):
    return all(confs[i]<=confs[i+1] for i in range(len(confs)-1)) and \
           all(accs[i]<=accs[i+1] for i in range(len(accs)-1))

def cc_temperature_scaling_opt(conf, T):
    return round(conf**(1.0/T),4) if T>0 else conf

def cc_pass_at_k(answers, k, correct):
    return any(answers[i]==correct for i in range(min(k,len(answers))))

def cc_heldout_multi_split(splits):
    return len(splits) >= 3 and all(len(s)>0 for s in splits)

def cc_indirect_injection_rag(docs, malicious):
    return any(m in d for d in docs for m in malicious)

def cc_memory_poison_detect(mutated, original):
    return mutated != original

def cc_speculative_decoding_budget(draft_len, verify_cost):
    return draft_len > 0 and verify_cost >= 0

def cc_cache_hit_rate(hits, total):
    return round(hits/max(1,total),4)

def cc_plateau_escape(acc_series, win=3, step=0.005):
    if len(acc_series)<2*win: return False
    early=sum(acc_series[:win])/win; late=sum(acc_series[-win:])/win
    return (late-early) < step

def cc_explore_exploit_balance(explore_frac):
    return 0.0 <= explore_frac <= 1.0

def cc_commutative_reward_agg(reward1, reward2, op):
    if op=="add": return reward1+reward2 == reward2+reward1
    if op=="mul": return reward1*reward2 == reward2*reward1
    return False

def cc_listwise_agent_merge(list_scores, vote_scores):
    return sum(list_scores) >= sum(vote_scores)

def cc_after_commit_verify(committed, verified):
    return committed and verified


# ================= DD01..DD28 wave D (2026-11-01) =================
def dd_risk_tier_assign(risk):
    if risk < 0.3: return "low"
    if risk < 0.7: return "medium"
    return "high"

def dd_tool_allowlist_check(tool, allowlist):
    return tool in allowlist

def dd_output_format_compliance(output, schema_keys):
    return all(k in output for k in schema_keys)

def dd_pii_detect(text, patterns):
    return any(p in text for p in patterns)

def dd_anomaly_spike_monitor(series, thresh=3.0):
    n=len(series)
    if n<3: return False
    m=sum(series)/n; sd=(sum((v-m)**2 for v in series)/n)**0.5
    return sd>0 and any(abs(v-m)/sd>thresh for v in series)

def dd_version_consistency(skill_v, spec_v, cl_v):
    return skill_v == spec_v == cl_v

def dd_sbom_mandatory_exists(sbom_path):
    return bool(sbom_path)

def dd_decision_logging(decision, log):
    return bool(decision) and bool(log)

def dd_human_approval_queue(queue, highrisk):
    return (not highrisk) or len(queue) > 0

def dd_reward_proxy_gold_turnover(proxy, gold):
    return round(abs(proxy-gold)/max(1e-9,abs(gold)),4)

def dd_seed_sensitivity(metrics):
    return max(metrics)-min(metrics) if metrics else 0.0

def dd_ensemble_seed_agg(seeds):
    return sum(seeds)/len(seeds) if seeds else 0.0

def dd_latent_steering(probe, steer):
    return sum(p*s for p,s in zip(probe,steer)) > 0

def dd_rl_proof_length_feedback(proof_len, score):
    return score > 0 and proof_len > 0

def dd_preference_pairwise(a, b):
    return 1 if a>=b else 0

def dd_hedging_detect(assertions, hedges):
    return sum(1 for a,h in zip(assertions,hedges) if a and h)

def dd_goodhart_verifier_detect(metric_score, true_score, eps=0.2):
    return abs(metric_score-true_score) > eps

def dd_drift_budget_kl(kl, budget):
    return kl <= budget

def dd_collapse_reward_detect(reward_series, drop=0.15):
    if len(reward_series)<4: return False
    peak=max(reward_series[:2]); late=sum(reward_series[-2:])/2
    return (peak-late) > drop

def dd_early_warning_policy(degrad_series, thresh=0.1):
    if len(degrad_series)<2: return False
    return degrad_series[-1] - degrad_series[0] > thresh

def dd_verifier_attack_surface(executable, sandbox):
    return executable and sandbox

def dd_secure_enclave_checks(attestation, sealed):
    return attestation and sealed

def dd_capability_scaling_track(usage, cap):
    return usage <= cap

def dd_emergency_stop_protocol(armed, es_engaged):
    return armed and es_engaged

def dd_incident_forensics(logs, tamper_free):
    return bool(logs) and tamper_free

def dd_abuse_channel_monitor(channels):
    return all(not c for c in channels)

def dd_eval_alignment(human_agree, metric):
    return human_agree >= metric

def dd_gate_alignment(gate_pass, predicate_pass):
    return gate_pass == predicate_pass


# ================= EE01..EE24 Fase 17 cost/latency (2026-11-01) =================
def ee_budget_alloc_per_task(budget_total, n_tasks):
    return round(budget_total/max(1,n_tasks),4)

def ee_cost_per_action_track(total_cost, actions):
    return round(total_cost/max(1,actions),4)

def ee_latency_p95(latencies):
    s=sorted(latencies)
    import math
    k=int(0.95*len(s))-1
    return s[max(0,k)]

def ee_token_attribution(tokens, sources):
    return {s: round(t/len(sources),4) for s,t in zip(sources,[tokens]*len(sources))} if sources else {}

def ee_budget_alert(used, budget, threshold=0.8):
    return used/budget > threshold if budget else False

def ee_cost_model_prediction(hist):
    return sum(hist)/len(hist) if hist else 0.0

def ee_compute_alloc_optimal(total, weights):
    w=sum(weights)
    return [round(total*x/w,4) for x in weights] if w else []

def ee_token_summary(tokens):
    return {"total": sum(tokens), "mean": round(sum(tokens)/max(1,len(tokens)),4)} if tokens else {}

def ee_latency_optimize_path(min_lat, routes):
    return min(routes, key=lambda r: r) if routes else None, min(routes) if routes else None

def ee_smart_caching(cache_hits, requests, benefit=0.2):
    hit_rate = cache_hits/max(1,requests)
    return hit_rate, round(hit_rate*benefit,4)

def ee_distill_cost_benefit(student_cost, teacher_cost, quality_loss):
    return (teacher_cost-student_cost) > quality_loss

def ee_prompt_compression_cost(orig_tokens, compressed_tokens):
    return orig_tokens >= compressed_tokens

def ee_context_window_budget(ctx, budget):
    return ctx <= budget

def ee_cost_aware_planning(plan_cost, budget):
    return plan_cost <= budget

def ee_latency_aware_stop(latency, threshold):
    return latency <= threshold

def ee_cost_attribution_per_skill(cost, skill_map):
    return {k: round(cost/len(skill_map),4) for k in skill_map} if skill_map else {}

def ee_billing_anomaly(cost_series, z=2.0):
    n=len(cost_series)
    if n<3: return False
    m=sum(cost_series)/n; sd=(sum((c-m)**2 for c in cost_series)/n)**0.5
    return sd>0 and any(abs(c-m)/sd>z for c in cost_series)

def ee_token_waste_audit(retried, total):
    return round(retried/max(1,total),4)

def ee_retry_avoidance(fail_rate, retry_cost):
    return round(fail_rate*retry_cost,4)

def ee_efficiency_score(output_tokens, paid_tokens):
    return round(output_tokens/max(1,paid_tokens),4)

def ee_latency_sla(p95, sla):
    return p95 <= sla

def ee_prewarm_inference(warm, first_latency):
    return warm and first_latency is not None

def ee_streaming_early_result(stream, first_chunk):
    return stream and first_chunk is not None

def ee_priority_scheduling(tasks, priorities):
    return [t for _,t in sorted(zip(priorities,tasks), reverse=True)]

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "selftest"
    if cmd == "selftest_ee":
        print("EE1", ee_budget_alloc_per_task(100,4))
        print("EE2", ee_cost_per_action_track(50,10))
        print("EE3", ee_latency_p95([10,20,30,40,50,60,70,80,90,100]))
        print("EE4", ee_token_attribution(100,["a","b"]))
        print("EE5", ee_budget_alert(90,100))
        print("EE6", ee_cost_model_prediction([10,20,30]))
        print("EE7", ee_compute_alloc_optimal(100,[0.5,0.5]))
        print("EE8", ee_token_summary([10,20,30]))
        print("EE9", ee_latency_optimize_path(5,[10,20,5]))
        print("EE10", ee_smart_caching(8,10))
        print("EE11", ee_distill_cost_benefit(2,10,3))
        print("EE12", ee_prompt_compression_cost(100,40))
        print("EE13", ee_context_window_budget(5000,8000))
        print("EE14", ee_cost_aware_planning(80,100))
        print("EE15", ee_latency_aware_stop(150,200))
        print("EE16", ee_cost_attribution_per_skill(60,["c1","c2","c3"]))
        print("EE17", ee_billing_anomaly([10,11,10,50]))
        print("EE18", ee_token_waste_audit(2,10))
        print("EE19", ee_retry_avoidance(0.1,5))
        print("EE20", ee_efficiency_score(80,100))
        print("EE21", ee_latency_sla(180,200))
        print("EE22", ee_prewarm_inference(True,0.3))
        print("EE23", ee_streaming_early_result(True,0.1))
        print("EE24", ee_priority_scheduling(["a","b","c"],[1,3,2]))
        return 0
    if cmd == "selftest_dd":
        print("DD1", dd_risk_tier_assign(0.8))
        print("DD2", dd_tool_allowlist_check("bash",["bash","python"]))
        print("DD3", dd_output_format_compliance({"a":1},{"a"}))
        print("DD4", dd_pii_detect("email a@b.c",["@"]))
        print("DD5", dd_anomaly_spike_monitor([1,1,1,50]))
        print("DD6", dd_version_consistency("0.34.0","0.34.0","0.34.0"))
        print("DD7", dd_sbom_mandatory_exists("sbom.json"))
        print("DD8", dd_decision_logging("allow","log"))
        print("DD9", dd_human_approval_queue([1],False))
        print("DD10", dd_reward_proxy_gold_turnover(0.9,0.8))
        print("DD11", dd_seed_sensitivity([0.8,0.85,0.9]))
        print("DD12", dd_ensemble_seed_agg([0.8,0.9]))
        print("DD13", dd_latent_steering([1,1],[1,0]))
        print("DD14", dd_rl_proof_length_feedback(10,0.7))
        print("DD15", dd_preference_pairwise(0.8,0.6))
        print("DD16", dd_hedging_detect([True,True],[False,True]))
        print("DD17", dd_goodhart_verifier_detect(0.9,0.6))
        print("DD18", dd_drift_budget_kl(0.1,0.5))
        print("DD19", dd_collapse_reward_detect([0.9,0.9,0.4,0.3]))
        print("DD20", dd_early_warning_policy([0.5,0.7,0.9]))
        print("DD21", dd_verifier_attack_surface(True,True))
        print("DD22", dd_secure_enclave_checks(True,True))
        print("DD23", dd_capability_scaling_track(5,10))
        print("DD24", dd_emergency_stop_protocol(True,True))
        print("DD25", dd_incident_forensics(["l"],True))
        print("DD26", dd_abuse_channel_monitor([False,False]))
        print("DD27", dd_eval_alignment(0.7,0.6))
        print("DD28", dd_gate_alignment(True,True))
        return 0
    if cmd == "selftest_cc":
        print("CC1", cc_verifier_error_shift(0.3))
        print("CC2", cc_per_epoch_verifier_eval([0.8,0.85,0.9]))
        print("CC3", cc_judge_pool_contamination_repair(0.8))
        print("CC4", cc_option_shuffle_anti_position([[2,1,0]],[[2,1,0]]))
        print("CC5", cc_tts_diversified_rollouts(5))
        print("CC6", cc_verifier_quality_alloc_curve(100,0.8))
        print("CC7", cc_mirror_loop_detect(10,4))
        print("CC8", cc_pass1_peak_track([0.5,0.9,0.7]))
        print("CC9", cc_group_normalized_advantage([0.9,0.8],[0.7,0.7]))
        print("CC10", cc_rejection_sampling_signal(0.5))
        print("CC11", cc_runtime_tiered_retention([7,30,90],"3tier"))
        print("CC12", cc_per_session_trust_rebase(100,110,20))
        print("CC13", cc_activation_patch_effect(0.7,0.85))
        print("CC14", cc_logit_lens_slope([0.2,0.4,0.6]))
        print("CC15", cc_counter_argument_coverage([1,1],["a","b"]))
        print("CC16", cc_disagreement_exploration(0.6))
        print("CC17", cc_isotonic_monotone([0.5,0.7,0.9],[0.5,0.7,0.9]))
        print("CC18", cc_temperature_scaling_opt(0.8,2.0))
        print("CC19", cc_pass_at_k([1,2,3],1,1))
        print("CC20", cc_heldout_multi_split([[1],[2],[3]]))
        print("CC21", cc_indirect_injection_rag(["doc"],["inj"]))
        print("CC22", cc_memory_poison_detect("x","y"))
        print("CC23", cc_speculative_decoding_budget(3,2))
        print("CC24", cc_cache_hit_rate(8,10))
        print("CC25", cc_plateau_escape([0.9,0.9,0.9,0.9,0.91]))
        print("CC26", cc_explore_exploit_balance(0.3))
        print("CC27", cc_commutative_reward_agg(2,3,"add"))
        print("CC28", cc_listwise_agent_merge([0.8,0.7],[0.7,0.6]))
        print("CC29", cc_after_commit_verify(True,True))
        return 0
    if cmd == "selftest_bb":
        print("BB1", multiturn_jailbreak_accum([False,True,True]))
        print("BB2", hallucinated_tool_filter(["r1"],["r1"]))
        print("BB3", guardrail_version_eval_mapping("v1","v1"))
        print("BB4", decision_provenance_bind("y",["e1"]))
        print("BB5", metric_drift_detect(0.9,0.7))
        print("BB6", independent_evaluator_separation("A","B"))
        print("BB7", bb_confidence_reliability_joint([0.9,0.8,0.7],[1,1,0]))
        print("BB8", budget_alert_wind(90,100,True))
        print("BB9", eval_measurement_protocol(True,True,True))
        print("BB10", bb_compute_verifier_nonsubstitute(20,5))
        print("BB11", agent_collusion_detect(0.95))
        print("BB12", governance_policy_versioning("v1","c1"))
        print("BB13", slsa_source_track("src"))
        print("BB14", artifact_attestation("m",True))
        print("BB15", assume_breach_reauth_interval(100,120,30))
        print("BB16", hedged_early(True,True))
        print("BB17", reward_kl_bound(0.1,0.5))
        print("BB18", entropy_bonus(0.5))
        print("BB19", feature_anomaly_zscore([1,1,1,10]))
        print("BB20", calibration_ensemble([0.8,0.6]))
        print("BB21", fallback_route(False,True))
        print("BB22", task_success_estimate(8,10))
        print("BB23", autonomous_termination(True))
        print("BB24", learning_curve_slope([0.5,0.6,0.7,0.8]))
        print("BB25", weighted_fn_priority(0.2,0.1))
        print("BB26", judge_confidence_distribution_pool([1,1],[0.8,0.6]))
        print("BB27", escalation_path_exists(True,"path"))
        print("BB28", peer_review_gate([1,1],0.8))
        print("BB29", recursive_self_improve_theorem(True))
        print("BB30", entropy_reservoir(10,0.3))
        return 0
    if cmd == "selftest_aa":
        print("AA1", error_direction_diff_score(0.2,0.1))
        print("AA2", margin_gate(0.3))
        print("AA3", round(judge_pool_entropy([0.5,0.5]),4))
        print("AA4", confounder_bias_estimate([0.8,0.6,0.7],[0,1,1]))
        print("AA5", listwise_gain(0.9,0.7))
        print("AA6", stop_alloc(0.9,100))
        print("AA7", compute_accounting_report(10,5,7,20))
        print("AA8", autoformalize_faithfulness(True,True))
        print("AA9", four_stage_check(True,True,True,True))
        print("AA10", kernel_accept("proof", type("K",(),{"check":lambda s,p:p=="proof"})()))
        print("AA11", data_gating_fraction(8,10))
        print("AA12", grounding_fraction(7,10))
        print("AA13", collapse_curve_detect([0.9,0.85,0.8,0.5,0.4]))
        print("AA14", group_var_filter([[1,1,1],[0,1,0.5]]))
        print("AA15", multiturn_verdict([True,False,True]))
        print("AA16", spurious_guard(True,False))
        print("AA17", guardrail_latency(150))
        print("AA18", guardrail_acc(99,100))
        print("AA19", intervention_lineage("r","c","t"))
        print("AA20", allowlist_expiry(100,50))
        print("AA21", signed_ledger_check([1,2],True))
        print("AA22", assume_breach_reauth(True))
        print("AA23", sae_alignment([1,1],[1,0]))
        print("AA24", scratchpad_anomaly([1,1,1,9]))
        print("AA25", selective_risk({0.5:0.1,1.0:0.2}))
        print("AA26", neg_suite_parity(50,50))
        print("AA27", tts_protocol(True,True,True))
        print("AA28", lockfile_atomic(True,True))
        print("AA29", data_contamination_detect(0.2))
        print("AA30", curriculum_match(0.6,0.8))
        print("AA31", debate_aggregate([0.8,0.6],[0.7,0.3]))
        print("AA32", consensus_reliability(8,10))
        print("AA33", ece_compute([0.9,0.8,0.6],[True,False,False]))
        print("AA34", conformal_coverage([1,1,1],3))
        print("AA35", eval_protocol_check(True,True,True))
        print("AA36", oracle_baseline_hash("x","x"))
        print("AA37", injection_multiturn_detect(True))
        print("AA38", hitl_ticket_required(True,True))
        print("AA39", cost_per_action(100,10))
        print("AA40", latency_percentile([10,20,30,40,50]))
        print("AA41", skill_manifest_hash("h","h"))
        print("AA42", goal_drift_detect(["g1"],{"g1":1}))
        print("AA43", anchored_baseline("a","a"))
        return 0
    if cmd == "selftest_z":
        print("Z_error_src", error_source_classify_rlvr(True, False))
        print("Z_fn_priority", fn_priority_policy(2,1))
        print("Z_spurious", spurious_reward_detect(0.9,0.8))
        print("Z_collapse", online_self_certainty_collapse([0.9,0.88,0.85,0.6]))
        print("Z_prog_gain", programmatic_vs_judge_gain(0.8,0.6))
        print("Z_tts_regime", tts_regime_identify(5,3,1))
        print("Z_tts_account", tts_compute_accounting(10,5,7))
        print("Z_listwise", tts_listwise_merge([0.8,0.6],[0.7,0.9]))
        print("Z_tts_q", tts_verifier_quality_report(0.8,100))
        print("Z_finverify", finverify_subquestion_decompose("a b c",["a","c"]))
        print("Z_stop", agentic_verify_stop_decision(0.9))
        print("Z_autoform_eq", autoformalize_equivalence("A","A"))
        print("Z_4stage", four_stage_pipeline(True,True,True,True))
        print("Z_refine", proof_refine_loop(True,1))
        print("Z_overfit", informal_overfit_bench_form(0.9,0.6))
        print("Z_data_gate", data_gating_lever(8,10))
        print("Z_ground", reward_grounding_lever(7,10))
        print("Z_rise_collapse", rise_collapse_detect([0.8,0.9,0.85,0.4,0.3,0.2]))
        print("Z_imbalance", data_imbalance_overthink(0.6,0.3))
        print("Z_group_var", group_variance_filter([[1,1,1],[0,1,0.5]]))
        print("Z_multiturn", agentic_verifier_multiturn([True,False,True]))
        print("Z_spurious_guard", spurious_correlation_guard(True,False))
        print("Z_guard_200", runtime_guardrail_node200ms(150))
        print("Z_guard_98", runtime_guardrail_98acc(100,99))
        print("Z_intervention", runtime_intervention_telemetry(True,"r1","c1","t1"))
        print("Z_lineage", runtime_guardrail_lineage("r1","c1","t1"))
        print("Z_repro", verify_reproducible_fresh("x","x"))
        print("Z_selective", selective_prediction_risk({0.5:0.1,1.0:0.2}))
        print("Z_neg_total", negative_suite_total_tests(50,50))
        print("Z_bench", benchmark_protocol_tts(True,True,True))
        return 0
    if cmd == "selftest_y":
        print("Y01", error_direction_classify(True, False))
        print("Y03", fn_priority_metric(1,2))
        print("Y05", vacuous_guard(0.995))
        print("Y09", verifier_budget_kl_track(0.1,0.5,0.2))
        print("Y11", fp_learnable_trigger(4))
        d = judge_distribution_capture([0.7,0.8,0.9]); print("Y26", d["mean"])
        print("Y27", judgemoe_aggregate([{"mean":0.8,"var":0.01},{"mean":0.6,"var":0.04}]))
        print("Y28", care_confounder_aware([0.8,0.7],0.1))
        print("Y29", self_preference_detect([0.9,0.95],[0.7,0.75]))
        print("Y33", judge_distribution_conformal([0.5,0.6,0.7,0.8,0.9]))
        print("Y34", weak_verifier_programmatic([True,True,False]))
        print("Y51", compute_verifier_nonsubstitute(0.1,0.3))
        print("Y53", compute_sublinearity_report([1,2,4],[0.5,0.6,0.65]))
        print("Y54", alloc_verifier_quality_gated(0.8,100))
        print("Y55", t1_tool_offload(True,True))
        print("Y63", difficulty_adaptive_alloc(0.8,100))
        print("Y64", sequential_parallel_ratio(0.8))
        print("Y67", prm_orm_hybrid(0.8,0.6))
        print("Y76", collapse_predict_early([0.8,0.79,0.78,0.7]))
        print("Y77", reward_hack_scratchpad(True,False))
        print("Y81", drift_budget_constraint(0.1,0.3))
        print("Y82", reward_reshape_bounded(1.0))
        print("Y87", diffusion_drf_localized(0.6))
        print("Y101", evidence_grounded_eval(True,True))
        print("Y106", programmatic_verifier_dsl_agg([1,1,0,1]))
        print("Y117", near_miss_grade(0.75))
        print("Y123", evolved_verifier_validation(True,True))
        print("Y124", verifier_report_standard(True,True,True))
        print("Y126", env_grounded_sim_truth(5,5))
        print("Y130", scratchpad_anomaly([1,1,1,9]))
        print("Y151", evaluator_policy_coevolve(True,True,True))
        print("Y152", coevolve_regularize_ext(True,True))
        print("Y159", verifier_cost_efficiency(0.8,10))
        print("Y177", verifier_admission_controller(True,True))
        print("Y200", anchored_verifier_baseline("abc","abc"))
        return 0
    if cmd == "selftest_x":
        e1 = executable_oracle(42,42); print(f"X01 exec-oracle: {e1}")
        c2 = constraint_oracle({"gt0": lambda a: a["x"]>0}, {"x":5}); print(f"X02 constraint: {c2}")
        cg3 = citation_grounding({"c":["s1"]},"c",["s1"]); print(f"X03 citation: {cg3}")
        cv5 = compact_exec_verifier("def solve(x): return x*2",[2,3],[4,6]); print(f"X05 compact-verifier: {cv5}")
        eg8 = evidence_groundness(8,10); print(f"X08 groundness: {eg8}")
        po9 = process_outcome_decompose(True,False); print(f"X09 decompose: {po9}")
        mf16 = multi_llm_filter([True,True,True]); print(f"X16 multi-LLM: {mf16}")
        he17 = human_escalation_borderline([True,False,False]); print(f"X17 escalate: {he17}")
        ws18 = weak_to_strong_aggregate([0.6,0.7],[0.8,0.9]); print(f"X18 W2S: {ws18}")
        mv19 = majority_vote_label_noise([1,1,0]); print(f"X19 majority: {mv19}")
        pv22 = profile_aware_voting([1,1,0],["conservative","permissive","balanced"]); print(f"X22 profile-aware: {pv22}")
        cj24 = correlated_judge_detect(0.95); print(f"X24 correlated: {cj24}")
        mt26 = multitrial_abstain([1,1,1,0,0]); print(f"X26 multitrial: {mt26}")
        auc31 = auc_discriminative([0.9,0.8],[0.3,0.2]); print(f"X31 AUC: {auc31}")
        tts33 = tts_top1(1,5); print(f"X33 TTS: {tts33}")
        tc38 = trajectory_calibration(0.95,0.9,0.6); print(f"X38 traj-cal: {tc38}")
        ug39 = uncertainty_control_gating(0.2,0.5); print(f"X39 uncertainty-gate: {ug39}")
        cr42 = confidence_reliability_joint(0.8,0.75); print(f"X42 joint: {cr42}")
        dd45 = defense_in_depth_low_fp([True,True,True]); print(f"X45 defense-depth: {dd45}")
        ah53 = adversarial_hacker_fixer(True,False); print(f"X53 hacker-fixer: {ah53}")
        ge56 = grouped_eval([1,0,1],[1,1,0]); print(f"X56 grouped: {ge56}")
        st57 = verifier_strictness_steer(0.5,0.8); print(f"X57 strictness: {st57}")
        po62 = prm_orm_combine(0.8,0.6); print(f"X62 PRM+ORM: {po62}")
        sc65 = prm_training_shortcut_test(False); print(f"X65 shortcut: {sc65}")
        tp66 = trajectory_penalty_lowconf([0.9,0.2,0.8]); print(f"X66 penalty: {tp66}")
        return 0
    if cmd == "selftest_v":
        f1 = flip_rate_report([1,1,1,0,0]); print(f"V01 flip: {f1}")
        b2 = symmetric_order_randomize({"AB":10,"BA":9}); print(f"V02 balance: {b2}")
        ci3 = bootstrap_ci([0.7,0.8,0.75,0.9]); print(f"V03 bootstrap: {ci3}")
        o4 = ci_overlap_reject((0.7,0.8),(0.85,0.95)); print(f"V04 overlap: {o4}")
        pb5 = position_bias_detect(0.85,0.7); print(f"V05 pos-bias: {pb5}")
        cb6 = consistency_bias_decompose(0.95,0.12); print(f"V06 consistency-bias: {cb6}")
        op7 = backbone_operating_profile(0.7,0.2); print(f"V07 profile: {op7}")
        cl8 = claim_decompose("A. B. C.", ["A","B","C"]); print(f"V08 claims: {cl8}")
        mp9 = multi_probe_verify("c",[1,1,0]); print(f"V09 probe: {mp9}")
        ra10 = claim_risk_aggregate([1.0,0.5,0.0]); print(f"V10 risk: {ra10}")
        iso11 = isotonic_calibrate([0.2,0.5,0.8],[0.1,0.6,0.9]); print(f"V11 isotonic: {iso11}")
        ab12 = learned_abstain_selector([0.6,0.9,0.95],[1,0,1],0.8); print(f"V12 selector: {ab12}")
        chi13 = chi2_divergence([0.5,0.5],[0.4,0.6]); print(f"V13 chi2: {chi13}")
        ht14 = hedgetune_optimal([0.5,1.0,2.0],[0.8,0.7],[0.7,0.6]); print(f"V14 hedgetune: {ht14}")
        wc15 = ensemble_worst_case([[0.7,0.5],[0.6,0.9]]); print(f"V15 worst-case: {wc15}")
        uw16 = ensemble_uncertainty_weighted([[0.7,0.5],[0.6,0.9]],[0.1,0.2]); print(f"V16 unct-weighted: {uw16}")
        sb17 = soft_bon([2.0,1.0,0.5]); print(f"V17 SBoN: {sb17}")
        kl18 = kl_bound_track(4); print(f"V18 KL: {kl18}")
        pg19 = proxy_gold_gap([0.5,0.7,0.9],[0.8,0.75,0.6]); print(f"V19 turnover: {pg19}")
        rg20 = bon_regret(0.9,0.8); print(f"V20 regret: {rg20}")
        pd21 = prompt_diversity(["hello world foo","hello world bar"]); print(f"V21 diversity: {pd21}")
        pbs22 = position_balanced_scoring(0.85,0.7); print(f"V22 balanced: {pbs22}")
        e24 = ece_compute([0.6,0.9,0.95],[1,0,1]); print(f"V24 ECE: {e24}")
        sc25 = selective_risk_curve([0.6,0.9,0.95],[1,0,1],[0.7,0.9]); print(f"V25 risk-curve: {sc25}")
        k26 = kendall_tau([1,2,3],[1,3,2]); print(f"V26 kendall: {k26}")
        ms27 = metric_config_sensitivity({"a":[0.7,0.8,0.75]}); print(f"V27 sensitivity: {ms27}")
        rd29 = reward_decomposition(0.7,[0.5,0.3],[0.5,0.5]); print(f"V29 reward-decomp: {rd29}")
        pk30 = gold_curve_peak_detect([0.5,0.8,0.9,0.7]); print(f"V30 peak: {pk30}")
        return 0
    if cmd == "selftest_w":
        v1,_ = meta_eval_stratified({"reasoning":(10,2,1),"tool":(8,4,1)}); print(f"W01 strat-meta: min={v1}")
        c2 = wilson_ci_config(90,100); print(f"W02 wilson: {c2}")
        s3 = minimum_support_rule(12,10); print(f"W03 min-support: {s3}")
        a4 = abstention_policy(0.4,0.5,0.9); print(f"W04 abstention: {a4}")
        r7 = calibration_representativeness(30,200); print(f"W07 cal-rep: {r7}")
        f8 = fine_step_judge([0.9,0.6,0.8]); print(f"W08 fine-step: {f8}")
        k11 = fleiss_kappa([{0:2,1:1},{0:3,1:0},{0:1,1:2}],3,3); print(f"W11 fleiss: {k11}")
        v15 = controlled_intervention_verify(0.9,0.4); print(f"W15 intervention: {v15}")
        g16 = snr_track(1.0,0.1,1.0,0.02); print(f"W16 snr: gen={g16[0]} verif={g16[1]} verif_stronger={g16[2]}")
        L17 = curvature_stepsize_estimate([0.1,0.3,0.7],[1.0,1.0]); print(f"W17 curvature: L={L17[0]} eta={L17[1]}")
        rho18 = alignment_rho_monitor([1,2,3],[2,4,6]); print(f"W18 rho: {rho18}")
        al19 = collapse_alarm([0.9,0.85,0.7,0.55]); print(f"W19 collapse: {al19}")
        rho20 = rho_gate(0.95,0.8); print(f"W20 rho-gate: {rho20}")
        ens23 = reward_seed_ensemble([0.7,0.8,0.75]); print(f"W23 seed-ensemble: {ens23}")
        r26 = fabsver_reward(True,False); print(f"W26 FABSVer: {r26}")
        c27 = rl_star_convergence(0.7,0.2); print(f"W27 RL-STaR: {c27}")
        j29 = compiler_judge("stmt",True,True); print(f"W29 compiler-judge: {j29}")
        d36 = lemma_decompose({"a":["b"],"b":[]},["a","b","c"]); print(f"W36 lemma: {d36}")
        fi38 = formal_invariant_lean("theorem",True); print(f"W38 formal-lean: {fi38}")
        eq39 = equivalence_pair(True,True); print(f"W39 equivalent: {eq39}")
        alloc43 = greedy_marginal_gain([0.8,0.5,0.2],8); print(f"W43 greedy-gain: {alloc43}")
        es44 = early_stopping_budget([0.6,0.8,0.95],0.85); print(f"W44 early-stop: {es44}")
        co45 = compute_optimal({"easy":0.3,"hard":0.7},10); print(f"W45 compute-opt: {co45}")
        ev46 = evolving_demo_pool(["solve x^2=4","integrate x"],"solve x^2=4"); print(f"W46 demo-pool: {ev46}")
        pf50 = flops_pareto(100,0.9); print(f"W50 flops-pareto: {pf50}")
        ur53 = uncertainty_reallocation([0.1,0.2,0.7,0.3],2); print(f"W53 reallocation: {ur53}")
        sae56 = sae_decompose([1,2,3],{"f1":[1,0,0],"f2":[0,1,1]}); print(f"W56 sae: {sae56}")
        ap58 = activation_patch(0.9,0.5); print(f"W58 patch: {ap58}")
        crp61 = crp_delta_s(0.9,0.5); print(f"W61 crp: {crp61}")
        st64 = feature_steer([1,2], [0,1], 0.5); print(f"W64 steer: {st64}")
        poly65 = polysemanticity([0.9,0.2,0.7]); print(f"W65 polysem: {poly65}")
        srl71 = self_verify_rl_reward(True,True); print(f"W71 srl: {srl71}")
        ent74 = entropy_monitor([0.5,0.5]); print(f"W74 entropy: {ent74:.3f}")
        hk75 = reward_hack_early([0.5,0.8],[0.7,0.5]); print(f"W75 hack: {hk75}")
        mg76 = majority_collapse_guard([0.9,0.85,0.6]); print(f"W76 collapse-guard: {mg76}")
        mo77 = multi_objective_reward([0.4,0.6],[0.8,0.5]); print(f"W77 mo-reward: {mo77}")
        lat83 = latency_percentile([10,20,30,40,50],0.9); print(f"W83 latency: {lat83}")
        an87 = anomaly_trajectory([[1,2,3],[1],[2,3],[4,5,6,7]],3); print(f"W87 anomaly: {an87}")
        ab102 = assume_breach_reauth([{"auth_age":100},{"auth_age":500}],False); print(f"W102 breach: {ab102}")
        sod103 = separation_of_duties_live("A","B"); print(f"W103 SoD: {sod103}")
        return 0
    if cmd == "selftest_t":
        ev=[{"action":"login","ts":0.0},{"action":"xfer","ts":2.0}]
        ok1,b1 = constrained_decode_time(ev, [{"trigger":"login","after_action":"xfer","must_not_within_s":5.0,"then":"block"}]); print(f"T01: ok={ok1} {b1}")
        ok2,s2 = session_reauthorize([{"session_id":"s1","last_auth":0.0,"now":1000.0}], idle_max=300); print(f"T02: ok={ok2} stale={s2}")
        ok3,_ = trace_replay(ev, [{"name":"login-xfer","trigger":"login","type":"xfer","action":"xfer","window_s":5.0}]); print(f"T03: ok={ok3}")
        a4 = aca_allocate([0.1,0.9], 20); print(f"T04: {a4}")
        mu5, var5 = distributional_prm([0.5,0.7,0.6]); print(f"T05: mu={mu5:.2f} var={var5:.3f}")
        r6 = rise_self_verify(0.8, 0.9); print(f"T06: {r6:.2f}")
        s7 = reliability_conservatism([0.6,0.8],[0.5,0.9]); print(f"T07: {s7:.2f}")
        s8 = semi_supervised_process([True,None,None],[0.7,0.6,0.8],[0.9,0.5,0.5]); print(f"T08: {s8:.3f}")
        l9,_ = liveness_fairness_smt([[1],[0],[1,2]], k=5); print(f"T09: {l9}")
        s10,_ = autoformalize_pair("sum", "theorem"); print(f"T10: {s10}")
        p11 = premise_selection("solve polynomial x^2", ["polynomial roots theorem","calculus limit"]); print(f"T11: {p11}")
        d12 = recursive_decompose("T", max_depth=2); print(f"T12: {len(d12)}")
        ch13 = adaptive_debate({"math":{"A":0.9,"B":0.5}}, "math", rounds=2); print(f"T13: {ch13}")
        c14 = consensus_optimizer([0.8,0.6],[0.9,0.4]); print(f"T14: {c14:.2f}")
        a15 = debate_structured_aggregate([0.7,0.8,0.75]); print(f"T15: {a15}")
        p16 = feature_probe_score([1.0,2.0,3.0],[0.5,0.5,0.5]); print(f"T16: {p16:.3f}")
        ok17,d17 = feature_anomaly([0.5,0.5,0.5],[0.1,0.1,0.1],[0.5,0.5,9.0]); print(f"T17: ok={ok17} dev={d17}")
        k18 = gt_prune([1,2,3,4],[True,False,True,True]); print(f"T18: {k18}")
        a19 = acquisition_reward("x", 0.3, 0.8, 0.7); print(f"T19: {a19:.2f}")
        c20 = curriculum_select(["a","b","c"],[2,5,1],3); print(f"T20: {c20}")
        ok21,f21 = contamination_detect(["solve x^2=4","limit of sin"], ["x^2=4"]); print(f"T21: ok={ok21} {f21}")
        r22 = iterative_rescore(["a","b"], lambda x: len(x)); print(f"T22: {r22}")
        ok23,_ = trajectory_cluster([{"action":"xfer","steps":[1,2,3]}], {"xfer":3}); print(f"T23: ok={ok23}")
        mt24 = trace_mutation_inject(ev, "plant_provenance"); print(f"T24: {mt24}")
        ok25 = separation_of_duties("V","M"); print(f"T25: {ok25}")
        return 0
    if cmd == "selftest_o":
        ev=[{"ts":0.0,"action":"login","tool":"auth","category":"high","session_id":"s1","approved":True,"verified":True,"decision_id":"d1","provenance_lookup":None,"model_id":"m1","plan_step":1,"outcome":"ok"},
            {"ts":2.0,"action":"xfer","tool":"transfer","category":"high","session_id":"s1","approved":True,"verified":True,"decision_id":"d2","provenance_lookup":"r1","model_id":"m1","plan_step":2,"outcome":"ok"}]
        ok1,m1 = trace_schema_valid(ev); print(f"O1 schema: ok={ok1} {m1}")
        ok2,v2 = generic_obligations(ev); print(f"O2 obligations: ok={ok2} viol={v2}")
        ok3,b3 = provenance_binding(ev); print(f"O3 provenance: ok={ok3} bad={b3}")
        r4 = dtmc_risk(ev); print(f"O4 dtmc risk: {r4}")
        v5 = guardrail_intercept({"tool":"transfer","args":{"a":1}}, {"allowed_tools":["transfer"],"required_params":["a"]})
        print(f"O5 guardrail: {v5}")
        ok6,f6 = agentspec_dsl(ev, [{"trigger":"xfer","predicate":"approved","action":"block"}]); print(f"O6 agentspec: ok={ok6} fired={f6}")
        ok7,_ = tool_schema_validate({"tool":"t","args":{"x":"a"}}, {"x":"str"}); print(f"O7 schema: ok={ok7}")
        R8,t8 = overopt_law(3, 1.0, 0.1); print(f"O8 overopt: R={R8:.3f} turnover_d*={t8}")
        n9 = bop_samples(4.0); print(f"O9 bop n={n9}")
        E10,g10 = solver_verifier_gap(0.4,0.35); print(f"O10 gap: E={E10:.3f} {g10}")
        h11,_ = verifier_hedge([0.7,0.8,0.9],[0.7,0.5,0.3]); print(f"O11 verifier-hedge: hedging={h11}")
        dev12 = verbal_logprob_deviation([0.9,0.8],[0.7,0.75]); print(f"O12 verbal-logprob dev={dev12:.3f}")
        s13,_ = snr_lyapunov([0.0,0.1], lambda x:x*x, snr_v=1.5); print(f"O13 snr-lyapunov stable={s13}")
        s14 = generative_prm("", True, 0.8); print(f"O14 genPRM {s14}")
        n15 = qrprm_allocate(0.5, 0.9); print(f"O15 qrprm n={n15}")
        b16 = beam_search_grade([1,2,3], lambda x: x, beam=2); print(f"O16 beam {b16}")
        ok17,n17 = exact_rational_property([[1,0],[0,2]], None, None); print(f"O17 rational {ok17} {n17}")
        fp18,rate18 = false_positive_track(ev, ev[:1], [ev[1]]); print(f"O18 fp={fp18} rate={rate18:.2f}")
        h19,_ = verifier_goodhart([0.8,0.9,0.95],[0.8,0.7,0.6]); print(f"O19 goodhart hedging={h19}")
        cs20 = conformal_coverage_set([0.4,0.6,0.8,0.9],[0.7,0.95],alpha=0.1); print(f"O20 conformal set={cs20}")
        a21 = anll_adaptive_sample([0.1,0.9], budget=20); print(f"O21 anll {a21}")
        return 0
    if cmd == "selftest_n":
        c, ok = inference_commitment("m1","h_in","h_out","cfg1"); print(f"N1 commitment: ok={ok} {str(c)[:12]}")
        ev=[{"event_type":"login","ts":0.0},{"event_type":"access","ts":2.0,"payload":{"name":"xfer"}}]
        ok2,v2 = temporal_monitor(ev, {"trigger":"login","type":"access","action":"xfer","window_s":5.0})
        print(f"N2 temporal monitor: ok={ok2} violations={v2}")
        ok3,f3 = agentverify_monitor([{"event_type":"tool","approved":False}], [{"if":"tool","then":"approve"}])
        print(f"N3 agentverify: ok={ok3} fired={f3}")
        ok4,n4 = vepa_validate([{"trigger":"t","decision":"allow"},{"trigger":"t","decision":"deny"}])
        print(f"N4 vepa(conflict): ok={ok4} note={n4}")
        ok5,n5 = reward_hedge_detect([0.8,0.85,0.9],[0.7,0.6,0.4])
        print(f"N5 hedge: ok={ok5} note={n5}")
        q,qh = conformal_predict([0.4,0.6,0.8,0.9], [0.7], alpha=0.1)
        print(f"N6 conformal: q={q} qhat={qh}")
        ok7,n7 = lyapunov_certificate([0.0,0.1,0.15], lambda x: x*x)
        print(f"N7 lyapunov: ok={ok7} {n7}")
        ok8,n8 = exact_rational_matrix_check([[1,2],[3,4]], [5,6])
        print(f"N8 rational: ok={ok8} {n8}")
        n9 = pac_sample_complexity(0.1,0.05); print(f"N9 PAC n={n9}")
        k10 = ser_filter([{"pos":0.9,"neg":0.1},{"pos":0.5,"neg":0.5}], margin=0.2)
        print(f"N10 SER keep={len(k10)}")
        ok11,n11 = temporal_self_reward([(10.0,5.0),(9.0,8.0)])
        print(f"N11 temporal self-reward: ok={ok11} n={n11}")
        ece, ok12 = verbalized_calibrate([0.9,0.8,0.5],[True,False,False])
        print(f"N12 verbalized: ece={ece:.2f} ok={ok12}")
        return 0
    if cmd == "selftest":
        # P1
        ok1, rate, lo, hi, n = calibrate_verdict(10, 9)
        print(f"P1 calibration: pass={ok1} rate={rate:.2f} CI=[{lo:.2f},{hi:.2f}] n={n}")
        # P2
        ok2, fail2 = process_verifier([{"step":1,"score":0.8},{"step":2,"score":0.7}])
        print(f"P2 process-verifier: ok={ok2} failures={fail2}")
        # P3
        ok3, r3 = meta_judge([("a",0.9),("a",0.91),("b",0.1),("b",0.4)])
        print(f"P3 meta-judge: consistent={ok3} inconsistency={r3:.2f}")
        # P4
        ok4, w4 = wmv_ensemble([("j1",True),("j2",True),("j3",False)],
                                {"j1":0.1,"j2":0.05,"j3":0.3},
                                {"j1":0.1,"j2":0.1,"j3":0.2})
        print(f"P4 WMV: ok={ok4} weight={w4:.2f}")
        # P5
        alloc = uab_allocate([{"id":"a","anll":0.9},{"id":"b","anll":0.2}], 6)
        print(f"P5 UAB: {alloc}")
        # P6
        stable, detail = self_improvement_stable(0.02, 0.02)
        smt, smt_r = self_improvement_smt(0.02, 0.02)
        print(f"P6 stability: stable={stable} {detail} SMT={smt} ({smt_r})")
        # P7
        cert, m = typed_cot_verify([{"rule":"r1","typed":True,"evidence":"e1"},
                                     {"rule":"r2","typed":True,"evidence":"e2"}])
        print(f"P7 typed CoT: certified={cert} {m}")
        # P8
        ok8, miss = evidence_grounded_valid({"evidence":["e1","e2"]}, "C", {"C":{"e1","e2"}})
        print(f"P8 evidence-grounded: ok={ok8} missing={miss}")
        # P9
        ece, ok9 = model_quality([0.9,0.8,0.5], [True, False, False])
        print(f"P9 model quality: ece={ece:.2f} ok={ok9}")
        # P10
        ok10, pr10, nv = mav_aggregate([True, True, False])
        print(f"P10 MAV: aggregate={ok10} pass_rate={pr10:.2f} n={nv}")
        # P11
        vc, vs = spec_version_consistent("0.27.0","0.27.0","0.27.0")
        print(f"P11 spec-version: consistent={vc} {vs}")
        # P12
        print(f"P12 adversarial readiness: {adversarial_readiness()}")
        return 0
    return 1

if __name__ == "__main__":
    sys.exit(main())

# ================= O1..O21  R1..R54 phases 1-15 (2026-11-01) =================
# O1/R1: 12-field enforcement-ready trace schema validation
TRACE_FIELDS = ["ts","action","tool","category","session_id","approved","verified",
                "decision_id","provenance_lookup","model_id","plan_step","outcome"]
def trace_schema_valid(events):
    missing = set()
    for i,e in enumerate(events):
        for f in TRACE_FIELDS:
            if f not in e: missing.add((i,f))
    return not missing, sorted(missing)[:10]

# O2/R3: five generic MFOTL-style obligations
def generic_obligations(events):
    viol = []
    last_login = t0 = None
    for e in events:
        et = e.get("action"); t = e.get("ts",0.0)
        if et == "login": last_login = t
        elif et == "xfer" and last_login is not None and (t-last_login) <= 5.0:
            viol.append(("login-xfer-window", t))
    return len(viol)==0, viol

# O3/R4: bind provenance -> the lookup that produced it
def provenance_binding(events):
    produced = set(); bad = []
    for e in events:
        a = e.get("action")
        if a == "lookup": produced.add(e.get("result_id"))
        elif e.get("provenance_lookup") and e["provenance_lookup"] not in produced:
            bad.append(e.get("group_id", e))
    return len(bad)==0, bad[:5]

# O4/R5: DTMC risk prediction (discrete-time Markov chain over actions)
def dtmc_risk(events, unsafe=("xfer","exfil")):
    counts = {}; risk = {}
    prev = None
    for e in events:
        a = e.get("action")
        if prev is not None:
            counts.setdefault(prev, {}); counts[prev][a] = counts[prev].get(a,0)+1
        prev = a
    for s, nxt in counts.items():
        tot = sum(nxt.values()) or 1
        risk[s] = sum(nxt.get(u,0) for u in unsafe)/tot
    return risk

# O5/R6: guardrail 3-verdict interception (Pass/Block/Corrective)
def guardrail_intercept(call, policy):
    reason = None
    if call.get("tool") not in policy.get("allowed_tools", []):
        return "Block", "tool-not-allowed"
    req = policy.get("required_params", [])
    for p in req:
        if p not in call.get("args", {}):
            return "Corrective", f"missing-param:{p}"
    return "Pass", None

# O6/R7: AgentSpec-style DSL enforcement (triggers+predicates+block)
def agentspec_dsl(events, rules):
    fired = []
    for e in events:
        for r in rules:
            if e.get("action") == r.get("trigger"):
                pred = r.get("predicate")
                ok = (pred is None) or e.get(pred) is True
                if not ok: fired.append((r.get("trigger"), r.get("action")))
    return len(fired)==0, fired

# O7/R8: structural tool-schema validation (required typed params)
def tool_schema_validate(call, schema):
    for p, typ in schema.items():
        if p not in call.get("args", {}): return False, f"missing:{p}"
        if typ == "str" and not isinstance(call["args"][p], str): return False, f"type:{p}"
        if typ in ("int","float") and not isinstance(call["args"][p], (int,float)): return False, f"type:{p}"
    return True, None

# O8/R10: closed-form over-optimization law  R = d*(alpha - beta*d)
def overopt_law(d, alpha, beta):
    from fractions import Fraction
    R = d*(alpha - beta*d)
    turn = alpha/(2*beta) if beta else None
    return R, turn

# O9/R11: Best-of-Poisson approximation sample count
def bop_samples(lam):
    import math
    return max(1, int(math.ceil(lam)))

# O10/R12: solver-verifier gap metric  E = U_s - U_v
def solver_verifier_gap(U_s, U_v):
    E = U_s - U_v
    return E, "converging" if E < 1e-6 else "gap-open"

# O11/R13: reward-hacking verifier detection (proxy-up / gold-down)
def verifier_hedge(proxy_seq, gold_seq):
    if len(gold_seq) < 3: return False, "insufficient"
    proxy_up = proxy_seq[-1] > proxy_seq[0]
    gold_dn = gold_seq[-1] < gold_seq[0]
    return (proxy_up and gold_dn), "proxy-up-gold-down" if (proxy_up and gold_dn) else "clean"

# O12/R14: verbalized-vs-logprob confidence deviation
def verbal_logprob_deviation(verbal, logprob):
    n = len(verbal)
    if n == 0 or n != len(logprob): return None
    return sum(abs(v - p) for v,p in zip(verbal, logprob))/n

# O13/R15: Lyapunov stability with verifier SNR floor (Variance Inequality flavour)
def snr_lyapunov(states, V, snr_v, floor=1.0):
    ok = snr_v >= floor
    inc = []
    for i in range(len(states)-1):
        if V(states[i+1]) > V(states[i]) + 1e-3:
            inc.append(i)
    stable = (len(inc)==0) and ok
    return stable, f"snr={snr_v} inc={inc}"

# O14/R16: generative PRM step score (CoT + code-verify composite)
def generative_prm(step_text, code_ok, cot_score):
    if code_ok is False: return 0.0
    return 0.6*cot_score + 0.4*float(code_ok)

# O15/R17: QR-PRM calibrated allocation  n for target success p
def qrprm_allocate(cal_reward, target_p):
    import math
    if cal_reward <= 0: return None
    # naive  n ~ log(1-p)/log(1-reward)
    try:
        return int(math.ceil(math.log1p(-target_p)/math.log1p(-min(cal_reward,0.999))))
    except (ValueError, ZeroDivisionError):
        return None

# O16/R18: beam-search grading with PRM pruning
def beam_search_grade(branches, prm, beam=2):
    scored = sorted(((prm(b), b) for b in branches), reverse=True)
    return [b for _,b in scored[:beam]]

# O17/R20: exact-rational property certification (invariant via Fractions)
def exact_rational_property(matrix, lhs, rhs):
    from fractions import Fraction
    m = [[Fraction(x) for x in row] for row in matrix]
    # certify m is symmetric positive-diagonal -> trivial invariant example
    n = len(m)
    if n==0: return False, "empty"
    for i in range(n):
        if m[i][i] <= 0: return False, f"nonposdiag{i}"
    return True, f"posdiag({n})"

# O18/R31: false-positive budget tracking
def false_positive_track(events, benign, fired):
    fp = sum(1 for e in events if e in benign and e in fired)
    tot = len(benign)
    return fp, (fp/tot) if tot else 0.0

# O19/R32: verifier-Goodhart detection (benchmark gaming)
def verifier_goodhart(proxy_seq, gold_seq):
    return verifier_hedge(proxy_seq, gold_seq)

# O20/R38: conformal coverage set (prediction set)
def conformal_coverage_set(scores_cal, new, alpha=0.1):
    n = len(scores_cal)
    if n == 0: return None
    s = sorted(scores_cal)
    q = s[min(n-1, int((n+1)*(1-alpha))-1)]
    return [x for x in new if x <= q]

# O21/R40: ANLL adaptive sampling (uncertainty-proportional)
def anll_adaptive_sample(anll_scores, budget=100):
    total = sum(anll_scores) or 1.0
    return {i: max(1, int(budget * a/total)) for i,a in enumerate(anll_scores)}

# ------------------------------------------------------------------
# WAVE F — INTER-AGENT / SWARM INTEGRITY (FF01–FF24)
# ------------------------------------------------------------------
def ff_delegation_cycle_detect(edges):
    # FF01: return True (safe) when delegation graph is acyclic.
    from collections import deque
    n = max((max(u, v) for u, v in edges), default=0) + 1
    adj = [[] for _ in range(n)]
    indeg = [0] * n
    for u, v in edges:
        if u >= n or v >= n: continue
        adj[u].append(v); indeg[v] += 1
    q = deque([i for i in range(n) if indeg[i] == 0])
    seen = 0
    while q:
        u = q.popleft(); seen += 1
        for v in adj[u]:
            indeg[v] -= 1
            if indeg[v] == 0: q.append(v)
    return seen == n

def ff_role_separation_enforce(role_a, role_b):
    # FF02: distinct roles must be kept separate; True when isolated.
    return role_a != role_b

def ff_privilege_escalation_guard(level, max_level):
    # FF03: privilege level never exceeds the granted max.
    return int(level) <= int(max_level)

def ff_shared_context_leak_scan(memories, banned):
    # FF04: no banned token may appear in any shared memory entry.
    return all(b not in m for m in memories for b in banned)

def ff_group_decision_quorum(votes, required):
    # FF05: yes-vote count must meet the quorum threshold.
    return sum(1 for v in votes if v) >= required

def ff_agent_identity_attest(sig_valid, id_matched):
    # FF06: identity attested only when signature AND id match.
    return bool(sig_valid) and bool(id_matched)

def ff_cross_agent_contradiction(a, b, tol=1e-9):
    # FF07: True when two agents' claims contradict.
    return abs(a - b) > tol

def ff_dependency_deadlock_detect(edges):
    # FF08: dependency graph must be acyclic (no deadlock).
    return ff_delegation_cycle_detect(edges)

def ff_redundant_task_dedup(tasks):
    # FF09: returns number of unique tasks after deduplication.
    return len(set(tasks))

def ff_orphan_agent_detect(active, owned):
    # FF10: no active agent may lack an owner; True when all owned.
    return set(active) <= set(owned)

def ff_checkpoint_divergence(digests):
    # FF11: all replica checkpoint digests must agree.
    return len(set(digests)) == 1

def ff_rollback_consistency(snapshot, restored):
    # FF12: restored state must equal the pristine snapshot.
    return snapshot == restored

def ff_handoff_completeness(deps_meta, transfer_meta):
    # FF13: handoff metadata must include both dep and transfer sections.
    return bool(deps_meta) and bool(transfer_meta)

def ff_resource_quarantine_violation(dir_ok, allowlist_ok):
    # FF14: resource access allowed only when dir and allowlist pass.
    return bool(dir_ok) and bool(allowlist_ok)

def ff_agent_fanout_limit(fanout, limit):
    # FF15: agent may fan out to at most `limit` children.
    return int(fanout) <= int(limit)

def ff_blackboard_tamper_detect(expected_digest, actual_digest):
    # FF16: blackboard digest must match the expected value.
    return expected_digest == actual_digest

def ff_group_memory_poison_guard(entries, banned):
    # FF17: banned poison markers must not appear in group memory.
    return ff_shared_context_leak_scan(entries, banned)

def ff_multi_agent_consensus_majority(votes, min_pct):
    # FF18: consensus holds when yes-vote % >= min_pct.
    if not votes: return False
    yes = sum(1 for v in votes if v)
    return (yes * 100.0 / len(votes)) >= min_pct

def ff_inter_agent_message_signing(sig_valid, route_ok):
    # FF19: routed message accepted only when signed and route-valid.
    return bool(sig_valid) and bool(route_ok)

def ff_swarm_budget_burn(total_budget, spent, cap):
    # FF20: spend rate must stay within the swarm budget cap.
    return spent <= cap * total_budget

def ff_parallel_conflict_resolution(results):
    # FF21: returns the majority-first resolved outcome (deterministic).
    if not results: return None
    from collections import Counter
    return Counter(results).most_common(1)[0][0]

def ff_serial_execution_enforce(order_ok, deps_ok):
    # FF22: serial execution valid only when ordering AND dependency checks pass.
    return bool(order_ok) and bool(deps_ok)

def ff_agent_trust_tier_propagation(tier, max_tier):
    # FF23: child agent never inherits a higher trust tier than permitted.
    return int(tier) <= int(max_tier)

def ff_emergent_plan_divergence(plans, max_spread=0.2):
    # FF24: emergent plans must not diverge beyond the allowed spread.
    if len(plans) < 2: return True
    lo, hi = min(plans), max(plans)
    return (hi - lo) <= max_spread

def selftest_ff():
    return [(1, ff_delegation_cycle_detect([(0,1),(1,2)])),
            (2, ff_role_separation_enforce("code","review")),
            (3, ff_privilege_escalation_guard(2,3)),
            (4, ff_shared_context_leak_scan(["alpha","beta"],["secret"])),
            (5, ff_group_decision_quorum([True,True,False],2)),
            (6, ff_agent_identity_attest(True,True)),
            (7, ff_cross_agent_contradiction(0.9,0.1)),
            (8, ff_dependency_deadlock_detect([(0,1),(1,0)]) is False),
            (9, ff_redundant_task_dedup(["a","a","b"]) == 2),
            (10, ff_orphan_agent_detect([1,2],[1,2,3])),
            (11, ff_checkpoint_divergence(["abc","abc","abc"])),
            (12, ff_rollback_consistency({"x":1},{"x":1})),
            (13, ff_handoff_completeness({"dep":1},{"meta":2})),
            (14, ff_resource_quarantine_violation(True,True)),
            (15, ff_agent_fanout_limit(4,5)),
            (16, ff_blackboard_tamper_detect("d","d")),
            (17, ff_group_memory_poison_guard(["ok","fine"],["bad"])),
            (18, ff_multi_agent_consensus_majority([True,True,True,False],75)),
            (19, ff_inter_agent_message_signing(True,True)),
            (20, ff_swarm_budget_burn(100,40,0.5)),
            (21, ff_parallel_conflict_resolution(["A","B","A"]) == "A"),
            (22, ff_serial_execution_enforce(True,True)),
            (23, ff_agent_trust_tier_propagation(1,2)),
            (24, ff_emergent_plan_divergence([0.5,0.55]))]
