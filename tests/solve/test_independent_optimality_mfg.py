"""T1.2 — manufacturing FREE-search Z3 independent-optimality.

Two halves:

1. PARITY — Z3 (a DIFFERENT engine than CP-SAT) corroborates the CP-SAT optimum
   exactly where the same-engine tripwire returns ``True``, and refutes a
   one-worse level-2 claim (the strict-improvement disjunction is wired right).

2. REGION-CORRESPONDENCE (must-fix #4) — the MODEL-INDEPENDENT gate that wires
   ``feasible.checker.checker.check`` as the oracle. It proves the Z3 feasible
   REGION corresponds to the closed checker's region (not larger, not too tight),
   using the closed checker as a model-independent oracle:
     (a) NOT-LARGER  — SAMPLE decoded SAT witnesses -> checker.check().passed
         (RC-2: a SAMPLE over a large witness space, NOT exhaustive containment);
     (b) NOT-TOO-TIGHT — the optimum is in-region;
     (c) the 3-chain changeover is the IMMEDIATE-ADJACENCY sum (no every-pair
         over-count) — a FEASIBLE plan (RE-HOMED here per RC-5/F2), pinned to the
         FEASIBILITY-ONLY layer (SAT) with its ``co`` asserted == the canonical
         consecutive-pair recompute;
     (d) EXCLUDES-CHECKER-INFEASIBLE — pin CONSTRUCTED checker-REJECTED adversaries
         (maintenance-straddle cleanout, night-only cleanout) to the
         FEASIBILITY-ONLY layer (RC-1, no objective confound) -> UNSAT on the
         specific breached rule_id, PLUS a POSITIVE CONTROL (known-feasible plan
         -> SAT) so the test cannot pass vacuously.
"""
from __future__ import annotations

import z3

from feasible.checker.checker import check
from feasible.domains import get_domain
from feasible.ir.domain import Plan
from feasible.scenario import build_scenario_ir
from feasible.solve.independent_optimality import Verdict, independent_optimality_check
from feasible.solve.orchestrate import solve, total_changeover_time


# --------------------------------------------------------------------------- #
# Parity (load-bearing): Z3 agrees with the CP-SAT tripwire on the golden.     #
# --------------------------------------------------------------------------- #


def test_z3_corroborates_the_cpsat_optimum():
    ir = build_scenario_ir()
    res = solve(ir, max_seconds=30.0, workers=1, seed=1)
    V = res.objective                       # the golden optimum, == (0, 90)
    from feasible.solve.optimality import optimality_tripwire

    assert optimality_tripwire(ir, V) is True            # CP-SAT same-engine: nothing beats V
    assert independent_optimality_check(ir, V) is Verdict.corroborated  # Z3 AGREES (disjoint engine)


def test_z3_refutes_a_one_worse_level2_claim():
    # claim V = (optimum_wt, optimum_co + 1): a plan equal to the true optimum is
    # strictly better on level 2 -> a strictly-better plan EXISTS -> SAT -> refuted.
    ir = build_scenario_ir()
    res = solve(ir, max_seconds=30.0, workers=1, seed=1)
    wt, co = res.objective
    assert independent_optimality_check(ir, (wt, co + 1)) is Verdict.refuted


# --------------------------------------------------------------------------- #
# Region-correspondence test fixtures.                                         #
# --------------------------------------------------------------------------- #

_ALLERGEN = ["J1", "J5"]
_OTHER = ["J2", "J3", "J4", "J6"]


def _base_feasible_plan(ir) -> Plan:
    """A clean, checker-FEASIBLE plan with the family-isolated mix/fill layout so
    the ONLY changeover lives on the (single) Labeler. The Labeler order is the
    3-chain Allergen(J1) -> Standard(J3) -> Spicy(J4), then J2, J5, J6 — so the
    plan exercises a 3-op same-machine chain whose changeover the encoding must
    NOT over-count."""
    inst = ir.instance

    def dur(opid: str) -> int:
        return inst.operation(opid).duration

    def fam(job_id: str) -> str:
        return inst.job(job_id).family

    assignments: dict[str, tuple[int, str]] = {}
    # mixes: allergen on Mixer-B, others on Mixer-A (no Allergen<->non-allergen adjacency)
    t = 0
    for j in _ALLERGEN:
        assignments[f"{j}-mix"] = (t, "Mixer-B"); t += dur(f"{j}-mix")
    t = 0
    for j in _OTHER:
        assignments[f"{j}-mix"] = (t, "Mixer-A"); t += dur(f"{j}-mix")
    # fills: allergen on Filler-2 (well before the 1200 maintenance window), others on Filler-1
    t = 0
    for j in _ALLERGEN:
        me = assignments[f"{j}-mix"][0] + dur(f"{j}-mix")
        s = max(t, me); assignments[f"{j}-fill"] = (s, "Filler-2"); t = s + dur(f"{j}-fill")
    t = 0
    for j in _OTHER:
        me = assignments[f"{j}-mix"][0] + dur(f"{j}-mix")
        s = max(t, me); assignments[f"{j}-fill"] = (s, "Filler-1"); t = s + dur(f"{j}-fill")
    # labels: the 3-chain order on the single Labeler, with cleanouts where setup>0
    order = ["J1-label", "J3-label", "J4-label", "J2-label", "J5-label", "J6-label"]
    cleanouts: list[tuple[str, int, int, str]] = []
    t = 0
    prev: str | None = None
    for opid in order:
        j = opid.split("-")[0]
        fe = assignments[f"{j}-fill"][0] + dur(f"{j}-fill")
        s = max(t, fe)
        if prev is not None:
            req = inst.setup(fam(prev.split("-")[0]), fam(j))
            if req > 0:
                cs = s
                cleanouts.append(("Labeler", cs, cs + req, f"cleanout {prev}->{opid}"))
                s = cs + req
        assignments[opid] = (s, "Labeler"); t = s + dur(opid); prev = opid
    return Plan(assignments=assignments, cleanouts=cleanouts)


def _three_chain_feasible_plan(ir) -> Plan:
    return _base_feasible_plan(ir)


def _expected_immediate_adjacency_co(ir) -> int:
    """The IMMEDIATE-adjacency changeover of the 3-chain plan, computed by the
    canonical consecutive-pair recompute (``total_changeover_time``) — the
    independent oracle the encoding's ``co`` must match (NOT the every-pair
    over-count)."""
    return total_changeover_time(ir, _three_chain_feasible_plan(ir))


def _maintenance_straddle_plan(ir) -> Plan:
    """A complete checker-FEASIBLE-SHAPE plan whose ONLY rule breach is a
    MATERIALIZED cleanout STRADDLING the Filler-2 [1200,1440) maintenance window
    (J1-fill Allergen immediately before J2-fill Standard on Filler-2). Routing,
    no-overlap and setup are all satisfied — the cleanout straddle is the sole
    breach. Because the [1200,1440) window sits at a NIGHT minute-of-day in this
    instance, the straddle is unavoidably ALSO a night breach; the test cites
    ``R-MAINT`` (which the must-fix #3 materialized-disjointness assertion owns)."""
    a: dict[str, tuple[int, str]] = {
        # the J1(Allergen) -> J2(Standard) chain routed around the maintenance window
        "J1-mix": (1100, "Mixer-B"), "J1-fill": (1150, "Filler-2"), "J1-label": (1500, "Labeler"),
        "J2-mix": (1100, "Mixer-A"), "J2-fill": (1440, "Filler-2"), "J2-label": (1700, "Labeler"),
        # the other jobs placed trivially feasibly, far from any setup adjacency
        "J3-mix": (0, "Mixer-A"), "J4-mix": (40, "Mixer-A"), "J6-mix": (70, "Mixer-A"),
        "J5-mix": (0, "Mixer-B"),
        "J3-fill": (100, "Filler-1"), "J4-fill": (130, "Filler-1"),
        "J6-fill": (160, "Filler-1"), "J5-fill": (200, "Filler-1"),
        "J3-label": (300, "Labeler"), "J4-label": (400, "Labeler"),
        "J6-label": (500, "Labeler"), "J5-label": (600, "Labeler"),
    }
    cleanouts = [
        # the STRADDLING cleanout (must-fix #3 adversary): [1180,1270) overlaps [1200,1440)
        ("Filler-2", 1180, 1270, "cleanout J1-fill->J2-fill"),
        # a legitimate DAY cleanout for the J1->J2 LABEL adjacency (minute-of-day 170, valid)
        ("Labeler", 1610, 1700, "cleanout J1-label->J2-label"),
    ]
    return Plan(assignments=a, cleanouts=cleanouts)


def _night_only_plan(ir) -> Plan:
    """A complete plan whose ONLY rule breach is a NIGHT-band cleanout on the
    (maintenance-free) Labeler: J1-label (Allergen) immediately before J2-label
    (Standard) with the required cleanout at minute-of-day 1000 (NIGHT). Isolates
    must-fix #6 (the night band on the materialized cleanout ``cs``)."""
    a: dict[str, tuple[int, str]] = {
        "J1-mix": (0, "Mixer-B"), "J5-mix": (50, "Mixer-B"),
        "J2-mix": (0, "Mixer-A"), "J3-mix": (40, "Mixer-A"),
        "J4-mix": (80, "Mixer-A"), "J6-mix": (120, "Mixer-A"),
        "J1-fill": (100, "Filler-2"), "J5-fill": (130, "Filler-2"),
        "J2-fill": (100, "Filler-1"), "J3-fill": (130, "Filler-1"),
        "J4-fill": (160, "Filler-1"), "J6-fill": (190, "Filler-1"),
        # Labeler order J5(A),J1(A),J2(Std),J3,J6,J4 -> the ONLY setup adjacency is J1->J2
        "J5-label": (700, "Labeler"),    # ends 830 (A)
        "J1-label": (830, "Labeler"),    # ends 940 (A->A: no cleanout)
        "J2-label": (1090, "Labeler"),   # after the NIGHT cleanout; ends 1190
        "J3-label": (1190, "Labeler"), "J6-label": (1280, "Labeler"),
        "J4-label": (1350, "Labeler"),
    }
    cleanouts = [("Labeler", 1000, 1090, "cleanout J1-label->J2-label")]  # minute-of-day 1000 = NIGHT
    return Plan(assignments=a, cleanouts=cleanouts)


def _constructed_infeasible_plans(ir):
    """Yield ``(plan, rule_id)`` for the two CHECKER-REJECTED adversaries whose
    Z3 witnesses must be EXCLUDED by the feasibility-only layer."""
    return [
        (_maintenance_straddle_plan(ir), "R-MAINT"),
        (_night_only_plan(ir), "R-6.1-NIGHT-CLEANOUT"),
    ]


# --------------------------------------------------------------------------- #
# (a) NOT-LARGER — sampled decoded witnesses are checker-feasible (RC-2).      #
# --------------------------------------------------------------------------- #


def test_every_z3_sat_witness_decodes_to_a_checker_passing_plan():
    ir = build_scenario_ir()
    res = solve(ir, max_seconds=30.0, workers=1, seed=1)
    wt, co = res.objective
    _, verifier = get_domain("manufacturing")
    s = verifier.independent_optimality_encode(ir, (wt, co + 1))   # refuting bound -> SAT witnesses exist
    assert s is not None
    seen = 0
    while s.check() == z3.sat and seen < 20:              # SAMPLE <=20 witnesses (not exhaustive)
        m = s.model()
        plan = verifier._decode_witness(m, ir)
        assert check(plan, ir).passed is True            # sampled Z3-feasible => checker-feasible
        seen += 1
        s.add(verifier._block_model(m))                  # enumerate distinct witnesses
    assert seen >= 1


# --------------------------------------------------------------------------- #
# (b) NOT-TOO-TIGHT — the optimum is in-region.                               #
# --------------------------------------------------------------------------- #


def test_achieved_optimum_is_in_region():
    ir = build_scenario_ir()
    res = solve(ir, max_seconds=30.0, workers=1, seed=1)
    wt, co = res.objective
    _, verifier = get_domain("manufacturing")
    s = verifier.independent_optimality_encode(ir, (wt, co + 1))
    assert s is not None
    assert s.check() == z3.sat                            # the optimum is reachable in-region


# --------------------------------------------------------------------------- #
# (c) the 3-chain changeover is the immediate-adjacency sum, not over-counted. #
# --------------------------------------------------------------------------- #


def test_three_chain_changeover_is_not_over_counted():
    ir = build_scenario_ir()
    three_chain = _three_chain_feasible_plan(ir)         # Allergen->Standard->Spicy on the Labeler
    assert check(three_chain, ir).passed is True         # it is FEASIBLE (a mis-sum, not a breach)
    _, verifier = get_domain("manufacturing")
    s_feas, _vars = verifier._feasibility_only_encode(ir)
    s_feas.add(verifier._pin_to_plan(three_chain, ir))   # pin to the FEASIBILITY-ONLY layer
    assert s_feas.check() == z3.sat                       # a feasible plan IS in the region
    co_val = verifier._changeover_of(three_chain, ir)    # the encoding's immediate-adjacency co
    assert co_val == _expected_immediate_adjacency_co(ir)  # consecutive-pair sum, NOT the over-count


# --------------------------------------------------------------------------- #
# (d) EXCLUDES-CHECKER-INFEASIBLE — feasibility-only layer + positive control. #
# --------------------------------------------------------------------------- #


def test_encoding_excludes_constructed_checker_infeasible_plans():
    ir = build_scenario_ir()
    _, verifier = get_domain("manufacturing")

    # POSITIVE CONTROL (mandatory): a KNOWN checker-FEASIBLE plan pins SAT, proving
    # the pins are admissible (an over-constraining _pin_to_plan would make every
    # pin UNSAT and this test would pass VACUOUSLY).
    good_plan = _base_feasible_plan(ir)
    assert check(good_plan, ir).passed is True
    s_ctrl, _ = verifier._feasibility_only_encode(ir)
    s_ctrl.add(verifier._pin_to_plan(good_plan, ir))
    assert s_ctrl.check() == z3.sat                       # the feasible plan IS pin-admissible

    for bad_plan, rule_id in _constructed_infeasible_plans(ir):   # straddle / night-only
        rejected = check(bad_plan, ir)
        assert rejected.passed is False                  # precondition: the checker rejects it
        assert any(v.rule_id == rule_id for v in rejected.violations)   # for the SPECIFIC rule
        s_feas, _ = verifier._feasibility_only_encode(ir)   # FEASIBILITY-ONLY layer (no objective)
        s_feas.add(verifier._pin_to_plan(bad_plan, ir))     # pin start/mp/cs to the bad plan
        assert s_feas.check() == z3.unsat                    # the hard-constraint region EXCLUDES it
