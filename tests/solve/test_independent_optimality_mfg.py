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
         FEASIBILITY-ONLY layer (SAT) with the ENCODING'S ``co`` expression read
         straight out of a Z3 model (``_changeover_expr_value`` — NOT a Python
         recompute) and asserted == the canonical consecutive-pair sum and STRICTLY
         less than the every-ordered-pair over-count, so an every-pair regression
         (which would change the SHARED ``_changeover_expr``) is CAUGHT;
     (d) EXCLUDES-CHECKER-INFEASIBLE — pin CONSTRUCTED checker-REJECTED adversaries
         to the FEASIBILITY-ONLY layer (RC-1, no objective confound) -> UNSAT on the
         specific breached rule_id, PLUS a POSITIVE CONTROL (known-feasible plan
         -> SAT) so the test cannot pass vacuously. THREE adversaries, each isolating
         exactly ONE must-fix on the only instance where that rule is INDEPENDENTLY
         load-bearing:
           - night-only cleanout (R-6.1-NIGHT-CLEANOUT)        -> isolates #6;
           - DAY-band maintenance-straddle on a DAY-2 Labeler window [1840,1940)
             whose straddling cleanout has minute-of-day 440 (DAY-valid, so #6 does
             NOT fire) -> isolates #3 (the cleanout-maint-disjointness on ``cs``);
             a discrimination probe confirms dropping #3 alone flips this to SAT;
           - the original night-window maintenance-straddle (R-MAINT) is retained as
             a belt-and-braces adversary even though on the sole demo window #6
             subsumes #3 (which is WHY the day-2 window above exists — to give #3 an
             independent witness).
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


def _every_ordered_pair_co(ir, plan) -> int:
    """The WRONG every-ordered-same-machine-pair changeover sum (the over-count the
    encoding must NOT compute). On Allergen->Standard->Spicy this charges all THREE
    ordered pairs — Allergen->Standard (90), Allergen->Spicy (90), Standard->Spicy
    (0) = 180 — where the correct immediate-adjacency cost is only 90. The
    regression value the discriminating leg (c) proves the encoding's ``co`` is NOT
    equal to."""
    inst = ir.instance

    def fam(opid: str) -> str:
        return inst.job(inst.operation(opid).job_id).family

    total = 0
    for mc in inst.machines:
        on_mc = [
            opid for opid, (_st, m) in plan.assignments.items() if m == mc
        ]
        for i_id in on_mc:
            for j_id in on_mc:
                if i_id == j_id:
                    continue
                if plan.start(i_id) < plan.start(j_id):  # every ORDERED same-machine pair
                    total += inst.setup(fam(i_id), fam(j_id))
    return total


def _maintenance_straddle_plan(ir) -> Plan:
    """A complete checker-FEASIBLE-SHAPE plan whose cleanout STRADDLES the Filler-2
    [1200,1440) maintenance window (J1-fill Allergen immediately before J2-fill
    Standard on Filler-2). The checker cites ``R-MAINT`` for the straddle.

    HONESTY (concern-2 fix): on the SOLE demo maintenance window [1200,1440) — which
    sits ENTIRELY in the night band [960,1440) — any straddling cleanout necessarily
    has a NIGHT minute-of-day, so this adversary's UNSAT is OVER-DETERMINED (it trips
    BOTH must-fix #3 AND #6). It therefore does NOT independently isolate #3. The
    INDEPENDENT #3 witness is ``_day_band_straddle_plan`` on a DAY-2 Labeler window
    whose straddling cleanout is DAY-valid (#6 cannot fire). This plan is retained as
    a belt-and-braces R-MAINT adversary, not as the #3 discriminator."""
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
# Day-band straddle: the INDEPENDENT #3 witness (concern-2 fix).               #
#                                                                             #
# The sole demo maintenance window [1200,1440) is entirely at night, so a     #
# straddling cleanout trips #6 too (over-determined). To give must-fix #3     #
# (cleanout-maint-disjointness on `cs`) an INDEPENDENT witness, add a DAY-2   #
# Labeler maintenance window [1840,1940) (minutes 400-500 of day 2). A        #
# cleanout straddling it at minute-of-day 440 is DAY-VALID — so #6 CANNOT     #
# fire and the only rule that excludes the straddle is #3.                    #
# --------------------------------------------------------------------------- #

_DAY2_MAINT = ("Labeler", 1840, 1940)   # minutes 400-500 of day 2


def _day_band_maint_ir(ir):
    """A deep copy of ``ir`` with an ADDED day-band Labeler maintenance window so a
    straddling cleanout can sit at a DAY minute-of-day. The encoding reads
    ``inst.maintenance`` so the extra window is picked up automatically; the demo
    scenario itself is untouched (the copy is test-local)."""
    mod = ir.model_copy(deep=True)
    mod.instance.maintenance = list(mod.instance.maintenance) + [_DAY2_MAINT]
    return mod


def _day_band_assign() -> dict[str, tuple[int, str]]:
    """Shared mix/fill layout for the day-2 fixtures: family-isolated, all well
    before any maintenance window, no cross-family adjacency off the Labeler."""
    return {
        "J1-mix": (0, "Mixer-B"), "J5-mix": (40, "Mixer-B"),
        "J2-mix": (0, "Mixer-A"), "J3-mix": (40, "Mixer-A"),
        "J4-mix": (80, "Mixer-A"), "J6-mix": (120, "Mixer-A"),
        "J1-fill": (100, "Filler-2"), "J5-fill": (130, "Filler-2"),
        "J2-fill": (100, "Filler-1"), "J3-fill": (130, "Filler-1"),
        "J4-fill": (160, "Filler-1"), "J6-fill": (190, "Filler-1"),
    }


def _day_band_straddle_plan(ir) -> Plan:
    """The INDEPENDENT must-fix #3 adversary: a complete checker-FEASIBLE-SHAPE plan
    whose ONLY breach is a materialized cleanout STRADDLING the DAY-2 Labeler window
    [1840,1940). The cleanout [1880,1970) has minute-of-day 1880%1440 = 440, which is
    DAY-VALID (440 >= 0 and 440+90 <= 960) -> the night band (#6) does NOT fire -> the
    checker cites ONLY ``R-MAINT`` and the feasibility-only encoding's UNSAT is
    attributable to #3 ALONE. The sole Labeler setup adjacency is J1(Allergen)->
    J3(Standard); the tail order J3->J4->J2->J6->J5 has no further Allergen->Std/Spicy
    immediate pair (every other consecutive transition is 0-cost)."""
    a = _day_band_assign()
    a["J1-label"] = (1700, "Labeler")   # ends 1810 (before window 1840)
    a["J3-label"] = (1970, "Labeler")   # ends 2060 (after the straddling cleanout)
    a["J4-label"] = (2060, "Labeler")   # Std->Spicy = 0
    a["J2-label"] = (2140, "Labeler")   # Spicy->Std = 0
    a["J6-label"] = (2240, "Labeler")   # Std->Std = 0
    a["J5-label"] = (2310, "Labeler")   # Std->Allergen = 0; J5 last -> no A->Std after it
    cleanouts = [("Labeler", 1880, 1970, "cleanout J1-label->J3-label")]  # straddles [1840,1940)
    return Plan(assignments=a, cleanouts=cleanouts)


def _day_band_control_plan(ir) -> Plan:
    """The POSITIVE CONTROL for the day-2 fixture: the SAME shape as the straddle but
    with the J1->J3 cleanout placed in a clean DAY slot [1610,1700) that does NOT
    overlap the [1840,1940) window. Checker-FEASIBLE -> SAT, proving the day-2 pins
    are admissible (so the straddle's UNSAT is a real #3 exclusion, not a pin
    artefact)."""
    a = _day_band_assign()
    a["J1-label"] = (1500, "Labeler")   # ends 1610
    a["J3-label"] = (1700, "Labeler")   # ends 1790 (before window 1840)
    a["J4-label"] = (1940, "Labeler")   # resumes after the window; ends 2020
    a["J2-label"] = (2020, "Labeler")
    a["J6-label"] = (2120, "Labeler")
    a["J5-label"] = (2190, "Labeler")
    cleanouts = [("Labeler", 1610, 1700, "cleanout J1-label->J3-label")]  # clean DAY slot
    return Plan(assignments=a, cleanouts=cleanouts)


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

    # DISCRIMINATING: read the ENCODING'S `co` expression (Sum(If(adj(i,j,mc), req,
    # 0))) straight out of a Z3 model — NOT a Python recompute. The Labeler order is
    # the 3-chain Allergen(J1)->Standard(J3)->Spicy(J4) then J2(Std), J5(A), J6(Std):
    # its IMMEDIATE adjacencies are J1->J3 (Allergen->Standard=90) and J5->J6
    # (Allergen->Standard=90) — every other consecutive pair is 0 (Std->Spicy,
    # Spicy->Std, Std->Allergen) — for a correct immediate-adjacency cost of 180. An
    # every-ordered-pair over-count would ALSO charge the NON-adjacent
    # Allergen->Standard/Spicy pairs (e.g. J1->J4, J1->J2, J1->J6, J5 vs the earlier
    # Standards), inflating the sum to 450. Because `_changeover_expr_value` evals the
    # very `co` term the cert ships (with its immediate-adjacency `adj` guard), a
    # regression to the every-pair sum WOULD flip this assertion (450 != 180).
    co_from_encoding = verifier._changeover_expr_value(three_chain, ir)
    assert co_from_encoding == _expected_immediate_adjacency_co(ir)   # == total_changeover_time
    over_count = _every_ordered_pair_co(ir, three_chain)  # the regression value the encoding rejects
    assert over_count > co_from_encoding                  # the over-count is STRICTLY larger (450 > 180)
    assert co_from_encoding != over_count                 # the encoding does NOT over-count


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

    # #6 ISOLATION: the night-only adversary's SOLE breach is the night band — it does
    # NOT also trip R-MAINT (its cleanout is on the maintenance-free Labeler), so its
    # UNSAT is attributable to #6 ALONE (not over-determined by a maintenance straddle).
    night_only = _night_only_plan(ir)
    night_viols = {v.rule_id for v in check(night_only, ir).violations}
    assert night_viols == {"R-6.1-NIGHT-CLEANOUT"}       # exactly #6, nothing else


def test_day_band_straddle_independently_isolates_maint_disjointness():
    # CONCERN-2 FIX: the sole demo window [1200,1440) is entirely at night, so a
    # straddling cleanout there trips BOTH #3 and #6 (over-determined) — that adversary
    # cannot independently isolate must-fix #3. This test gives #3 an INDEPENDENT
    # witness: a DAY-2 Labeler window [1840,1940) whose straddling cleanout sits at
    # minute-of-day 440 (DAY-valid). The night band (#6) therefore CANNOT fire, so the
    # checker cites ONLY R-MAINT and the feasibility-only encoding's UNSAT is
    # attributable to the cleanout-maint-disjointness (#3) ALONE.
    ir = _day_band_maint_ir(build_scenario_ir())
    _, verifier = get_domain("manufacturing")

    # POSITIVE CONTROL: the same shape with a CLEAN day cleanout is checker-feasible
    # and pins SAT (the day-2 pins are admissible -> the straddle UNSAT is real).
    control = _day_band_control_plan(ir)
    assert check(control, ir).passed is True
    s_ctrl, _ = verifier._feasibility_only_encode(ir)
    s_ctrl.add(verifier._pin_to_plan(control, ir))
    assert s_ctrl.check() == z3.sat

    # the day-band straddle: checker rejects it for R-MAINT and #6 does NOT fire.
    straddle = _day_band_straddle_plan(ir)
    rejected = check(straddle, ir)
    assert rejected.passed is False
    viol_ids = {v.rule_id for v in rejected.violations}
    assert "R-MAINT" in viol_ids                          # the straddle breaches maintenance
    assert "R-6.1-NIGHT-CLEANOUT" not in viol_ids         # ...and the night band does NOT fire
    assert viol_ids == {"R-MAINT"}                         # R-MAINT is the SOLE breach

    # the feasibility-only encoding EXCLUDES the straddle (UNSAT), and — because #6
    # cannot fire here — this UNSAT is attributable to #3 (the cleanout-maint
    # disjointness on `cs`) ALONE. A discrimination probe (scratchpad) confirms that
    # dropping ONLY the #3 assertion flips this same pin to SAT.
    s_feas, _ = verifier._feasibility_only_encode(ir)
    s_feas.add(verifier._pin_to_plan(straddle, ir))
    assert s_feas.check() == z3.unsat
