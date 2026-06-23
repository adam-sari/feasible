"""T1.3 — datacenter FREE-search Z3 independent-optimality.

The HEADLINE upgrade: the datacenter same-engine ``optimality_tripwire`` OPTS OUT
(returns ``False`` — no optimality backing at all). A disjoint Z3 free-search
``(stranded, makespan)`` strict-improvement encoding now gives REAL independent
optimality — a genuine upgrade from "no optimality backing" to "corroborated by a
disjoint engine."

Two halves (mirroring T1.2):

1. PARITY / UPGRADE — where ``optimality_tripwire`` returns ``False``, Z3 (a
   DIFFERENT engine than CP-SAT) returns ``corroborated`` on the golden optimum, and
   refutes a one-worse makespan claim (the strict-improvement disjunction is wired
   right).

2. REGION-CORRESPONDENCE (must-fix #4) — the MODEL-INDEPENDENT gate that wires
   ``feasible.checker.checker.check`` (-> ``DatacenterVerifier.check_predicates``) as
   the oracle. It proves the Z3 feasible REGION corresponds to the closed checker's
   region (not larger, not too tight):
     (a) NOT-LARGER  — SAMPLE decoded SAT witnesses -> checker.check().passed
         (RC-2: a SAMPLE over a large witness space, NOT exhaustive containment);
     (b) NOT-TOO-TIGHT — the optimum is in-region;
     (c) EXCLUDES-CHECKER-INFEASIBLE — pin CONSTRUCTED checker-REJECTED adversaries
         (a maintenance-window straddle -> dc:maintenance_window; a redundancy-floor
         breach -> dc:redundancy_floor) to the FEASIBILITY-ONLY layer (RC-1, no
         objective confound) -> UNSAT on the specific breached rule_id, PLUS a
         POSITIVE CONTROL (known-feasible plan -> SAT) so the test cannot pass
         vacuously.
"""
from __future__ import annotations

import z3

from feasible.checker.checker import check
from feasible.conflict.policy import DATACENTER_POLICY
from feasible.domains import get_domain
from feasible.domains.datacenter.scenario import build_dc_extracted_pack
from feasible.domains.datacenter.solve import dc_solve
from feasible.govern.pipeline import govern_pack
from feasible.ir.domain import Plan
from feasible.solve.independent_optimality import Verdict, independent_optimality_check


def _active_ir():
    return govern_pack(build_dc_extracted_pack(), DATACENTER_POLICY).active_ir


# --------------------------------------------------------------------------- #
# Parity / the genuine upgrade (load-bearing).                                 #
# --------------------------------------------------------------------------- #


def test_dc_z3_corroborates_the_optimum():
    ir = _active_ir()
    res = dc_solve(ir, workers=1, seed=1)
    V = res.objective                       # the golden optimum, == (0, 4)
    # the same-engine tripwire OPTS OUT (returns False) -> no backing today; Z3 gives REAL backing.
    _, verifier = get_domain("datacenter")
    assert verifier.optimality_tripwire(ir, V) is False
    assert independent_optimality_check(ir, V) is Verdict.corroborated   # disjoint engine: real backing


def test_dc_z3_refutes_a_one_better_makespan_claim():
    ir = _active_ir()
    res = dc_solve(ir, workers=1, seed=1)
    stranded, makespan = res.objective
    # claim the makespan is one worse than optimum -> the true optimum strictly beats it -> SAT -> refuted
    assert independent_optimality_check(ir, (stranded, makespan + 1)) is Verdict.refuted


# --------------------------------------------------------------------------- #
# Region-correspondence test fixtures (constructed adversaries).               #
# --------------------------------------------------------------------------- #


def _window_straddle_plan(ir) -> Plan:
    """A complete checker-FEASIBLE-SHAPE plan whose ONLY breach is the maintenance
    task T1 (path F1) running INSIDE the forbidden change-freeze window [0,2) on F1.
    T1 at [0,2) overlaps [0,2) -> the checker cites ``dc:maintenance_window``. T2 sits
    trivially clear at [0,1) on F4."""
    return Plan(assignments={"task:T1": (0, "F1"), "task:T2": (0, "F4")}, cleanouts=[])


def _floor_breach_plan(ir) -> Plan:
    """A complete checker-FEASIBLE-SHAPE plan whose ONLY breach is the redundancy
    floor: T1 (unit F1) runs over [6,8) where F3 is FIXED-down [6,8), so group G1
    (units F1,F2,F3; floor 2) has only F2 available (1 < 2) at t=6,7 -> the checker
    cites ``dc:redundancy_floor``. T1 at [6,8) does NOT overlap the forbidden window
    [0,2), so the maintenance-window rule does NOT fire (the breach is isolated to the
    floor)."""
    return Plan(assignments={"task:T1": (6, "F1"), "task:T2": (0, "F4")}, cleanouts=[])


def _dc_constructed_infeasible_plans(ir):
    """Yield ``(plan, rule_id)`` for the two CHECKER-REJECTED adversaries whose Z3
    witnesses must be EXCLUDED by the feasibility-only layer."""
    return [
        (_window_straddle_plan(ir), "dc:maintenance_window"),
        (_floor_breach_plan(ir), "dc:redundancy_floor"),
    ]


# --------------------------------------------------------------------------- #
# (a) NOT-LARGER — sampled decoded witnesses are checker-feasible (RC-2).      #
# --------------------------------------------------------------------------- #


def test_dc_every_z3_sat_witness_decodes_to_a_checker_passing_plan():
    ir = _active_ir()
    res = dc_solve(ir, workers=1, seed=1)
    stranded, makespan = res.objective
    _, verifier = get_domain("datacenter")
    s = verifier.independent_optimality_encode(ir, (stranded, makespan + 1))
    assert s is not None
    seen = 0
    while s.check() == z3.sat and seen < 20:                  # SAMPLE <=20 witnesses (not exhaustive)
        m = s.model()
        plan = verifier._decode_witness(m, ir)
        assert check(plan, ir).passed is True
        seen += 1
        s.add(verifier._block_model(m))
    assert seen >= 1


# --------------------------------------------------------------------------- #
# (b) NOT-TOO-TIGHT — the optimum is in-region.                               #
# --------------------------------------------------------------------------- #


def test_dc_achieved_optimum_is_in_region():
    ir = _active_ir()
    res = dc_solve(ir, workers=1, seed=1)
    stranded, makespan = res.objective
    _, verifier = get_domain("datacenter")
    s = verifier.independent_optimality_encode(ir, (stranded, makespan + 1))
    assert s is not None
    assert s.check() == z3.sat


# --------------------------------------------------------------------------- #
# (c) EXCLUDES-CHECKER-INFEASIBLE — feasibility-only layer + positive control. #
# --------------------------------------------------------------------------- #


def test_dc_encoding_excludes_a_constructed_infeasible_plan():
    ir = _active_ir()
    _, verifier = get_domain("datacenter")

    # POSITIVE CONTROL (mandatory): pin the KNOWN checker-FEASIBLE optimum to the
    # feasibility-only layer and assert SAT — without it, an over-constraining
    # `_pin_to_plan` would make EVERY pin UNSAT and test (c) would pass VACUOUSLY.
    res = dc_solve(ir, workers=1, seed=1)
    good_plan = res.plan
    assert check(good_plan, ir).passed is True
    s_ctrl, _ = verifier._feasibility_only_encode(ir)
    s_ctrl.add(verifier._pin_to_plan(good_plan, ir))
    assert s_ctrl.check() == z3.sat                           # the feasible optimum IS pin-admissible

    for bad_plan, rule_id in _dc_constructed_infeasible_plans(ir):   # window-straddle / floor-breach
        rejected = check(bad_plan, ir)
        assert rejected.passed is False
        # RC-5/F2: the rejection must cite the SPECIFIC rule_id (a window straddle ->
        # dc:maintenance_window; a floor breach -> dc:redundancy_floor), so a plan
        # rejected for the wrong reason cannot pose as the adversary.
        assert any(v.rule_id == rule_id for v in rejected.violations)
        s_feas, _ = verifier._feasibility_only_encode(ir)    # FEASIBILITY-ONLY layer (no objective)
        s_feas.add(verifier._pin_to_plan(bad_plan, ir))
        assert s_feas.check() == z3.unsat
