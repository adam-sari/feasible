"""Task 7: CP-SAT compile + dc solve path + REAL signed objective via the Spec 0.5
``verifier.objective`` seam + extraction determinism.

The datacenter solve path is CODE-DISJOINT from the checker: ``DatacenterVerifier.compile``
builds a ``cp_model.CpModel`` scheduling each maintenance task's start over the time
grid subject to (a) the forbidden ``dc:maintenance_window`` intervals on its path,
(b) the per-timestep ``dc:redundancy_floor`` aggregation (a task derating a unit), and
(c) the STRUCTURAL ``dc:power_cap``/``dc:anti_affinity`` invariants as fixed
feasibility checks. ``dc_solve`` runs the STAGED lexicographic search (minimize
stranded power, freeze, minimize makespan), then ``dc_extract_plan`` reads the model
vars into a frozen ``Plan`` DETERMINISTICALLY (sorted; single-worker, seeded). Finally
``dc_solve`` sets ``result.objective = verifier.objective(ir, plan)`` — the REAL
``(stranded_power_kw, makespan)`` tuple recomputed SOLVER-FREE from the extracted plan
+ instance — and ``verify`` recomputes the SAME via the seam (equal by construction,
NO ``recompute_objective``, NO objective-slot encoding). B-11: extraction is
byte-deterministic (the Task-12 golden precondition).
"""
from __future__ import annotations

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
from feasible.checker.checker import check
from feasible.domains import get_domain
from feasible.domains.datacenter.instance import pack_dc_instance
from feasible.domains.datacenter.scenario import build_dc_scenario_dc_instance
from feasible.domains.datacenter.solve import dc_solve
from feasible.ir.domain import CompileMode, FCIR, Severity
from feasible.smt.attest import attest_feasibility


def _dc_active_ir() -> FCIR:
    """The synthetic active set: the Task-1 scenario facility, packed into the frozen
    ``Instance``/``Plan`` shape, with the PLAN-DEPENDENT ``dc:maintenance_window``
    promoted to HARD/PLAN_CONSTRAINT (active) so the solver respects the forbidden
    windows. ``dc:redundancy_floor`` is already HARD/PLAN_CONSTRAINT; the STRUCTURAL
    ``dc:power_cap``/``dc:anti_affinity`` stay instance invariants. Task 8 produces
    this active set through the real governance pipeline; Task 7 promotes inline."""
    dc = build_dc_scenario_dc_instance()
    inst, rules = pack_dc_instance(dc)
    for r in rules:
        if r.rule_id == "dc:maintenance_window":
            r.severity = Severity.HARD
            r.compile_mode = CompileMode.PLAN_CONSTRAINT
    return FCIR(rules=rules, instance=inst, domain_id="datacenter")


def test_dc_solve_objective_is_real_and_seam_recomputes():
    ir = _dc_active_ir()  # the synthetic active set
    res = dc_solve(ir, workers=1, seed=1)
    assert res.plan is not None and res.status in ("OPTIMAL", "FEASIBLE")
    _, verifier = get_domain("datacenter")
    # the REAL (stranded_power_kw, makespan) tuple; verify recomputes via THIS seam (Spec 0.5 T1)
    assert tuple(res.objective) == verifier.objective(ir, res.plan)
    assert len(res.objective) == 2 and verifier.objective_labels == ("stranded_power_kw", "makespan")


def test_dc_solved_plan_passes_checker_and_z3():
    ir = _dc_active_ir()
    res = dc_solve(ir, workers=1, seed=1)
    assert check(res.plan, ir).passed
    assert attest_feasibility(res.plan, ir).feasible


def test_dc_extraction_is_byte_deterministic():  # B-11 precondition for the golden
    ir = _dc_active_ir()
    a = dc_solve(ir, workers=1, seed=1).plan
    b = dc_solve(ir, workers=1, seed=1).plan
    assert a.model_dump(mode="json") == b.model_dump(mode="json")


def test_dc_solved_plan_stranded_is_zero_floor_held():
    """The redundancy floor is a HARD plan constraint, so a feasible solve holds the
    floor everywhere -> stranded_power_kw == 0 (no buffer spent). The makespan is the
    last maintenance-task end (a positive integer; tasks must be scheduled)."""
    ir = _dc_active_ir()
    res = dc_solve(ir, workers=1, seed=1)
    stranded, makespan = res.objective
    assert stranded == 0          # floor held -> no redundancy shortfall
    assert makespan >= 1          # at least one task scheduled (T1 dur 2, T2 dur 1)


def test_dc_objective_generalized_to_full_facility():
    """The objective seam is generalized from the Task-0 single-group spike to the full
    facility: stranded power sums the redundancy shortfall over EVERY active group +
    timestep, and makespan is the last maintenance-TASK end (the task-outage mechanism,
    not just plan_outage cleanouts)."""
    ir = _dc_active_ir()
    res = dc_solve(ir, workers=1, seed=1)
    _, verifier = get_domain("datacenter")
    # re-derive solver-free over the extracted plan -> identical to the solver-reported tuple
    assert verifier.objective(ir, res.plan) == tuple(res.objective)
