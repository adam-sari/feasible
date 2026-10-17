"""The datacenter solve path (Task 7) — CP-SAT staged lexicographic search.

``dc_solve`` builds the datacenter CP-SAT model via ``DatacenterVerifier.compile``
(the SINGLE CP-SAT source the dc solve path uses — code-disjoint from the checker),
runs the STAGED lexicographic search (minimize stranded power, freeze it as a hard
bound, then minimize makespan), extracts a byte-deterministic ``Plan`` via
``dc_extract_plan``, and sets ``result.objective = verifier.objective(ir, plan)`` —
the REAL ``(stranded_power_kw, makespan)`` tuple recomputed SOLVER-FREE from the
extracted plan + instance (NO FJSP ``recompute_objective``, NO objective-slot
encoding). ``verify_plan_cert`` recomputes the SAME via the Spec 0.5
``verifier.objective`` seam (Spec 0.5 T1) -> equal by construction.

The stranded-power / makespan recompute is the SAME helper (``verifier.stranded_power``
/ ``verifier.maintenance_makespan`` via ``verifier.objective`` -> ``dc_objective``)
that ``kpi.py`` (Task 8) reuses, so the signed objective leaf and the KPI surface
agree.

B-11 (determinism precondition for the Task-12 golden): ``dc_extract_plan`` is
byte-deterministic — ``dc_solve(workers=1, seed=1)`` twice yields byte-equal plans.
Single-worker + seeded + sorted extraction pins extraction byte-stability.
"""
from __future__ import annotations

from ortools.sat.cp_model_pb2 import CpSolverStatus
from ortools.sat.python import cp_model

from feasible.domains import get_domain
from feasible.domains.datacenter.verifier import DcVarIndex, _dc_build_model
from feasible.ir.domain import FCIR, Plan
from feasible.solve.orchestrate import SolveResult


def _stage_solve(
    m: cp_model.CpModel, solver: cp_model.CpSolver, vi: DcVarIndex
) -> CpSolverStatus:
    """Staged lexicographic solve: minimize stranded power, freeze it as a hard
    bound, then minimize makespan. Returns the final CP-SAT status."""
    assert vi.stranded is not None and vi.makespan is not None
    m.minimize(vi.stranded)
    status1 = solver.solve(m)
    if status1 not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        return status1
    best_stranded = int(solver.value(vi.stranded))
    m.add(vi.stranded == best_stranded)  # freeze level 1
    m.minimize(vi.makespan)  # replaces the objective
    return solver.solve(m)


def dc_extract_plan(solver: cp_model.CpSolver, vi: DcVarIndex) -> Plan:
    """Read the solved maintenance-task starts into a frozen ``Plan`` DETERMINISTICALLY.

    Every instance op is a ``task:<id>`` maintenance task on its path machine; its
    start is the solved schedulable decision. Assignments are built in SORTED op_id
    order (a dict preserves insertion order; byte-stability comes from sorting) so the
    extraction is byte-deterministic (B-11). No cleanouts (the full-facility outage
    mechanism is the task ops themselves, not plan_outage cleanouts)."""
    assert vi.ir is not None
    assignments: dict[str, tuple[int, str]] = {}
    for op in sorted(vi.ir.instance.operations, key=lambda o: o.op_id):
        start = int(solver.value(vi.task_start[op.op_id]))
        assignments[op.op_id] = (start, vi.task_path[op.op_id])
    return Plan(assignments=assignments, cleanouts=[])


def dc_degenerate_solve(
    ir: FCIR, max_seconds: float = 30.0, *, workers: int = 1, seed: int = 1
) -> Plan:
    """The DOCUMENTED degenerate-objective solve that produces the HERO gotcha
    incumbent (B-2: ``dc_incumbent_a``) — an EMERGENT N+1 breach, NOT a hand-planted
    floor cleanout.

    It routes through the SAME ``DatacenterVerifier.compile`` (the single CP-SAT
    source) but with ``relax_redundancy=True`` (the per-timestep ``avail >= floor``
    HARD constraint is DROPPED), then replaces the staged ``(stranded, makespan)``
    objective with a DEGENERATE one: **MAXIMIZE the sum of maintenance-task starts** —
    i.e. "defer all preventive maintenance to the end of the horizon to consolidate
    downtime into the already-planned outage window." This is a realistic-sounding but
    degenerate operator heuristic. With the floor relaxed, the F1 cooling-path task is
    pushed to the latest legal start, landing it ON TOP of the fixed F3 outage window —
    so a floored group drops below N+1 at a specific timestep as an EMERGENT consequence
    of that objective (the planner walks straight into the floor breach the certificate
    catches). The maintenance-window constraint is STILL enforced (the degenerate plan
    is otherwise well-formed), only the redundancy floor is relaxed.

    Single-worker + seeded + sorted extraction → byte-deterministic (B-11), so
    ``dc_incumbent_a`` is a stable fixed plan reproducible by the gotcha test calling
    THIS helper (it is NOT a literal hand-built Plan).

    Builds via the module-level ``_dc_build_model`` (the SAME builder
    ``DatacenterVerifier.compile`` delegates to) directly — the degenerate
    ``relax_redundancy=True`` build is an INTERNAL datacenter helper off the certify
    path (the frozen ``DomainVerifier.compile`` Protocol seam takes no such flag), not a
    widening of the cross-domain seam."""
    m, vi = _dc_build_model(ir, relax_redundancy=True)
    # replace the staged objective with the degenerate "defer maintenance to end of
    # horizon" objective: maximize sum of task starts. The floor being relaxed lets the
    # F1 task slide onto the F3 outage window -> the emergent buffer-spend.
    if vi.task_start:
        m.maximize(sum(vi.task_start.values()))
    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = max_seconds
    solver.parameters.num_search_workers = workers
    solver.parameters.random_seed = seed
    status = solver.solve(m)
    if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        raise RuntimeError(f"degenerate solve produced no plan: status={solver.status_name(status)}")
    return dc_extract_plan(solver, vi)


def dc_solve(
    ir: FCIR, max_seconds: float = 30.0, *, workers: int = 1, seed: int = 1
) -> SolveResult:
    """Solve the datacenter active set ``ir`` for the certified plan.

    Builds the model via the verifier's ``compile`` (the single CP-SAT source),
    runs the staged lexicographic search, extracts a byte-deterministic plan, and
    sets ``result.objective = verifier.objective(ir, plan)`` (the REAL
    ``(stranded_power_kw, makespan)`` tuple, recomputed solver-free). Single-worker
    + seeded by default so extraction is byte-stable (B-11)."""
    _, verifier = get_domain("datacenter")
    m, vi = verifier.compile(ir, None)
    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = max_seconds
    solver.parameters.num_search_workers = workers
    solver.parameters.random_seed = seed
    status = _stage_solve(m, solver, vi)
    status_name = solver.status_name(status)
    if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        return SolveResult(plan=None, status=status_name, objective=None, gap=None)
    plan = dc_extract_plan(solver, vi)
    # the REAL objective, recomputed SOLVER-FREE via the Spec 0.5 objective seam.
    objective = verifier.objective(ir, plan)
    gap = 0.0 if status == cp_model.OPTIMAL else None
    return SolveResult(plan=plan, status=status_name, objective=objective, gap=gap)
