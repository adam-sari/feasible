"""Solve orchestration + independent objective/KPI recompute.

``solve`` performs the staged lexicographic optimization and extracts a plan.
The objective/KPI helpers re-derive the metrics directly FROM THE PLAN (code
path disjoint from the compiler), so the certificate's ``objective_recompute``
claim is independent of the solver's internal accounting. They are the single
source of truth (re-exported by the scenario package).
"""
from __future__ import annotations

from ortools.sat.python import cp_model
from pydantic import BaseModel

from feasible.compile.cpsat import build_model, extract_plan, freeze_l1_and_minimize_changeover
from feasible.checker.checker import machine_sequence
from feasible.ir.domain import FCIR, Plan


class SolveResult(BaseModel):
    plan: Plan | None
    status: str
    objective: tuple[int, int] | None  # (weighted_tardiness, total_changeover)
    gap: float | None


def _family(ir: FCIR, op_id: str) -> str:
    op = ir.instance.operation(op_id)
    return ir.instance.job(op.job_id).family


def _completion(ir: FCIR, plan: Plan, job_id: str) -> int:
    ends = [
        plan.start(o.op_id) + o.duration
        for o in ir.instance.operations
        if o.job_id == job_id and o.op_id in plan.assignments
    ]
    return max(ends) if ends else 0


def weighted_tardiness(ir: FCIR, plan: Plan) -> int:
    total = 0
    for job in ir.instance.jobs:
        tard = max(0, _completion(ir, plan, job.id) - job.due_date)
        total += (4 - job.priority) * tard
    return total


def late_priority_orders(ir: FCIR, plan: Plan) -> int:
    return sum(
        1 for job in ir.instance.jobs if _completion(ir, plan, job.id) > job.due_date
    )


def total_changeover_time(ir: FCIR, plan: Plan) -> int:
    total = 0
    for mc in ir.instance.machines:
        seq = machine_sequence(plan, mc)
        for i_id, j_id in zip(seq, seq[1:]):
            total += ir.instance.setup(_family(ir, i_id), _family(ir, j_id))
    return total


def recompute_objective(ir: FCIR, plan: Plan) -> tuple[int, int]:
    """The canonical integer objective tuple recomputed from the plan."""
    return (weighted_tardiness(ir, plan), total_changeover_time(ir, plan))


def solve(ir: FCIR, max_seconds: float = 30.0) -> SolveResult:
    m, vi = build_model(ir)
    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = max_seconds
    status = freeze_l1_and_minimize_changeover(m, solver, vi)
    status_name = solver.status_name(status)
    if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        return SolveResult(plan=None, status=status_name, objective=None, gap=None)
    plan = extract_plan(solver, vi)
    objective = recompute_objective(ir, plan)
    gap = 0.0 if status == cp_model.OPTIMAL else None
    return SolveResult(plan=plan, status=status_name, objective=objective, gap=gap)
