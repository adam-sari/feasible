"""Shared CP-SAT feasibility helpers for the cross-validation suite."""
from __future__ import annotations

from ortools.sat.python import cp_model

from feasible.compile.cpsat import build_model
from feasible.ir.domain import FCIR, Plan


def cpsat_feasible(ir: FCIR, max_seconds: float = 10.0) -> bool:
    """Existence query: is the compiled model satisfiable at all?"""
    m, _vi = build_model(ir)
    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = max_seconds
    return solver.solve(m) in (cp_model.OPTIMAL, cp_model.FEASIBLE)


def cpsat_feasible_with_plan(ir: FCIR, plan: Plan, max_seconds: float = 10.0) -> bool:
    """Pin the plan's op starts + machine choices; is the model still feasible?"""
    m, vi = build_model(ir)
    for op_id, (st, mc) in plan.assignments.items():
        if op_id in vi.starts:
            m.add(vi.starts[op_id] == st)
        if (op_id, mc) in vi.machine_presence:
            m.add(vi.machine_presence[(op_id, mc)] == 1)
    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = max_seconds
    return solver.solve(m) in (cp_model.OPTIMAL, cp_model.FEASIBLE)
