"""Same-engine optimality tripwire.

Re-solves the CP-SAT model forbidding any plan STRICTLY better than the achieved
objective ``V = (weighted_tardiness, total_changeover)`` (lexicographic), with no
objective. INFEASIBLE => nothing beats V => the headline optimum is corroborated.
Labelled honestly as a SAME-ENGINE tripwire (it defends optimal-but-wrong /
wrong-bound, not the false-INFEASIBLE class); the genuinely independent backing
(a different solver) is a post-v1.1 roadmap item.
"""
from __future__ import annotations

from ortools.sat.python import cp_model

from feasible.compile.cpsat import build_model
from feasible.ir.domain import FCIR


def optimality_tripwire(ir: FCIR, V: tuple[int, int], max_seconds: float = 20.0) -> bool:
    """True iff no feasible plan is lexicographically better than V."""
    m, vi = build_model(ir)
    v0, v1 = V
    better_l1 = m.new_bool_var("better_l1")
    better_l2 = m.new_bool_var("better_l2")
    # better_l1 => weighted_tardiness < v0
    m.add(vi.weighted_tardiness < v0).only_enforce_if(better_l1)
    # better_l2 => weighted_tardiness == v0 AND total_changeover < v1
    m.add(vi.weighted_tardiness == v0).only_enforce_if(better_l2)
    m.add(vi.total_changeover < v1).only_enforce_if(better_l2)
    m.add_bool_or([better_l1, better_l2])  # require some strict improvement
    # no objective — pure feasibility of "exists a strictly-better plan"
    solver = cp_model.CpSolver()
    solver.parameters.num_search_workers = 1
    solver.parameters.max_time_in_seconds = max_seconds
    status = solver.solve(m)
    return status == cp_model.INFEASIBLE
