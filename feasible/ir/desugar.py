"""Desugar the FJSP domain layer into the wedge-agnostic kernel.

A structural projection: routing -> Precedence, per-machine -> NoOverlap, due
dates -> SoftPenalty(tardiness). The CP-SAT compiler and the checker read the
FCIR directly; this projection makes the two-tier design explicit and testable.
Tardiness weight = (4 - priority) so priority-1 jobs weigh most.
"""
from __future__ import annotations

from feasible.ir.domain import FCIR
from feasible.ir.kernel import Interval, KernelModel, NoOverlap, Precedence, SoftPenalty


def tardiness_weight(priority: int) -> int:
    return 4 - priority


def desugar(ir: FCIR) -> KernelModel:
    inst = ir.instance

    intervals = [
        Interval(
            op_id=o.op_id,
            machine=o.eligible_machines[0] if o.eligible_machines else "",
            duration=o.duration,
        )
        for o in inst.operations
    ]

    precedences: list[Precedence] = []
    by_job: dict[str, list] = {}
    for o in inst.operations:
        by_job.setdefault(o.job_id, []).append(o)
    for ops in by_job.values():
        ordered = sorted(ops, key=lambda o: o.seq)
        for a, b in zip(ordered, ordered[1:]):
            precedences.append(Precedence(before_op=a.op_id, after_op=b.op_id, gap=0))

    no_overlaps = [
        NoOverlap(
            machine=m,
            interval_ids=[o.op_id for o in inst.operations if m in o.eligible_machines],
        )
        for m in inst.machines
    ]

    soft_penalties = [
        SoftPenalty(term=f"tardiness_{j.id}", weight=tardiness_weight(j.priority))
        for j in inst.jobs
    ]

    return KernelModel(
        intervals=intervals,
        no_overlaps=no_overlaps,
        precedences=precedences,
        soft_penalties=soft_penalties,
    )
