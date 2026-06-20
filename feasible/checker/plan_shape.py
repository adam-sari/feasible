"""Structural plan well-formedness (R-PLAN-SHAPE) — runs alongside rule checks.

A plan that is structurally malformed (missing/unknown op, ineligible machine,
out-of-horizon, bad cleanout) cannot be meaningfully certified. Each failed
predicate is one Violation with ``span=None`` and a ``counter_witness`` whose
``predicate`` token is pinned (so the checker and the Z3 attestor agree on the
encoding). An orphan/extra cleanout is NOT a malformation — it is rule-checkable
(R-6.1 catches a night one, R-SETUP a missing one).
"""
from __future__ import annotations

from feasible.checker.result import Violation
from feasible.ir.domain import FCIR, Plan

RULE_ID = "R-PLAN-SHAPE"


def _v(predicate: str, message: str, **witness) -> Violation:
    return Violation(rule_id=RULE_ID, span=None, message=message,
                     counter_witness={"predicate": predicate, **witness})


def validate_plan_shape(plan: Plan, ir: FCIR) -> list[Violation]:
    inst = ir.instance
    known_ops = {o.op_id for o in inst.operations}
    known_machines = set(inst.machines)
    out: list[Violation] = []

    # every instance op appears exactly once; no unknown ops
    for op in inst.operations:
        if op.op_id not in plan.assignments:
            out.append(_v("missing_op", f"operation {op.op_id} is not in the plan", op=op.op_id))
    for op_id in plan.assignments:
        if op_id not in known_ops:
            out.append(_v("unknown_op", f"plan assigns an unknown operation {op_id}", op=op_id))

    # per-op: eligible machine, non-negative start, end within horizon
    for op in inst.operations:
        if op.op_id not in plan.assignments:
            continue
        start, machine = plan.assignments[op.op_id]
        if machine not in op.eligible_machines:
            out.append(_v("ineligible_machine",
                          f"{op.op_id} assigned to ineligible machine {machine}",
                          op=op.op_id, machine=machine, eligible=op.eligible_machines))
        if not isinstance(start, int) or start < 0:
            out.append(_v("negative_start", f"{op.op_id} has start {start!r} < 0", op=op.op_id, start=start))
        elif start + op.duration > inst.horizon:
            out.append(_v("end_over_horizon",
                          f"{op.op_id} ends at {start + op.duration} > horizon {inst.horizon}",
                          op=op.op_id, end=start + op.duration, horizon=inst.horizon))

    # cleanouts: known machine, positive duration, in horizon, non-empty reason
    for k, (mc, cs, ce, reason) in enumerate(plan.cleanouts):
        if mc not in known_machines:
            out.append(_v("cleanout_unknown_machine", f"cleanout {k} on unknown machine {mc}", index=k, machine=mc))
        if ce <= cs:
            out.append(_v("cleanout_nonpositive_duration",
                          f"cleanout {k} has non-positive duration [{cs},{ce})", index=k, start=cs, end=ce))
        if cs < 0 or ce > inst.horizon:
            out.append(_v("cleanout_out_of_horizon",
                          f"cleanout {k} [{cs},{ce}) is outside [0,{inst.horizon})", index=k, start=cs, end=ce))
        if not str(reason).strip():
            out.append(_v("cleanout_empty_reason", f"cleanout {k} has an empty reason", index=k))

    return out
