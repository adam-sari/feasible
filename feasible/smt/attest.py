"""Independent Z3 feasibility attestation of a final plan + UNSAT core.

A SEPARATE arithmetic encoding (Z3) of the SAME hard predicates the polynomial
checker evaluates — reconstructing the per-machine sequence solely from start
times, re-deriving setup obligations from the setup matrix, never importing
CP-SAT arc literals. Independence is at the code level (Z3 vs Python); it is
correlated with the checker on setup attribution, so golden fixtures + the spike
property test are the real guard there.

Z3 is a feasibility attestor ONLY — it never bounds optimality. An UNSAT core
is NOT globally minimal and NOT a proof object; ``minimization_status`` records
this honestly (``feasible`` is the SAT-path sentinel).
"""
from __future__ import annotations

import z3
from pydantic import BaseModel, Field

from feasible.checker.checker import DAY_DEFAULT, machine_sequence
from feasible.checker.plan_shape import validate_plan_shape
from feasible.ir.domain import FCIR, Plan
from feasible.registry import unsupported_hard_rules


class AttestResult(BaseModel):
    feasible: bool
    unsat_core: list[str] = Field(default_factory=list)
    minimization_status: str = "feasible"  # feasible | not_minimized | locally_minimized


def _family(ir: FCIR, op_id: str) -> str:
    op = ir.instance.operation(op_id)
    return ir.instance.job(op.job_id).family


def attest_feasibility(plan: Plan, ir: FCIR) -> AttestResult:
    inst = ir.instance

    # Mirror the checker's structural + fail-closed registry gate so the pair agrees
    # on malformed / unsupported plans (and so the Z3 encoding never sees a ghost op).
    gate = [f"R-PLAN-SHAPE:{v.counter_witness['predicate']}" for v in validate_plan_shape(plan, ir)]
    gate += [f"R-UNSUPPORTED-RULE:{r.rule_id}" for r in unsupported_hard_rules(ir)]
    if gate:
        return AttestResult(feasible=False, unsat_core=gate, minimization_status="not_minimized")

    s = z3.Solver()
    s.set(unsat_core=True)

    # pin op starts/ends and cleanout intervals to the concrete plan
    start = {op.op_id: z3.Int(f"start_{op.op_id}") for op in inst.operations}
    end = {op.op_id: z3.Int(f"end_{op.op_id}") for op in inst.operations}
    for op in inst.operations:
        if op.op_id in plan.assignments:
            s.add(start[op.op_id] == plan.start(op.op_id))
            s.add(end[op.op_id] == plan.start(op.op_id) + op.duration)

    cs_vars = [z3.Int(f"cs_{k}") for k in range(len(plan.cleanouts))]
    ce_vars = [z3.Int(f"ce_{k}") for k in range(len(plan.cleanouts))]
    for k, (mc, cs, ce, _r) in enumerate(plan.cleanouts):
        s.add(cs_vars[k] == cs)
        s.add(ce_vars[k] == ce)

    def track(name: str, expr) -> None:
        s.assert_and_track(expr, name)

    # R-ROUTING: ops of a job in seq order
    if ir.has_active("R-ROUTING"):
        by_job: dict[str, list] = {}
        for o in inst.operations:
            by_job.setdefault(o.job_id, []).append(o)
        for ops_j in by_job.values():
            ordered = sorted(ops_j, key=lambda o: o.seq)
            for a, b in zip(ordered, ordered[1:]):
                if a.op_id in plan.assignments and b.op_id in plan.assignments:
                    track(f"R-ROUTING:{a.op_id}->{b.op_id}", start[b.op_id] >= end[a.op_id])

    # R-NOOVERLAP: ops + cleanouts on a machine pairwise disjoint
    if ir.has_active("R-NOOVERLAP"):
        for mc in inst.machines:
            blocks: list[tuple] = []
            for op in inst.operations:
                if op.op_id in plan.assignments and plan.machine(op.op_id) == mc:
                    blocks.append((start[op.op_id], end[op.op_id], op.op_id))
            for k, (cm, cs, ce, _r) in enumerate(plan.cleanouts):
                if cm == mc:
                    blocks.append((cs_vars[k], ce_vars[k], f"cleanout{k}"))
            for a in range(len(blocks)):
                for b in range(a + 1, len(blocks)):
                    xa, ya, na = blocks[a]
                    xb, yb, nb = blocks[b]
                    track(f"R-NOOVERLAP:{mc}:{na}|{nb}", z3.Or(ya <= xb, yb <= xa))

    # R-SETUP: a sufficient cleanout exists between each allergen->non-allergen pair
    if ir.has_active("R-SETUP"):
        for mc in inst.machines:
            seq = machine_sequence(plan, mc, ir)
            for i_id, j_id in zip(seq, seq[1:]):
                req = inst.setup(_family(ir, i_id), _family(ir, j_id))
                if req <= 0:
                    continue
                disj = []
                for k, (cm, cs, ce, _r) in enumerate(plan.cleanouts):
                    if cm == mc:
                        disj.append(z3.And(cs_vars[k] >= end[i_id], ce_vars[k] <= start[j_id], ce_vars[k] - cs_vars[k] >= req))
                track(f"R-SETUP:{mc}:{i_id}->{j_id}", z3.Or(*disj) if disj else z3.BoolVal(False))

    # R-MAINT
    if ir.has_active("R-MAINT"):
        for w, (mc, mstart, mend) in enumerate(inst.maintenance):
            for op in inst.operations:
                if op.op_id in plan.assignments and plan.machine(op.op_id) == mc:
                    track(f"R-MAINT:{mc}:{op.op_id}:{w}", z3.Or(end[op.op_id] <= mstart, start[op.op_id] >= mend))
            for k, (cm, cs, ce, _r) in enumerate(plan.cleanouts):
                if cm == mc:
                    track(f"R-MAINT:{mc}:cleanout{k}:{w}", z3.Or(ce_vars[k] <= mstart, cs_vars[k] >= mend))

    # R-6.1-NIGHT-CLEANOUT: each cleanout fully inside a day window
    night_rule = ir.rule("R-6.1-NIGHT-CLEANOUT")
    if ir.has_active("R-6.1-NIGHT-CLEANOUT"):
        p = {**DAY_DEFAULT, **(night_rule.params if night_rule else {})}
        for k, (mc, cs, ce, _r) in enumerate(plan.cleanouts):
            mod = cs_vars[k] % 1440
            track(
                f"R-6.1-NIGHT-CLEANOUT:cleanout{k}",
                z3.And(mod >= p["day_start"], mod + (ce - cs) <= p["day_end"]),
            )

    result = s.check()
    if result == z3.sat:
        return AttestResult(feasible=True, unsat_core=[], minimization_status="feasible")
    core = [str(c) for c in s.unsat_core()]
    return AttestResult(feasible=False, unsat_core=core, minimization_status="not_minimized")
