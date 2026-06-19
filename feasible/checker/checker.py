"""The polynomial plan checker — total, in P, CODE-DISJOINT from the compiler.

Evaluates every hard ``PLAN_CONSTRAINT`` as a CLOSED predicate over a concrete
plan (start times + machine assignments + materialized cleanouts). No search,
no timeouts — always a concrete yes/no with the offending op and the source
span. Permissions / CONFLICT_ONLY rules are never plan predicates and are
ignored here (symmetric absence with the compiler). The canonical machine
sequence ``(start, stable_op_id)`` is the ONLY thing shared with the compiler.

This is the authoritative verifier; Z3 corroborates and ``feasible verify``
re-runs this exact code.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from feasible.ir.domain import CellRef, FCIR, OpClass, Plan, TextSpan

DAY_DEFAULT = {"day_start": 0, "day_end": 960, "night_start": 960, "night_end": 1440}


class Violation(BaseModel):
    rule_id: str
    span: TextSpan | CellRef | None = None
    message: str
    counter_witness: dict = Field(default_factory=dict)


class CheckResult(BaseModel):
    passed: bool
    violations: list[Violation] = Field(default_factory=list)


def rule_span(ir: FCIR, rule_id: str) -> TextSpan | CellRef | None:
    r = ir.rule(rule_id)
    if r is None:
        return None
    primary = [s for s in r.provenance.spans if getattr(s, "role", "") == "primary_normative"]
    if primary:
        return primary[0]
    return r.provenance.spans[0] if r.provenance.spans else None


def machine_sequence(plan: Plan, machine: str) -> list[str]:
    """Op ids on ``machine`` in canonical (start, stable_op_id) order."""
    ops = [op for op, (_, mc) in plan.assignments.items() if mc == machine]
    return sorted(ops, key=lambda o: (plan.start(o), o))


def _family(ir: FCIR, op_id: str) -> str:
    op = ir.instance.operation(op_id)
    return ir.instance.job(op.job_id).family


def _end(ir: FCIR, plan: Plan, op_id: str) -> int:
    return plan.start(op_id) + ir.instance.operation(op_id).duration


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    # half-open [start, end)
    return a_start < b_end and b_start < a_end


def check(plan: Plan, ir: FCIR) -> CheckResult:
    violations: list[Violation] = []
    inst = ir.instance

    # R-ROUTING: ops of a job run in seq order (next starts at/after prev ends)
    if ir.has_active("R-ROUTING"):
        by_job: dict[str, list] = {}
        for o in inst.operations:
            by_job.setdefault(o.job_id, []).append(o)
        for job_id, ops_j in by_job.items():
            ordered = sorted(ops_j, key=lambda o: o.seq)
            for a, b in zip(ordered, ordered[1:]):
                if a.op_id in plan.assignments and b.op_id in plan.assignments:
                    if plan.start(b.op_id) < _end(ir, plan, a.op_id):
                        violations.append(Violation(
                            rule_id="R-ROUTING",
                            span=rule_span(ir, "R-ROUTING"),
                            message=f"routing precedence violated: {b.op_id} starts before {a.op_id} ends",
                            counter_witness={"before": a.op_id, "after": b.op_id,
                                             "before_end": _end(ir, plan, a.op_id),
                                             "after_start": plan.start(b.op_id)},
                        ))

    # R-NOOVERLAP: ops + cleanouts + maintenance on a machine never overlap
    if ir.has_active("R-NOOVERLAP"):
        for mc in inst.machines:
            blocks: list[tuple[int, int, str]] = []
            for op in inst.operations:
                if op.op_id in plan.assignments and plan.machine(op.op_id) == mc:
                    blocks.append((plan.start(op.op_id), _end(ir, plan, op.op_id), op.op_id))
            for (cm, cs, ce, reason) in plan.cleanouts:
                if cm == mc:
                    blocks.append((cs, ce, reason))
            blocks.sort(key=lambda b: (b[0], b[2]))
            for x, y in zip(blocks, blocks[1:]):
                if _overlaps(x[0], x[1], y[0], y[1]):
                    violations.append(Violation(
                        rule_id="R-NOOVERLAP",
                        span=rule_span(ir, "R-NOOVERLAP"),
                        message=f"machine {mc}: '{x[2]}' overlaps '{y[2]}'",
                        counter_witness={"machine": mc, "a": x[2], "b": y[2],
                                         "a_end": x[1], "b_start": y[0]},
                    ))

    # R-SETUP: every Allergen->non-allergen adjacency has a sufficient cleanout
    if ir.has_active("R-SETUP"):
        for mc in inst.machines:
            seq = machine_sequence(plan, mc)
            for i_id, j_id in zip(seq, seq[1:]):
                required = inst.setup(_family(ir, i_id), _family(ir, j_id))
                if required <= 0:
                    continue
                i_end, j_start = _end(ir, plan, i_id), plan.start(j_id)
                has = any(
                    cm == mc and cs >= i_end and ce <= j_start and (ce - cs) >= required
                    for (cm, cs, ce, _r) in plan.cleanouts
                )
                if not has:
                    violations.append(Violation(
                        rule_id="R-SETUP",
                        span=rule_span(ir, "R-SETUP"),
                        message=(f"machine {mc}: missing {required}-min cleanout between "
                                 f"{i_id} ({_family(ir, i_id)}) and {j_id} ({_family(ir, j_id)})"),
                        counter_witness={"machine": mc, "from_op": i_id, "to_op": j_id,
                                         "required": required, "gap": j_start - i_end},
                    ))

    # R-MAINT: nothing runs on a machine during its maintenance window
    if ir.has_active("R-MAINT"):
        for (mc, mstart, mend) in inst.maintenance:
            occupants: list[tuple[int, int, str]] = []
            for op in inst.operations:
                if op.op_id in plan.assignments and plan.machine(op.op_id) == mc:
                    occupants.append((plan.start(op.op_id), _end(ir, plan, op.op_id), op.op_id))
            for (cm, cs, ce, reason) in plan.cleanouts:
                if cm == mc:
                    occupants.append((cs, ce, reason))
            for (s, e, who) in occupants:
                if _overlaps(s, e, mstart, mend):
                    violations.append(Violation(
                        rule_id="R-MAINT",
                        span=rule_span(ir, "R-MAINT"),
                        message=f"machine {mc}: '{who}' runs during maintenance [{mstart},{mend})",
                        counter_witness={"machine": mc, "who": who, "window": [mstart, mend]},
                    ))

    # R-SHIFT: ops stay within the operating horizon (the calendar fact)
    if ir.has_active("R-SHIFT"):
        for op in inst.operations:
            if op.op_id in plan.assignments:
                if plan.start(op.op_id) < 0 or _end(ir, plan, op.op_id) > inst.horizon:
                    violations.append(Violation(
                        rule_id="R-SHIFT",
                        span=rule_span(ir, "R-SHIFT"),
                        message=f"{op.op_id} runs outside the operating horizon",
                        counter_witness={"op": op.op_id, "horizon": inst.horizon},
                    ))

    # R-6.1-NIGHT-CLEANOUT (the HERO): cleanouts only during the day shift
    night_rule = ir.rule("R-6.1-NIGHT-CLEANOUT")
    if ir.has_active("R-6.1-NIGHT-CLEANOUT"):
        p = {**DAY_DEFAULT, **(night_rule.params if night_rule else {})}
        for (mc, cs, ce, reason) in plan.cleanouts:
            mod = cs % 1440
            dur = ce - cs
            in_day = (mod >= p["day_start"]) and (mod + dur <= p["day_end"])
            if not in_day:
                violations.append(Violation(
                    rule_id="R-6.1-NIGHT-CLEANOUT",
                    span=rule_span(ir, "R-6.1-NIGHT-CLEANOUT"),
                    message=(f"cleanout on {mc} at minute {cs} (minute-of-day {mod}) "
                             f"violates the night-shift sanitation ban"),
                    counter_witness={"machine": mc, "cleanout_start": cs, "minute_of_day": mod,
                                     "op_class": OpClass.SANITATION.value, "reason": reason},
                ))

    return CheckResult(passed=len(violations) == 0, violations=violations)
