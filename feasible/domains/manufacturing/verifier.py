"""Manufacturing predicate bundle behind the ``DomainVerifier`` seam.

This is a PURE RELOCATION of the manufacturing rule predicates that previously
lived inline in ``feasible.checker.checker`` (the polynomial closed predicates)
and ``feasible.smt.attest`` (the parallel Z3 encoding). The bodies are copied
verbatim — same per-rule logic, same counter-witnesses, same Z3 tracking names —
so the top-level ``check`` / ``attest_feasibility`` dispatch through the
domain's verifier without changing any certificate truth claim. The manufacturing
rule_ids stay un-namespaced (``R-*``) until a later task; the oracle proves the
relocation preserved behavior.
"""
from __future__ import annotations

from typing import Any

import z3

from feasible.checker.result import Violation
from feasible.ingest.segment import Segment
from feasible.ir.domain import CellRef, ClauseKind, FCIR, OpClass, Plan, Rule, TextSpan

# The day-shift window default for the night-cleanout rule (relocated from
# checker.py; kept identical so the predicate is byte-for-byte the same).
DAY_DEFAULT = {"day_start": 0, "day_end": 960, "night_start": 960, "night_end": 1440}

# Manufacturing natural-language renderer (relocated verbatim from
# govern/backtranslate.py ``_RENDER``; ``back_translate`` is now a per-domain hook).
_RENDER = {
    "routing_precedence": "operations of a job must run in Mix -> Fill -> Label order",
    "no_overlap": "a machine must not run two operations at once",
    "setup_cleanout": "a 90-minute cleanout must be performed when switching from an allergen product",
    "maintenance": "Filler-2 must not run during its Tuesday maintenance window",
    "shift": "the plant operates a day and a night shift",
    "night_cleanout": "a cleanout must not be performed during the night shift",
    "non_preemption": None,  # scope-dependent, see below
    "permission": "Filler-1 may change product family without a cleanout",
}


def rule_span(ir: FCIR, rule_id: str) -> TextSpan | CellRef | None:
    r = ir.rule(rule_id)
    if r is None:
        return None
    primary = [s for s in r.provenance.spans if getattr(s, "role", "") == "primary_normative"]
    if primary:
        return primary[0]
    return r.provenance.spans[0] if r.provenance.spans else None


def machine_sequence(plan: Plan, machine: str, ir: FCIR | None = None) -> list[str]:
    """Op ids on ``machine`` in canonical (start, stable_op_id) order.

    When ``ir`` is given, op ids not in ``ir.instance.operations`` are skipped
    (predicate totality: a malformed plan with a ghost op must not raise)."""
    ops = [op for op, (_, mc) in plan.assignments.items() if mc == machine]
    if ir is not None:
        known = {o.op_id for o in ir.instance.operations}
        ops = [o for o in ops if o in known]
    return sorted(ops, key=lambda o: (plan.start(o), o))


def _family(ir: FCIR, op_id: str) -> str:
    op = ir.instance.operation(op_id)
    return ir.instance.job(op.job_id).family


def _end(ir: FCIR, plan: Plan, op_id: str) -> int:
    return plan.start(op_id) + ir.instance.operation(op_id).duration


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    # half-open [start, end)
    return a_start < b_end and b_start < a_end


class ManufacturingVerifier:
    """The manufacturing ``DomainVerifier`` predicate bundle (relocated bodies)."""

    domain_id: str = "manufacturing"
    rule_kinds: frozenset[str] = frozenset({
        "routing_precedence", "no_overlap", "setup_cleanout", "maintenance",
        "shift", "night_cleanout",
    })
    evaluated_rule_ids: frozenset[str] = frozenset({
        "R-ROUTING", "R-NOOVERLAP", "R-SETUP", "R-MAINT", "R-SHIFT", "R-6.1-NIGHT-CLEANOUT",
    })
    structural_rule_kinds: frozenset[str] = frozenset({"non_preemption"})

    def check_predicates(self, plan: Plan, ir: FCIR) -> list[Violation]:
        """The per-rule closed predicates (relocated verbatim from checker.py).

        Plan-shape + the fail-closed registry gate stay in the top-level
        ``check``; this returns only the manufacturing rule violations."""
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
                seq = machine_sequence(plan, mc, ir)
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

        return violations

    def z3_encode(self, plan: Plan, ir: FCIR) -> "z3.Solver":
        """The parallel Z3 attestation (relocated verbatim from attest.py).

        Builds a fresh ``z3.Solver`` with ``unsat_core=True``, pins op
        starts/ends + cleanout intervals to the concrete plan, and tracks each
        active hard rule as a named assertion (so an UNSAT core names the
        offending rule). Code-disjoint from CP-SAT (no arc literals). The caller
        runs ``s.check()`` / reads ``s.unsat_core()``."""
        inst = ir.instance
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

        def track(name: str, expr: "z3.BoolRef") -> None:
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

        return s

    # --------------------------------------------------------------------- #
    # The remaining ``DomainVerifier`` members are relocated behind the seam #
    # by later Spec-0 tasks (per-domain registry, govern hooks, KPI         #
    # registry). They are declared here so this class satisfies the         #
    # ``DomainVerifier`` Protocol; nothing in the Task-5 dispatch reaches    #
    # them yet (the oracle + suite prove only check/z3 are exercised).       #
    # --------------------------------------------------------------------- #

    def compile(self, ir: Any, model: Any) -> Any:  # noqa: A003
        raise NotImplementedError("manufacturing compile() is relocated in a later task")

    def objective(self, ir: Any, plan: Any) -> tuple[int, ...]:
        raise NotImplementedError("manufacturing objective() is relocated in a later task")

    def kpis(self) -> list[Any]:
        raise NotImplementedError("manufacturing kpis() is relocated in a later task")

    def gotcha_rule_id(self) -> str | None:
        raise NotImplementedError("manufacturing gotcha_rule_id() is relocated in a later task")

    def classify_segment(self, seg: Segment) -> str:
        """The deterministic keyword normativity classifier (relocated verbatim
        from ``govern/coverage.classify``). A HARD deontic operator ALWAYS wins
        over the soft-target keywords (the omission moat must not fail open)."""
        text = seg.text.strip().lower()
        if seg.text.lstrip().startswith("#"):
            return "metadata"
        if not text:
            return "boilerplate"
        prohibition = any(k in text for k in ["may only", "may not", "does not", "not work", "unavailable", "no filler"])
        obligation = any(k in text for k in ["is required", "must ", "shall"])
        conditional = "when" in text or "if " in text
        if prohibition:
            return "hard_prohibition"
        if obligation and conditional:
            return "conditional_obligation"
        if obligation:
            return "hard_obligation"
        if "take precedence" in text or "are expected" in text or "priority" in text:
            return "soft_target"
        return "boilerplate"

    def back_translate(self, rule: Rule) -> str:
        """The manufacturing NL renderer (relocated verbatim from
        ``govern/backtranslate.back_translate``)."""
        if rule.kind == "non_preemption":
            scope = rule.params.get("scope", "fill_op")
            if scope == "whole_line":
                return ("once an allergen order starts, NO other order may use ANY machine on its "
                        "route until it finishes (whole-line lock)")
            return "an allergen order's fill operation must run to completion without interruption"
        body = _RENDER.get(rule.kind) or f"rule {rule.rule_id}"
        return body

    def conflict_realizable(self, ir: FCIR, permission: Rule) -> bool:
        """Allergen-transition realizability (relocated verbatim from
        ``govern/conflict._scope_realizable``): does the instance realize the
        permission's scope (machine + priority + a real Allergen->non-allergen
        transition)?"""
        machine = permission.params.get("scope_machine")
        priority = permission.params.get("scope_priority")
        inst = ir.instance
        allergen_here = [
            o for o in inst.operations
            if machine in o.eligible_machines
            and inst.job(o.job_id).family == "Allergen"
            and (priority is None or inst.job(o.job_id).priority == priority)
        ]
        nonallergen_here = [
            o for o in inst.operations
            if machine in o.eligible_machines and inst.job(o.job_id).family != "Allergen"
        ]
        return bool(allergen_here) and bool(nonallergen_here)

    def conflict_unsat_core(self, obligation_id: str, permission_id: str) -> list[str] | None:
        """The rule-vs-rule Z3 UNSAT core (relocated verbatim from
        ``govern/conflict._normative_unsat``): obligation says cleanout_required,
        permission says NOT — jointly UNSAT."""
        s = z3.Solver()
        s.set(unsat_core=True)
        required = z3.Bool("cleanout_required_over_scope_S")
        s.assert_and_track(required, obligation_id)  # obligation: required
        s.assert_and_track(z3.Not(required), permission_id)  # permission: not required
        if s.check() == z3.unsat:
            return [str(c) for c in s.unsat_core()]
        return None
