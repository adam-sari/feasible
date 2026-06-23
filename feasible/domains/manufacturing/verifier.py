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


def _parse_cleanout_reason(reason: str) -> tuple[str, str] | None:
    """Parse a materialized-cleanout reason ``"cleanout {i}->{j}"`` into ``(i, j)``
    so ``_pin_to_plan`` can address the matching free ``cs[(i,j,mc)]`` var. Returns
    ``None`` for any reason not in that canonical shape."""
    prefix = "cleanout "
    if not reason.startswith(prefix) or "->" not in reason:
        return None
    body = reason[len(prefix):]
    i, _, j = body.partition("->")
    if not i or not j:
        return None
    return i, j


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
    # The names of the FJSP lexicographic objective levels, in order — matching
    # ``solve.orchestrate.recompute_objective`` (weighted_tardiness, then
    # total_changeover). A SIGNED, per-domain claim (``emit`` writes the leaf,
    # ``render_html`` reads it, ``verify`` re-derives it + checks arity); a
    # NON-FJSP domain declares ITS own labels for ITS own objective tuple.
    objective_labels: tuple[str, ...] = ("weighted_tardiness", "total_changeover")
    # The complete set of rule_ids manufacturing owns (the cross-domain isolation
    # guard checks this set against a cert's signed domain). It is the evaluated
    # (checked) ids PLUS the structural-kind-bearing id (``R-5.2``, the
    # ``non_preemption`` compiled-only obligation) PLUS the conflict-only
    # permission (``R-4.4``, the §4.4 cleanout-skip permission). Manufacturing
    # keeps its existing un-namespaced ``R-*`` ids (no mass rename).
    known_rule_ids: frozenset[str] = evaluated_rule_ids | frozenset({"R-5.2", "R-4.4"})

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

        # R-SHIFT: every scheduled op stays within the operating horizon (the
        # parallel of the checker's start>=0 & end<=horizon predicate; without this
        # block R-SHIFT was checked polynomially but UN-attested by Z3 — a fail-open
        # the registry-membership meta-test now forbids).
        if ir.has_active("R-SHIFT"):
            for op in inst.operations:
                if op.op_id in plan.assignments:
                    track(
                        f"R-SHIFT:{op.op_id}",
                        z3.And(start[op.op_id] >= 0, end[op.op_id] <= inst.horizon),
                    )

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
    # T1.2: FREE-SEARCH Z3 independent-optimality (two-layer encoding).      #
    #                                                                        #
    # The encoding is CODE-DISJOINT from CP-SAT (no ``cpsat.py`` import — the #
    # arithmetic is re-expressed in z3-py, integers only). It mirrors        #
    # ``cpsat.build_model``: immediate same-machine adjacency ``adj(i,j,mc)`` #
    # (the free-search equivalent of the AddCircuit arc literal, replacing    #
    # the plan-readout ``machine_sequence``), a MATERIALIZED free cleanout    #
    # start ``cs`` per changeover (disjoint from maintenance, night-banded —  #
    # never a gap-only assertion), and the immediate-adjacency changeover     #
    # (no every-ordered-pair over-count).                                     #
    # --------------------------------------------------------------------- #

    def _build_free_vars(self, ir: FCIR) -> dict[str, Any]:
        """Construct the FREE decision vars + the structural primitives shared by
        every layer/helper. Returns a dict carrying the var maps plus the
        ``adj`` predicate factory, the req>0 ``setup_pairs``, the per-machine op
        lists, and the horizon ``H`` — so the feasibility layer, the objective
        layer, and the white-box helpers all address the SAME vars."""
        inst = ir.instance
        H = inst.horizon

        start: dict[str, Any] = {op.op_id: z3.Int(f"start_{op.op_id}") for op in inst.operations}
        end: dict[str, Any] = {op.op_id: z3.Int(f"end_{op.op_id}") for op in inst.operations}
        # machine-assignment Bools, one per (op, eligible machine)
        mp: dict[tuple[str, str], Any] = {}
        for op in inst.operations:
            for mc in op.eligible_machines:
                mp[(op.op_id, mc)] = z3.Bool(f"mp_{op.op_id}_{mc}")

        # ops eligible on each machine (free-search analogue of machine_sequence's domain)
        ops_on: dict[str, list[str]] = {mc: [] for mc in inst.machines}
        for op in inst.operations:
            for mc in op.eligible_machines:
                ops_on[mc].append(op.op_id)

        def adj(i: str, j: str, mc: str) -> Any:
            # i immediately precedes j on machine mc: both on mc, i before j, and
            # NO third op k on mc sits between them. The free-search equivalent of
            # two ops being consecutive in machine_sequence(plan, mc, ir) — the
            # order is a DECISION, so "no op between" is an explicit guard.
            between_k = [
                z3.And(mp[(k, mc)], end[i] <= start[k], end[k] <= start[j])
                for k in ops_on[mc] if k != i and k != j
            ]
            guard = z3.Not(z3.Or(*between_k)) if between_k else z3.BoolVal(True)
            return z3.And(mp[(i, mc)], mp[(j, mc)], end[i] <= start[j], guard)

        # the req>0 changeover pairs (the materialized-cleanout / changeover set)
        setup_pairs: list[tuple[str, str, str, int]] = []
        cs: dict[tuple[str, str, str], Any] = {}
        for mc in inst.machines:
            here = ops_on[mc]
            for i in here:
                for j in here:
                    if i == j:
                        continue
                    req = inst.setup(_family(ir, i), _family(ir, j))
                    if req > 0:
                        setup_pairs.append((i, j, mc, req))
                        cs[(i, j, mc)] = z3.Int(f"cs_{i}_{j}_{mc}")

        return {
            "start": start, "end": end, "mp": mp, "cs": cs,
            "ops_on": ops_on, "adj": adj, "setup_pairs": setup_pairs, "H": H,
        }

    def _feasibility_only_encode(self, ir: FCIR) -> tuple["z3.Solver", dict[str, Any]]:
        """The FULL hard-constraint encoding over the FREE decision vars — i.e.
        EVERYTHING except the objective vars (``wt``, ``co``) and the
        strict-improvement disjunction. Returns the solver AND the var maps so the
        white-box helpers (``_pin_to_plan`` / ``_decode_witness``) can address the
        free vars. The load-bearing split (RC-1): the region test (c) pins to THIS
        layer, removing the objective confound."""
        inst = ir.instance
        v = self._build_free_vars(ir)
        start, end, mp, cs = v["start"], v["end"], v["mp"], v["cs"]
        adj, setup_pairs = v["adj"], v["setup_pairs"]
        H = v["H"]

        night_rule = ir.rule("R-6.1-NIGHT-CLEANOUT")
        night_active = ir.has_active("R-6.1-NIGHT-CLEANOUT")
        night = {**DAY_DEFAULT, **(night_rule.params if night_rule else {})}

        s = z3.Solver()

        # end == start + duration; start >= 0
        for op in inst.operations:
            s.add(end[op.op_id] == start[op.op_id] + op.duration)
            s.add(start[op.op_id] >= 0)
            # EXACTLY-ONE eligible machine
            lits = [(mp[(op.op_id, mc)], 1) for mc in op.eligible_machines]
            s.add(z3.PbEq(lits, 1))

        # R-ROUTING: consecutive ops in a job run in seq order (machine-independent)
        if ir.has_active("R-ROUTING"):
            by_job: dict[str, list] = {}
            for o in inst.operations:
                by_job.setdefault(o.job_id, []).append(o)
            for ops_j in by_job.values():
                ordered = sorted(ops_j, key=lambda o: o.seq)
                for a, b in zip(ordered, ordered[1:]):
                    s.add(start[b.op_id] >= end[a.op_id])

        # R-NOOVERLAP: same-machine ops pairwise disjoint when co-assigned
        if ir.has_active("R-NOOVERLAP"):
            for mc in inst.machines:
                here = v["ops_on"][mc]
                for a_i in range(len(here)):
                    for b_i in range(a_i + 1, len(here)):
                        a, b = here[a_i], here[b_i]
                        s.add(z3.Implies(
                            z3.And(mp[(a, mc)], mp[(b, mc)]),
                            z3.Or(end[a] <= start[b], end[b] <= start[a]),
                        ))

        # R-SETUP: changeover via immediate adjacency + a MATERIALIZED cleanout cs,
        # the cleanout interval [cs, cs+req) disjoint from every maintenance window.
        if ir.has_active("R-SETUP"):
            for (i, j, mc, req) in setup_pairs:
                a = adj(i, j, mc)
                csv = cs[(i, j, mc)]
                s.add(z3.Implies(a, end[i] <= csv))            # cleanout after op i
                s.add(z3.Implies(a, csv + req <= start[j]))    # cleanout before op j
                if ir.has_active("R-MAINT"):
                    for (m_mc, m_start, m_end) in inst.maintenance:
                        if m_mc == mc:
                            s.add(z3.Implies(a, z3.Or(csv + req <= m_start, csv >= m_end)))

        # R-MAINT (ops): each op on mc disjoint from its maintenance windows
        if ir.has_active("R-MAINT"):
            for (m_mc, m_start, m_end) in inst.maintenance:
                for op in inst.operations:
                    if m_mc in op.eligible_machines:
                        s.add(z3.Implies(
                            mp[(op.op_id, m_mc)],
                            z3.Or(end[op.op_id] <= m_start, start[op.op_id] >= m_end),
                        ))

        # R-SHIFT: every op stays within the operating horizon
        if ir.has_active("R-SHIFT"):
            for op in inst.operations:
                s.add(z3.And(start[op.op_id] >= 0, end[op.op_id] <= H))

        # R-6.1-NIGHT-CLEANOUT: the MATERIALIZED cleanout's minute-of-day in the day band
        if night_active and ir.has_active("R-SETUP"):
            for (i, j, mc, req) in setup_pairs:
                a = adj(i, j, mc)
                mod = cs[(i, j, mc)] % 1440
                s.add(z3.Implies(a, z3.And(mod >= night["day_start"], mod + req <= night["day_end"])))

        return s, v

    def independent_optimality_encode(self, ir: FCIR, V: tuple[int, ...]) -> "z3.Solver | None":
        """FREE-SEARCH Z3 strict-improvement encoding (the layer ON TOP of the
        feasibility-only layer): the full hard-constraint set over FREE vars PLUS
        the objective vars (``wt``, immediate-adjacency ``co``) PLUS the two-level
        lexicographic strict-improvement disjunction ``Or(wt<v0, And(wt==v0,
        co<v1))``. UNSAT => no feasible plan beats V => corroborated.

        The SEAM imposes no arity: a non-2-level ``V`` is the honest ``None``
        opt-out (the FJSP objective has exactly two levels; a deeper objective is
        not a manufacturing objective). This matches the seam's documented
        ``None`` opt-out and the T1.1 variable-length seam contract; the encoding
        is well-defined only for the 2-tuple."""
        if len(V) != 2:
            return None
        inst = ir.instance
        s, v = self._feasibility_only_encode(ir)
        end = v["end"]

        # wt == priority-weighted tardiness over the free plan
        wt_terms = []
        for job in inst.jobs:
            last_op = max((o for o in inst.operations if o.job_id == job.id), key=lambda o: o.seq)
            tard = z3.Int(f"tard_{job.id}")
            s.add(tard >= end[last_op.op_id] - job.due_date)
            s.add(tard >= 0)
            wt_terms.append((4 - job.priority) * tard)
        wt = z3.Int("wt")
        s.add(wt == (z3.Sum(wt_terms) if wt_terms else 0))

        # co == immediate-adjacency changeover (NO every-ordered-pair over-count)
        co = z3.Int("co")
        s.add(co == self._changeover_expr(v))

        # the two-level lexicographic strict-improvement disjunction (mirror
        # optimality.py:30-37): require SOME strict improvement over V.
        v0, v1 = V
        better_l1 = wt < v0
        better_l2 = z3.And(wt == v0, co < v1)
        s.add(z3.Or(better_l1, better_l2))
        return s

    # ---- white-box helpers for the region-correspondence test (pure, integers) #

    @staticmethod
    def _changeover_expr(v: dict[str, Any]) -> Any:
        """The SINGLE definition of the encoding's ``co`` objective expression over
        the free vars: ``Sum(If(adj(i,j,mc), req, 0))`` — IMMEDIATE adjacency ONLY,
        each changeover charged at most once. Used BOTH by
        ``independent_optimality_encode`` (so the shipped ``co`` is this expression)
        AND by ``_changeover_expr_value`` (so the region test reads THIS expression,
        not a Python re-derivation). A regression to an every-ordered-pair sum would
        therefore change the value the test reads AND the value the cert ships."""
        adj, setup_pairs = v["adj"], v["setup_pairs"]
        co_terms = [z3.If(adj(i, j, mc), req, 0) for (i, j, mc, req) in setup_pairs]
        return z3.Sum(co_terms) if co_terms else z3.IntVal(0)

    def _changeover_expr_value(self, plan: Plan, ir: FCIR) -> int:
        """Read the ENCODING'S ``co`` expression for a concrete plan straight out of
        a Z3 model — NOT a Python recompute. Pins ``plan`` to the feasibility-only
        layer, solves, and evaluates ``_changeover_expr`` (the very expression the
        cert ships) in the resulting model. This is what makes region-test leg (c)
        DISCRIMINATING: it exercises the ``Sum(If(adj(...), req, 0))`` term with its
        immediate-adjacency ``adj`` guard, so an every-ordered-pair over-count
        regression (Allergen->Standard->Spicy charging 90+90=180) WOULD be caught
        here (the model would eval ``co`` to 180, not the immediate 90)."""
        s, v = self._feasibility_only_encode(ir)
        s.add(self._pin_to_plan(plan, ir))
        assert s.check() == z3.sat, "the plan must be pin-admissible to read co from a model"
        m = s.model()
        return int(m.eval(self._changeover_expr(v), model_completion=True).as_long())

    def _changeover_of(self, plan: Plan, ir: FCIR) -> int:
        """The encoding's IMMEDIATE-adjacency changeover for a concrete plan: the
        sum of ``setup`` over consecutive same-machine pairs (the consecutive-pair
        sum the ``co`` objective computes — NOT the every-ordered-pair over-count)."""
        total = 0
        for mc in ir.instance.machines:
            seq = machine_sequence(plan, mc, ir)
            for i_id, j_id in zip(seq, seq[1:]):
                total += ir.instance.setup(_family(ir, i_id), _family(ir, j_id))
        return total

    def _pin_to_plan(self, plan: Plan, ir: FCIR) -> list[Any]:
        """Constrain the FREE vars of ``_feasibility_only_encode`` to a concrete
        plan: pin every ``start[i]``, every machine Bool ``mp[(i,mc)]``, and each
        MATERIALIZED cleanout ``cs[(i,j,mc)]`` to the plan's matching cleanout
        start. A concrete plan that the closed checker REJECTS becomes UNSAT here
        (a breached hard rule); a checker-feasible plan stays SAT (the positive
        control). Pure: returns the assertions, never mutates a solver."""
        v = self._build_free_vars(ir)
        start, mp, cs = v["start"], v["mp"], v["cs"]
        cons: list[Any] = []
        for op in ir.instance.operations:
            if op.op_id in plan.assignments:
                cons.append(start[op.op_id] == plan.start(op.op_id))
                assigned = plan.machine(op.op_id)
                for mc in op.eligible_machines:
                    cons.append(mp[(op.op_id, mc)] == (mc == assigned))
        # pin each plan cleanout to its matching materialized cs var (by reason+machine)
        for (mc, cstart, _ce, reason) in plan.cleanouts:
            pair = _parse_cleanout_reason(reason)
            if pair is not None and (pair[0], pair[1], mc) in cs:
                cons.append(cs[(pair[0], pair[1], mc)] == cstart)
        return cons

    def _decode_witness(self, model: "z3.ModelRef", ir: FCIR) -> Plan:
        """Read a Z3 model into a concrete ``Plan`` (the SAME shape ``extract_plan``
        builds) so a witness is checkable by ``feasible.checker.checker.check``
        without trusting the encoding. A cleanout is emitted for ``(i,j,mc)`` ONLY
        when the model says ``adj(i,j,mc)`` holds (an adj-FALSE ``cs`` is
        unconstrained garbage and must NOT pollute the decoded plan)."""
        v = self._build_free_vars(ir)
        start, mp, cs, adj = v["start"], v["mp"], v["cs"], v["adj"]
        assignments: dict[str, tuple[int, str]] = {}
        for op in ir.instance.operations:
            st = model.eval(start[op.op_id], model_completion=True).as_long()
            machine = next(
                mc for mc in op.eligible_machines
                if z3.is_true(model.eval(mp[(op.op_id, mc)], model_completion=True))
            )
            assignments[op.op_id] = (st, machine)
        cleanouts: list[tuple[str, int, int, str]] = []
        for (i, j, mc, req) in v["setup_pairs"]:
            if z3.is_true(model.eval(adj(i, j, mc), model_completion=True)):
                cs_val = model.eval(cs[(i, j, mc)], model_completion=True).as_long()
                cleanouts.append((mc, cs_val, cs_val + req, f"cleanout {i}->{j}"))
        return Plan(assignments=assignments, cleanouts=cleanouts)

    def _block_model(self, model: "z3.ModelRef") -> Any:
        """Negate a model over its decision vars so the caller can enumerate
        DISTINCT witnesses (``s.add(_block_model(m))`` forbids re-finding it)."""
        terms = []
        for d in model.decls():
            val = model[d]
            if val is not None and d.arity() == 0:
                terms.append(d() != val)
        return z3.Or(*terms) if terms else z3.BoolVal(False)

    # --------------------------------------------------------------------- #
    # The remaining ``DomainVerifier`` members are relocated behind the seam #
    # by later Spec-0 tasks (per-domain registry, govern hooks, KPI         #
    # registry). They are declared here so this class satisfies the         #
    # ``DomainVerifier`` Protocol; nothing in the Task-5 dispatch reaches    #
    # them yet (the oracle + suite prove only check/z3 are exercised).       #
    # --------------------------------------------------------------------- #

    def compile(self, ir: Any, model: Any = None) -> Any:  # noqa: A003
        """Build the manufacturing CP-SAT model for ``ir``.

        Delegates to the existing ``feasible.compile.cpsat.build_model`` (which
        constructs the model + var index from the IR — the ``model`` argument is
        accepted for the seam signature but the builder owns model construction).
        Lazy import to avoid a compile<->domain import cycle."""
        from feasible.compile.cpsat import build_model

        return build_model(ir)

    def objective(self, ir: Any, plan: Any) -> tuple[int, ...]:
        """The canonical lexicographic objective recomputed from ``plan``.

        Delegates to the existing ``feasible.solve.orchestrate.recompute_objective``
        (variable-length tuple). Lazy import to avoid a solve<->domain cycle."""
        from feasible.solve.orchestrate import recompute_objective

        return recompute_objective(ir, plan)

    def optimality_tripwire(self, ir: Any, objective: tuple[int, ...]) -> bool:
        """The manufacturing same-engine optimality tripwire.

        Delegates VERBATIM to ``feasible.solve.optimality.optimality_tripwire``
        — the FJSP CP-SAT model with exactly two lexicographic levels
        (weighted_tardiness, total_changeover). That implementation keeps its
        own ``len == 2`` assertion (a deeper objective is not a manufacturing
        objective); the *seam* itself imposes no arity, so a non-FJSP domain can
        opt out honestly without that assertion. Lazy import to avoid a
        solve<->domain import cycle (mirrors ``objective`` above)."""
        from feasible.solve.optimality import optimality_tripwire

        return optimality_tripwire(ir, objective)

    def gotcha_rule_id(self) -> str | None:
        """The single rule the headline incumbent-A gotcha cites: the night-shift
        sanitation ban (``R-6.1-NIGHT-CLEANOUT``). ``verify`` asserts the cert's
        ``incumbent_A_failure.violated_rule_ref`` equals THIS id (no ``violations[0]``
        fallback) — so an arbitrary hard-rule failure cannot pose as the hero gotcha."""
        return "R-6.1-NIGHT-CLEANOUT"

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
