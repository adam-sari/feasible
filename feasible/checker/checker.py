"""The polynomial plan checker — total, in P, CODE-DISJOINT from the compiler.

Evaluates every hard ``PLAN_CONSTRAINT`` as a CLOSED predicate over a concrete
plan (start times + machine assignments + materialized cleanouts). No search,
no timeouts — always a concrete yes/no with the offending op and the source
span. Permissions / CONFLICT_ONLY rules are never plan predicates and are
ignored here (symmetric absence with the compiler). The canonical machine
sequence ``(start, stable_op_id)`` is the ONLY thing shared with the compiler.

This is the authoritative verifier; Z3 corroborates and ``feasible verify``
re-runs this exact code.

The per-rule predicates are dispatched through the IR's domain verifier
(``get_domain(ir.domain_id)``); plan-shape well-formedness and the fail-closed
registry gate stay here so they fire for every domain. ``DAY_DEFAULT``,
``machine_sequence`` and ``rule_span`` are re-exported from the manufacturing
verifier for the modules that import them from here (back-compat).
"""
from __future__ import annotations

import feasible.domains.manufacturing  # noqa: F401  (registers the manufacturing domain)
from feasible.checker.plan_shape import validate_plan_shape
from feasible.checker.result import CheckResult, Violation
from feasible.domains import get_domain
from feasible.domains.manufacturing.verifier import DAY_DEFAULT, machine_sequence, rule_span
from feasible.ir.domain import FCIR, Plan
from feasible.registry import unsupported_hard_rules

__all__ = ["Violation", "CheckResult", "check", "machine_sequence", "rule_span", "DAY_DEFAULT"]


def check(plan: Plan, ir: FCIR) -> CheckResult:
    # Structural well-formedness + the fail-closed registry run ALONGSIDE the rule
    # predicates (no early-return) so a malformed plan is reported AND R-6.1 still
    # fires. The rule predicates are total (machine_sequence skips ghost ops).
    violations: list[Violation] = list(validate_plan_shape(plan, ir))
    for r in unsupported_hard_rules(ir):
        violations.append(Violation(
            rule_id="R-UNSUPPORTED-RULE", span=None,
            message=f"active hard rule {r.rule_id} (kind {r.kind}) has no evaluator",
            counter_witness={"rule_id": r.rule_id, "kind": r.kind}))

    # Per-rule predicates: dispatch to the IR's domain verifier (behavior-identical
    # relocation of the inline manufacturing predicates).
    _, verifier = get_domain(ir.domain_id)
    violations += verifier.check_predicates(plan, ir)

    return CheckResult(passed=len(violations) == 0, violations=violations)
