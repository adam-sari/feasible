"""Deontic facet guards: a PERMISSION is NEVER a plan predicate (symmetric
absence from both the checker and the compiler), and the obligation/permission
fixtures carry the right compile modes — so an LLM that silently re-typed a hard
constraint as a permission could not bypass the verifier.
"""
from __future__ import annotations

from feasible.ir.domain import (
    ClauseKind,
    CompileMode,
    FCIR,
    Instance,
    Job,
    Operation,
    Plan,
    Provenance,
    Rule,
    Severity,
    TextSpan,
)
from feasible.checker.checker import check
from tests.crossval.conftest import cpsat_feasible


def _plan_rule(rule_id: str, kind: str, clause: ClauseKind) -> Rule:
    return Rule(
        rule_id=rule_id, kind=kind, params={}, severity=Severity.HARD, clause_kind=clause,
        compile_mode=CompileMode.PLAN_CONSTRAINT, resolution_class="SAFETY_SANITATION",
        provenance=Provenance(spans=[TextSpan(quoted_text=f"{rule_id} clause")]),
    )


def _permission(rule_id: str) -> Rule:
    return Rule(
        rule_id=rule_id, kind="permission", params={}, severity=Severity.SOFT,
        clause_kind=ClauseKind.PERMISSION, compile_mode=CompileMode.CONFLICT_ONLY,
        resolution_class="CUSTOMER_PRIORITY",
        provenance=Provenance(spans=[TextSpan(quoted_text="Filler-1 may do back-to-back changes")]),
    )


def _inst() -> Instance:
    return Instance(
        jobs=[
            Job(id="JA", product="Peanut", family="Allergen", qty=1, due_date=5000, priority=1),
            Job(id="JS", product="Mild", family="Standard", qty=1, due_date=5000, priority=3),
        ],
        operations=[
            Operation(op_id="JA-op", job_id="JA", seq=0, eligible_machines=["M"], duration=100),
            Operation(op_id="JS-op", job_id="JS", seq=0, eligible_machines=["M"], duration=100),
        ],
        machines=["M"], setup_matrix={"Allergen|Standard": 90}, maintenance=[], horizon=5000,
    )


def test_permission_is_not_active() -> None:
    ir = FCIR(rules=[_plan_rule("R-SETUP", "setup_cleanout", ClauseKind.OBLIGATION), _permission("R-4.4")],
              instance=_inst())
    # the obligation is a hard plan constraint; the permission is never active
    assert ir.has_active("R-SETUP") is True
    assert ir.has_active("R-4.4") is False


def test_permission_adds_no_checker_predicate() -> None:
    base = [_plan_rule("R-NOOVERLAP", "no_overlap", ClauseKind.PROHIBITION),
            _plan_rule("R-SETUP", "setup_cleanout", ClauseKind.OBLIGATION)]
    ir_without = FCIR(rules=base, instance=_inst())
    ir_with = FCIR(rules=[*base, _permission("R-4.4")], instance=_inst())
    plan = Plan(assignments={"JA-op": (0, "M"), "JS-op": (100, "M")}, cleanouts=[])
    r_without = check(plan, ir_without)
    r_with = check(plan, ir_with)
    # identical verdict + identical violation rule-ids: the permission is inert
    assert r_without.passed == r_with.passed
    assert {v.rule_id for v in r_without.violations} == {v.rule_id for v in r_with.violations}


def test_permission_adds_no_cpsat_constraint() -> None:
    base = [_plan_rule("R-ROUTING", "routing_precedence", ClauseKind.OBLIGATION),
            _plan_rule("R-NOOVERLAP", "no_overlap", ClauseKind.PROHIBITION),
            _plan_rule("R-SETUP", "setup_cleanout", ClauseKind.OBLIGATION)]
    ir_without = FCIR(rules=base, instance=_inst())
    ir_with = FCIR(rules=[*base, _permission("R-4.4")], instance=_inst())
    assert cpsat_feasible(ir_with) == cpsat_feasible(ir_without) is True


def test_obligation_is_plan_constraint_permission_is_conflict_only() -> None:
    setup = _plan_rule("R-SETUP", "setup_cleanout", ClauseKind.OBLIGATION)
    perm = _permission("R-4.4")
    assert setup.compile_mode == CompileMode.PLAN_CONSTRAINT
    assert perm.compile_mode == CompileMode.CONFLICT_ONLY
