"""Faithfulness is EARNED: two independent verifiers (the polynomial checker and
the Z3 attestor) must agree on every generated plan; the compiler-produced plan
must satisfy both; and the red-team / mutation cases must fail.
"""
from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from feasible.checker.checker import check
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
from feasible.smt.attest import attest_feasibility
from feasible.solve.orchestrate import solve
from tests.crossval.conftest import cpsat_feasible, cpsat_feasible_with_plan


def _rule(rule_id: str, kind: str, clause: ClauseKind, params: dict | None = None) -> Rule:
    return Rule(
        rule_id=rule_id, kind=kind, params=params or {}, severity=Severity.HARD,
        clause_kind=clause, compile_mode=CompileMode.PLAN_CONSTRAINT,
        resolution_class="SAFETY_SANITATION",
        provenance=Provenance(spans=[TextSpan(quoted_text=f"{rule_id} clause")]),
    )


def _two_op_ir() -> FCIR:
    inst = Instance(
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
    return FCIR(
        rules=[
            _rule("R-ROUTING", "routing_precedence", ClauseKind.OBLIGATION),
            _rule("R-NOOVERLAP", "no_overlap", ClauseKind.PROHIBITION),
            _rule("R-SETUP", "setup_cleanout", ClauseKind.OBLIGATION),
            _rule("R-6.1-NIGHT-CLEANOUT", "night_cleanout", ClauseKind.PROHIBITION,
                  {"day_start": 0, "day_end": 960, "night_start": 960, "night_end": 1440}),
        ],
        instance=inst,
    )


_IR = _two_op_ir()


@settings(max_examples=60, deadline=None)
@given(
    ja=st.integers(min_value=0, max_value=1500),
    js=st.integers(min_value=0, max_value=1500),
    has_clean=st.booleans(),
    cstart=st.integers(min_value=0, max_value=1500),
)
def test_checker_and_z3_always_agree(ja: int, js: int, has_clean: bool, cstart: int) -> None:
    """The two independent verifiers agree on EVERY generated plan."""
    cleanouts = [("M", cstart, cstart + 90, "cleanout JA->JS")] if has_clean else []
    plan = Plan(assignments={"JA-op": (ja, "M"), "JS-op": (js, "M")}, cleanouts=cleanouts)
    assert check(plan, _IR).passed == attest_feasibility(plan, _IR).feasible


def test_cpsat_existence() -> None:
    assert cpsat_feasible(_IR) is True


def test_compiler_plan_is_cpsat_feasible_with_plan() -> None:
    result = solve(_IR, max_seconds=15.0)
    assert result.plan is not None
    assert cpsat_feasible_with_plan(_IR, result.plan) is True


def test_red_team_incumbent_a_fails_both() -> None:
    """A night cleanout (the incumbent-A archetype) fails BOTH verifiers."""
    plan = Plan(
        assignments={"JA-op": (0, "M"), "JS-op": (1140, "M")},
        cleanouts=[("M", 1050, 1140, "cleanout JA->JS")],
    )
    chk = check(plan, _IR)
    att = attest_feasibility(plan, _IR)
    assert chk.passed is False and att.feasible is False
    assert any(v.rule_id == "R-6.1-NIGHT-CLEANOUT" for v in chk.violations)


def test_verifier_mutation_self_test() -> None:
    """A verified plan, mutated to overlap, must flip the checker to FAIL."""
    good = Plan(assignments={"JA-op": (0, "M"), "JS-op": (190, "M")},
                cleanouts=[("M", 100, 190, "cleanout JA->JS")])
    assert check(good, _IR).passed is True
    mutated = Plan(assignments={"JA-op": (0, "M"), "JS-op": (50, "M")},
                   cleanouts=[("M", 100, 190, "cleanout JA->JS")])
    assert check(mutated, _IR).passed is False
