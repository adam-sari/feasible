from __future__ import annotations

from pathlib import Path

from feasible.checker.checker import check
from feasible.ingest.golden import load_golden_ir
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
from feasible.solve.optimality import optimality_tripwire
from feasible.solve.orchestrate import recompute_objective, solve

MINI = Path(__file__).resolve().parent.parent / "fixtures" / "mini"


def _mini_ir() -> FCIR:
    return load_golden_ir(MINI / "golden_ir.json", {"shop_rules.md": (MINI / "shop_rules.md").read_text(encoding="utf-8")})


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
    rules = [
        _rule("R-ROUTING", "routing_precedence", ClauseKind.OBLIGATION),
        _rule("R-NOOVERLAP", "no_overlap", ClauseKind.PROHIBITION),
        _rule("R-SETUP", "setup_cleanout", ClauseKind.OBLIGATION),
        _rule("R-6.1-NIGHT-CLEANOUT", "night_cleanout", ClauseKind.PROHIBITION,
              {"day_start": 0, "day_end": 960, "night_start": 960, "night_end": 1440}),
    ]
    return FCIR(rules=rules, instance=inst)


def test_attest_feasible_plan() -> None:
    ir = _two_op_ir()
    plan = Plan(assignments={"JA-op": (0, "M"), "JS-op": (190, "M")},
                cleanouts=[("M", 100, 190, "cleanout JA->JS")])
    res = attest_feasibility(plan, ir)
    assert res.feasible is True
    assert res.minimization_status == "feasible"


def test_attest_night_cleanout_infeasible_with_core() -> None:
    ir = _two_op_ir()
    plan = Plan(assignments={"JA-op": (0, "M"), "JS-op": (1140, "M")},
                cleanouts=[("M", 1050, 1140, "cleanout JA->JS")])  # 23:30 night
    res = attest_feasibility(plan, ir)
    assert res.feasible is False
    assert any("R-6.1-NIGHT-CLEANOUT" in c for c in res.unsat_core)
    assert res.minimization_status == "not_minimized"


def test_attest_missing_cleanout_infeasible() -> None:
    ir = _two_op_ir()
    plan = Plan(assignments={"JA-op": (0, "M"), "JS-op": (100, "M")}, cleanouts=[])
    res = attest_feasibility(plan, ir)
    assert res.feasible is False
    assert any("R-SETUP" in c for c in res.unsat_core)


def test_attest_agrees_with_checker_on_mini() -> None:
    ir = _mini_ir()
    result = solve(ir, max_seconds=20.0)
    assert result.plan is not None
    chk = check(result.plan, ir)
    att = attest_feasibility(result.plan, ir)
    # 3-way agreement on the optimized plan
    assert chk.passed == att.feasible == True


def test_optimality_tripwire_holds_at_optimum() -> None:
    ir = _mini_ir()
    result = solve(ir, max_seconds=20.0)
    assert result.objective is not None
    v0, v1 = result.objective
    # nothing beats the achieved optimum
    assert optimality_tripwire(ir, (v0, v1)) is True
    # a relaxed bound (allow co == v1) IS beatable by the optimum itself
    assert optimality_tripwire(ir, (v0, v1 + 1)) is False


def test_optimality_tripwire_on_cleanout_instance() -> None:
    ir = _two_op_ir()
    result = solve(ir, max_seconds=20.0)
    assert result.objective is not None
    assert optimality_tripwire(ir, result.objective) is True
