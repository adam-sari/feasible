from __future__ import annotations

from pathlib import Path

from ortools.sat.python import cp_model

from feasible.compile.cpsat import build_model, extract_plan, freeze_l1_and_minimize_changeover
from feasible.ingest.golden import load_golden_ir
from feasible.ir.domain import (
    ClauseKind,
    CompileMode,
    FCIR,
    Instance,
    Job,
    Operation,
    OpClass,
    Provenance,
    Rule,
    Severity,
    TextSpan,
)

MINI = Path(__file__).resolve().parent.parent / "fixtures" / "mini"


def _mini_ir() -> FCIR:
    return load_golden_ir(MINI / "golden_ir.json", {"shop_rules.md": (MINI / "shop_rules.md").read_text(encoding="utf-8")})


def _rule(rule_id: str, kind: str, clause: ClauseKind, params: dict | None = None) -> Rule:
    return Rule(
        rule_id=rule_id,
        kind=kind,
        params=params or {},
        severity=Severity.HARD,
        clause_kind=clause,
        compile_mode=CompileMode.PLAN_CONSTRAINT,
        resolution_class="SAFETY_SANITATION",
        provenance=Provenance(spans=[TextSpan(quoted_text=f"{rule_id} clause")]),
    )


def _single_machine_cleanout_ir() -> FCIR:
    """One machine M; an Allergen job with a tight due date that must run before
    a Standard job -> forces an Allergen->Standard cleanout."""
    inst = Instance(
        jobs=[
            Job(id="JA", product="Peanut", family="Allergen", qty=1, due_date=150, priority=1),
            Job(id="JS", product="Mild", family="Standard", qty=1, due_date=5000, priority=3),
        ],
        operations=[
            Operation(op_id="JA-op", job_id="JA", seq=0, eligible_machines=["M"], duration=100),
            Operation(op_id="JS-op", job_id="JS", seq=0, eligible_machines=["M"], duration=100),
        ],
        machines=["M"],
        setup_matrix={"Allergen|Standard": 90},
        maintenance=[],
        horizon=5000,
    )
    rules = [
        _rule("R-ROUTING", "routing_precedence", ClauseKind.OBLIGATION),
        _rule("R-NOOVERLAP", "no_overlap", ClauseKind.PROHIBITION),
        _rule("R-SETUP", "setup_cleanout", ClauseKind.OBLIGATION, {"cleanout_minutes": 90}),
        _rule("R-6.1-NIGHT-CLEANOUT", "night_cleanout", ClauseKind.PROHIBITION,
              {"day_start": 0, "day_end": 960, "night_start": 960, "night_end": 1440}),
    ]
    return FCIR(rules=rules, instance=inst)


def _solve(ir: FCIR):
    m, vi = build_model(ir)
    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = 20.0
    status = freeze_l1_and_minimize_changeover(m, solver, vi)
    return solver, status, vi


def test_varindex_has_pinned_fields() -> None:
    _, vi = build_model(_mini_ir())
    for field in (
        "starts", "ends", "presence", "machine_presence", "arcs",
        "cleanout_intervals", "tardiness", "weighted_tardiness", "total_changeover",
        "horizon", "ir",
    ):
        assert hasattr(vi, field)
    # machine_presence is keyed by (op_id, machine)
    assert ("J1-mix", "Mixer-A") in vi.machine_presence


def test_mini_solves_and_extracts_plan() -> None:
    solver, status, vi = _solve(_mini_ir())
    assert status in (cp_model.OPTIMAL, cp_model.FEASIBLE)
    plan = extract_plan(solver, vi)
    # all 9 ops assigned to an eligible machine within the horizon
    assert len(plan.assignments) == 9
    for op in vi.ir.instance.operations:
        start, machine = plan.assignments[op.op_id]
        assert machine in op.eligible_machines
        assert 0 <= start <= vi.horizon


def test_routing_precedence_respected() -> None:
    solver, status, vi = _solve(_mini_ir())
    plan = extract_plan(solver, vi)
    # J1: mix -> fill -> label
    assert plan.start("J1-mix") + 31 <= plan.start("J1-fill")
    assert plan.start("J1-fill") + 19 <= plan.start("J1-label")


def test_cleanout_materialized_and_day_shift() -> None:
    solver, status, vi = _solve(_single_machine_cleanout_ir())
    assert status in (cp_model.OPTIMAL, cp_model.FEASIBLE)
    plan = extract_plan(solver, vi)
    # the tight allergen due date forces JA before JS -> a cleanout exists
    assert len(plan.cleanouts) == 1
    mc, cstart, cend, reason = plan.cleanouts[0]
    assert mc == "M"
    assert cend - cstart == 90
    # cleanout sits fully inside a day window [0, 960) modulo 1440
    assert (cstart % 1440) + 90 <= 960
    # and it is between JA (allergen) and JS (standard)
    assert plan.start("JA-op") < cstart
    assert cstart + 90 <= plan.start("JS-op")


def test_lexicographic_prefers_low_tardiness() -> None:
    solver, status, vi = _solve(_single_machine_cleanout_ir())
    # allergen job (priority 1) should not be late
    ja_end = solver.value(vi.ends["JA-op"])
    assert ja_end <= 150  # met its due date
