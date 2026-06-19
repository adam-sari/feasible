from __future__ import annotations

from pathlib import Path

from feasible.checker.checker import check
from feasible.cert.textcert import text_certificate
from feasible.ingest.golden import load_golden_ir
from feasible.ir.domain import (
    FCIR,
    Instance,
    Job,
    Operation,
    Plan,
)
from feasible.solve.orchestrate import (
    late_priority_orders,
    recompute_objective,
    solve,
    total_changeover_time,
    weighted_tardiness,
)

MINI = Path(__file__).resolve().parent.parent / "fixtures" / "mini"


def _mini_ir() -> FCIR:
    return load_golden_ir(MINI / "golden_ir.json", {"shop_rules.md": (MINI / "shop_rules.md").read_text(encoding="utf-8")})


def _kpi_ir() -> FCIR:
    inst = Instance(
        jobs=[
            Job(id="J1", product="A", family="Allergen", qty=1, due_date=100, priority=1),
            Job(id="J2", product="B", family="Standard", qty=1, due_date=100, priority=3),
        ],
        operations=[
            Operation(op_id="J1-op", job_id="J1", seq=0, eligible_machines=["M"], duration=50),
            Operation(op_id="J2-op", job_id="J2", seq=0, eligible_machines=["M"], duration=50),
        ],
        machines=["M"], setup_matrix={"Allergen|Standard": 90}, maintenance=[], horizon=5000,
    )
    return FCIR(rules=[], instance=inst)


# ---- walking skeleton end-to-end (golden IR -> solve -> checker -> cert) ----
def test_end_to_end_mini_passes() -> None:
    ir = _mini_ir()
    result = solve(ir, max_seconds=20.0)
    assert result.status in ("OPTIMAL", "FEASIBLE")
    assert result.plan is not None
    chk = check(result.plan, ir)
    assert chk.passed, [v.message for v in chk.violations]

    cert = text_certificate(ir, result.plan, result, chk)
    assert "PASS" in cert
    assert "objective" in cert
    assert "incumbent" in cert


# ---- independent objective / KPI recompute ---------------------------------
def test_weighted_tardiness_recompute() -> None:
    ir = _kpi_ir()
    # J1 (allergen, prio1, due100) ends at 200 -> tard 100, weight 3 -> 300
    # J2 (standard, prio3, due100) ends at 100 -> tard 0
    plan = Plan(assignments={"J1-op": (150, "M"), "J2-op": (50, "M")})
    assert weighted_tardiness(ir, plan) == 300


def test_late_priority_orders_count() -> None:
    ir = _kpi_ir()
    plan = Plan(assignments={"J1-op": (150, "M"), "J2-op": (50, "M")})
    # only J1 is late (ends 200 > 100)
    assert late_priority_orders(ir, plan) == 1


def test_total_changeover_time_recompute() -> None:
    ir = _kpi_ir()
    # J1 (allergen) then J2 (standard) on M -> one Allergen->Standard = 90 setup
    plan = Plan(assignments={"J1-op": (0, "M"), "J2-op": (140, "M")})
    assert total_changeover_time(ir, plan) == 90
    # reversed: Standard->Allergen = 0
    plan2 = Plan(assignments={"J2-op": (0, "M"), "J1-op": (60, "M")})
    assert total_changeover_time(ir, plan2) == 0


def test_recompute_objective_tuple() -> None:
    ir = _kpi_ir()
    plan = Plan(assignments={"J1-op": (0, "M"), "J2-op": (140, "M")})
    assert recompute_objective(ir, plan) == (weighted_tardiness(ir, plan), 90)


def test_solve_objective_matches_recompute() -> None:
    ir = _mini_ir()
    result = solve(ir, max_seconds=20.0)
    assert result.plan is not None
    assert result.objective == recompute_objective(ir, result.plan)
