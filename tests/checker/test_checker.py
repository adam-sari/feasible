from __future__ import annotations

from pathlib import Path

from ortools.sat.python import cp_model

from feasible.checker.checker import check, machine_sequence, rule_span
from feasible.compile.cpsat import build_model, extract_plan, freeze_l1_and_minimize_changeover
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
        machines=["M"],
        setup_matrix={"Allergen|Standard": 90},
        maintenance=[("M", 2000, 2100)],
        horizon=5000,
    )
    rules = [
        _rule("R-ROUTING", "routing_precedence", ClauseKind.OBLIGATION),
        _rule("R-NOOVERLAP", "no_overlap", ClauseKind.PROHIBITION),
        _rule("R-SETUP", "setup_cleanout", ClauseKind.OBLIGATION),
        _rule("R-MAINT", "maintenance", ClauseKind.PROHIBITION),
        _rule("R-SHIFT", "shift", ClauseKind.OBLIGATION),
        _rule("R-6.1-NIGHT-CLEANOUT", "night_cleanout", ClauseKind.PROHIBITION,
              {"day_start": 0, "day_end": 960, "night_start": 960, "night_end": 1440}),
    ]
    return FCIR(rules=rules, instance=inst)


# ---- machine_sequence ------------------------------------------------------
def test_machine_sequence_canonical_order() -> None:
    plan = Plan(assignments={"b": (50, "M"), "a": (50, "M"), "c": (10, "M")})
    assert machine_sequence(plan, "M") == ["c", "a", "b"]  # (start, op_id) tie-break


# ---- compiler output passes the checker (mini parity) ----------------------
def test_compiler_plan_passes_checker() -> None:
    ir = _mini_ir()
    m, vi = build_model(ir)
    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = 20.0
    status = freeze_l1_and_minimize_changeover(m, solver, vi)
    assert status in (cp_model.OPTIMAL, cp_model.FEASIBLE)
    plan = extract_plan(solver, vi)
    result = check(plan, ir)
    assert result.passed, [v.message for v in result.violations]


# ---- HERO red-team: the incumbent's 23:30 cleanout fails with the §6.1 span -
def test_night_cleanout_caught_with_source_span() -> None:
    ir = _mini_ir()
    plan = Plan(
        assignments={"J1-mix": (0, "Mixer-A")},
        cleanouts=[("Filler-1", 1050, 1140, "cleanout J1->J2")],  # 23:30 -> night
    )
    result = check(plan, ir)
    assert not result.passed
    night = [v for v in result.violations if v.rule_id == "R-6.1-NIGHT-CLEANOUT"]
    assert len(night) == 1
    v = night[0]
    assert v.counter_witness["minute_of_day"] == 1050
    assert v.span is not None
    assert "Cleanouts may only be performed during the day shift" in v.span.quoted_text


def test_day_cleanout_passes_night_rule() -> None:
    ir = _two_op_ir()
    # JA 0-100, day cleanout 100-190, JS 190-290 -> no night violation, no setup gap
    plan = Plan(
        assignments={"JA-op": (0, "M"), "JS-op": (190, "M")},
        cleanouts=[("M", 100, 190, "cleanout JA->JS")],
    )
    result = check(plan, ir)
    assert result.passed, [v.message for v in result.violations]


# ---- boundary fixtures -----------------------------------------------------
def test_cleanout_crossing_2200_is_night() -> None:
    ir = _two_op_ir()
    # cleanout 940-1030 starts in day but crosses 22:00 (960) -> night violation
    plan = Plan(
        assignments={"JA-op": (840, "M"), "JS-op": (1030, "M")},
        cleanouts=[("M", 940, 1030, "cleanout JA->JS")],
    )
    result = check(plan, ir)
    night = [v for v in result.violations if v.rule_id == "R-6.1-NIGHT-CLEANOUT"]
    assert len(night) == 1


def test_cleanout_at_day_boundary_870_passes() -> None:
    ir = _two_op_ir()
    # cleanout 870-960 ends exactly at the day boundary (half-open) -> legal
    plan = Plan(
        assignments={"JA-op": (770, "M"), "JS-op": (960, "M")},
        cleanouts=[("M", 870, 960, "cleanout JA->JS")],
    )
    result = check(plan, ir)
    night = [v for v in result.violations if v.rule_id == "R-6.1-NIGHT-CLEANOUT"]
    assert night == []


# ---- R-SETUP: missing cleanout between families ----------------------------
def test_missing_cleanout_fails_setup() -> None:
    ir = _two_op_ir()
    # JA (allergen) immediately followed by JS (standard), no cleanout
    plan = Plan(assignments={"JA-op": (0, "M"), "JS-op": (100, "M")}, cleanouts=[])
    result = check(plan, ir)
    setup = [v for v in result.violations if v.rule_id == "R-SETUP"]
    assert len(setup) == 1
    assert setup[0].counter_witness["from_op"] == "JA-op"


def test_standard_before_allergen_needs_no_cleanout() -> None:
    ir = _two_op_ir()
    # JS (standard) then JA (allergen): Standard->Allergen setup = 0, no cleanout needed
    plan = Plan(assignments={"JS-op": (0, "M"), "JA-op": (100, "M")}, cleanouts=[])
    result = check(plan, ir)
    assert [v for v in result.violations if v.rule_id == "R-SETUP"] == []


# ---- R-NOOVERLAP -----------------------------------------------------------
def test_overlap_fails() -> None:
    ir = _two_op_ir()
    plan = Plan(assignments={"JA-op": (0, "M"), "JS-op": (50, "M")}, cleanouts=[])
    result = check(plan, ir)
    assert any(v.rule_id == "R-NOOVERLAP" for v in result.violations)


# ---- R-MAINT ---------------------------------------------------------------
def test_maintenance_overlap_fails() -> None:
    ir = _two_op_ir()
    # JS-op 2050-2150 overlaps maintenance [2000,2100)
    plan = Plan(assignments={"JA-op": (0, "M"), "JS-op": (2050, "M")},
                cleanouts=[("M", 100, 190, "cleanout JA->JS")])
    result = check(plan, ir)
    assert any(v.rule_id == "R-MAINT" for v in result.violations)


# ---- R-ROUTING -------------------------------------------------------------
def test_routing_violation_fails() -> None:
    inst = Instance(
        jobs=[Job(id="J", product="P", family="Standard", qty=1, due_date=5000, priority=2)],
        operations=[
            Operation(op_id="J-mix", job_id="J", seq=0, eligible_machines=["M1"], duration=30),
            Operation(op_id="J-fill", job_id="J", seq=1, eligible_machines=["M2"], duration=20),
        ],
        machines=["M1", "M2"], setup_matrix={}, maintenance=[], horizon=5000,
    )
    ir = FCIR(rules=[_rule("R-ROUTING", "routing_precedence", ClauseKind.OBLIGATION)], instance=inst)
    # fill starts before mix ends
    plan = Plan(assignments={"J-mix": (100, "M1"), "J-fill": (0, "M2")})
    result = check(plan, ir)
    assert any(v.rule_id == "R-ROUTING" for v in result.violations)


def test_rule_span_prefers_primary_normative() -> None:
    ir = _mini_ir()
    span = rule_span(ir, "R-6.1-NIGHT-CLEANOUT")
    assert span is not None and span.role == "primary_normative"
