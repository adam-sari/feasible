from __future__ import annotations

import pytest
from pydantic import ValidationError

from feasible.ir.desugar import desugar, tardiness_weight
from feasible.ir.domain import (
    CellRef,
    ClauseKind,
    CompileMode,
    ExceptionMode,
    FCIR,
    Instance,
    Job,
    Operation,
    OpClass,
    Plan,
    Provenance,
    Rule,
    Severity,
    TextSpan,
    TrustTier,
)
from feasible.ir.schema import export_json_schema


def _span(text: str = "no changeovers during night shift") -> Provenance:
    return Provenance(spans=[TextSpan(quoted_text=text)])


def _hard_rule(rule_id: str = "R-6.1-NIGHT-CLEANOUT") -> Rule:
    return Rule(
        rule_id=rule_id,
        kind="night_cleanout",
        severity=Severity.HARD,
        clause_kind=ClauseKind.PROHIBITION,
        compile_mode=CompileMode.PLAN_CONSTRAINT,
        resolution_class="SAFETY_SANITATION",
        provenance=_span(),
    )


def _tiny_instance() -> Instance:
    return Instance(
        jobs=[Job(id="J1", product="P1", family="Allergen", qty=1, due_date=600, priority=1)],
        operations=[
            Operation(op_id="J1-mix", job_id="J1", seq=0, eligible_machines=["Mixer-A"], duration=40),
            Operation(op_id="J1-fill", job_id="J1", seq=1, eligible_machines=["Filler-1"], duration=30),
        ],
        machines=["Mixer-A", "Filler-1"],
        setup_matrix={"Allergen|Standard": 90},
        maintenance=[("Filler-2", 1200, 1440)],
        horizon=4320,
    )


def test_rule_roundtrip() -> None:
    r = _hard_rule()
    again = Rule.model_validate(r.model_dump())
    assert again == r


def test_fcir_json_roundtrip() -> None:
    ir = FCIR(rules=[_hard_rule()], instance=_tiny_instance())
    blob = ir.model_dump(mode="json")
    again = FCIR.model_validate(blob)
    assert again == ir


def test_permission_must_be_conflict_only() -> None:
    with pytest.raises(ValidationError):
        Rule(
            rule_id="R-4.4",
            kind="permission",
            severity=Severity.SOFT,
            clause_kind=ClauseKind.PERMISSION,
            compile_mode=CompileMode.PLAN_CONSTRAINT,  # illegal for a permission
            provenance=_span("Filler-1 may perform back-to-back changes"),
        )


def test_permission_conflict_only_is_accepted() -> None:
    r = Rule(
        rule_id="R-4.4",
        kind="permission",
        severity=Severity.SOFT,
        clause_kind=ClauseKind.PERMISSION,
        compile_mode=CompileMode.CONFLICT_ONLY,
        provenance=_span("Filler-1 may perform back-to-back changes"),
    )
    assert r.compile_mode == CompileMode.CONFLICT_ONLY


def test_empty_quoted_text_rejected() -> None:
    with pytest.raises(ValidationError):
        TextSpan(quoted_text="   ")


def test_cellref_in_provenance() -> None:
    prov = Provenance(spans=[CellRef(sheet="orders", a1="B4")])
    again = Provenance.model_validate(prov.model_dump())
    assert again.spans[0].kind == "cell"


def test_setup_accessor() -> None:
    inst = _tiny_instance()
    assert inst.setup("Allergen", "Standard") == 90
    assert inst.setup("Standard", "Spicy") == 0


def test_fcir_helpers() -> None:
    ir = FCIR(rules=[_hard_rule()], instance=_tiny_instance())
    assert ir.has_active("R-6.1-NIGHT-CLEANOUT") is True
    assert ir.has_active("R-NONEXISTENT") is False
    assert len(ir.hard_plan_rules()) == 1


def test_plan_accessors() -> None:
    p = Plan(assignments={"J1-mix": (0, "Mixer-A")}, cleanouts=[("Mixer-A", 100, 190, "allergen")])
    assert p.start("J1-mix") == 0
    assert p.machine("J1-mix") == "Mixer-A"
    again = Plan.model_validate(p.model_dump(mode="json"))
    assert again == p


def test_desugar_faithfulness() -> None:
    ir = FCIR(rules=[_hard_rule()], instance=_tiny_instance())
    k = desugar(ir)
    # one routing precedence J1-mix -> J1-fill
    assert any(p.before_op == "J1-mix" and p.after_op == "J1-fill" for p in k.precedences)
    # a no-overlap per machine
    assert {n.machine for n in k.no_overlaps} == {"Mixer-A", "Filler-1"}
    # tardiness weight = 4 - priority, priority 1 -> 3
    assert any(sp.weight == 3 for sp in k.soft_penalties)


def test_tardiness_weight() -> None:
    assert tardiness_weight(1) == 3
    assert tardiness_weight(3) == 1


def test_op_class_default() -> None:
    o = Operation(op_id="x", job_id="J", seq=0, eligible_machines=["M"], duration=10)
    assert o.op_class == OpClass.PROCESS


def test_schema_export() -> None:
    schema = export_json_schema()
    assert schema["type"] == "object"
    assert "rules" in schema["properties"]
    assert "instance" in schema["properties"]


def test_trust_tier_enum() -> None:
    assert TrustTier.T4.value == "T4"
    assert ExceptionMode.NONE.value == "NONE"
