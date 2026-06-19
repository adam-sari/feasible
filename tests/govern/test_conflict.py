from __future__ import annotations

from feasible.conflict.policy import MANUFACTURING_POLICY
from feasible.govern.conflict import (
    active_after_resolution,
    detect_normative_conflicts,
    resolve_conflicts,
)
from feasible.ir.domain import (
    ClauseKind,
    CompileMode,
    ExceptionMode,
    FCIR,
    Provenance,
    Rule,
    Severity,
    TextSpan,
)
from feasible.scenario import build_scenario_ir


def _permission(exception: ExceptionMode = ExceptionMode.NONE, resclass: str = "CUSTOMER_PRIORITY") -> Rule:
    return Rule(
        rule_id="R-4.4", kind="permission",
        params={"target_rule": "R-SETUP", "scope_machine": "Filler-1", "scope_priority": 1},
        severity=Severity.SOFT, clause_kind=ClauseKind.PERMISSION,
        compile_mode=CompileMode.CONFLICT_ONLY, resolution_class=resclass,
        exception_mode=exception,
        provenance=Provenance(spans=[TextSpan(
            quoted_text="Filler-1 may perform back-to-back family changes without an intervening cleanout",
            role="primary_normative")]),
    )


def _ir_with_permission(perm: Rule) -> FCIR:
    base = build_scenario_ir()
    return FCIR(rules=[*base.rules, perm], instance=base.instance)


def test_detect_normative_conflict() -> None:
    ir = _ir_with_permission(_permission())
    conflicts = detect_normative_conflicts(ir)
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c.obligation_id == "R-SETUP" and c.permission_id == "R-4.4"
    # both clause ids appear in the recorded Z3 core
    assert "R-SETUP" in c.z3_core and "R-4.4" in c.z3_core


def test_auto_resolve_safety_wins() -> None:
    ir = _ir_with_permission(_permission())
    conflicts = detect_normative_conflicts(ir)
    res = resolve_conflicts(ir, conflicts, MANUFACTURING_POLICY)
    assert len(res) == 1
    r = res[0]
    assert r.resolution_mode == "AUTO_BY_POLICY"
    assert r.dropped_rule_id == "R-4.4"
    assert "SAFETY_SANITATION(100)" in r.rationale and "CUSTOMER_PRIORITY(50)" in r.rationale


def test_active_set_drops_permission_keeps_pack_feasible() -> None:
    ir = _ir_with_permission(_permission())
    conflicts = detect_normative_conflicts(ir)
    res = resolve_conflicts(ir, conflicts, MANUFACTURING_POLICY)
    active = active_after_resolution(ir, res)
    assert ir.rule("R-4.4") is not None  # still in the rule pack universe
    assert active.rule("R-4.4") is None  # inactive for the plan
    assert active.rule("R-SETUP") is not None  # the safety obligation stays


def test_exception_marker_escalates() -> None:
    ir = _ir_with_permission(_permission(exception=ExceptionMode.HUMAN_OVERRIDE))
    conflicts = detect_normative_conflicts(ir)
    res = resolve_conflicts(ir, conflicts, MANUFACTURING_POLICY)
    assert res[0].resolution_mode == "ESCALATE"
    assert res[0].dropped_rule_id is None


def test_equal_priority_escalates() -> None:
    # give the permission the same priority class as the obligation
    ir = _ir_with_permission(_permission(resclass="SAFETY_SANITATION"))
    conflicts = detect_normative_conflicts(ir)
    res = resolve_conflicts(ir, conflicts, MANUFACTURING_POLICY)
    assert res[0].resolution_mode == "ESCALATE"


def test_no_conflict_when_scope_not_realizable() -> None:
    # a permission scoped to a machine with no allergen work -> no conflict
    perm = _permission()
    perm.params["scope_machine"] = "Labeler"  # labels of allergen jobs exist, but fill-level scope differs
    base = build_scenario_ir()
    # remove allergen label eligibility realization by scoping to a machine with no allergen *fill*
    perm.params["scope_machine"] = "NoSuchMachine"
    ir = FCIR(rules=[*base.rules, perm], instance=base.instance)
    assert detect_normative_conflicts(ir) == []
