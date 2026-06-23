"""Task 6: every datacenter witness kind round-trips through its registered schema.

For each witness kind a dc:* predicate emits — ``coverage_floor`` (the redundancy
floor), ``power_cap``, ``maintenance_window``, ``anti_affinity``, and the
fail-closed ``missing_param`` — serialize → ``validate_witness(kind, w)`` →
``model_dump(mode="json")`` is byte-equal to the original, and ``witness_version
== "v1"``. ``validate_witness("bogus", {})`` raises ``KeyError`` (the registry is
fail-closed: an unregistered kind is rejected, never validated).
"""
from __future__ import annotations

import pytest

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter witness schemas)
from feasible.checker.checker import check
from feasible.domains.base import validate_witness
from feasible.ir.domain import (
    ClauseKind,
    CompileMode,
    ExceptionMode,
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


def _rule(rule_id: str, kind: str, params: dict, *,
          severity: Severity = Severity.HARD,
          mode: CompileMode = CompileMode.PLAN_CONSTRAINT) -> Rule:
    return Rule(
        rule_id=rule_id, kind=kind, params=params,
        severity=severity, clause_kind=ClauseKind.OBLIGATION, compile_mode=mode,
        resolution_class="SAFETY_SANITATION" if rule_id == "dc:redundancy_floor" else "EFFICIENCY",
        exception_mode=ExceptionMode.NONE,
        provenance=Provenance(spans=[TextSpan(quoted_text=f"{rule_id} (test)", role="modeling_decision")]),
    )


def _ir(units: list[str], rules: list[Rule], *, horizon: int = 4) -> FCIR:
    jobs = [Job(id=u, product=u, family="unit", qty=1, due_date=horizon, priority=3) for u in units]
    ops = [Operation(op_id=u, job_id=u, seq=0, eligible_machines=[u], duration=1) for u in units]
    inst = Instance(jobs=jobs, operations=ops, machines=list(units),
                    setup_matrix={}, maintenance=[], horizon=horizon)
    return FCIR(rules=rules, instance=inst, domain_id="datacenter")


def _plan(ir: FCIR) -> Plan:
    return Plan(assignments={op.op_id: (0, op.eligible_machines[0]) for op in ir.instance.operations})


def _witness_of(ir: FCIR, plan: Plan, rule_id: str) -> dict:
    vs = [v for v in check(plan, ir).violations if v.rule_id == rule_id]
    assert vs, f"expected a {rule_id} violation to harvest a witness"
    return vs[0]


def test_coverage_floor_witness_round_trips():
    # a redundancy group breaching at one timestep yields a coverage_floor witness.
    ir = _ir(
        ["U1", "U2", "U3"],
        [_rule("dc:redundancy_floor", "redundancy_floor", {
            "group_id": "G1", "units": ["U1", "U2", "U3"], "floor": 3, "horizon": 4,
            "maintenance": {"U3": [[1, 2]]},  # U3 down at t=1 -> available 2 < floor 3
        })],
    )
    v = _witness_of(ir, _plan(ir), "dc:redundancy_floor")
    assert v.witness_kind == "coverage_floor" and v.witness_version == "v1"
    model = validate_witness("coverage_floor", v.counter_witness)
    assert model.model_dump(mode="json") == v.counter_witness


def test_power_cap_witness_round_trips():
    ir = _ir(
        ["U1", "U2"],
        [_rule("dc:power_cap", "power_cap", {
            "cap_id": "CAP", "scope_units": ["U1", "U2"], "cap_kw": 100,
            "per_member_pct": 80, "draws": {"U1": 60, "U2": 60},  # sum 120 > 100
        })],
    )
    v = _witness_of(ir, _plan(ir), "dc:power_cap")
    assert v.witness_kind == "power_cap" and v.witness_version == "v1"
    model = validate_witness("power_cap", v.counter_witness)
    assert model.model_dump(mode="json") == v.counter_witness


def test_maintenance_window_witness_round_trips():
    ir = _ir(
        ["pathA"],
        [_rule("dc:maintenance_window", "maintenance_window", {
            "path_id": "pathA", "forbidden": [[3, 7]], "derate_kw": {},
        })],
        horizon=10,
    )
    plan = Plan(assignments={"pathA": (4, "pathA")})  # task [4,6) inside [3,7)
    # the op duration is 1 here; widen by giving the op duration 2 via the instance.
    ir.instance.operations[0].duration = 2
    v = _witness_of(ir, plan, "dc:maintenance_window")
    assert v.witness_kind == "maintenance_window" and v.witness_version == "v1"
    model = validate_witness("maintenance_window", v.counter_witness)
    assert model.model_dump(mode="json") == v.counter_witness


def test_anti_affinity_witness_round_trips():
    ir = _ir(
        ["U1", "U2"],
        [_rule("dc:anti_affinity", "anti_affinity", {
            "group_id": "AA", "replicas": ["U1", "U2"],
            "fault_domain_of": {"U1": "FD-A", "U2": "FD-A"},  # shared -> collision
        })],
    )
    v = _witness_of(ir, _plan(ir), "dc:anti_affinity")
    assert v.witness_kind == "anti_affinity" and v.witness_version == "v1"
    model = validate_witness("anti_affinity", v.counter_witness)
    assert model.model_dump(mode="json") == v.counter_witness


def test_missing_param_witness_round_trips():
    # the fail-closed missing-param violation carries a missing_param witness that
    # MUST round-trip through a REGISTERED schema (an unregistered witness kind a
    # predicate can emit is a fail-closed hole: validate_witness would KeyError).
    ir = _ir(
        ["U1", "U2", "U3"],
        [_rule("dc:redundancy_floor", "redundancy_floor", {
            "group_id": "G1", "units": ["U1", "U2", "U3"], "floor": 2, "horizon": 4,
            "maintenance": {},
        })],
    )
    del ir.rule("dc:redundancy_floor").params["floor"]
    v = _witness_of(ir, _plan(ir), "dc:redundancy_floor")
    assert v.witness_kind == "missing_param" and v.witness_version == "v1"
    model = validate_witness("missing_param", v.counter_witness)
    assert model.model_dump(mode="json") == v.counter_witness


def test_validate_witness_bogus_kind_is_failclosed():
    with pytest.raises(KeyError):
        validate_witness("bogus_witness_kind", {})
