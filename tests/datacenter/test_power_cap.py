"""Task 2: dc:power_cap — closed/total instance-invariant checker + Z3 mirror.

B-4: in v1 the per-rack ``draws`` are FIXED instance facts (a rack's nameplate
draw is not a plan decision), so ``dc:power_cap`` is STRUCTURAL (instance-level /
plan-independent). Its kind goes in ``structural_rule_kinds`` + the id in
``known_rule_ids`` (NOT ``evaluated_rule_ids``). A checker predicate STILL runs
(a structural-kind rule MAY carry one) — it validates the instance-level cap
invariant deterministically and is Z3-mirrored.
"""
from __future__ import annotations

import copy

import pytest

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
from feasible.checker.checker import check
from feasible.domains import get_domain
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
from feasible.smt.attest import attest_feasibility


def _ir_with_power_cap(*, cap_kw: int, draws: dict[str, int], per_member_pct: int) -> FCIR:
    """A shape-valid datacenter IR carrying ONE HARD/PLAN_CONSTRAINT dc:power_cap
    rule over the racks in ``draws`` (each rack -> one op on its own machine so
    validate_plan_shape passes; the cap topology lives entirely in the params)."""
    units = sorted(draws)
    jobs = [Job(id=u, product=u, family="rack", qty=1, due_date=4, priority=3) for u in units]
    ops = [Operation(op_id=u, job_id=u, seq=0, eligible_machines=[u], duration=1) for u in units]
    inst = Instance(jobs=jobs, operations=ops, machines=list(units),
                    setup_matrix={}, maintenance=[], horizon=4)
    rule = Rule(
        rule_id="dc:power_cap", kind="power_cap",
        params={
            "cap_id": "capA", "scope_units": list(units), "cap_kw": int(cap_kw),
            "per_member_pct": int(per_member_pct),
            "draws": {u: int(kw) for u, kw in sorted(draws.items())},
        },
        severity=Severity.HARD, clause_kind=ClauseKind.OBLIGATION,
        compile_mode=CompileMode.PLAN_CONSTRAINT, resolution_class="EFFICIENCY",
        exception_mode=ExceptionMode.NONE,
        provenance=Provenance(spans=[TextSpan(quoted_text="power cap (test)", role="modeling_decision")]),
    )
    return FCIR(rules=[rule], instance=inst, domain_id="datacenter")


def _plan(ir: FCIR) -> Plan:
    return Plan(assignments={op.op_id: (0, op.eligible_machines[0]) for op in ir.instance.operations})


def test_power_cap_at_cap_and_within_pct_passes():
    # sum == cap (100), each member 50 <= 80% of 100 -> NO violation.
    ir = _ir_with_power_cap(cap_kw=100, draws={"R1": 50, "R2": 50}, per_member_pct=80)
    vs = [v for v in check(_plan(ir), ir).violations if v.rule_id == "dc:power_cap"]
    assert vs == []
    assert attest_feasibility(_plan(ir), ir).feasible is True


def test_power_cap_aggregate_over_is_flagged():
    ir = _ir_with_power_cap(cap_kw=100, draws={"R1": 60, "R2": 60}, per_member_pct=80)  # sum 120 > 100
    vs = [v for v in check(_plan(ir), ir).violations if v.rule_id == "dc:power_cap"]
    assert vs and vs[0].counter_witness["draw"] == 120 and vs[0].counter_witness["cap"] == 100
    assert vs[0].witness_kind == "power_cap" and vs[0].witness_version == "v1"


def test_power_cap_per_member_pct_over_is_flagged_even_under_aggregate():
    ir = _ir_with_power_cap(cap_kw=100, draws={"R1": 90, "R2": 5}, per_member_pct=80)  # sum 95<=100 but R1=90>80
    vs = [v for v in check(_plan(ir), ir).violations if v.rule_id == "dc:power_cap"]
    assert any(v.counter_witness.get("members_over_pct") for v in vs)


def test_power_cap_z3_unsat_when_over():
    ir = _ir_with_power_cap(cap_kw=100, draws={"R1": 60, "R2": 60}, per_member_pct=80)
    assert attest_feasibility(_plan(ir), ir).feasible is False


def test_power_cap_z3_unsat_when_per_member_over():
    ir = _ir_with_power_cap(cap_kw=100, draws={"R1": 90, "R2": 5}, per_member_pct=80)
    assert attest_feasibility(_plan(ir), ir).feasible is False


def test_power_cap_is_structural_not_evaluated():
    # B-4: kind in structural_rule_kinds + id in known_rule_ids, NOT evaluated_rule_ids.
    _, verifier = get_domain("datacenter")
    assert "power_cap" in verifier.structural_rule_kinds
    assert "dc:power_cap" in verifier.known_rule_ids
    assert "dc:power_cap" not in verifier.evaluated_rule_ids
    assert "power_cap" in verifier.rule_kinds


def test_power_cap_active_rule_is_supported_no_unsupported_violation():
    # A HARD/PLAN_CONSTRAINT structural-kind rule is SUPPORTED (kind in
    # structural_rule_kinds) -> no R-UNSUPPORTED-RULE, yet its predicate still runs.
    ir = _ir_with_power_cap(cap_kw=100, draws={"R1": 50, "R2": 50}, per_member_pct=80)
    res = check(_plan(ir), ir)
    assert not any(v.rule_id == "R-UNSUPPORTED-RULE" for v in res.violations)
    assert res.passed is True


@pytest.mark.parametrize("param", ["cap_kw", "scope_units", "per_member_pct", "draws"])
def test_power_cap_missing_param_fails_closed_without_raising(param):
    # B-5: a self-signed cert omitting a required param must NOT crash check()
    # (an uncaught KeyError in check_predicates is a crash-DoS in verify_plan_cert).
    # A missing required param -> deterministic fail-closed violation, never silent pass.
    ir = _ir_with_power_cap(cap_kw=100, draws={"R1": 50, "R2": 50}, per_member_pct=80)
    bad = copy.deepcopy(ir)
    del bad.rule("dc:power_cap").params[param]
    res = check(_plan(bad), bad)              # must NOT raise
    assert res.passed is False                # fail-closed
    assert any(v.rule_id == "dc:power_cap" for v in res.violations)
