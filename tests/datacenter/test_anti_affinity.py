"""Task 5: dc:anti_affinity — closed/total instance-invariant checker + Z3 mirror.

B-4 (same classification as ``dc:power_cap``): in v1 the ``fault_domain_of``
replica->fault-domain assignment is a FIXED instance fact (placement is not a
plan decision), so ``dc:anti_affinity`` is STRUCTURAL (instance-level /
plan-independent). Its kind (``"anti_affinity"``) goes in
``structural_rule_kinds`` + the id (``"dc:anti_affinity"``) in
``known_rule_ids`` (NOT ``evaluated_rule_ids``). A checker predicate STILL runs
as an instance-invariant guard (it flags two replicas sharing a fault domain)
and is Z3-mirrored (``fd[r1] != fd[r2]`` per pair).

B-5 (TOTAL param reads): every param via ``p.get(...)`` with a fail-closed
deterministic single violation — a missing replica->fd mapping maps to a
DISTINCT sentinel fd-per-replica so an OMITTED mapping fails CLOSED as a
collision-with-unknown rather than vacuously passing; never a ``KeyError``.
"""
from __future__ import annotations

import copy

import pytest

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
from feasible.checker.checker import check
from feasible.domains import get_domain
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
from feasible.smt.attest import attest_feasibility


def _ir_with_anti_affinity(
    *, replicas: list[str], fault_domain_of: dict[str, str], group_id: str = "agA",
) -> FCIR:
    """A shape-valid datacenter IR carrying ONE HARD/PLAN_CONSTRAINT dc:anti_affinity
    rule over ``replicas`` (each replica -> one op on its own machine so
    validate_plan_shape passes; the affinity topology lives entirely in the params:
    the replica->fault-domain assignment is a FIXED instance fact in v1)."""
    units = sorted(set(replicas))
    jobs = [Job(id=u, product=u, family="replica", qty=1, due_date=4, priority=3) for u in units]
    ops = [Operation(op_id=u, job_id=u, seq=0, eligible_machines=[u], duration=1) for u in units]
    inst = Instance(jobs=jobs, operations=ops, machines=list(units),
                    setup_matrix={}, maintenance=[], horizon=4)
    rule = Rule(
        rule_id="dc:anti_affinity", kind="anti_affinity",
        params={
            "group_id": group_id, "replicas": list(replicas),
            "fault_domain_of": {u: fd for u, fd in sorted(fault_domain_of.items())},
        },
        severity=Severity.HARD, clause_kind=ClauseKind.OBLIGATION,
        compile_mode=CompileMode.PLAN_CONSTRAINT, resolution_class="EFFICIENCY",
        exception_mode=ExceptionMode.NONE,
        provenance=Provenance(spans=[TextSpan(quoted_text="anti-affinity (test)", role="modeling_decision")]),
    )
    return FCIR(rules=[rule], instance=inst, domain_id="datacenter")


def _plan(ir: FCIR) -> Plan:
    return Plan(assignments={op.op_id: (0, op.eligible_machines[0]) for op in ir.instance.operations})


def test_anti_affinity_distinct_fault_domains_pass():
    # two replicas in DISTINCT fault domains -> NO violation, Z3 SAT.
    ir = _ir_with_anti_affinity(replicas=["A", "B"], fault_domain_of={"A": "fd1", "B": "fd2"})
    vs = [v for v in check(_plan(ir), ir).violations if v.rule_id == "dc:anti_affinity"]
    assert vs == []
    assert attest_feasibility(_plan(ir), ir).feasible is True


def test_anti_affinity_shared_fault_domain_is_flagged():
    # two replicas SHARING a fault domain -> flagged with the shared fd in the witness.
    ir = _ir_with_anti_affinity(replicas=["A", "B"], fault_domain_of={"A": "fd1", "B": "fd1"})
    vs = [v for v in check(_plan(ir), ir).violations if v.rule_id == "dc:anti_affinity"]
    assert vs
    w = vs[0].counter_witness
    assert w["group_id"] == "agA"
    assert sorted(w["replicas"]) == ["A", "B"]
    assert w["shared_fault_domain"] == "fd1"
    assert vs[0].witness_kind == "anti_affinity" and vs[0].witness_version == "v1"


def test_anti_affinity_z3_unsat_for_collision():
    ir = _ir_with_anti_affinity(replicas=["A", "B"], fault_domain_of={"A": "fd1", "B": "fd1"})
    assert attest_feasibility(_plan(ir), ir).feasible is False


def test_anti_affinity_three_replicas_one_collision_pair():
    # A,B share fd1; C in fd2 -> exactly the (A,B) pair flagged (not A/C or B/C).
    ir = _ir_with_anti_affinity(
        replicas=["A", "B", "C"],
        fault_domain_of={"A": "fd1", "B": "fd1", "C": "fd2"},
    )
    vs = [v for v in check(_plan(ir), ir).violations if v.rule_id == "dc:anti_affinity"]
    pairs = {tuple(sorted(v.counter_witness["replicas"])) for v in vs}
    assert pairs == {("A", "B")}
    assert all(v.counter_witness["shared_fault_domain"] == "fd1" for v in vs)


def test_anti_affinity_is_structural_not_evaluated():
    # B-4: kind in structural_rule_kinds + id in known_rule_ids, NOT evaluated_rule_ids.
    _, verifier = get_domain("datacenter")
    assert "anti_affinity" in verifier.structural_rule_kinds
    assert "dc:anti_affinity" in verifier.known_rule_ids
    assert "dc:anti_affinity" not in verifier.evaluated_rule_ids
    assert "anti_affinity" in verifier.rule_kinds


def test_anti_affinity_active_rule_is_supported_no_unsupported_violation():
    # A HARD/PLAN_CONSTRAINT structural-kind rule is SUPPORTED (kind in
    # structural_rule_kinds) -> no R-UNSUPPORTED-RULE, yet its predicate still runs.
    ir = _ir_with_anti_affinity(replicas=["A", "B"], fault_domain_of={"A": "fd1", "B": "fd2"})
    res = check(_plan(ir), ir)
    assert not any(v.rule_id == "R-UNSUPPORTED-RULE" for v in res.violations)
    assert res.passed is True


def test_anti_affinity_witness_round_trips_schema():
    ir = _ir_with_anti_affinity(replicas=["A", "B"], fault_domain_of={"A": "fd1", "B": "fd1"})
    vs = [v for v in check(_plan(ir), ir).violations if v.rule_id == "dc:anti_affinity"]
    w = vs[0].counter_witness
    model = validate_witness("anti_affinity", w)
    assert model.model_dump(mode="json") == w


@pytest.mark.parametrize("param", ["group_id", "replicas"])
def test_anti_affinity_missing_required_param_fails_closed_without_raising(param):
    # B-5: a self-signed cert omitting a required param must NOT crash check()
    # (an uncaught KeyError in check_predicates is a crash-DoS in verify_plan_cert).
    ir = _ir_with_anti_affinity(replicas=["A", "B"], fault_domain_of={"A": "fd1", "B": "fd2"})
    bad = copy.deepcopy(ir)
    del bad.rule("dc:anti_affinity").params[param]
    res = check(_plan(bad), bad)              # must NOT raise
    assert res.passed is False                # fail-closed
    assert any(v.rule_id == "dc:anti_affinity" for v in res.violations)


def test_anti_affinity_missing_fd_mapping_fails_closed_as_collision_with_unknown():
    # B-5: an OMITTED replica->fd mapping must FAIL CLOSED (a distinct sentinel
    # fd-per-replica means an unknown placement reads as a potential collision,
    # never a vacuous pass). Here BOTH replicas lack a mapping -> they cannot be
    # proven in distinct fault domains -> flagged. Never a KeyError.
    ir = _ir_with_anti_affinity(replicas=["A", "B"], fault_domain_of={})
    res = check(_plan(ir), ir)                 # must NOT raise
    vs = [v for v in res.violations if v.rule_id == "dc:anti_affinity"]
    assert vs                                  # fail-closed, never a silent pass
    assert res.passed is False


def test_anti_affinity_partial_unmapped_fails_closed_in_checker():
    # B-5 partial case: ONE replica mapped (A->fd1), the OTHER unmapped (B). The
    # unmapped placement could be anywhere — including fd1 — so the pair CANNOT be
    # proven distinct. The checker MUST flag it (fail closed), never a vacuous pass.
    ir = _ir_with_anti_affinity(replicas=["A", "B"], fault_domain_of={"A": "fd1"})
    res = check(_plan(ir), ir)
    vs = [v for v in res.violations if v.rule_id == "dc:anti_affinity"]
    assert vs                                  # fail-closed
    assert res.passed is False
    assert {tuple(sorted(v.counter_witness["replicas"])) for v in vs} == {("A", "B")}


def test_anti_affinity_z3_agrees_with_checker_on_partial_unmapped():
    # The Z3 mirror MUST fail closed on the SAME partial-unmapped pair the checker
    # flags: a mapped-vs-unmapped pair is NOT provably distinct, so the attestation
    # must be UNSAT (infeasible), matching the checker's violation. (Regression for
    # the shared -1 sentinel divergence where 0 != -1 read as SAT / no collision.)
    ir = _ir_with_anti_affinity(replicas=["A", "B"], fault_domain_of={"A": "fd1"})
    vs = [v for v in check(_plan(ir), ir).violations if v.rule_id == "dc:anti_affinity"]
    assert vs                                  # checker flags it ...
    assert attest_feasibility(_plan(ir), ir).feasible is False  # ... and Z3 agrees


def test_anti_affinity_three_replicas_partial_unmapped_isolates_unknown_pairs():
    # A->fd1, B->fd2 (distinct, known), C unmapped. Only pairs TOUCHING the unknown
    # replica C fail closed; the fully-known distinct pair (A,B) does NOT collide.
    ir = _ir_with_anti_affinity(
        replicas=["A", "B", "C"], fault_domain_of={"A": "fd1", "B": "fd2"},
    )
    vs = [v for v in check(_plan(ir), ir).violations if v.rule_id == "dc:anti_affinity"]
    pairs = {tuple(sorted(v.counter_witness["replicas"])) for v in vs}
    assert pairs == {("A", "C"), ("B", "C")}   # exactly the unknown-touching pairs
    assert attest_feasibility(_plan(ir), ir).feasible is False  # Z3 agrees (UNSAT)
