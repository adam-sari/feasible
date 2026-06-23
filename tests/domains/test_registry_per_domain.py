"""Per-domain registry invariants.

The fail-open the registry closes is: a rule_id that is "supported"
(``evaluated_rule_ids``) but not actually WIRED into an evaluator. The design
requires every ``evaluated_rule_id`` be checked in BOTH engines — the polynomial
checker (``check_predicates``) AND the Z3 attestor (``z3_encode``). These tests
make that executable so a future id added to ``evaluated_rule_ids`` without
wiring a predicate fails CI instead of silently failing open.
"""
from __future__ import annotations

import inspect

import pytest
import z3

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
import feasible.domains.manufacturing  # noqa: F401  (registers the manufacturing domain)
from feasible.conflict.policy import MANUFACTURING_POLICY
from feasible.domains import get_domain
from feasible.govern.pipeline import govern_pack
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
from feasible.registry import UnsupportedHardRuleError, assert_all_hard_rules_supported
from feasible.scenario import build_extracted_pack, build_scenario_ir
from feasible.solve.orchestrate import solve


def test_cross_domain_rule_id_is_unsupported_failclosed():
    ir = build_scenario_ir()
    bad = FCIR(rules=ir.rules, instance=ir.instance, domain_id="datacenter")  # mfg rules under dc domain
    with pytest.raises(UnsupportedHardRuleError):
        assert_all_hard_rules_supported(bad)


# A per-domain (active_ir, feasible_plan) builder. Each registered domain that wants
# the membership-implies-predicate guard to run over a REAL scenario contributes one
# entry; manufacturing is the only registered domain in Spec 0.
def _manufacturing_scenario() -> tuple[FCIR, object]:
    gov = govern_pack(build_extracted_pack(), MANUFACTURING_POLICY)
    res = solve(gov.active_ir, max_seconds=30.0, workers=1, seed=1)
    assert res.plan is not None
    return gov.active_ir, res.plan


def _datacenter_scenario() -> tuple[FCIR, object]:
    """A small datacenter ``(active_ir, plan)`` carrying BOTH PLAN-DEPENDENT
    evaluated ids ACTIVE (``dc:redundancy_floor`` + ``dc:maintenance_window``) so
    the meta-test's membership⇒predicate guard runs over a REAL datacenter scenario
    in BOTH engines. The dc solve path lands in Task 7; this builder constructs the
    IR + a shape-valid plan directly (no solver needed for the membership check)."""
    units = ["U1", "U2", "U3", "U4"]
    horizon = 4
    jobs = [Job(id=u, product=u, family="unit", qty=1, due_date=horizon, priority=3) for u in units]
    ops = [Operation(op_id=u, job_id=u, seq=0, eligible_machines=[u], duration=1) for u in units]
    inst = Instance(jobs=jobs, operations=ops, machines=list(units),
                    setup_matrix={}, maintenance=[], horizon=horizon)

    def _rule(rule_id: str, kind: str, params: dict) -> Rule:
        return Rule(
            rule_id=rule_id, kind=kind, params=params,
            severity=Severity.HARD, clause_kind=ClauseKind.OBLIGATION,
            compile_mode=CompileMode.PLAN_CONSTRAINT,
            resolution_class="SAFETY_SANITATION" if rule_id == "dc:redundancy_floor" else "EFFICIENCY",
            exception_mode=ExceptionMode.NONE,
            provenance=Provenance(spans=[TextSpan(quoted_text=f"{rule_id} (test)", role="modeling_decision")]),
        )

    rules = [
        _rule("dc:redundancy_floor", "redundancy_floor", {
            "group_id": "G1", "units": ["U1", "U2", "U3"], "floor": 2, "horizon": horizon,
            "maintenance": {},
        }),
        _rule("dc:maintenance_window", "maintenance_window", {
            "path_id": "U4", "forbidden": [[0, 1]], "derate_kw": {},
        }),
        _rule("dc:power_cap", "power_cap", {
            "cap_id": "CAP", "scope_units": ["U1", "U2"], "cap_kw": 100,
            "per_member_pct": 80, "draws": {"U1": 40, "U2": 40},
        }),
        _rule("dc:anti_affinity", "anti_affinity", {
            "group_id": "AA", "replicas": ["U1", "U3"],
            "fault_domain_of": {"U1": "FD-A", "U3": "FD-B"},
        }),
    ]
    ir = FCIR(rules=rules, instance=inst, domain_id="datacenter")
    plan = Plan(assignments={op.op_id: (0, op.eligible_machines[0]) for op in ir.instance.operations})
    return ir, plan


_SCENARIOS = {
    "manufacturing": _manufacturing_scenario,
    "datacenter": _datacenter_scenario,
}


def _z3_tracked_names(verifier, plan, ir) -> set[str]:
    """The set of ``assert_and_track`` label names ``z3_encode`` emits for this
    scenario, captured by spying on ``z3.Solver.assert_and_track`` (the tracked
    name is exactly the per-rule attestation label, prefixed by the rule_id)."""
    tracked: list[str] = []
    original = z3.Solver.assert_and_track

    def _spy(self, expr, name):  # noqa: ANN001
        tracked.append(str(name))
        return original(self, expr, name)

    z3.Solver.assert_and_track = _spy
    try:
        verifier.z3_encode(plan, ir)
    finally:
        z3.Solver.assert_and_track = original
    return set(tracked)


@pytest.mark.parametrize("domain_id", sorted(_SCENARIOS))
def test_registry_membership_implies_predicate(domain_id):
    """Every ``evaluated_rule_id`` must be wired into BOTH engines:

    - the Z3 attestor: it appears as an ``assert_and_track`` label (``rule_id`` or
      ``rule_id:...``) on the domain's real active scenario, so an UNSAT core can
      name it — proving the attestor actually constrains the rule;
    - the polynomial checker: its id literal is referenced in ``check_predicates``.

    This is a REAL assertion: adding an id to ``evaluated_rule_ids`` without an
    encoding in z3_encode (or a branch in check_predicates) FAILS this test.
    """
    _, verifier = get_domain(domain_id)
    evaluated = verifier.evaluated_rule_ids
    assert evaluated, f"{domain_id} has no evaluated_rule_ids"

    ir, plan = _SCENARIOS[domain_id]()

    # 1) Z3 attestor: each evaluated id must produce a tracked assertion.
    tracked = _z3_tracked_names(verifier, plan, ir)
    z3_covered = {
        rid for rid in evaluated
        if any(name == rid or name.startswith(rid + ":") for name in tracked)
    }
    assert z3_covered == set(evaluated), (
        f"{domain_id}: evaluated_rule_ids NOT attested by Z3 (no tracked assertion): "
        f"{sorted(set(evaluated) - z3_covered)}"
    )

    # 2) polynomial checker: each evaluated id must be referenced in check_predicates.
    src = inspect.getsource(verifier.check_predicates)
    checker_covered = {rid for rid in evaluated if repr(rid) in src or rid in src}
    assert checker_covered == set(evaluated), (
        f"{domain_id}: evaluated_rule_ids with NO checker branch: "
        f"{sorted(set(evaluated) - checker_covered)}"
    )

    # The invariant the two halves jointly prove: membership => predicate in BOTH.
    assert set(evaluated) <= (z3_covered & checker_covered)
