"""Task 6: registry-membership ⇒ predicate (BOTH engines) for datacenter.

Mirrors ``tests/domains/test_registry_per_domain.py::test_registry_membership_
implies_predicate`` (the manufacturing meta-test) for the datacenter bundle:

- Every PLAN-DEPENDENT ``evaluated_rule_id`` (``dc:redundancy_floor`` /
  ``dc:maintenance_window``) must appear as a tracked Z3 ``assert_and_track``
  label AND as a literal in ``check_predicates`` source — so an UNSAT core can
  name it AND the polynomial checker actually branches on it. Adding an id to
  ``evaluated_rule_ids`` without wiring BOTH engines fails this test.

- SEPARATELY (B-4): each STRUCTURAL kind id (``dc:power_cap`` /
  ``dc:anti_affinity``) is in ``known_rule_ids``, its ``kind`` in
  ``structural_rule_kinds``, and STILL carries a tracked Z3 label + a
  ``check_predicates`` literal (its instance-invariant guard runs even though the
  registry does not REQUIRE it).

- The cross-domain isolation guard ``domains_known_rule_ids_disjoint()`` is True.
"""
from __future__ import annotations

import inspect

import z3

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
import feasible.domains.manufacturing  # noqa: F401  (so disjointness sees both domains)
from feasible.domains import get_domain
from feasible.domains.base import domains_known_rule_ids_disjoint
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


def _rule(rule_id: str, kind: str, params: dict) -> Rule:
    return Rule(
        rule_id=rule_id, kind=kind, params=params,
        severity=Severity.HARD, clause_kind=ClauseKind.OBLIGATION,
        compile_mode=CompileMode.PLAN_CONSTRAINT,
        resolution_class="SAFETY_SANITATION" if rule_id == "dc:redundancy_floor" else "EFFICIENCY",
        exception_mode=ExceptionMode.NONE,
        provenance=Provenance(spans=[TextSpan(quoted_text=f"{rule_id} (test)", role="modeling_decision")]),
    )


def _dc_all_rules_active_ir_and_plan() -> tuple[FCIR, Plan]:
    """A shape-valid datacenter IR carrying ALL FOUR dc:* rules ACTIVE
    (HARD/PLAN_CONSTRAINT) so EVERY predicate + Z3 mirror runs over one scenario,
    plus a shape-valid plan. Units U1..U4 each map to one op on their own machine."""
    units = ["U1", "U2", "U3", "U4"]
    horizon = 4
    jobs = [Job(id=u, product=u, family="unit", qty=1, due_date=horizon, priority=3) for u in units]
    ops = [Operation(op_id=u, job_id=u, seq=0, eligible_machines=[u], duration=1) for u in units]
    inst = Instance(jobs=jobs, operations=ops, machines=list(units),
                    setup_matrix={}, maintenance=[], horizon=horizon)
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


def _z3_tracked_names(verifier, plan, ir) -> set[str]:
    """The ``assert_and_track`` label names ``z3_encode`` emits for this scenario,
    captured by spying on ``z3.Solver.assert_and_track``."""
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


def test_evaluated_ids_wired_into_both_engines():
    """Each PLAN-DEPENDENT evaluated id is a tracked Z3 label AND a check_predicates
    literal (membership ⇒ predicate in BOTH engines)."""
    _, verifier = get_domain("datacenter")
    evaluated = verifier.evaluated_rule_ids
    assert evaluated == frozenset({"dc:redundancy_floor", "dc:maintenance_window"})

    ir, plan = _dc_all_rules_active_ir_and_plan()

    tracked = _z3_tracked_names(verifier, plan, ir)
    z3_covered = {
        rid for rid in evaluated
        if any(name == rid or name.startswith(rid + ":") for name in tracked)
    }
    assert z3_covered == set(evaluated), (
        f"evaluated_rule_ids NOT attested by Z3: {sorted(set(evaluated) - z3_covered)}"
    )

    src = inspect.getsource(verifier.check_predicates)
    checker_covered = {rid for rid in evaluated if repr(rid) in src or rid in src}
    assert checker_covered == set(evaluated), (
        f"evaluated_rule_ids with NO checker branch: {sorted(set(evaluated) - checker_covered)}"
    )

    assert set(evaluated) <= (z3_covered & checker_covered)


def test_structural_ids_still_wired_into_both_engines():
    """B-4: each STRUCTURAL kind id is in known_rule_ids, its kind in
    structural_rule_kinds, and STILL carries a tracked Z3 label + a check_predicates
    literal (the instance-invariant guard runs even though the registry does not
    REQUIRE it)."""
    _, verifier = get_domain("datacenter")
    structural_ids = {"dc:power_cap", "dc:anti_affinity"}
    assert structural_ids <= verifier.known_rule_ids
    assert {"power_cap", "anti_affinity"} <= verifier.structural_rule_kinds
    # structural ids are NOT in evaluated_rule_ids (the registry does not require them)
    assert not (structural_ids & verifier.evaluated_rule_ids)

    ir, plan = _dc_all_rules_active_ir_and_plan()

    tracked = _z3_tracked_names(verifier, plan, ir)
    z3_covered = {
        rid for rid in structural_ids
        if any(name == rid or name.startswith(rid + ":") for name in tracked)
    }
    assert z3_covered == structural_ids, (
        f"structural ids NOT Z3-mirrored: {sorted(structural_ids - z3_covered)}"
    )

    src = inspect.getsource(verifier.check_predicates)
    checker_covered = {rid for rid in structural_ids if repr(rid) in src or rid in src}
    assert checker_covered == structural_ids, (
        f"structural ids with NO checker branch: {sorted(structural_ids - checker_covered)}"
    )


def test_known_rule_ids_pairwise_disjoint_across_domains():
    """Cross-domain isolation: every registered domain's known_rule_ids are
    pairwise-disjoint (a dc:* id colliding with an R-* id would fail CI)."""
    assert domains_known_rule_ids_disjoint() is True
