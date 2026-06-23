"""Task 3: dc:maintenance_window — closed/total PLAN-DEPENDENT checker + Z3 mirror.

A scheduled maintenance task whose interval ``[start, start+duration)`` (the start
is the schedulable decision in the plan; the duration is the packed op duration)
OVERLAPS a FORBIDDEN window on its path (e.g. a change-freeze window) is flagged.
Uses the frozen half-open ``_overlaps`` convention (``a_start < b_end and
b_start < a_end``) so endpoint inclusivity is exact: a task ending precisely at
``forbidden_start`` passes; a task starting precisely at ``forbidden_end`` passes.

This is a PLAN-DEPENDENT evaluated id (the schedule decides whether a task lands in
a freeze window), so it lives in ``evaluated_rule_ids`` / ``known_rule_ids`` /
``rule_kinds``. TOTAL param reads (B-5): a missing ``path_id``/``forbidden`` yields
a deterministic fail-closed single violation, never a ``KeyError``.
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


def _ir_with_window(*, forbidden: list[tuple[int, int]], task_duration: int = 2,
                    horizon: int = 10) -> FCIR:
    """A shape-valid datacenter IR with ONE maintenance task (``task:T1`` on path
    ``pathA``, ``task_duration`` timesteps) and ONE HARD/PLAN_CONSTRAINT
    dc:maintenance_window rule over ``pathA``'s ``forbidden`` windows."""
    jobs = [Job(id="task:T1", product="task:T1", family="maint", qty=1,
                due_date=horizon, priority=3)]
    ops = [Operation(op_id="task:T1", job_id="task:T1", seq=0,
                     eligible_machines=["pathA"], duration=int(task_duration))]
    inst = Instance(jobs=jobs, operations=ops, machines=["pathA"],
                    setup_matrix={}, maintenance=[], horizon=horizon)
    rule = Rule(
        rule_id="dc:maintenance_window", kind="maintenance_window",
        params={
            "path_id": "pathA",
            "forbidden": [[a, b] for (a, b) in forbidden],
            "derate_kw": {},
        },
        severity=Severity.HARD, clause_kind=ClauseKind.OBLIGATION,
        compile_mode=CompileMode.PLAN_CONSTRAINT, resolution_class="EFFICIENCY",
        exception_mode=ExceptionMode.NONE,
        provenance=Provenance(spans=[TextSpan(quoted_text="maintenance window (test)",
                                              role="modeling_decision")]),
    )
    return FCIR(rules=[rule], instance=inst, domain_id="datacenter")


def _plan_at(ir: FCIR, start: int) -> Plan:
    """Schedule the single task at ``start`` on its path machine."""
    return Plan(assignments={"task:T1": (start, "pathA")})


def test_window_task_inside_forbidden_is_flagged():
    # forbidden [3,7); task [4,6) lands strictly inside -> flagged with the witness.
    ir = _ir_with_window(forbidden=[(3, 7)], task_duration=2)
    vs = [v for v in check(_plan_at(ir, 4), ir).violations
          if v.rule_id == "dc:maintenance_window"]
    assert vs, "a task scheduled inside a forbidden window must be flagged"
    w = vs[0].counter_witness
    assert w["path_id"] == "pathA"
    assert w["task"] == "task:T1"
    assert w["window"] == [3, 7]
    assert vs[0].witness_kind == "maintenance_window" and vs[0].witness_version == "v1"


def test_window_task_fully_outside_passes():
    # forbidden [3,7); task [8,10) fully after -> NO violation.
    ir = _ir_with_window(forbidden=[(3, 7)], task_duration=2)
    vs = [v for v in check(_plan_at(ir, 8), ir).violations
          if v.rule_id == "dc:maintenance_window"]
    assert vs == []


def test_window_task_ending_exactly_at_forbidden_start_passes():
    # half-open [a,b): a task ENDING exactly at forbidden_start does NOT overlap.
    # forbidden [4,8); task [2,4) -> task_end == forbidden_start == 4 -> passes.
    ir = _ir_with_window(forbidden=[(4, 8)], task_duration=2)
    vs = [v for v in check(_plan_at(ir, 2), ir).violations
          if v.rule_id == "dc:maintenance_window"]
    assert vs == []


def test_window_task_starting_exactly_at_forbidden_end_passes():
    # half-open [a,b): a task STARTING exactly at forbidden_end does NOT overlap.
    # forbidden [2,4); task [4,6) -> task_start == forbidden_end == 4 -> passes.
    ir = _ir_with_window(forbidden=[(2, 4)], task_duration=2)
    vs = [v for v in check(_plan_at(ir, 4), ir).violations
          if v.rule_id == "dc:maintenance_window"]
    assert vs == []


def test_window_overlap_z3_unsat():
    # the Z3 mirror is UNSAT (infeasible) for the overlap.
    ir = _ir_with_window(forbidden=[(3, 7)], task_duration=2)
    assert attest_feasibility(_plan_at(ir, 4), ir).feasible is False


def test_window_no_overlap_z3_sat():
    # the Z3 mirror is SAT (feasible) when the task is outside every window.
    ir = _ir_with_window(forbidden=[(3, 7)], task_duration=2)
    assert attest_feasibility(_plan_at(ir, 8), ir).feasible is True


def test_window_multiple_forbidden_windows():
    # a task overlapping the SECOND of two windows is flagged with THAT window.
    ir = _ir_with_window(forbidden=[(0, 2), (6, 9)], task_duration=2)
    vs = [v for v in check(_plan_at(ir, 7), ir).violations
          if v.rule_id == "dc:maintenance_window"]
    assert vs and vs[0].counter_witness["window"] == [6, 9]


def test_maintenance_window_is_evaluated_and_known():
    # PLAN-DEPENDENT evaluated id: in evaluated_rule_ids / known_rule_ids / rule_kinds.
    _, verifier = get_domain("datacenter")
    assert "dc:maintenance_window" in verifier.evaluated_rule_ids
    assert "dc:maintenance_window" in verifier.known_rule_ids
    assert "maintenance_window" in verifier.rule_kinds


@pytest.mark.parametrize("param", ["path_id", "forbidden"])
def test_maintenance_window_missing_param_fails_closed_without_raising(param):
    # B-5: a self-signed cert omitting a required param must NOT crash check()
    # (an uncaught KeyError in check_predicates is a crash-DoS in verify_plan_cert).
    ir = _ir_with_window(forbidden=[(3, 7)], task_duration=2)
    bad = copy.deepcopy(ir)
    del bad.rule("dc:maintenance_window").params[param]
    res = check(_plan_at(bad, 4), bad)              # must NOT raise
    assert res.passed is False                      # fail-closed
    assert any(v.rule_id == "dc:maintenance_window" for v in res.violations)
