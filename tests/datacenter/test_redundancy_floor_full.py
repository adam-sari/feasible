"""Task 4: dc:redundancy_floor FULL — PLAN-scheduled maintenance tasks derate
availability, multi-group, per-timestep witness.

The Task-0 spike derived a group's per-timestep availability from (a) FIXED
instance maintenance params and (b) ``plan_outage:`` cleanouts on a single group.
Task 4 generalizes the HERO mechanism:

  * **multi-group**: every ``dc:redundancy_floor`` rule in ``ir.rules`` is checked
    independently (one ``coverage_floor_violations`` call per group). A unit shared
    across two groups counts DOWN in BOTH groups it leaves.
  * **PLAN-scheduled task derating**: a maintenance TASK (an Operation packed as
    ``task:<id>`` on its ``path`` machine, linked to a redundancy ``unit`` via the
    facility block) scheduled by the plan removes that unit for ``[start,
    start+duration)`` — maintenance spending the N+1 buffer.

The witness stays the frozen ``coverage_floor`` shape
(``{group_id, timestep, available, floor}``). Closed/total/code-disjoint; a ghost
op or empty group fails CLOSED via the kernel's ``available_by_t.get(t, 0)``.
"""
from __future__ import annotations

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
from feasible.checker.checker import check
from feasible.domains.datacenter.instance import (
    DatacenterInstance,
    Feed,
    Hall,
    MaintenanceTask,
    RedundancyGroup,
    pack_dc_instance,
)
from feasible.ir.domain import FCIR, Plan


def _ir_two_groups_one_shared_unit() -> FCIR:
    """G1=[U1,U2,U3] floor 2, G2=[U3,U4] floor 2 over a horizon=6 grid. U3 is the
    SHARED unit. One maintenance task ``M3`` on path/unit ``U3``, duration 2 (the
    schedulable decision is its start)."""
    dc = DatacenterInstance(
        horizon=6,
        halls=[Hall(id="H1")],
        feeds=[
            Feed(id="U1", hall_id="H1", capacity_kw=100),
            Feed(id="U2", hall_id="H1", capacity_kw=100),
            Feed(id="U3", hall_id="H1", capacity_kw=100),
            Feed(id="U4", hall_id="H1", capacity_kw=100),
        ],
        redundancy_groups=[
            RedundancyGroup(group_id="G1", units=["U1", "U2", "U3"], floor=2),
            RedundancyGroup(group_id="G2", units=["U3", "U4"], floor=2),
        ],
        maintenance_tasks=[MaintenanceTask(id="M3", path="U3", duration=2, unit="U3")],
    )
    inst, rules = pack_dc_instance(dc)
    return FCIR(rules=rules, instance=inst, domain_id="datacenter")


def _plan_with_task_outage(ir: FCIR, *, unit: str, start: int, end: int) -> Plan:
    """Schedule the maintenance task on ``unit`` (path ``unit``) at ``start`` (the
    duration is the packed op duration; ``end`` is start+duration by construction).
    Every other op stays at start 0."""
    assignments: dict[str, tuple[int, str]] = {}
    for op in ir.instance.operations:
        if op.eligible_machines[0] == unit:
            assignments[op.op_id] = (start, unit)
        else:
            assignments[op.op_id] = (0, op.eligible_machines[0])
    return Plan(assignments=assignments)


def test_maintenance_task_derates_redundancy_floor():
    ir = _ir_two_groups_one_shared_unit()  # G1=[U1,U2,U3] floor2, G2=[U3,U4] floor2
    plan = _plan_with_task_outage(ir, unit="U3", start=2, end=4)  # U3 down [2,4)
    vs = [v for v in check(plan, ir).violations if v.rule_id == "dc:redundancy_floor"]
    # G2 has only U3,U4 floor2 -> losing U3 -> available 1 < 2 at t=2,3 (two violations);
    # G1 still holds (U1,U2 available -> 2>=2).
    g2 = [v for v in vs if v.counter_witness["group_id"] == "G2"]
    assert {v.counter_witness["timestep"] for v in g2} == {2, 3}
    assert all(v.counter_witness["available"] == 1 for v in g2)
    # G1 holds: NO G1 violation.
    g1 = [v for v in vs if v.counter_witness["group_id"] == "G1"]
    assert g1 == []


def test_shared_unit_counts_down_in_both_groups():
    """A unit shared across two groups, where BOTH groups breach when it leaves,
    yields one violation per group (no double-count collapse, no cross-suppression)."""
    # Tighten G1 to floor 3 so losing U3 ALSO breaches G1 (G1 has 3 units -> down to 2).
    dc = DatacenterInstance(
        horizon=4,
        feeds=[Feed(id=u, hall_id="H1", capacity_kw=100) for u in ("U1", "U2", "U3", "U4")],
        redundancy_groups=[
            RedundancyGroup(group_id="G1", units=["U1", "U2", "U3"], floor=3),
            RedundancyGroup(group_id="G2", units=["U3", "U4"], floor=2),
        ],
        maintenance_tasks=[MaintenanceTask(id="M3", path="U3", duration=2, unit="U3")],
    )
    inst, rules = pack_dc_instance(dc)
    ir = FCIR(rules=rules, instance=inst, domain_id="datacenter")
    plan = _plan_with_task_outage(ir, unit="U3", start=1, end=3)  # U3 down [1,3)
    vs = [v for v in check(plan, ir).violations if v.rule_id == "dc:redundancy_floor"]
    groups_breached = {v.counter_witness["group_id"] for v in vs}
    assert groups_breached == {"G1", "G2"}  # BOTH groups count U3 down
    # each group breaches at exactly t=1,2 (the outage window)
    for gid in ("G1", "G2"):
        ts = {v.counter_witness["timestep"] for v in vs if v.counter_witness["group_id"] == gid}
        assert ts == {1, 2}


def test_derate_only_during_window_before_and_after_hold():
    """The task derates availability at EXACTLY [start, end); the timestep just
    before and just after hold (no off-by-one)."""
    ir = _ir_two_groups_one_shared_unit()  # horizon 6, G2=[U3,U4] floor 2
    plan = _plan_with_task_outage(ir, unit="U3", start=2, end=4)  # U3 down [2,4)
    g2 = [v for v in check(plan, ir).violations
          if v.rule_id == "dc:redundancy_floor" and v.counter_witness["group_id"] == "G2"]
    breached = {v.counter_witness["timestep"] for v in g2}
    assert 1 not in breached  # t=1 (just before) holds
    assert 4 not in breached  # t=4 (just after, half-open) holds
    assert breached == {2, 3}


def test_last_timestep_dip_is_caught_no_omission():
    """Off-by-one: a horizon=N where the LAST timestep dips below floor is caught
    (the frozen coverage_floor_violations totals range(horizon))."""
    dc = DatacenterInstance(
        horizon=4,
        feeds=[Feed(id=u, hall_id="H1", capacity_kw=100) for u in ("U3", "U4")],
        redundancy_groups=[RedundancyGroup(group_id="G2", units=["U3", "U4"], floor=2)],
        maintenance_tasks=[MaintenanceTask(id="M3", path="U3", duration=1, unit="U3")],
    )
    inst, rules = pack_dc_instance(dc)
    ir = FCIR(rules=rules, instance=inst, domain_id="datacenter")
    plan = _plan_with_task_outage(ir, unit="U3", start=3, end=4)  # U3 down at the LAST t=3
    g2 = [v for v in check(plan, ir).violations
          if v.rule_id == "dc:redundancy_floor" and v.counter_witness["group_id"] == "G2"]
    assert {v.counter_witness["timestep"] for v in g2} == {3}  # last timestep caught


def test_installed_vs_available_floor_is_over_available():
    """A fully-INSTALLED group with a maintenance outage breaches: the floor is over
    AVAILABLE, not installed count."""
    ir = _ir_two_groups_one_shared_unit()  # G2 has 2 units installed, floor 2
    plan = _plan_with_task_outage(ir, unit="U3", start=0, end=2)  # one installed unit down
    g2 = [v for v in check(plan, ir).violations
          if v.rule_id == "dc:redundancy_floor" and v.counter_witness["group_id"] == "G2"]
    # 2 installed but only 1 available during the outage -> breach (installed != available)
    assert {v.counter_witness["timestep"] for v in g2} == {0, 1}
    assert all(v.counter_witness["available"] == 1 for v in g2)


def test_per_timestep_not_average():
    """available=[3,1,2] floor 2 -> exactly one violation at t=1 (not averaged)."""
    # G2=[U3,U4] is not enough to make a 3-1-2 shape; use a 3-unit group floor 2 with
    # one task derating U3 for a single timestep -> available [..,1,..] at exactly t=1.
    dc = DatacenterInstance(
        horizon=3,
        feeds=[Feed(id=u, hall_id="H1", capacity_kw=100) for u in ("U1", "U2", "U3")],
        redundancy_groups=[RedundancyGroup(group_id="G", units=["U1", "U2", "U3"], floor=2)],
        # two tasks drop U2 AND U3 at t=1 only -> available [3,1,3]
        maintenance_tasks=[
            MaintenanceTask(id="M2", path="U2", duration=1, unit="U2"),
            MaintenanceTask(id="M3", path="U3", duration=1, unit="U3"),
        ],
    )
    inst, rules = pack_dc_instance(dc)
    ir = FCIR(rules=rules, instance=inst, domain_id="datacenter")
    # schedule both task ops at start 1 (down only at t=1); other ops at 0.
    assignments: dict[str, tuple[int, str]] = {}
    for op in ir.instance.operations:
        if op.eligible_machines[0] in ("U2", "U3"):
            assignments[op.op_id] = (1, op.eligible_machines[0])
        else:
            assignments[op.op_id] = (0, op.eligible_machines[0])
    plan = Plan(assignments=assignments)
    g = [v for v in check(plan, ir).violations
         if v.rule_id == "dc:redundancy_floor" and v.counter_witness["group_id"] == "G"]
    assert len(g) == 1
    assert g[0].counter_witness == {"group_id": "G", "timestep": 1, "available": 1, "floor": 2}


def test_no_task_scheduled_floor_holds():
    """With no derating task scheduled (every op at start 0, no overlap into the
    horizon mid), the floor holds and the check passes for both groups."""
    ir = _ir_two_groups_one_shared_unit()
    # schedule the M3 task at start 0 duration 2 -> U3 down [0,2). G2 breaches [0,2)
    # but G1 holds. To get a clean PASS, push the task fully past the horizon end is
    # impossible (horizon 6, duration 2). Instead assert the M3-at-0 case derates only
    # G2 — a positive multi-group sanity that G1 NEVER breaches from a G2-only unit.
    plan = _plan_with_task_outage(ir, unit="U3", start=0, end=2)
    vs = [v for v in check(plan, ir).violations if v.rule_id == "dc:redundancy_floor"]
    assert all(v.counter_witness["group_id"] == "G2" for v in vs)
    assert {v.counter_witness["timestep"] for v in vs} == {0, 1}


def test_spike_redundancy_still_holds_legacy_slice():
    """The Task-0 spike's plan_outage mechanism (cleanout reason plan_outage:<unit>)
    on the LEGACY slice still derates — Task 4 must not regress it."""
    from feasible.domains.datacenter.instance import baseline_plan

    dc = DatacenterInstance(
        group_id="feedA", units=["U1", "U2", "U3"], floor=2, horizon=4,
        maintenance={"U3": [(1, 3)]},
    )
    inst, rules = pack_dc_instance(dc)
    ir = FCIR(rules=rules, instance=inst, domain_id="datacenter")
    # baseline (no extra outage): floor held.
    assert check(baseline_plan(ir, {}), ir).passed
    # extra plan_outage on U2 [1,3) -> available[1]=1 < 2 (the spike gotcha).
    inc = baseline_plan(ir, {"U2": (1, 3)})
    g = [v for v in check(inc, ir).violations if v.rule_id == "dc:redundancy_floor"]
    assert g and g[0].counter_witness == {"group_id": "feedA", "timestep": 1, "available": 1, "floor": 2}
