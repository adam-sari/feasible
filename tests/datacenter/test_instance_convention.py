"""Task 1: the full DatacenterInstance facility <-> frozen Instance/Plan convention.

The facility serializes losslessly into the FROZEN Instance + dc:* rule params
(delta #1: the cert core is hardwired to Instance/Plan; we encode the facility
INTO it). The round-trip is IDENTITY and the packed Instance is shape-clean for
the baseline plan (so validate_plan_shape — the frozen FJSP-coded gate — passes).
"""
from __future__ import annotations

from feasible.checker.plan_shape import validate_plan_shape
from feasible.domains.datacenter.instance import (
    baseline_plan,
    pack_dc_instance,
    unpack_dc_instance,
)
from feasible.domains.datacenter.scenario import build_dc_scenario_dc_instance
from feasible.ir.domain import FCIR


def test_pack_unpack_is_identity():
    dc = build_dc_scenario_dc_instance()
    inst, rules = pack_dc_instance(dc)
    ir = FCIR(rules=rules, instance=inst, domain_id="datacenter")
    assert unpack_dc_instance(ir) == dc


def test_packed_instance_is_shape_valid():
    dc = build_dc_scenario_dc_instance()
    inst, rules = pack_dc_instance(dc)
    ir = FCIR(rules=rules, instance=inst, domain_id="datacenter")
    assert validate_plan_shape(baseline_plan(ir, {}), ir) == []  # no shape violations


def test_packed_instance_carries_all_four_rule_kinds():
    # the representative facility exercises every dc:* rule kind, so the convention
    # is exercised over the full surface (not just the redundancy slice).
    dc = build_dc_scenario_dc_instance()
    _inst, rules = pack_dc_instance(dc)
    kinds = {r.kind for r in rules}
    assert {"redundancy_floor", "power_cap", "maintenance_window", "anti_affinity"} <= kinds


def test_round_trip_is_deterministic():
    # pack twice -> byte-identical params + ops (no float, sorted ordering -> stable).
    dc = build_dc_scenario_dc_instance()
    inst1, rules1 = pack_dc_instance(dc)
    inst2, rules2 = pack_dc_instance(dc)
    assert inst1.model_dump(mode="json") == inst2.model_dump(mode="json")
    assert [r.model_dump(mode="json") for r in rules1] == [r.model_dump(mode="json") for r in rules2]


def test_legacy_redundancy_slice_still_packs():
    # the Task-0 spike constructs the flat redundancy slice; pack/unpack must keep
    # supporting it byte-for-byte (the spike e2e cert stays green).
    from feasible.domains.datacenter.instance import DatacenterInstance

    dc = DatacenterInstance(
        group_id="feedA", units=["U1", "U2", "U3"], floor=2, horizon=4,
        maintenance={"U3": [(1, 3)]},
    )
    inst, rules = pack_dc_instance(dc)
    ir = FCIR(rules=rules, instance=inst, domain_id="datacenter")
    assert unpack_dc_instance(ir) == dc
