"""The synthetic datacenter facility builder.

Task 1 lands a SMALL but representative facility (every dc:* rule kind present,
every structural sub-model populated) so the pack/unpack convention is exercised
over the full surface. Task 8 fleshes this into the hero scenario (capacity policy,
governance, KPIs, the N+1-buffer gotcha). The facility is INTEGERS-ONLY and
normalized (sorted intervals) so pack/unpack is exact identity.
"""
from __future__ import annotations

from feasible.domains.datacenter.instance import (
    AntiAffinityGroup,
    DatacenterInstance,
    FaultDomain,
    Feed,
    Hall,
    MaintenanceTask,
    MaintenanceWindow,
    PowerCap,
    Rack,
    RedundancyGroup,
)

HORIZON = 8  # 8 integer timesteps


def build_dc_scenario_dc_instance() -> DatacenterInstance:
    """A small representative facility: 1 hall, 4 feeds (one N+1 redundant group of
    3 + a spare), 4 racks across 2 fault domains, one power cap, one anti-affinity
    pair, two maintenance tasks (one on a redundant feed -> the buffer mechanism),
    one forbidden maintenance window."""
    halls = [Hall(id="H1")]
    fault_domains = [FaultDomain(id="FD-A"), FaultDomain(id="FD-B")]
    feeds = [
        Feed(id="F1", hall_id="H1", capacity_kw=500),
        Feed(id="F2", hall_id="H1", capacity_kw=500),
        Feed(id="F3", hall_id="H1", capacity_kw=500),
        Feed(id="F4", hall_id="H1", capacity_kw=500),
    ]
    racks = [
        Rack(id="R1", hall_id="H1", feed_id="F1", fault_domain_id="FD-A", draw_kw=60),
        Rack(id="R2", hall_id="H1", feed_id="F2", fault_domain_id="FD-A", draw_kw=60),
        Rack(id="R3", hall_id="H1", feed_id="F3", fault_domain_id="FD-B", draw_kw=70),
        Rack(id="R4", hall_id="H1", feed_id="F4", fault_domain_id="FD-B", draw_kw=70),
    ]
    redundancy_groups = [
        RedundancyGroup(
            group_id="G1", units=["F1", "F2", "F3"], floor=2,
            maintenance={"F3": [(6, 8)]},  # a FIXED outage near horizon end (sorted)
        ),
    ]
    power_caps = [
        PowerCap(
            cap_id="CAP-H1", scope_units=["R1", "R2", "R3", "R4"], cap_kw=300,
            per_member_pct=40, draws={"R1": 60, "R2": 60, "R3": 70, "R4": 70},
        ),
    ]
    anti_affinity_groups = [
        AntiAffinityGroup(
            group_id="AA1", replicas=["R1", "R3"],
            fault_domain_of={"R1": "FD-A", "R3": "FD-B"},
        ),
    ]
    maintenance_tasks = [
        MaintenanceTask(id="T1", path="F1", duration=2, unit="F1"),
        MaintenanceTask(id="T2", path="F4", duration=1, unit=None),
    ]
    maintenance_windows = [
        MaintenanceWindow(
            path_id="F1", forbidden=[(0, 2)], derate_kw={"F1": 100},
        ),
    ]
    return DatacenterInstance(
        horizon=HORIZON,
        halls=halls, feeds=feeds, racks=racks, fault_domains=fault_domains,
        redundancy_groups=redundancy_groups, power_caps=power_caps,
        anti_affinity_groups=anti_affinity_groups,
        maintenance_tasks=maintenance_tasks, maintenance_windows=maintenance_windows,
    )
