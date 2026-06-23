"""The DatacenterInstance + the lossless convention that serializes a facility
into the FROZEN Instance/Plan shape (delta #1: the cert core is hardwired to
Instance/Plan; we encode the facility INTO it rather than touch cert/).

Two construction modes share one model:

  * the **legacy redundancy slice** (Task 0 spike) — flat ``group_id``/``units``/
    ``floor``/``maintenance`` fields — kept byte-for-byte so the spike cert stays
    green; and
  * the **full facility** (Task 1+) — ``halls``/``feeds``/``racks``/
    ``fault_domains``/``redundancy_groups``/``power_caps``/``maintenance_tasks``/
    ``anti_affinity_groups``/``maintenance_windows``.

``pack_dc_instance`` is a deterministic, total, lossless encoder into the frozen
``Instance`` + the four ``dc:*`` rule kinds; ``unpack_dc_instance`` is its exact
inverse (STRICT — it may raise on a malformed IR; it is NEVER called inside
``check_predicates`` — the predicates read params TOTALLY via ``p.get(...)``).

INTEGERS ONLY (kW, integer timesteps) — no floats in the hashed body.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

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

# ---------------------------------------------------------------------------
# Facility sub-models (integers-only; ids are strings)
# ---------------------------------------------------------------------------


class Hall(BaseModel):
    id: str


class FaultDomain(BaseModel):
    id: str


class Feed(BaseModel):
    id: str
    hall_id: str
    capacity_kw: int


class Rack(BaseModel):
    id: str
    hall_id: str
    feed_id: str
    fault_domain_id: str
    draw_kw: int


class RedundancyGroup(BaseModel):
    group_id: str
    units: list[str]          # feed ids forming the redundant group
    floor: int                # N+1/2N: at least `floor` units available every t
    maintenance: dict[str, list[tuple[int, int]]] = Field(default_factory=dict)  # FIXED outages


class PowerCap(BaseModel):
    cap_id: str
    scope_units: list[str]    # rack ids under the cap
    cap_kw: int
    per_member_pct: int       # NEC/failover: each member <= per_member_pct% of cap
    draws: dict[str, int]     # rack id -> nameplate draw kW (FIXED instance fact, v1)


class AntiAffinityGroup(BaseModel):
    group_id: str
    replicas: list[str]
    fault_domain_of: dict[str, str]   # replica -> fault-domain id (FIXED, v1)


class MaintenanceWindow(BaseModel):
    path_id: str
    forbidden: list[tuple[int, int]] = Field(default_factory=list)   # half-open [a,b)
    derate_kw: dict[str, int] = Field(default_factory=dict)          # unit -> derate kW


class MaintenanceTask(BaseModel):
    id: str
    path: str            # the feed/path "machine" it runs on (eligible machine)
    duration: int        # timesteps
    unit: str | None = None   # the redundancy unit it removes while running (if any)


class DatacenterInstance(BaseModel):
    """A datacenter facility (or the Task-0 redundancy slice).

    The legacy flat ``group_id``/``units``/``floor``/``maintenance`` fields are the
    Task-0 spike slice; the structured lists are the full facility. A given object
    populates ONE mode (the spike uses the flat fields; the scenario uses the lists)."""

    horizon: int

    # --- legacy redundancy slice (Task 0 spike) ---
    group_id: str | None = None
    units: list[str] = Field(default_factory=list)
    floor: int | None = None
    maintenance: dict[str, list[tuple[int, int]]] = Field(default_factory=dict)

    # --- full facility (Task 1+) ---
    halls: list[Hall] = Field(default_factory=list)
    feeds: list[Feed] = Field(default_factory=list)
    racks: list[Rack] = Field(default_factory=list)
    fault_domains: list[FaultDomain] = Field(default_factory=list)
    redundancy_groups: list[RedundancyGroup] = Field(default_factory=list)
    power_caps: list[PowerCap] = Field(default_factory=list)
    maintenance_tasks: list[MaintenanceTask] = Field(default_factory=list)
    anti_affinity_groups: list[AntiAffinityGroup] = Field(default_factory=list)
    maintenance_windows: list[MaintenanceWindow] = Field(default_factory=list)

    def _is_legacy_slice(self) -> bool:
        """True when this object is the Task-0 flat redundancy slice (the spike)."""
        return self.group_id is not None and not self.redundancy_groups


# ---------------------------------------------------------------------------
# Provenance helper (the dc rules anchor against capacity_policy.md in Task 8;
# at Task 1 they carry modeling-decision spans, which are NOT re-anchored).
# ---------------------------------------------------------------------------


def _span(quoted: str) -> Provenance:
    return Provenance(spans=[TextSpan(quoted_text=quoted, role="modeling_decision")])


def _redundancy_rule(group_id: str, units: list[str], floor: int, horizon: int,
                     maintenance: dict[str, list[tuple[int, int]]],
                     facility: dict | None = None) -> Rule:
    params: dict = {
        "group_id": group_id,
        "units": list(units),
        "floor": int(floor),
        "horizon": int(horizon),
        # JSON-safe: lists not tuples; sorted for determinism.
        "maintenance": {u: [[a, b] for (a, b) in sorted(v)] for u, v in sorted(maintenance.items())},
    }
    if facility is not None:
        params["facility"] = facility
    return Rule(
        rule_id="dc:redundancy_floor", kind="redundancy_floor", params=params,
        severity=Severity.HARD, clause_kind=ClauseKind.OBLIGATION,
        compile_mode=CompileMode.PLAN_CONSTRAINT,
        # CRITICAL (B-3): the resolution_class is literally SAFETY_SANITATION, NOT a
        # bespoke "REDUNDANCY" id. The frozen no_permission_outranks_safety guard keys
        # ONLY on SAFETY_CLASS_ID == "SAFETY_SANITATION": a policy demoting redundancy
        # below acceleration is only CAUGHT if redundancy IS the safety class.
        resolution_class="SAFETY_SANITATION",
        exception_mode=ExceptionMode.NONE,
        provenance=_span(f"redundancy floor {group_id} (N+{floor})"),
    )


def _facility_block(dc: DatacenterInstance) -> dict:
    """The structural descriptors (halls/feeds/racks/fault_domains) that the dc:*
    rules don't otherwise carry, serialized JSON-safe + deterministically so the
    round-trip is exact identity. Stored on the first redundancy rule's params (the
    checker ignores this key; it reads only group_id/units/floor/horizon/maintenance)."""
    return {
        "halls": [h.model_dump(mode="json") for h in sorted(dc.halls, key=lambda h: h.id)],
        "feeds": [f.model_dump(mode="json") for f in sorted(dc.feeds, key=lambda f: f.id)],
        "racks": [r.model_dump(mode="json") for r in sorted(dc.racks, key=lambda r: r.id)],
        "fault_domains": [d.model_dump(mode="json") for d in sorted(dc.fault_domains, key=lambda d: d.id)],
    }


def pack_dc_instance(dc: DatacenterInstance) -> tuple[Instance, list[Rule]]:
    """Encode the facility into a frozen Instance + the dc:* Rules (deterministic,
    total, lossless). Two modes:

      * legacy slice -> exactly the Task-0 redundancy rule (byte-for-byte);
      * full facility -> one Operation per maintenance task + one rule per
        redundancy group / power cap / anti-affinity group / maintenance window.

    Each unit/path/rack -> a per-unit "machine" so validate_plan_shape (frozen,
    FJSP-coded) passes. The redundancy/power/affinity topology lives ENTIRELY in the
    rule params (re-derivable, never solver state)."""
    if dc._is_legacy_slice():
        assert dc.group_id is not None and dc.floor is not None
        jobs = [Job(id=u, product=u, family="unit", qty=1, due_date=dc.horizon, priority=3)
                for u in dc.units]
        ops = [Operation(op_id=u, job_id=u, seq=0, eligible_machines=[u], duration=1)
               for u in dc.units]
        inst = Instance(jobs=jobs, operations=ops, machines=list(dc.units),
                        setup_matrix={}, maintenance=[], horizon=dc.horizon)
        rule = _redundancy_rule(dc.group_id, dc.units, dc.floor, dc.horizon, dc.maintenance)
        return inst, [rule]

    # --- full facility ---
    # Machines: every feed (redundancy unit / maintenance path) + every rack
    # (power-cap member). Sorted for determinism.
    machine_set: set[str] = set()
    for f in dc.feeds:
        machine_set.add(f.id)
    for r in dc.racks:
        machine_set.add(r.id)
    for t in dc.maintenance_tasks:
        machine_set.add(t.path)
    machines = sorted(machine_set)

    # Maintenance tasks -> one Operation each (the schedulable decision the solver
    # makes). op_id = "task:<id>", on its path "machine", duration in timesteps.
    tasks = sorted(dc.maintenance_tasks, key=lambda t: t.id)
    jobs = [Job(id=f"task:{t.id}", product=f"task:{t.id}", family="maint", qty=1,
                due_date=dc.horizon, priority=3) for t in tasks]
    ops = [Operation(op_id=f"task:{t.id}", job_id=f"task:{t.id}", seq=0,
                     eligible_machines=[t.path], duration=int(t.duration)) for t in tasks]
    inst = Instance(jobs=jobs, operations=ops, machines=machines,
                    setup_matrix={}, maintenance=[], horizon=dc.horizon)

    rules: list[Rule] = []

    # Redundancy groups -> one dc:redundancy_floor rule per group. The FIRST one
    # carries the facility structural block (lossless identity).
    rgroups = sorted(dc.redundancy_groups, key=lambda g: g.group_id)
    facility = _facility_block(dc)
    # Also serialize the maintenance-task <-> unit mapping (so unpack recovers each
    # task's `unit`/`path`/`duration` exactly — the Operation carries path+duration,
    # the facility block carries the per-task unit linkage).
    facility["maintenance_tasks"] = [
        {"id": t.id, "path": t.path, "duration": int(t.duration), "unit": t.unit}
        for t in tasks
    ]
    for i, g in enumerate(rgroups):
        rules.append(_redundancy_rule(
            g.group_id, g.units, g.floor, dc.horizon, g.maintenance,
            facility=facility if i == 0 else None,
        ))
    if not rgroups:
        # No redundancy group: still emit the facility carrier so identity holds,
        # as an INACTIVE (SOFT/conflict-only) structural carrier rule.
        rules.append(Rule(
            rule_id="dc:facility", kind="facility", params={"facility": facility},
            severity=Severity.SOFT, clause_kind=ClauseKind.OBLIGATION,
            compile_mode=CompileMode.CONFLICT_ONLY, resolution_class="EFFICIENCY",
            exception_mode=ExceptionMode.NONE,
            provenance=_span("facility topology (structural carrier)"),
        ))

    # Power caps -> one dc:power_cap rule per cap. STRUCTURAL (B-4): instance-level,
    # plan-independent in v1 (draws are FIXED nameplate facts), so SOFT/CONFLICT_ONLY
    # at Task 1 (Task 2 wires the checker branch + structural_rule_kinds membership).
    for cap in sorted(dc.power_caps, key=lambda c: c.cap_id):
        rules.append(Rule(
            rule_id="dc:power_cap", kind="power_cap",
            params={
                "cap_id": cap.cap_id, "scope_units": list(cap.scope_units),
                "cap_kw": int(cap.cap_kw), "per_member_pct": int(cap.per_member_pct),
                "draws": {u: int(kw) for u, kw in sorted(cap.draws.items())},
            },
            severity=Severity.SOFT, clause_kind=ClauseKind.OBLIGATION,
            compile_mode=CompileMode.CONFLICT_ONLY, resolution_class="EFFICIENCY",
            exception_mode=ExceptionMode.NONE,
            provenance=_span(f"power cap {cap.cap_id} <= {cap.cap_kw}kW"),
        ))

    # Maintenance windows -> one dc:maintenance_window rule per window (PLAN-DEPENDENT,
    # evaluated in Task 3 -> HARD/PLAN_CONSTRAINT). At Task 1 SOFT/CONFLICT_ONLY (no
    # verifier branch yet) so `check` over a Task-1 IR stays clean.
    for win in sorted(dc.maintenance_windows, key=lambda w: w.path_id):
        rules.append(Rule(
            rule_id="dc:maintenance_window", kind="maintenance_window",
            params={
                "path_id": win.path_id,
                "forbidden": [[a, b] for (a, b) in sorted(win.forbidden)],
                "derate_kw": {u: int(kw) for u, kw in sorted(win.derate_kw.items())},
            },
            severity=Severity.SOFT, clause_kind=ClauseKind.OBLIGATION,
            compile_mode=CompileMode.CONFLICT_ONLY, resolution_class="EFFICIENCY",
            exception_mode=ExceptionMode.NONE,
            provenance=_span(f"maintenance window on {win.path_id}"),
        ))

    # Anti-affinity groups -> one dc:anti_affinity rule per group. STRUCTURAL (B-4).
    for ag in sorted(dc.anti_affinity_groups, key=lambda a: a.group_id):
        rules.append(Rule(
            rule_id="dc:anti_affinity", kind="anti_affinity",
            params={
                "group_id": ag.group_id, "replicas": list(ag.replicas),
                "fault_domain_of": {u: fd for u, fd in sorted(ag.fault_domain_of.items())},
            },
            severity=Severity.SOFT, clause_kind=ClauseKind.OBLIGATION,
            compile_mode=CompileMode.CONFLICT_ONLY, resolution_class="EFFICIENCY",
            exception_mode=ExceptionMode.NONE,
            provenance=_span(f"anti-affinity {ag.group_id}"),
        ))

    return inst, rules


def _find_facility(ir: FCIR) -> dict:
    for r in ir.rules:
        if "facility" in r.params:
            return r.params["facility"]
    return {}


def unpack_dc_instance(ir: FCIR) -> DatacenterInstance:
    """The EXACT inverse of pack_dc_instance (STRICT — may raise on a malformed IR;
    NEVER called inside check_predicates). Two modes mirror the packer."""
    redundancy_rules = [r for r in ir.rules if r.rule_id == "dc:redundancy_floor"]

    # Legacy slice: a single redundancy rule with NO facility block.
    facility = _find_facility(ir)
    if redundancy_rules and not facility and len(redundancy_rules) == 1 and not _has_full_rules(ir):
        p = redundancy_rules[0].params
        return DatacenterInstance(
            group_id=p["group_id"], units=list(p["units"]), floor=p["floor"],
            horizon=p["horizon"],
            maintenance={u: [(a, b) for (a, b) in v] for u, v in p.get("maintenance", {}).items()},
        )

    # --- full facility ---
    horizon = ir.instance.horizon
    halls = [Hall(**h) for h in facility.get("halls", [])]
    feeds = [Feed(**f) for f in facility.get("feeds", [])]
    racks = [Rack(**r) for r in facility.get("racks", [])]
    fault_domains = [FaultDomain(**d) for d in facility.get("fault_domains", [])]
    maintenance_tasks = [
        MaintenanceTask(id=t["id"], path=t["path"], duration=int(t["duration"]), unit=t.get("unit"))
        for t in facility.get("maintenance_tasks", [])
    ]

    redundancy_groups = [
        RedundancyGroup(
            group_id=r.params["group_id"], units=list(r.params["units"]),
            floor=int(r.params["floor"]),
            maintenance={u: [(a, b) for (a, b) in v]
                         for u, v in r.params.get("maintenance", {}).items()},
        )
        for r in redundancy_rules
    ]
    power_caps = [
        PowerCap(
            cap_id=r.params["cap_id"], scope_units=list(r.params["scope_units"]),
            cap_kw=int(r.params["cap_kw"]), per_member_pct=int(r.params["per_member_pct"]),
            draws={u: int(kw) for u, kw in r.params["draws"].items()},
        )
        for r in ir.rules if r.rule_id == "dc:power_cap"
    ]
    maintenance_windows = [
        MaintenanceWindow(
            path_id=r.params["path_id"],
            forbidden=[(a, b) for (a, b) in r.params.get("forbidden", [])],
            derate_kw={u: int(kw) for u, kw in r.params.get("derate_kw", {}).items()},
        )
        for r in ir.rules if r.rule_id == "dc:maintenance_window"
    ]
    anti_affinity_groups = [
        AntiAffinityGroup(
            group_id=r.params["group_id"], replicas=list(r.params["replicas"]),
            fault_domain_of=dict(r.params["fault_domain_of"]),
        )
        for r in ir.rules if r.rule_id == "dc:anti_affinity"
    ]

    return DatacenterInstance(
        horizon=horizon,
        halls=halls, feeds=feeds, racks=racks, fault_domains=fault_domains,
        redundancy_groups=redundancy_groups, power_caps=power_caps,
        maintenance_tasks=maintenance_tasks, anti_affinity_groups=anti_affinity_groups,
        maintenance_windows=maintenance_windows,
    )


def _has_full_rules(ir: FCIR) -> bool:
    return any(r.rule_id in {"dc:power_cap", "dc:maintenance_window", "dc:anti_affinity", "dc:facility"}
               for r in ir.rules)


def baseline_plan(ir: FCIR, extra_outage: dict[str, tuple[int, int]]) -> Plan:
    """A shape-valid Plan: every op scheduled at start 0 on its (only) eligible machine.

    For the legacy slice each unit-op is at start 0 on its unit machine. For the full
    facility each maintenance-task op is at start 0 on its path machine. extra_outage
    records PLAN-scheduled outages (carried in the plan, NOT the instance) — encoded as
    a cleanout interval on the unit machine, used by the incumbent gotcha."""
    assignments: dict[str, tuple[int, str]] = {}
    for op in ir.instance.operations:
        assignments[op.op_id] = (0, op.eligible_machines[0])
    cleanouts = [(u, a, b, f"plan_outage:{u}") for u, (a, b) in sorted(extra_outage.items())]
    return Plan(assignments=assignments, cleanouts=cleanouts)
