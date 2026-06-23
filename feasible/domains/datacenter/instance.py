"""The DatacenterInstance + the lossless convention that serializes a facility
into the FROZEN Instance/Plan shape (delta #1: the cert core is hardwired to
Instance/Plan; we encode the facility INTO it rather than touch cert/)."""
from __future__ import annotations
from pydantic import BaseModel, Field
from feasible.ir.domain import (
    ClauseKind, CompileMode, ExceptionMode, FCIR, Instance, Job, Operation,
    Plan, Provenance, Rule, Severity, TextSpan,
)


class DatacenterInstance(BaseModel):
    """The redundancy-floor slice (Task 0). Task 4/8 add halls/feeds/racks/power/
    cooling/fault-domains. Integers only (no floats in the hashed body)."""
    group_id: str
    units: list[str]
    floor: int
    horizon: int
    maintenance: dict[str, list[tuple[int, int]]] = Field(default_factory=dict)  # unit -> [(start,end)]


def pack_dc_instance(dc: DatacenterInstance) -> tuple[Instance, list[Rule]]:
    """Encode the facility into a frozen Instance + the dc:redundancy_floor Rule.

    Each unit -> one Job + one Operation on a per-unit machine (machine == unit),
    duration 1, so validate_plan_shape (frozen, FJSP-coded) passes. The redundancy
    topology lives entirely in the rule params (re-derivable, never solver state)."""
    jobs = [Job(id=u, product=u, family="unit", qty=1, due_date=dc.horizon, priority=3) for u in dc.units]
    ops = [Operation(op_id=u, job_id=u, seq=0, eligible_machines=[u], duration=1) for u in dc.units]
    inst = Instance(jobs=jobs, operations=ops, machines=list(dc.units),
                    setup_matrix={}, maintenance=[], horizon=dc.horizon)
    params = {
        "group_id": dc.group_id, "units": list(dc.units), "floor": dc.floor,
        "horizon": dc.horizon,
        # JSON-safe: lists not tuples; sorted for determinism
        "maintenance": {u: [[a, b] for (a, b) in sorted(v)] for u, v in sorted(dc.maintenance.items())},
    }
    rule = Rule(
        rule_id="dc:redundancy_floor", kind="redundancy_floor", params=params,
        severity=Severity.HARD, clause_kind=ClauseKind.OBLIGATION,
        compile_mode=CompileMode.PLAN_CONSTRAINT,
        # CRITICAL (B-3): the resolution_class is literally SAFETY_SANITATION, NOT a
        # bespoke "REDUNDANCY" id. The frozen no_permission_outranks_safety guard keys
        # ONLY on SAFETY_CLASS_ID == "SAFETY_SANITATION" (conflict/policy.py:57,68): a
        # policy demoting redundancy below acceleration is only CAUGHT if redundancy IS
        # the safety class. A bespoke "REDUNDANCY" class would satisfy the guard
        # VACUOUSLY (the guard never looks at it), so an inverted policy would be
        # silently admitted. The N+1/2N redundancy floor IS this domain's safety floor.
        resolution_class="SAFETY_SANITATION",
        exception_mode=ExceptionMode.NONE,
        provenance=Provenance(spans=[TextSpan(quoted_text="redundancy floor (spike)", role="modeling_decision")]),
    )
    return inst, [rule]


def unpack_dc_instance(ir: FCIR) -> DatacenterInstance:
    r = ir.rule("dc:redundancy_floor")
    assert r is not None, "dc:redundancy_floor rule absent"
    p = r.params
    return DatacenterInstance(
        group_id=p["group_id"], units=list(p["units"]), floor=p["floor"], horizon=p["horizon"],
        maintenance={u: [(a, b) for (a, b) in v] for u, v in p.get("maintenance", {}).items()},
    )


def baseline_plan(ir: FCIR, extra_outage: dict[str, tuple[int, int]]) -> Plan:
    """A shape-valid Plan: every unit-op scheduled at start 0 on its unit machine.
    extra_outage records PLAN-scheduled outages used by the incumbent gotcha (carried
    in the plan, NOT the instance) — encoded as a cleanout interval on the unit machine."""
    assignments = {u: (0, u) for u in (o.op_id for o in ir.instance.operations)}
    cleanouts = [(u, a, b, f"plan_outage:{u}") for u, (a, b) in sorted(extra_outage.items())]
    return Plan(assignments=assignments, cleanouts=cleanouts)
