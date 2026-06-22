"""CoverageFloor: at EVERY timestep in [0, horizon), the count of available units in a
group must be >= floor. A LOWER bound (min-cardinality), distinct from Cumulative's upper
bound. Closed, total, P-time; the authoritative check re-derives availability and never
trusts rendered capacity_series."""
from __future__ import annotations
from pydantic import BaseModel
from feasible.checker.result import Violation
from feasible.domains.base import register_witness_schema


class CoverageFloorWitness(BaseModel):
    group_id: str
    timestep: int
    available: int
    floor: int


register_witness_schema("coverage_floor", CoverageFloorWitness)


def coverage_floor_violations(available_by_t: dict[int, int], floor: int,
                              group_id: str, horizon: int) -> list[Violation]:
    out: list[Violation] = []
    for t in range(horizon):                       # total over the whole horizon — no omission
        available = available_by_t.get(t, 0)       # missing timestep => 0 => fail-closed
        if available < floor:
            w = {"group_id": group_id, "timestep": t, "available": available, "floor": floor}
            out.append(Violation(
                rule_id="dc:redundancy_floor", span=None,
                message=f"{group_id}: {available} available < floor {floor} at t={t}",
                counter_witness=w, witness_kind="coverage_floor", witness_version="v1"))
    return out


import z3

def coverage_floor_z3(available_vars: dict[int, "z3.ArithRef"], floor: int, horizon: int) -> list["z3.BoolRef"]:
    return [available_vars[t] >= floor for t in range(horizon)]
