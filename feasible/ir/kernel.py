"""FC-IR kernel: the wedge-agnostic temporal/resource layer.

Every hard PLAN_CONSTRAINT desugars to these closed-form constraint families.
The kernel never grows per-wedge; new wedges add domain nodes (``domain.py``)
that desugar into exactly these types.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class Interval(BaseModel):
    """An optional operation interval on a specific machine."""

    op_id: str
    machine: str
    duration: int
    start: int | None = None
    end: int | None = None
    present: bool = True


class NoOverlap(BaseModel):
    """No two intervals on ``machine`` may overlap."""

    machine: str
    interval_ids: list[str]


class Cumulative(BaseModel):
    """Sum of ``demands`` active at any instant must not exceed ``capacity``."""

    resource: str
    demands: list[tuple[str, int]]  # (interval_id, demand)
    capacity: int


class CoverageFloor(BaseModel):
    group_id: str
    units: list[str]
    floor: int
    horizon: int


class Precedence(BaseModel):
    """``start[after_op] >= end[before_op] + gap`` (a difference constraint)."""

    before_op: str
    after_op: str
    gap: int = 0


class SoftPenalty(BaseModel):
    """A weighted objective contribution (e.g. per-job tardiness)."""

    term: str
    weight: int


class KernelModel(BaseModel):
    """A structural projection of an FCIR onto the kernel constraint families."""

    intervals: list[Interval] = Field(default_factory=list)
    no_overlaps: list[NoOverlap] = Field(default_factory=list)
    cumulatives: list[Cumulative] = Field(default_factory=list)
    precedences: list[Precedence] = Field(default_factory=list)
    soft_penalties: list[SoftPenalty] = Field(default_factory=list)
