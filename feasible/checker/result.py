"""Shared verifier result types (kept here so checker.py and plan_shape.py can
both import them without a circular dependency)."""
from __future__ import annotations

from pydantic import BaseModel, Field

from feasible.ir.domain import CellRef, TextSpan


class Violation(BaseModel):
    rule_id: str
    span: TextSpan | CellRef | None = None
    message: str
    counter_witness: dict = Field(default_factory=dict)


class CheckResult(BaseModel):
    passed: bool
    violations: list[Violation] = Field(default_factory=list)
