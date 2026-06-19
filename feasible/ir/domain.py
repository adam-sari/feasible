"""FC-IR FJSP domain layer + per-node metadata, provenance, and the Plan type.

A ``Rule`` carries the deontic facet (``clause_kind`` / ``compile_mode``), the
conflict ``resolution_class`` (opaque, validated by the signed ConflictPolicy),
``exception_mode`` / ``overrides`` (the lex-specialis interlock), ``severity``,
and ``trust_tier``. A PERMISSION is *never* a plan constraint — it must compile
to ``CONFLICT_ONLY`` (enforced by a model validator).
"""
from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(str, Enum):
    HARD = "HARD"
    SOFT = "SOFT"


class ClauseKind(str, Enum):
    OBLIGATION = "OBLIGATION"
    PROHIBITION = "PROHIBITION"
    PERMISSION = "PERMISSION"
    EXCEPTION_CANDIDATE = "EXCEPTION_CANDIDATE"


class CompileMode(str, Enum):
    PLAN_CONSTRAINT = "PLAN_CONSTRAINT"
    CONFLICT_ONLY = "CONFLICT_ONLY"
    DROPPED_BY_POLICY = "DROPPED_BY_POLICY"


class ExceptionMode(str, Enum):
    NONE = "NONE"
    EXPLICIT_OVERRIDE = "EXPLICIT_OVERRIDE"
    HUMAN_OVERRIDE = "HUMAN_OVERRIDE"


class TrustTier(str, Enum):
    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"
    T5 = "T5"


class OpClass(str, Enum):
    PROCESS = "PROCESS"
    SANITATION = "SANITATION"
    SETUP = "SETUP"


class TextSpan(BaseModel):
    kind: Literal["text"] = "text"
    source_sha256: str = ""
    char_start: int = -1
    char_end: int = -1
    quoted_text: str
    heading_path: str = ""
    role: str = "primary_normative"

    @field_validator("quoted_text")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("TextSpan.quoted_text must be non-empty")
        return v


class CellRef(BaseModel):
    kind: Literal["cell"] = "cell"
    source_sha256: str = ""
    sheet: str
    a1: str
    role: str = "primary_normative"


SpanRef = Annotated[Union[TextSpan, CellRef], Field(discriminator="kind")]


class Provenance(BaseModel):
    spans: list[SpanRef] = Field(default_factory=list)


class Rule(BaseModel):
    rule_id: str
    kind: str  # routing_precedence | no_overlap | setup_cleanout | maintenance | shift | night_cleanout | permission ...
    params: dict = Field(default_factory=dict)
    severity: Severity
    clause_kind: ClauseKind
    compile_mode: CompileMode
    resolution_class: str | None = None
    exception_mode: ExceptionMode = ExceptionMode.NONE
    overrides: list[str] = Field(default_factory=list)
    trust_tier: TrustTier = TrustTier.T4
    provenance: Provenance

    @model_validator(mode="after")
    def _permission_is_conflict_only(self) -> "Rule":
        if (
            self.clause_kind == ClauseKind.PERMISSION
            and self.compile_mode != CompileMode.CONFLICT_ONLY
        ):
            raise ValueError(
                f"rule {self.rule_id}: PERMISSION must have compile_mode=CONFLICT_ONLY "
                f"(a permission is never a hard plan constraint)"
            )
        return self


class Job(BaseModel):
    id: str
    product: str
    family: str
    qty: int
    due_date: int  # integer minutes from epoch
    priority: int  # 1 = highest


class Operation(BaseModel):
    op_id: str
    job_id: str
    seq: int  # position in the job's routing (0-based)
    eligible_machines: list[str]
    duration: int
    op_class: OpClass = OpClass.PROCESS


class Instance(BaseModel):
    jobs: list[Job]
    operations: list[Operation]
    machines: list[str]
    # 'FROM|TO' family-transition -> setup minutes (JSON-safe string keys).
    setup_matrix: dict[str, int] = Field(default_factory=dict)
    maintenance: list[tuple[str, int, int]] = Field(default_factory=list)  # (machine, start, end)
    horizon: int

    def setup(self, from_family: str, to_family: str) -> int:
        return self.setup_matrix.get(f"{from_family}|{to_family}", 0)

    def job(self, job_id: str) -> Job:
        return next(j for j in self.jobs if j.id == job_id)

    def operation(self, op_id: str) -> Operation:
        return next(o for o in self.operations if o.op_id == op_id)


class FCIR(BaseModel):
    rules: list[Rule]
    instance: Instance

    def hard_plan_rules(self) -> list[Rule]:
        return [
            r
            for r in self.rules
            if r.severity == Severity.HARD and r.compile_mode == CompileMode.PLAN_CONSTRAINT
        ]

    def rule(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.rule_id == rule_id), None)

    def has_active(self, rule_id: str) -> bool:
        r = self.rule(rule_id)
        return (
            r is not None
            and r.severity == Severity.HARD
            and r.compile_mode == CompileMode.PLAN_CONSTRAINT
        )


class Plan(BaseModel):
    # op_id -> (start_minute, machine)
    assignments: dict[str, tuple[int, str]]
    # (machine, start, end, reason)
    cleanouts: list[tuple[str, int, int, str]] = Field(default_factory=list)

    def start(self, op_id: str) -> int:
        return self.assignments[op_id][0]

    def machine(self, op_id: str) -> str:
        return self.assignments[op_id][1]
