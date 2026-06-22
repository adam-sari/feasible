"""Domain seam: protocols, view-models, and the witness-schema registry.

This module is pure scaffolding for the domain-pluggable trust core. It defines:

- the witness-schema registry (typed counter-witness validation, fail-closed),
- the ``DomainVerifier`` predicate-bundle ``Protocol`` (design §1.2),
- the ``Domain`` data/presentation ``Protocol`` (design §1.4),
- the ``KpiEntry`` verify-side registry shape (design §1.3),
- the frozen facade view-model dataclasses (design §1.5).

No crypto and no domain logic lives here — a domain owns no crypto. Concrete
``Domain``/``DomainVerifier`` implementations and the populated ``KPI_REGISTRY``
land in later Spec-0 tasks; this is the seam every track forks against.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, TypedDict, runtime_checkable

from pydantic import BaseModel

# --------------------------------------------------------------------------- #
# Witness-schema registry (typed counter-witnesses, fail-closed)              #
# --------------------------------------------------------------------------- #

_WITNESS_SCHEMAS: dict[str, type[BaseModel]] = {}


def register_witness_schema(witness_kind: str, model: type[BaseModel]) -> None:
    _WITNESS_SCHEMAS[witness_kind] = model


def validate_witness(witness_kind: str, counter_witness: dict) -> BaseModel:
    return _WITNESS_SCHEMAS[witness_kind].model_validate(counter_witness)  # KeyError = fail-closed


# --------------------------------------------------------------------------- #
# Verify-side KPI registry (design §1.3)                                       #
# --------------------------------------------------------------------------- #


class KpiEntry(TypedDict):
    """A single verify-side KPI binding. ``fn`` is a STATIC, allow-listed,
    solver-free + LLM-free recompute function; the ``(function_id,
    function_version, input_schema_digest)`` triple is the version pin the
    cert must match (mismatch => reject)."""

    fn: Callable[..., Any]
    function_id: str
    function_version: str
    input_schema_digest: str


# ``domain_id -> {kpi_key -> KpiEntry}``. Populated by registered domains in a
# later task; ``verify`` resolves ``fn`` from HERE, never from a cert field.
KPI_REGISTRY: dict[str, dict[str, KpiEntry]] = {}


# --------------------------------------------------------------------------- #
# DomainVerifier seam (design §1.2)                                           #
# --------------------------------------------------------------------------- #


@runtime_checkable
class DomainVerifier(Protocol):
    """The per-domain predicate bundle. The checker, Z3 attestor, registry,
    compiler, objective, conflict-detection, back-translation, and coverage
    classification dispatch through these members instead of branching on
    global manufacturing rule_ids. Predicates are closed, total, and P-time;
    rule_ids are namespaced (``mfg:`` / ``dc:``)."""

    domain_id: str
    rule_kinds: frozenset[str]
    evaluated_rule_ids: frozenset[str]
    structural_rule_kinds: frozenset[str]
    # The complete set of rule_ids this domain owns: the evaluated (checked) ids,
    # the structural (compiled-only) ids, and the conflict-only permission ids.
    # The signed ``domain_id`` selects the bundle; ``verify`` rejects any cert
    # rule_id not in THIS set (the cross-domain isolation guard, fail-closed).
    # Registered domains' ``known_rule_ids`` are asserted pairwise-disjoint
    # (``domains_known_rule_ids_disjoint``) so a future id collision fails CI.
    known_rule_ids: frozenset[str]

    def check_predicates(self, plan: Any, ir: Any) -> list[Any]:
        """Closed, total, P-time. Returns ``list[Violation]``."""
        ...

    def z3_encode(self, plan: Any, ir: Any) -> Any:
        """Parallel Z3 attestation bundle."""
        ...

    def compile(self, ir: Any, model: Any) -> Any:
        """CP-SAT variable mapping."""
        ...

    def objective(self, ir: Any, plan: Any) -> tuple[int, ...]:
        """Variable-length lexicographic objective."""
        ...

    def kpis(self) -> list[Any]:
        """Allow-listed (emit-only) KPI recompute fns."""
        ...

    def gotcha_rule_id(self) -> str | None:
        """Which rule the headline gotcha cites (namespaced), or ``None``."""
        ...

    def classify_segment(self, seg: Any) -> str:
        """Domain normativity taxonomy."""
        ...

    def back_translate(self, rule: Any) -> str:
        """Domain natural-language renderer."""
        ...

    def conflict_realizable(self, ir: Any, permission: Any) -> bool:
        """Replayed in ``verify``."""
        ...

    def conflict_unsat_core(self, obligation_id: str, permission_id: str) -> list[str] | None:
        ...


# --------------------------------------------------------------------------- #
# Domain protocol — data/presentation (design §1.4)                          #
# --------------------------------------------------------------------------- #


@runtime_checkable
class Domain(Protocol):
    """The data/presentation half of a domain. Owns NO crypto."""

    domain_id: str
    display_name: str

    def policy_doc(self) -> Any: ...
    def build_extracted_pack(self) -> Any: ...
    def golden_ir(self) -> Any: ...
    def incumbents(self) -> Any: ...
    def policy(self) -> Any: ...
    def viz_meta(self) -> Any: ...
    def trust_boundary_extra(self) -> Any: ...


# --------------------------------------------------------------------------- #
# Facade view-models (design §1.5) — frozen schema, datacenter-only fields    #
# default to ``None``/empty for manufacturing.                                #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ScenarioInfo:
    domain_id: str
    display_name: str
    data: str  # "real" | "synthetic"


@dataclass(frozen=True)
class InputsView:
    domain_id: str
    jobs: list[dict] = field(default_factory=list)
    operations: list[dict] = field(default_factory=list)
    machines: list[str] = field(default_factory=list)
    # datacenter-only:
    units: list[dict] | None = None
    groups: list[dict] | None = None


@dataclass(frozen=True)
class ConstraintsView:
    domain_id: str
    rules: list[dict] = field(default_factory=list)
    dropped: list[dict] = field(default_factory=list)
    # Gemini-draft sub-shape for Constraint Studio (datacenter/console track):
    draft: dict | None = None


@dataclass(frozen=True)
class TrustVector:
    signature: str  # "authenticated" | "self_described" | "unverified"
    checker: str    # "pass" | "fail"
    coverage: str   # "calibrated" | "preview"
    conflict_replay: str  # "verified" | "illustrative"
    data: str       # "real" | "synthetic"


@dataclass(frozen=True)
class CertifyResult:
    domain_id: str
    plan_cert: dict
    rule_pack_cert: dict
    trust_vector: TrustVector


@dataclass(frozen=True)
class TimelineView:
    domain_id: str
    lanes: list[dict] = field(default_factory=list)
    intervals: list[dict] = field(default_factory=list)
    # datacenter-only:
    capacity_series: list[dict] | None = None
    threshold_lines: list[dict] | None = None


@dataclass(frozen=True)
class CertsView:
    domain_id: str
    plan_cert: dict
    rule_pack_cert: dict


@dataclass(frozen=True)
class VerifyView:
    ok: bool
    reasons: list[str] = field(default_factory=list)
    trust_vector: TrustVector | None = None


# --------------------------------------------------------------------------- #
# Cross-domain rule-id isolation guard (design Global Constraint)             #
# --------------------------------------------------------------------------- #


def domains_known_rule_ids_disjoint() -> bool:
    """Assert every registered domain's ``known_rule_ids`` are pairwise-disjoint.

    Cross-domain isolation is enforced by the signed ``domain_id`` + per-domain
    ``known_rule_ids`` sets: a cert's every rule_id must belong to its signed
    domain's set (fail-closed). For that to be unambiguous the sets must not
    overlap — a single rule_id may belong to at most one domain. This guard is a
    CI tripwire: a future id collision (e.g. a datacenter rule reusing an ``R-*``
    id) flips it to ``False`` and fails the disjointness test.
    """
    # Imported lazily to avoid a base<->registry import cycle (the registry
    # module imports the protocols defined above from this module).
    from feasible.domains import _DOMAINS

    seen: set[str] = set()
    for _domain, verifier in _DOMAINS.values():
        ids = set(verifier.known_rule_ids)
        if ids & seen:
            return False
        seen |= ids
    return True
