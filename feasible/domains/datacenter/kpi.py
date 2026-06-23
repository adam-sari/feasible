"""The datacenter verify-side KPI registry entries (Task 8).

The headline "we beat the baseline" claims are re-derived by ``verify`` from a
STATIC, allow-listed, solver-free + LLM-free recompute fn resolved from
``KPI_REGISTRY["datacenter"][key]["fn"]`` — NEVER a callable carried on the cert.
Each entry pins a ``(function_id, function_version, input_schema_digest)`` version
triple (the cert echoes it; ``verify`` asserts byte-equality with the registered
one, so a re-signed cert cannot claim a different/fabricated fn for a KPI value).

``stranded_power`` / ``maintenance_makespan`` are the SAME helpers
``DatacenterVerifier.objective`` carries (``feasible.domains.datacenter.verifier``)
— relocated by reference, not re-implemented — so the cert's signed ``objective``
leaf and the KPI surface agree exactly (one helper -> consistent). ``sla_penalty`` is
a derived integer (a flat per-unit penalty over the redundancy shortfall). The N+1
redundancy FLOOR is a HARD CONSTRAINT, not a KPI (design §4.6).

``input_schema_digest`` is a digest over the ``Instance`` + ``Plan`` Pydantic JSON
schemas (the SAME shape as manufacturing — the cert reconstructs the frozen
``Instance``/``Plan``). Deterministic (schema is strings/ints only — no floats).
"""
from __future__ import annotations

from feasible.canon.canonical import digest_of
from feasible.domains.base import KPI_REGISTRY, KpiEntry
from feasible.domains.datacenter.verifier import maintenance_makespan, stranded_power
from feasible.ir.domain import FCIR, Instance, Plan

# Bump only on a behavior change (the cert<->registry triple equality turns a silent
# fn swap into a verify failure).
KPI_FUNCTION_VERSION = "v1"

# A digest over the input schemas every KPI fn consumes (Instance + Plan). Computed
# once at import; deterministic (schema has no floats).
INPUT_SCHEMA_DIGEST = digest_of({
    "instance": Instance.model_json_schema(),
    "plan": Plan.model_json_schema(),
})

# The flat per-shortfall SLA penalty (an N+1 breach at one timestep costs this much).
# Integer; the penalty is 0 whenever the floor holds (the redundancy floor is a HARD
# constraint, so a CERTIFIED plan strands no power -> zero penalty).
SLA_PENALTY_PER_SHORTFALL = 1000


def sla_penalty(ir: FCIR, plan: Plan) -> int:
    """A flat per-unit SLA penalty over the redundancy shortfall (stranded power):
    ``SLA_PENALTY_PER_SHORTFALL * stranded_power(ir, plan)``. Solver-free, integer,
    recomputed from the signed plan+instance; 0 when the floor holds."""
    return SLA_PENALTY_PER_SHORTFALL * stranded_power(ir, plan)


def _entry(function_id: str, fn) -> KpiEntry:  # noqa: ANN001  (fn is a recompute callable)
    return KpiEntry(
        fn=fn,
        function_id=function_id,
        function_version=KPI_FUNCTION_VERSION,
        input_schema_digest=INPUT_SCHEMA_DIGEST,
    )


# kpi_key -> KpiEntry. ``verify`` resolves ``fn`` from HERE (never from a cert field).
DATACENTER_KPIS: dict[str, KpiEntry] = {
    "stranded_power": _entry("dc:stranded_power", stranded_power),
    "maintenance_makespan": _entry("dc:maintenance_makespan", maintenance_makespan),
    "sla_penalty": _entry("dc:sla_penalty", sla_penalty),
}

KPI_REGISTRY["datacenter"] = DATACENTER_KPIS
