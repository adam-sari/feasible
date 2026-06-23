"""Manufacturing's verify-side KPI registry entries (Task 11).

The headline "we beat the baseline" claims are re-derived by ``verify`` from a
STATIC, allow-listed, solver-free + LLM-free recompute function resolved from
``KPI_REGISTRY[domain_id][key]["fn"]`` — NEVER a callable carried on the cert.
Each entry pins a ``(function_id, function_version, input_schema_digest)`` version
triple; the cert echoes the triple and ``verify`` asserts byte-equality with the
registered one (a re-signed cert cannot claim a different/fabricated function for
a KPI value). The three functions are the EXISTING manufacturing recompute helpers
(``feasible.solve.orchestrate``) — relocated by reference, not re-implemented — so
the KPI values are unchanged; only their provenance is now version-pinned.

``input_schema_digest`` is a digest over the ``Instance`` + ``Plan`` Pydantic JSON
schemas (the inputs every KPI fn consumes). It is deterministic (the schema is
strings/ints only — no floats) and binds the cert to the input shape the registered
fn was written against: if the instance/plan schema changes, the digest changes and
old certs no longer match the registry triple.
"""
from __future__ import annotations

from typing import Callable

from feasible.canon.canonical import digest_of
from feasible.domains.base import KPI_REGISTRY, KpiEntry
from feasible.ir.domain import FCIR, Instance, Plan

# The version pinned to every manufacturing KPI fn. Bump only on a behavior change
# (the cert<->registry triple equality turns a silent fn swap into a verify failure).
KPI_FUNCTION_VERSION = "v1"

# A digest over the input schemas every KPI fn consumes (Instance + Plan). Computed
# once at import; deterministic (schema has no floats).
INPUT_SCHEMA_DIGEST = digest_of({
    "instance": Instance.model_json_schema(),
    "plan": Plan.model_json_schema(),
})


# Import-style note (cf. ``datacenter/kpi.py``): manufacturing's recompute fns live in
# ``feasible.solve.orchestrate`` (an out-of-domain module that transitively imports the
# checker, which triggers THIS registration) — so they MUST be imported LAZILY to break
# the cycle. The datacenter KPIs source their fns from the datacenter verifier (an
# IN-package module, no cycle), so that file imports them DIRECTLY at module top. The
# fn here is the SAME existing helper, resolved by name from orchestrate (no re-impl).
def _orchestrate_fn(name: str) -> Callable[[FCIR, Plan], int]:
    def _call(ir: FCIR, plan: Plan) -> int:
        from feasible.solve import orchestrate

        return getattr(orchestrate, name)(ir, plan)

    _call.__name__ = name
    _call.__qualname__ = f"orchestrate.{name}"
    return _call


def _entry(function_id: str, name: str) -> KpiEntry:
    return KpiEntry(
        fn=_orchestrate_fn(name),
        function_id=function_id,
        function_version=KPI_FUNCTION_VERSION,
        input_schema_digest=INPUT_SCHEMA_DIGEST,
    )


# domain_id -> {kpi_key -> KpiEntry}. ``verify`` resolves ``fn`` from HERE.
MANUFACTURING_KPIS: dict[str, KpiEntry] = {
    "weighted_tardiness": _entry("mfg:weighted_tardiness", "weighted_tardiness"),
    "late_priority_orders": _entry("mfg:late_priority_orders", "late_priority_orders"),
    "total_changeover_time": _entry("mfg:total_changeover_time", "total_changeover_time"),
}

KPI_REGISTRY["manufacturing"] = MANUFACTURING_KPIS
