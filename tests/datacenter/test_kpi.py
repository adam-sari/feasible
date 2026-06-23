"""Task 8: KPI_REGISTRY["datacenter"] — integer, solver-free, beats the baseline.

The stranded-power / makespan KPIs are the SAME quantities the cert's signed
``objective`` carries (via ``DatacenterVerifier.objective`` -> ``dc_objective``),
so the KPI surface and the objective leaf are consistent (one shared helper).
The redundancy floor is a HARD CONSTRAINT, not a KPI.

  * each KPI fn is integer-valued + solver-free (recomputed from ``(ir, plan)``);
  * ``stranded_power(optimized) <= stranded_power(incumbent_b)`` (we beat the
    baseline);
  * the ``stranded_power`` KPI fn equals ``DatacenterVerifier.objective(...)[0]``
    (shared helper);
  * ``KPI_REGISTRY["datacenter"]`` triples are well-formed.
"""
from __future__ import annotations

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
from feasible.domains import get_domain
from feasible.domains.base import KPI_REGISTRY
from feasible.domains.datacenter.scenario import (
    build_dc_scenario_active_ir,
    dc_incumbent_b,
)
from feasible.domains.datacenter.solve import dc_solve


def test_registry_triples_well_formed():
    kpis = KPI_REGISTRY["datacenter"]
    assert set(kpis) == {"stranded_power", "maintenance_makespan", "sla_penalty"}
    for key, entry in kpis.items():
        assert callable(entry["fn"])
        assert entry["function_id"].startswith("dc:")
        assert entry["function_version"] == "v1"
        assert isinstance(entry["input_schema_digest"], str) and entry["input_schema_digest"]


def test_each_kpi_is_integer_and_solver_free():
    ir = build_dc_scenario_active_ir()
    plan = dc_solve(ir, workers=1, seed=1).plan
    assert plan is not None
    for key, entry in KPI_REGISTRY["datacenter"].items():
        v = entry["fn"](ir, plan)
        assert isinstance(v, int), f"{key} not integer: {v!r}"


def test_stranded_power_kpi_equals_objective_level0():
    ir = build_dc_scenario_active_ir()
    plan = dc_solve(ir, workers=1, seed=1).plan
    assert plan is not None
    _, verifier = get_domain("datacenter")
    fn = KPI_REGISTRY["datacenter"]["stranded_power"]["fn"]
    assert fn(ir, plan) == verifier.objective(ir, plan)[0]


def test_makespan_kpi_equals_objective_level1():
    ir = build_dc_scenario_active_ir()
    plan = dc_solve(ir, workers=1, seed=1).plan
    assert plan is not None
    _, verifier = get_domain("datacenter")
    fn = KPI_REGISTRY["datacenter"]["maintenance_makespan"]["fn"]
    assert fn(ir, plan) == verifier.objective(ir, plan)[1]


def test_optimized_beats_baseline_stranded_power():
    ir = build_dc_scenario_active_ir()
    optimized = dc_solve(ir, workers=1, seed=1).plan
    assert optimized is not None
    inc_b = dc_incumbent_b(ir)
    fn = KPI_REGISTRY["datacenter"]["stranded_power"]["fn"]
    assert fn(ir, optimized) <= fn(ir, inc_b)
