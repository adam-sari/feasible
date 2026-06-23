"""Datacenter predicate bundle (Task 0 slice: dc:redundancy_floor only)."""
from __future__ import annotations
from typing import Any
import z3
from feasible.checker.coverage_floor import coverage_floor_violations, coverage_floor_z3
from feasible.checker.result import Violation
from feasible.ir.domain import FCIR, Plan

# the sentinel a missing param collapses to, so the floor FAILS CLOSED (a missing
# floor must never read as "no floor required"). A deterministic single violation.
_MISSING = object()


def _missing_param_violation(rule_id: str, key: str) -> Violation:
    return Violation(
        rule_id=rule_id, span=None,
        message=f"{rule_id}: required param {key!r} missing — fail-closed",
        counter_witness={"missing_param": key},
        witness_kind="missing_param", witness_version="v1",
    )


def _plan_outage_intervals(plan: Plan) -> dict[str, list[tuple[int, int]]]:
    """PLAN-scheduled outages (the schedulable decision carried IN the plan, never
    instance state): a cleanout whose reason is ``plan_outage:<unit>`` removes that
    unit for ``[start, end)``."""
    plan_outage: dict[str, list[tuple[int, int]]] = {}
    for (mc, cs, ce, reason) in plan.cleanouts:
        if str(reason).startswith("plan_outage:"):
            plan_outage.setdefault(mc, []).append((cs, ce))
    return plan_outage


def _redundancy_floor_violations(plan: Plan, ir: FCIR) -> list[Violation]:
    """TOTAL param reads: any missing required param -> ONE deterministic violation
    (passed=False), never a KeyError, never a silent pass."""
    r = ir.rule("dc:redundancy_floor")
    if r is None:
        return []
    p = r.params
    for key in ("group_id", "units", "floor", "horizon"):  # required
        if p.get(key, _MISSING) is _MISSING:
            return [_missing_param_violation("dc:redundancy_floor", key)]
    gid, units, floor, horizon = p["group_id"], list(p["units"]), int(p["floor"]), int(p["horizon"])
    maintenance = p.get("maintenance", {})  # optional -> default empty (total)
    plan_outage = _plan_outage_intervals(plan)
    avail: dict[int, int] = {}
    for t in range(horizon):
        n = 0
        for u in units:
            down = any(a <= t < b for (a, b) in maintenance.get(u, []))
            down = down or any(a <= t < b for (a, b) in plan_outage.get(u, []))
            if not down:
                n += 1
        avail[t] = n
    return coverage_floor_violations(avail, floor, gid, horizon)


def _available_by_t(plan: Plan, ir: FCIR) -> tuple[str, int, int, dict[int, int]]:
    """Used by the Z3 mirror + the objective seam. Reads params TOTALLY; a missing
    required param collapses the group to floor-breaching emptiness (fail-closed)."""
    r = ir.rule("dc:redundancy_floor")
    p = r.params if r is not None else {}
    gid = p.get("group_id", "?")
    units = list(p.get("units", []))
    floor = int(p.get("floor", 1 << 30))   # missing floor -> unsatisfiable (fail-closed)
    horizon = int(p.get("horizon", 0))
    maintenance = p.get("maintenance", {})
    plan_outage = _plan_outage_intervals(plan)
    avail: dict[int, int] = {}
    for t in range(horizon):
        n = 0
        for u in units:
            down = any(a <= t < b for (a, b) in maintenance.get(u, []))
            down = down or any(a <= t < b for (a, b) in plan_outage.get(u, []))
            if not down:
                n += 1
        avail[t] = n
    return gid, floor, horizon, avail


class DatacenterVerifier:
    domain_id: str = "datacenter"
    rule_kinds: frozenset[str] = frozenset({"redundancy_floor"})
    evaluated_rule_ids: frozenset[str] = frozenset({"dc:redundancy_floor"})
    structural_rule_kinds: frozenset[str] = frozenset()
    known_rule_ids: frozenset[str] = evaluated_rule_ids

    def check_predicates(self, plan: Plan, ir: FCIR) -> list[Violation]:
        out: list[Violation] = []
        if ir.has_active("dc:redundancy_floor"):
            out += _redundancy_floor_violations(plan, ir)  # TOTAL param reads (B-5)
        return out

    def z3_encode(self, plan: Plan, ir: FCIR) -> "z3.Solver":
        s = z3.Solver()
        s.set(unsat_core=True)
        if ir.has_active("dc:redundancy_floor"):
            gid, floor, horizon, avail = _available_by_t(plan, ir)
            a = {t: z3.Int(f"avail_{gid}_{t}") for t in range(horizon)}
            for t in range(horizon):
                s.add(a[t] == avail[t])
            for t, expr in enumerate(coverage_floor_z3(a, floor, horizon)):
                s.assert_and_track(expr, f"dc:redundancy_floor:{gid}:{t}")
        return s

    def gotcha_rule_id(self) -> str | None:
        return "dc:redundancy_floor"

    # --- Spec 0.5 objective seam: the REAL datacenter objective is SIGNED here
    # (verify_plan_cert recomputes via verifier.objective, Spec 0.5 T1), NOT via the
    # FJSP recompute_objective. Even the spike returns the real (stranded_power_kw,
    # makespan) tuple so the cert's objective leaf is honest from Task 0 on. ---
    objective_labels: tuple[str, ...] = ("stranded_power_kw", "makespan")

    def objective(self, ir: FCIR, plan: Plan) -> tuple[int, ...]:
        # spike proxy (Task 7 generalizes to real stranded kW over the full facility):
        # stranded_power_kw = sum_t max(0, floor - available_t) — the per-timestep
        # redundancy SHORTFALL below the N+1 floor (0 when the floor holds, positive
        # for a buffer-spending plan); makespan = last plan-scheduled outage end (0 when
        # none). Both solver-free non-negative integers from the signed plan+instance.
        gid, floor, horizon, avail = _available_by_t(plan, ir)
        stranded = sum(max(0, floor - avail[t]) for t in range(horizon))
        makespan = max(
            [ce for (_mc, _cs, ce, reason) in plan.cleanouts
             if str(reason).startswith("plan_outage:")],
            default=0,
        )
        return (stranded, makespan)

    def optimality_tripwire(self, ir: FCIR, objective: tuple[int, ...]) -> bool:
        # the dc objective is solver-reported, not Z3-attested optimal -> opt out
        # honestly (the Spec 0.5 seam tolerates any tuple length; only the mfg impl
        # asserts len==2). Task 9 binds the trust_boundary note.
        return False

    # Protocol stubs filled by later tasks:
    def compile(self, ir: Any, model: Any = None) -> Any:
        raise NotImplementedError

    def kpis(self) -> list[Any]:
        return []

    def classify_segment(self, seg: Any) -> str:
        return "boilerplate"

    def back_translate(self, rule: Any) -> str:
        return rule.rule_id

    def conflict_realizable(self, ir: Any, permission: Any) -> bool:
        return False

    def conflict_unsat_core(self, o: str, p: str) -> list[str] | None:
        return None
