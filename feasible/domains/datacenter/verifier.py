"""Datacenter predicate bundle.

Task 0 slice: ``dc:redundancy_floor`` (PLAN-DEPENDENT evaluated).
Task 2 adds:  ``dc:power_cap`` (STRUCTURAL instance-invariant — B-4).
Task 3 adds:  ``dc:maintenance_window`` (PLAN-DEPENDENT evaluated — a scheduled
              maintenance task overlapping a forbidden window on its path).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import z3
from ortools.sat.python import cp_model
from pydantic import BaseModel
from feasible.checker.coverage_floor import coverage_floor_violations, coverage_floor_z3
from feasible.checker.result import Violation
from feasible.domains.base import register_witness_schema
from feasible.ir.domain import CompileMode, FCIR, Plan, Rule, Severity

# the sentinel a missing param collapses to, so the floor FAILS CLOSED (a missing
# floor must never read as "no floor required"). A deterministic single violation.
_MISSING = object()


class MissingParamWitness(BaseModel):
    """The fail-closed witness a TOTAL param read emits when a required param is
    omitted (B-5). It is a REGISTERED witness kind so ``validate_witness`` round-trips
    it like every other witness — an unregistered kind a predicate can emit would be
    a fail-closed hole (``validate_witness`` would ``KeyError`` on the cert's own
    counter-witness)."""

    missing_param: str


register_witness_schema("missing_param", MissingParamWitness)


def _missing_param_violation(rule_id: str, key: str) -> Violation:
    return Violation(
        rule_id=rule_id, span=None,
        message=f"{rule_id}: required param {key!r} missing — fail-closed",
        counter_witness={"missing_param": key},
        witness_kind="missing_param", witness_version="v1",
    )


# --------------------------------------------------------------------------- #
# dc:power_cap (Task 2) — STRUCTURAL instance-invariant (B-4)                  #
# --------------------------------------------------------------------------- #
# In v1 a rack's nameplate ``draw`` is a FIXED instance fact (not a plan
# decision), so the power cap is an instance-level structural invariant over the
# certified instance — NOT a plan-dependent predicate masquerading as
# plan-checked. Its kind lives in ``structural_rule_kinds`` (the registry does
# not REQUIRE a predicate for it), but a closed/total checker predicate STILL
# runs (a structural-kind rule MAY carry one) and is Z3-mirrored. INTEGERS ONLY:
# the per-member NEC/≤pct% rule is an integer cross-multiply (no float).


class PowerCapWitness(BaseModel):
    cap_id: str
    scope: list[str]
    draw: int                 # the aggregate draw over the cap's scope
    cap: int                  # the cap (kW)
    members_over_pct: list[dict]   # [{"unit": str, "draw": int}] over per_member_pct% of cap


register_witness_schema("power_cap", PowerCapWitness)


def _power_cap_violations(plan: Plan, ir: FCIR) -> list[Violation]:
    """Closed/total instance-invariant over the certified instance. TOTAL param
    reads (B-5): every required param via ``p.get(...)`` with a fail-closed
    deterministic single violation — a missing ``cap_kw`` collapses to ``0`` (so
    every nonzero draw breaches), a missing ``draws[u]`` for a scope member is
    treated as the cap (so it breaches) — NEVER a ``KeyError``, never a silent
    pass. (``plan`` is unused — the draws are FIXED instance facts in v1.)"""
    r = ir.rule("dc:power_cap")
    if r is None:
        return []
    p = r.params
    for key in ("cap_id", "scope_units", "cap_kw", "per_member_pct", "draws"):  # required
        if p.get(key, _MISSING) is _MISSING:
            return [_missing_param_violation("dc:power_cap", key)]
    # TOTAL reads only (no bare subscripts): the guard above already returned for any
    # missing key, so .get() here is value-identical — but it keeps every param read
    # in this file a .get(), so a future edit moving a read before its guard cannot
    # reintroduce the crash-DoS.
    cap_id = str(p.get("cap_id"))
    scope = [str(u) for u in p.get("scope_units", [])]
    cap_kw = int(p.get("cap_kw", 0))            # default never reached (guard returned above)
    per_member_pct = int(p.get("per_member_pct", 0))
    draws = p.get("draws", {})

    # A missing draw for a scope member fails CLOSED: treat it as the full cap so a
    # member with an omitted nameplate cannot vacuously pass (never a KeyError).
    def _draw(u: str) -> int:
        v = draws.get(u, _MISSING)
        return cap_kw if v is _MISSING else int(v)

    aggregate = sum(_draw(u) for u in scope)
    # per-member NEC/failover rule: 100 * draw[u] <= per_member_pct * cap_kw
    # (integer cross-multiply — NO float). Deterministic order (scope order).
    members_over: list[dict] = [
        {"unit": u, "draw": _draw(u)}
        for u in scope
        if 100 * _draw(u) > per_member_pct * cap_kw
    ]
    if aggregate <= cap_kw and not members_over:
        return []
    w = {
        "cap_id": cap_id, "scope": list(scope), "draw": aggregate, "cap": cap_kw,
        "members_over_pct": members_over,
    }
    msg = f"{cap_id}: aggregate {aggregate} vs cap {cap_kw}"
    if members_over:
        msg += f"; {len(members_over)} member(s) over {per_member_pct}%"
    return [Violation(
        rule_id="dc:power_cap", span=None, message=msg,
        counter_witness=w, witness_kind="power_cap", witness_version="v1")]


def _power_cap_z3(s: "z3.Solver", ir: FCIR) -> None:
    """Mirror the aggregate cap + per-member pct as TRACKED Z3 assertions (the
    UNSAT core names ``dc:power_cap:<cap_id>`` / ``...:<unit>:pct``). Same TOTAL
    fail-closed param reads as the checker (a missing param yields an
    UNSATISFIABLE tracked assertion, so attest fails closed)."""
    r = ir.rule("dc:power_cap")
    if r is None:
        return
    p = r.params
    cap_id = str(p.get("cap_id", "?"))
    scope = [str(u) for u in p.get("scope_units", [])]
    # missing cap_kw -> 0 (every nonzero draw breaches); missing per_member_pct -> 0.
    cap_kw = int(p.get("cap_kw", 0))
    per_member_pct = int(p.get("per_member_pct", 0))
    draws = p.get("draws", {})

    def _draw(u: str) -> int:
        v = draws.get(u, _MISSING)
        return cap_kw if v is _MISSING else int(v)

    d = {u: z3.Int(f"draw_{cap_id}_{u}") for u in scope}
    for u in scope:
        s.add(d[u] == _draw(u))
    # aggregate: sum(draws) <= cap_kw
    agg = z3.Sum([d[u] for u in scope]) if scope else z3.IntVal(0)
    s.assert_and_track(agg <= cap_kw, f"dc:power_cap:{cap_id}")
    # per-member: 100 * draw[u] <= per_member_pct * cap_kw (integer cross-multiply)
    for u in scope:
        s.assert_and_track(
            100 * d[u] <= per_member_pct * cap_kw,
            f"dc:power_cap:{cap_id}:{u}:pct",
        )


# --------------------------------------------------------------------------- #
# dc:maintenance_window (Task 3) — PLAN-DEPENDENT evaluated                    #
# --------------------------------------------------------------------------- #
# A scheduled maintenance TASK (an Operation on a path "machine") whose interval
# ``[start, start+duration)`` overlaps a FORBIDDEN window on that path (e.g. a
# change-freeze window) is a violation. The schedulable decision (the start) is
# the plan's; the duration is the packed op's. Half-open ``[a,b)`` so endpoint
# inclusivity is exact: a task ending precisely at ``forbidden_start`` (or
# starting precisely at ``forbidden_end``) does NOT overlap. Code-disjoint from
# CP-SAT; Z3-mirrored as a tracked assertion ``dc:maintenance_window:<path>:<task>``.


class MaintenanceWindowWitness(BaseModel):
    path_id: str
    task: str                 # the op_id of the offending maintenance task
    window: list[int]         # the forbidden [start, end) it overlaps
    task_start: int
    task_end: int


register_witness_schema("maintenance_window", MaintenanceWindowWitness)


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """The frozen half-open ``[start, end)`` overlap convention (mirror
    ``manufacturing.verifier._overlaps``)."""
    return a_start < b_end and b_start < a_end


def _path_tasks(plan: Plan, ir: FCIR, path_id: str) -> list[tuple[str, int, int]]:
    """Every scheduled maintenance task on ``path_id`` as ``(op_id, start, end)``
    where ``end = start + op.duration``. Reads the op duration from the certified
    instance; a task whose only eligible machine is ``path_id`` and which the plan
    schedules on ``path_id`` counts. TOTAL: an op absent from the plan is skipped
    (never a KeyError)."""
    out: list[tuple[str, int, int]] = []
    for op in ir.instance.operations:
        if op.op_id not in plan.assignments:
            continue
        if plan.machine(op.op_id) != path_id:
            continue
        start = plan.start(op.op_id)
        out.append((op.op_id, start, start + int(op.duration)))
    return out


def _maintenance_window_violations(plan: Plan, ir: FCIR) -> list[Violation]:
    """TOTAL param reads (B-5): a missing ``path_id``/``forbidden`` -> ONE
    deterministic violation (passed=False), never a KeyError, never a silent pass.
    A scheduled task overlapping a forbidden window on its path is flagged with a
    per-(task, window) witness."""
    out: list[Violation] = []
    for r in ir.rules:
        if r.rule_id != "dc:maintenance_window":
            continue
        if not ir.has_active(r.rule_id):
            continue
        p = r.params
        for key in ("path_id", "forbidden"):  # required
            if p.get(key, _MISSING) is _MISSING:
                out.append(_missing_param_violation("dc:maintenance_window", key))
                break
        else:
            path_id = str(p.get("path_id"))
            forbidden = [(int(a), int(b)) for (a, b) in p.get("forbidden", [])]
            for (op_id, ts, te) in _path_tasks(plan, ir, path_id):
                for (fa, fb) in forbidden:
                    if _overlaps(ts, te, fa, fb):
                        out.append(Violation(
                            rule_id="dc:maintenance_window", span=None,
                            message=(f"task {op_id} [{ts},{te}) on {path_id} overlaps "
                                     f"forbidden window [{fa},{fb})"),
                            counter_witness={
                                "path_id": path_id, "task": op_id,
                                "window": [fa, fb], "task_start": ts, "task_end": te,
                            },
                            witness_kind="maintenance_window", witness_version="v1",
                        ))
    return out


def _maintenance_window_z3(s: "z3.Solver", plan: Plan, ir: FCIR) -> None:
    """Mirror each (task, forbidden-window) disjointness as a TRACKED Z3 assertion
    ``dc:maintenance_window:<path>:<task>:<k>`` (``Or(task_end <= fa, task_start >=
    fb)``). Same TOTAL fail-closed param reads as the checker (a missing param
    yields an UNSATISFIABLE tracked assertion, so attest fails closed)."""
    for r in ir.rules:
        if r.rule_id != "dc:maintenance_window":
            continue
        if not ir.has_active(r.rule_id):
            continue
        p = r.params
        path_id = str(p.get("path_id", "?"))
        forbidden_raw = p.get("forbidden", _MISSING)
        if path_id == "?" or forbidden_raw is _MISSING:
            # fail closed: a missing required param -> an unsatisfiable tracked clause.
            s.assert_and_track(z3.BoolVal(False), f"dc:maintenance_window:{path_id}:MISSING_PARAM")
            continue
        forbidden = [(int(a), int(b)) for (a, b) in forbidden_raw]
        for (op_id, ts, te) in _path_tasks(plan, ir, path_id):
            ts_v = z3.Int(f"mw_start_{path_id}_{op_id}")
            te_v = z3.Int(f"mw_end_{path_id}_{op_id}")
            s.add(ts_v == ts)
            s.add(te_v == te)
            for k, (fa, fb) in enumerate(forbidden):
                s.assert_and_track(
                    z3.Or(te_v <= fa, ts_v >= fb),
                    f"dc:maintenance_window:{path_id}:{op_id}:{k}",
                )


# --------------------------------------------------------------------------- #
# dc:anti_affinity (Task 5) — STRUCTURAL instance-invariant (B-4)              #
# --------------------------------------------------------------------------- #
# In v1 the ``fault_domain_of`` replica->fault-domain assignment is a FIXED
# instance fact (replica PLACEMENT is not a plan decision), so anti-affinity is
# an instance-level structural invariant — NOT a plan-dependent predicate. Its
# kind lives in ``structural_rule_kinds`` (the registry does not REQUIRE a
# predicate for it), but a closed/total checker predicate STILL runs (a
# structural-kind rule MAY carry one) and is Z3-mirrored. Two replicas in the
# SAME power/cooling fault domain breach the group (a single fault knocks out
# both). INTEGERS ONLY in the Z3 mirror (fault domains mapped to integer ids).


class AntiAffinityWitness(BaseModel):
    group_id: str
    replicas: list[str]              # the colliding pair (sorted)
    shared_fault_domain: str         # the fd both replicas share (or an UNKNOWN sentinel)


register_witness_schema("anti_affinity", AntiAffinityWitness)

# the sentinel fd an UNMAPPED replica collapses to: a DISTINCT placeholder per
# replica that is treated as colliding with EVERY other replica (an unknown
# placement could be anywhere — fail closed as a collision-with-unknown, never a
# vacuous pass). The string carries the replica id so the witness is informative.
_UNKNOWN_FD_PREFIX = "__unknown_fd__:"


def _fd_of(fault_domain_of: dict, replica: str) -> tuple[str, bool]:
    """TOTAL read (B-5): the fault domain of ``replica``, and whether it is KNOWN.
    A missing mapping yields a distinct per-replica sentinel flagged unknown (so it
    cannot vacuously prove distinctness) — never a ``KeyError``."""
    v = fault_domain_of.get(replica, _MISSING)
    if v is _MISSING:
        return f"{_UNKNOWN_FD_PREFIX}{replica}", False
    return str(v), True


def _anti_affinity_violations(plan: Plan, ir: FCIR) -> list[Violation]:
    """Closed/total instance-invariant over the certified instance (B-4: the
    replica->fd placement is a FIXED instance fact in v1, so ``plan`` is unused).

    TOTAL param reads (B-5): a missing ``group_id``/``replicas`` -> ONE
    deterministic violation (passed=False), never a KeyError, never a silent pass.
    For every replica PAIR, if they share a fault domain (or EITHER is unmapped —
    an unknown placement fails CLOSED as a potential collision), emit a per-pair
    witness ``{group_id, replicas, shared_fault_domain}``. Deterministic order
    (sorted replica order, lexicographic pairs)."""
    out: list[Violation] = []
    for r in ir.rules:
        if r.rule_id != "dc:anti_affinity":
            continue
        if not ir.has_active(r.rule_id):
            continue
        p = r.params
        missing = next((k for k in ("group_id", "replicas")
                        if p.get(k, _MISSING) is _MISSING), None)
        if missing is not None:
            out.append(_missing_param_violation("dc:anti_affinity", missing))
            continue
        gid = str(p.get("group_id"))
        replicas = [str(u) for u in p.get("replicas", [])]
        fault_domain_of = p.get("fault_domain_of", {})  # optional -> total (unmapped fails closed)
        # deterministic lexicographic pairs over the replica list
        for i in range(len(replicas)):
            for j in range(i + 1, len(replicas)):
                r1, r2 = replicas[i], replicas[j]
                fd1, known1 = _fd_of(fault_domain_of, r1)
                fd2, known2 = _fd_of(fault_domain_of, r2)
                if fd1 == fd2:
                    shared = fd1
                elif not known1 or not known2:
                    # an unknown placement cannot be PROVEN distinct -> fail closed.
                    shared = fd1 if not known1 else fd2
                else:
                    continue  # both known and distinct -> no collision
                pair = sorted((r1, r2))
                out.append(Violation(
                    rule_id="dc:anti_affinity", span=None,
                    message=f"{gid}: replicas {pair[0]} and {pair[1]} share fault domain {shared}",
                    counter_witness={
                        "group_id": gid, "replicas": pair, "shared_fault_domain": shared,
                    },
                    witness_kind="anti_affinity", witness_version="v1",
                ))
    return out


def _anti_affinity_z3(s: "z3.Solver", ir: FCIR) -> None:
    """Mirror each replica PAIR's distinctness as a TRACKED Z3 assertion
    ``dc:anti_affinity:<group>:<r1>|<r2>``, fail-closed EXACTLY as the checker
    ``_anti_affinity_violations``:

    * BOTH replicas mapped (known fd) -> assert ``fd[r1] != fd[r2]`` over integer
      fault-domain ids (UNSAT iff they share a known fd — a real collision).
    * EITHER replica unmapped -> the placement is unknown and CANNOT be proven
      distinct, so the pair fails closed: assert a tracked ``False`` (forced
      UNSAT). This matches the checker, which emits a violation for any pair
      touching an unmapped replica (``elif not known1 or not known2``). NOTE: a
      shared sentinel int would be WRONG here — a mapped(=0)-vs-unmapped pair
      would read ``0 != sentinel`` -> SAT (no collision), silently diverging from
      the checker. Each unmapped replica therefore gets a UNIQUE fresh int (so the
      model is self-consistent), and the per-pair tracked ``False`` — not integer
      inequality — is what enforces the fail-closed UNSAT.
    * a missing required param yields an unsatisfiable tracked clause."""
    for r in ir.rules:
        if r.rule_id != "dc:anti_affinity":
            continue
        if not ir.has_active(r.rule_id):
            continue
        p = r.params
        gid = str(p.get("group_id", "?"))
        replicas_raw = p.get("replicas", _MISSING)
        if gid == "?" or replicas_raw is _MISSING:
            s.assert_and_track(z3.BoolVal(False), f"dc:anti_affinity:{gid}:MISSING_PARAM")
            continue
        replicas = [str(u) for u in replicas_raw]
        fault_domain_of = p.get("fault_domain_of", {})
        # map each DISTINCT KNOWN fault-domain string to a stable integer id
        # (deterministic by first-appearance over the sorted fd strings). Each
        # UNMAPPED replica gets its OWN fresh int beyond the known-fd range so the
        # model is consistent; the pair's fail-closed UNSAT comes from the tracked
        # False asserted below (not from a shared/sentinel integer value).
        known_fds = sorted({str(v) for v in fault_domain_of.values()})
        fd_id = {fd: idx for idx, fd in enumerate(known_fds)}
        next_unknown = len(known_fds)
        fd_var: dict[str, "z3.ArithRef"] = {}
        known: dict[str, bool] = {}
        for rep in replicas:
            v = fault_domain_of.get(rep, _MISSING)
            if v is _MISSING:
                pinned = next_unknown
                next_unknown += 1
                known[rep] = False
            else:
                pinned = fd_id[str(v)]
                known[rep] = True
            var = z3.Int(f"fd_{gid}_{rep}")
            s.add(var == pinned)
            fd_var[rep] = var
        for i in range(len(replicas)):
            for j in range(i + 1, len(replicas)):
                r1, r2 = replicas[i], replicas[j]
                tag = f"dc:anti_affinity:{gid}:{r1}|{r2}"
                if not known[r1] or not known[r2]:
                    # unknown placement -> not provably distinct -> fail closed.
                    s.assert_and_track(z3.BoolVal(False), tag)
                else:
                    s.assert_and_track(fd_var[r1] != fd_var[r2], tag)


def _plan_outage_intervals(plan: Plan) -> dict[str, list[tuple[int, int]]]:
    """PLAN-scheduled outages (the schedulable decision carried IN the plan, never
    instance state): a cleanout whose reason is ``plan_outage:<unit>`` removes that
    unit for ``[start, end)``."""
    plan_outage: dict[str, list[tuple[int, int]]] = {}
    for (mc, cs, ce, reason) in plan.cleanouts:
        if str(reason).startswith("plan_outage:"):
            plan_outage.setdefault(mc, []).append((cs, ce))
    return plan_outage


def _facility_block(ir: FCIR) -> dict[str, Any]:
    """The structural descriptor carried on the first redundancy/facility rule
    (mirror ``instance._facility_block``). TOTAL: an IR without one yields ``{}``."""
    for r in ir.rules:
        fac = r.params.get("facility")
        if isinstance(fac, dict):
            return fac
    return {}


def _task_outage_intervals(plan: Plan, ir: FCIR) -> dict[str, list[tuple[int, int]]]:
    """The HERO mechanism (Task 4): a PLAN-scheduled maintenance TASK derates the
    redundancy ``unit`` it runs on for ``[start, start+duration)``.

    The maintenance-task <-> unit linkage lives in the facility block
    (``maintenance_tasks: [{id, path, duration, unit}]``); the op is ``task:<id>``
    on its ``path`` machine; the start is the plan's schedulable decision and the
    duration is the packed op's. TOTAL: a task absent from the plan, with no
    ``unit`` linkage, or whose op is missing is SKIPPED (never a KeyError) — it
    simply contributes no outage."""
    facility = _facility_block(ir)
    tasks = facility.get("maintenance_tasks", [])
    if not isinstance(tasks, list):
        return {}
    # op_id -> instance op duration (TOTAL: missing -> skip).
    op_duration = {op.op_id: int(op.duration) for op in ir.instance.operations}
    out: dict[str, list[tuple[int, int]]] = {}
    for t in tasks:
        if not isinstance(t, dict):
            continue
        unit = t.get("unit")
        if unit is None:
            continue                       # a task with no redundancy linkage derates nothing
        op_id = f"task:{t.get('id')}"
        if op_id not in plan.assignments or op_id not in op_duration:
            continue                       # not scheduled / no op -> no outage (total)
        start = plan.start(op_id)
        dur = op_duration[op_id]
        if dur <= 0:
            continue                       # a zero-length task removes the unit for no time
        out.setdefault(str(unit), []).append((start, start + dur))
    return out


def _group_available_by_t(
    plan: Plan, ir: FCIR, params: dict[str, Any],
    task_outage: dict[str, list[tuple[int, int]]],
    plan_outage: dict[str, list[tuple[int, int]]],
) -> tuple[str, int, int, dict[int, int]]:
    """Per-group per-timestep AVAILABLE count, fail-closed on missing params.

    A unit is DOWN at ``t`` if any of (a) a FIXED instance maintenance interval,
    (b) a PLAN-scheduled maintenance TASK derating it, or (c) a ``plan_outage:``
    cleanout covers ``t``. ``available`` = installed units NOT down (floor is over
    AVAILABLE, never installed). Missing ``floor`` -> ``1<<30`` (unsatisfiable,
    fail-closed); missing ``units``/``horizon`` -> empty/0 (fail-closed via the
    kernel's ``range(horizon)`` + ``get(t, 0)``)."""
    gid = str(params.get("group_id", "?"))
    units = list(params.get("units", []))
    floor = int(params.get("floor", 1 << 30))   # missing floor -> unsatisfiable
    horizon = int(params.get("horizon", 0))
    maintenance = params.get("maintenance", {})
    avail: dict[int, int] = {}
    for t in range(horizon):
        n = 0
        for u in units:
            down = any(a <= t < b for (a, b) in maintenance.get(u, []))
            down = down or any(a <= t < b for (a, b) in task_outage.get(u, []))
            down = down or any(a <= t < b for (a, b) in plan_outage.get(u, []))
            if not down:
                n += 1
        avail[t] = n
    return gid, floor, horizon, avail


def _redundancy_groups(ir: FCIR) -> list[Rule]:
    """Every ``dc:redundancy_floor`` rule (multi-group). A unit shared across two
    groups counts DOWN in BOTH — each group is evaluated independently."""
    return [r for r in ir.rules if r.rule_id == "dc:redundancy_floor"]


def _active_redundancy_group(r: Rule) -> bool:
    """The SINGLE active-group predicate (mirrors ``FCIR.has_active``): a redundancy
    group is enforced iff it is HARD/PLAN_CONSTRAINT. The checker AND the Z3 mirror
    AND the objective seam all gate on THIS predicate, so check and attest agree
    GROUP-FOR-GROUP — an INACTIVE (SOFT/CONFLICT_ONLY) group that breaches is skipped
    by BOTH (the checker passes; the mirror must NOT over-constrain attest)."""
    return r.severity == Severity.HARD and r.compile_mode == CompileMode.PLAN_CONSTRAINT


def _active_redundancy_groups(ir: FCIR) -> list[Rule]:
    """The ACTIVE ``dc:redundancy_floor`` rules (the enforced groups). The shared
    iteration order for the checker, the Z3 mirror, and the objective seam."""
    return [r for r in _redundancy_groups(ir) if _active_redundancy_group(r)]


def _has_active_redundancy_group(ir: FCIR) -> bool:
    """Gate parity: TRUE iff at least one ACTIVE redundancy group exists. The checker
    gate and the Z3 gate both use THIS (not ``any rule_id == ...``), so an IR carrying
    ONLY inactive redundancy groups encodes no redundancy constraints in EITHER path."""
    return any(_active_redundancy_group(r) for r in _redundancy_groups(ir))


def _redundancy_floor_violations(plan: Plan, ir: FCIR) -> list[Violation]:
    """TOTAL param reads + MULTI-GROUP (Task 4): one ``coverage_floor_violations``
    call per ``dc:redundancy_floor`` rule. Any missing required param on a group ->
    ONE deterministic violation for THAT group (passed=False), never a KeyError,
    never a silent pass. Down-intervals merge fixed maintenance, PLAN-scheduled
    task derating, and ``plan_outage:`` cleanouts."""
    task_outage = _task_outage_intervals(plan, ir)
    plan_outage = _plan_outage_intervals(plan)
    out: list[Violation] = []
    for r in _active_redundancy_groups(ir):  # SHARED active-group predicate (= Z3 mirror)
        p = r.params
        missing = next((k for k in ("group_id", "units", "floor", "horizon")
                        if p.get(k, _MISSING) is _MISSING), None)
        if missing is not None:
            out.append(_missing_param_violation("dc:redundancy_floor", missing))
            continue
        gid, floor, horizon, avail = _group_available_by_t(
            plan, ir, p, task_outage, plan_outage)
        out += coverage_floor_violations(avail, floor, gid, horizon)
    return out


def _redundancy_groups_available(
    plan: Plan, ir: FCIR,
) -> list[tuple[str, int, int, dict[int, int]]]:
    """Per-group ``(group_id, floor, horizon, available_by_t)`` for every ACTIVE
    redundancy group — used by the Z3 mirror + the objective seam. Gated on the SAME
    ``_active_redundancy_group`` predicate as ``_redundancy_floor_violations``, so the
    Z3 mirror encodes ``avail>=floor`` for EXACTLY the groups the checker evaluates —
    check and attest agree GROUP-FOR-GROUP (an INACTIVE breaching group is skipped by
    both; the mirror never over-constrains attest into a FALSE INFEASIBLE). Reads
    params TOTALLY (a missing required param collapses that group to floor-breaching
    emptiness)."""
    task_outage = _task_outage_intervals(plan, ir)
    plan_outage = _plan_outage_intervals(plan)
    return [
        _group_available_by_t(plan, ir, r.params, task_outage, plan_outage)
        for r in _active_redundancy_groups(ir)
    ]


def _available_by_t(plan: Plan, ir: FCIR) -> tuple[str, int, int, dict[int, int]]:
    """Back-compat single-group view (the FIRST ACTIVE redundancy group), used by the
    objective seam's spike proxy. Gated on the SAME _active_redundancy_group predicate
    as the checker/mirror, so the objective measures the enforced floor (an INACTIVE
    group never drives stranded_power_kw). Multi-group consumers use
    ``_redundancy_groups_available``. Reads params TOTALLY (fail-closed)."""
    groups = _redundancy_groups_available(plan, ir)
    if groups:
        return groups[0]
    return "?", 1 << 30, 0, {}


# --------------------------------------------------------------------------- #
# Objective / KPI recompute helpers (Task 7) — the SINGLE source of the real  #
# (stranded_power_kw, makespan) tuple the cert's signed objective carries AND  #
# (Task 8) the kpi.py recompute fns reuse, so the objective leaf and the KPI   #
# surface agree. Solver-free, INTEGERS ONLY, recomputed from signed plan+inst. #
# --------------------------------------------------------------------------- #


def stranded_power(ir: FCIR, plan: Plan) -> int:
    """The redundancy SHORTFALL below the N+1 floor, summed over EVERY active group
    AND timestep: ``sum_g sum_t max(0, floor_g - available_{g,t})``. 0 when every
    floor holds; positive for a buffer-spending plan. Gated on the SAME
    ``_active_redundancy_group`` predicate as the checker/mirror (an INACTIVE group
    never strands power). Solver-free; reads params TOTALLY (fail-closed)."""
    total = 0
    for _gid, floor, horizon, avail in _redundancy_groups_available(plan, ir):
        total += sum(max(0, floor - avail.get(t, 0)) for t in range(horizon))
    return total


def maintenance_makespan(ir: FCIR, plan: Plan) -> int:
    """The last maintenance END over the plan: the latest of (a) a PLAN-scheduled
    maintenance TASK end (``task:<id>`` op start + its instance duration) — for EVERY
    task REGARDLESS of redundancy-``unit`` linkage — and (b) a legacy ``plan_outage:``
    cleanout end. 0 when nothing is scheduled. Solver-free; TOTAL (a task absent from
    the plan / op missing is skipped, never a KeyError).

    The full-task scope (not the unit-linked ``_task_outage_intervals`` subset) is
    REQUIRED for solver/cert parity: ``_dc_build_model`` constrains ``makespan >= e``
    for EVERY task end (``_maintenance_task_links`` includes unit-unlinked tasks), so
    the solver optimizes a makespan that counts a unit-unlinked task (e.g. scenario T2,
    ``unit=None``). The signed leaf must count it too or it undercounts the very plan
    it certifies."""
    ends: list[int] = []
    # task ops (the full facility): every PLAN-scheduled maintenance-task end, whether
    # or not the task derates a redundancy unit. Mirrors _dc_build_model's makespan,
    # which constrains over EVERY task end (_maintenance_task_links is unit-agnostic).
    for op_id, (_path, dur, _unit) in _maintenance_task_links(ir).items():
        if op_id not in plan.assignments or dur <= 0:
            continue                       # not scheduled / zero-length -> no end (total)
        ends.append(plan.start(op_id) + dur)
    # legacy slice: plan_outage cleanout ends.
    ends.extend(
        ce for (_mc, _cs, ce, reason) in plan.cleanouts
        if str(reason).startswith("plan_outage:")
    )
    return max(ends, default=0)


def dc_objective(ir: FCIR, plan: Plan) -> tuple[int, ...]:
    """The REAL ``(stranded_power_kw, makespan)`` lexicographic objective tuple,
    recomputed solver-free from the signed plan+instance. ``verifier.objective``
    delegates here; ``dc_solve`` sets ``result.objective`` to this SAME tuple after
    extraction, so ``verify`` (which recomputes via the Spec 0.5 ``verifier.objective``
    seam) matches by construction."""
    return (stranded_power(ir, plan), maintenance_makespan(ir, plan))


# --------------------------------------------------------------------------- #
# CP-SAT compile (Task 7) — CODE-DISJOINT from the checker                     #
# --------------------------------------------------------------------------- #
# The datacenter solve path schedules each maintenance task's START over the
# integer time grid. The checker NEVER imports these CP-SAT vars; this model
# NEVER imports the checker's Violation/coverage_floor kernel — the two are
# code-disjoint (the checker re-derives availability from the plan; the model
# constrains it during search). Forbidden windows (dc:maintenance_window), the
# per-timestep redundancy floor (dc:redundancy_floor), and the STRUCTURAL caps
# (dc:power_cap/dc:anti_affinity as fixed feasibility checks) are encoded as
# constraints; the lexicographic objective (stranded power then makespan) is the
# solver's business. INTEGERS ONLY (no float anywhere in the model).


@dataclass
class DcVarIndex:
    """The datacenter CP-SAT variable index. ``task_start``/``task_end`` are the
    schedulable maintenance-task vars (op_id ``task:<id>``); ``task_unit`` maps a
    task op to the redundancy unit it derates (if any); ``avail`` holds the
    per-(group, timestep) availability var; ``stranded``/``makespan`` are the two
    lexicographic objective vars."""

    task_start: dict[str, cp_model.IntVar] = field(default_factory=dict)
    task_end: dict[str, cp_model.IntVar] = field(default_factory=dict)
    task_path: dict[str, str] = field(default_factory=dict)
    task_unit: dict[str, str] = field(default_factory=dict)
    avail: dict[tuple[str, int], cp_model.IntVar] = field(default_factory=dict)
    stranded: cp_model.IntVar | None = None
    makespan: cp_model.IntVar | None = None
    horizon: int = 0
    ir: FCIR | None = None


def _maintenance_task_links(ir: FCIR) -> dict[str, tuple[str, int, str | None]]:
    """``task:<id>`` op_id -> (path, duration, unit) from the facility block's
    ``maintenance_tasks`` linkage (TOTAL: a task with no facility entry / no op is
    skipped). The duration comes from the packed Operation (authoritative)."""
    facility = _facility_block(ir)
    tasks = facility.get("maintenance_tasks", [])
    op_duration = {op.op_id: int(op.duration) for op in ir.instance.operations}
    out: dict[str, tuple[str, int, str | None]] = {}
    if not isinstance(tasks, list):
        return out
    for t in tasks:
        if not isinstance(t, dict):
            continue
        op_id = f"task:{t.get('id')}"
        if op_id not in op_duration:
            continue
        path = str(t.get("path", ""))
        unit = t.get("unit")
        out[op_id] = (path, op_duration[op_id], None if unit is None else str(unit))
    return out


def _dc_build_model(ir: FCIR) -> tuple[cp_model.CpModel, DcVarIndex]:
    """Build the datacenter CP-SAT model. CODE-DISJOINT from the checker.

    Decision vars: each maintenance-task start over ``[0, horizon - duration]``.
    Constraints:
      * dc:maintenance_window (active) — ``Or(end <= fa, start >= fb)`` per forbidden
        window on the task's path (a task may not overlap a change-freeze window).
      * dc:redundancy_floor (active) — per group, per timestep, ``available_t >=
        floor`` where ``available_t`` = installed units minus (fixed-maintenance-down
        + task-derated-down). A task derates its linked unit while running.
      * dc:power_cap / dc:anti_affinity (active structural) — FIXED feasibility checks:
        the v1 draws/placements are instance facts, so a breach makes the model
        infeasible (the checker also flags it; the compile must not optimize against a
        structurally-broken instance).
    Objective vars: ``stranded`` (the per-timestep redundancy shortfall, == 0 when the
    floor is a hard constraint and the model is feasible) and ``makespan`` (the last
    task end). The staged lexicographic search lives in ``dc_solve``."""
    m = cp_model.CpModel()
    H = ir.instance.horizon
    vi = DcVarIndex(horizon=H, ir=ir)

    links = _maintenance_task_links(ir)
    for op_id, (path, dur, unit) in sorted(links.items()):
        s = m.new_int_var(0, max(0, H - dur), f"dc_start_{op_id}")
        e = m.new_int_var(0, H, f"dc_end_{op_id}")
        m.add(e == s + dur)
        vi.task_start[op_id] = s
        vi.task_end[op_id] = e
        vi.task_path[op_id] = path
        if unit is not None:
            vi.task_unit[op_id] = unit

    # --- dc:maintenance_window (active): a task on a path must avoid forbidden windows.
    for r in ir.rules:
        if r.rule_id != "dc:maintenance_window" or not ir.has_active(r.rule_id):
            continue
        p = r.params
        path_id = str(p.get("path_id", ""))
        forbidden = [(int(a), int(b)) for (a, b) in p.get("forbidden", [])]
        for op_id, op_path in vi.task_path.items():
            if op_path != path_id:
                continue
            s, e = vi.task_start[op_id], vi.task_end[op_id]
            for k, (fa, fb) in enumerate(forbidden):
                # disjoint from [fa,fb): end <= fa OR start >= fb. Reify each side.
                before = m.new_bool_var(f"dc_mw_before_{op_id}_{k}")
                after = m.new_bool_var(f"dc_mw_after_{op_id}_{k}")
                m.add(e <= fa).only_enforce_if(before)
                m.add(s >= fb).only_enforce_if(after)
                m.add_bool_or([before, after])

    # --- dc:redundancy_floor (active): per-group per-timestep availability >= floor.
    # A unit is DOWN at t if (a) a FIXED instance maintenance interval covers t, or
    # (b) a maintenance task linked to that unit runs over t. installed - down >= floor.
    if _has_active_redundancy_group(ir):
        for r in _active_redundancy_groups(ir):
            p = r.params
            gid = str(p.get("group_id", "?"))
            units = [str(u) for u in p.get("units", [])]
            floor = int(p.get("floor", 1 << 30))
            maintenance = p.get("maintenance", {})
            # tasks derating each unit in THIS group.
            tasks_by_unit: dict[str, list[str]] = {}
            for op_id, unit in vi.task_unit.items():
                if unit in units:
                    tasks_by_unit.setdefault(unit, []).append(op_id)
            for t in range(H):
                up_terms: list[cp_model.IntVar | int] = []
                for u in units:
                    fixed_down = any(a <= t < b for (a, b) in maintenance.get(u, []))
                    if fixed_down:
                        continue  # a fixed outage removes the unit -> contributes 0 up
                    # the unit is up at t unless a linked task runs over t.
                    task_over = []
                    for op_id in tasks_by_unit.get(u, []):
                        s = vi.task_start[op_id]
                        # task runs over t iff start <= t < start + dur, i.e.
                        # start <= t AND start >= t - dur + 1. Reify each half so b
                        # is the exact conjunction (b <=> le AND ge).
                        dur = links[op_id][1]
                        le = m.new_bool_var(f"dc_le_{op_id}_{t}")
                        ge = m.new_bool_var(f"dc_ge_{op_id}_{t}")
                        m.add(s <= t).only_enforce_if(le)
                        m.add(s > t).only_enforce_if(le.Not())
                        m.add(s >= t - dur + 1).only_enforce_if(ge)
                        m.add(s < t - dur + 1).only_enforce_if(ge.Not())
                        b = m.new_bool_var(f"dc_over_{op_id}_{t}")
                        m.add_bool_and([le, ge]).only_enforce_if(b)
                        m.add_bool_or([le.Not(), ge.Not()]).only_enforce_if(b.Not())
                        task_over.append(b)
                    if task_over:
                        # up_u == 1 iff NO linked task runs over t.
                        up_u = m.new_bool_var(f"dc_up_{gid}_{u}_{t}")
                        m.add(sum(task_over) == 0).only_enforce_if(up_u)
                        m.add(sum(task_over) >= 1).only_enforce_if(up_u.Not())
                        up_terms.append(up_u)
                    else:
                        up_terms.append(1)
                avail = m.new_int_var(0, len(units), f"dc_avail_{gid}_{t}")
                m.add(avail == sum(up_terms))
                m.add(avail >= floor)
                vi.avail[(gid, t)] = avail

    # --- dc:power_cap (active structural): FIXED feasibility check (v1 draws fixed).
    for r in ir.rules:
        if r.rule_id != "dc:power_cap" or not ir.has_active(r.rule_id):
            continue
        p = r.params
        scope = [str(u) for u in p.get("scope_units", [])]
        cap_kw = int(p.get("cap_kw", 0))
        per_member_pct = int(p.get("per_member_pct", 0))
        draws = p.get("draws", {})
        aggregate = sum(int(draws.get(u, cap_kw)) for u in scope)
        # constant booleans: an infeasible structural invariant makes the model UNSAT.
        m.add(int(aggregate <= cap_kw) == 1)
        for u in scope:
            du = int(draws.get(u, cap_kw))
            m.add(int(100 * du <= per_member_pct * cap_kw) == 1)

    # --- dc:anti_affinity (active structural): FIXED feasibility check (v1 placement).
    for r in ir.rules:
        if r.rule_id != "dc:anti_affinity" or not ir.has_active(r.rule_id):
            continue
        p = r.params
        replicas = [str(u) for u in p.get("replicas", [])]
        fault_domain_of = p.get("fault_domain_of", {})
        for i in range(len(replicas)):
            for j in range(i + 1, len(replicas)):
                fd1 = fault_domain_of.get(replicas[i], _MISSING)
                fd2 = fault_domain_of.get(replicas[j], _MISSING)
                collide = (fd1 is _MISSING) or (fd2 is _MISSING) or (fd1 == fd2)
                m.add(int(not collide) == 1)  # a collision makes the model UNSAT

    # --- objective vars.
    # stranded: per-(group, timestep) shortfall below the floor. With the floor as a
    # hard constraint above, this is identically 0 on any feasible model; the var is
    # carried so the lexicographic search has a level-1 objective the extracted plan's
    # solver-free recompute (verifier.objective) reproduces exactly.
    shortfall_terms: list[cp_model.IntVar] = []
    for r in _active_redundancy_groups(ir):
        gid = str(r.params.get("group_id", "?"))
        floor = int(r.params.get("floor", 0))
        for t in range(H):
            avail_var = vi.avail.get((gid, t))
            if avail_var is None:
                continue
            sf = m.new_int_var(0, floor, f"dc_short_{gid}_{t}")
            m.add(sf >= floor - avail_var)
            shortfall_terms.append(sf)
    stranded = m.new_int_var(0, (1 << 30), "dc_stranded")
    m.add(stranded == (sum(shortfall_terms) if shortfall_terms else 0))
    vi.stranded = stranded

    # makespan: the last maintenance-task end (0 when no task).
    makespan = m.new_int_var(0, H, "dc_makespan")
    if vi.task_end:
        for e in vi.task_end.values():
            m.add(makespan >= e)
    else:
        m.add(makespan == 0)
    vi.makespan = makespan

    return m, vi


class DatacenterVerifier:
    domain_id: str = "datacenter"
    # rule_kinds: the PLAN-DEPENDENT evaluated kinds + the STRUCTURAL kinds (B-4).
    rule_kinds: frozenset[str] = frozenset({
        "redundancy_floor", "maintenance_window", "power_cap", "anti_affinity",
    })
    # evaluated (PLAN-DEPENDENT, registry-REQUIRED predicate) ids.
    evaluated_rule_ids: frozenset[str] = frozenset({
        "dc:redundancy_floor", "dc:maintenance_window",
    })
    # STRUCTURAL kinds (instance-level invariants — B-4): the registry does NOT
    # require a predicate, but a closed/total checker + Z3 mirror STILL run.
    structural_rule_kinds: frozenset[str] = frozenset({"power_cap", "anti_affinity"})
    # the COMPLETE set of rule_ids this domain owns (cross-domain isolation): the
    # evaluated ids + the structural ids.
    known_rule_ids: frozenset[str] = evaluated_rule_ids | frozenset(
        {"dc:power_cap", "dc:anti_affinity"})

    def check_predicates(self, plan: Plan, ir: FCIR) -> list[Violation]:
        out: list[Violation] = []
        # MULTI-GROUP (Task 4): _redundancy_floor_violations iterates every ACTIVE
        # dc:redundancy_floor rule (the shared _active_redundancy_group predicate).
        if _has_active_redundancy_group(ir):
            out += _redundancy_floor_violations(plan, ir)  # TOTAL param reads (B-5)
        if ir.has_active("dc:maintenance_window"):
            out += _maintenance_window_violations(plan, ir)  # PLAN-DEPENDENT; TOTAL reads (B-5)
        if ir.has_active("dc:power_cap"):
            out += _power_cap_violations(plan, ir)  # STRUCTURAL invariant; TOTAL reads (B-5)
        if ir.has_active("dc:anti_affinity"):
            out += _anti_affinity_violations(plan, ir)  # STRUCTURAL invariant; TOTAL reads (B-5)
        return out

    def z3_encode(self, plan: Plan, ir: FCIR) -> "z3.Solver":
        s = z3.Solver()
        s.set(unsat_core=True)
        # MULTI-GROUP (Task 4): one tracked block per ACTIVE redundancy group; a unit
        # shared across groups appears in BOTH groups' availability (code-disjoint from
        # CP-SAT). Gated + iterated on the SAME _active_redundancy_group predicate as the
        # checker, so check and attest agree group-for-group (no over-constraint on an
        # INACTIVE breaching group — never a FALSE INFEASIBLE).
        if _has_active_redundancy_group(ir):
            for gid, floor, horizon, avail in _redundancy_groups_available(plan, ir):
                a = {t: z3.Int(f"avail_{gid}_{t}") for t in range(horizon)}
                for t in range(horizon):
                    s.add(a[t] == avail[t])
                for t, expr in enumerate(coverage_floor_z3(a, floor, horizon)):
                    s.assert_and_track(expr, f"dc:redundancy_floor:{gid}:{t}")
        if ir.has_active("dc:maintenance_window"):
            _maintenance_window_z3(s, plan, ir)
        if ir.has_active("dc:power_cap"):
            _power_cap_z3(s, ir)
        if ir.has_active("dc:anti_affinity"):
            _anti_affinity_z3(s, ir)
        return s

    def gotcha_rule_id(self) -> str | None:
        return "dc:redundancy_floor"

    # --- Spec 0.5 objective seam: the REAL datacenter objective is SIGNED here
    # (verify_plan_cert recomputes via verifier.objective, Spec 0.5 T1), NOT via the
    # FJSP recompute_objective. Even the spike returns the real (stranded_power_kw,
    # makespan) tuple so the cert's objective leaf is honest from Task 0 on. ---
    objective_labels: tuple[str, ...] = ("stranded_power_kw", "makespan")

    def objective(self, ir: FCIR, plan: Plan) -> tuple[int, ...]:
        # The REAL datacenter objective over the FULL facility (Task 7 generalizes the
        # Task-0 single-group spike). Both levels are solver-free non-negative integers
        # recomputed from the signed plan+instance — NO floats, NO solver state.
        #   * stranded_power_kw = the redundancy SHORTFALL below the N+1 floor summed
        #     over EVERY active group AND timestep (sum_g sum_t max(0, floor_g -
        #     available_{g,t})). 0 when every floor holds; positive for a
        #     buffer-spending plan. The SAME quantity the kpi.py recompute (Task 8) and
        #     the cert's signed objective leaf carry (one helper -> consistent).
        #   * makespan = the last maintenance-task end (the task-outage mechanism), or
        #     the last plan_outage cleanout end for the legacy slice — whichever is
        #     later. 0 when no task/outage is scheduled.
        return dc_objective(ir, plan)

    def optimality_tripwire(self, ir: FCIR, objective: tuple[int, ...]) -> bool:
        # the dc objective is solver-reported, not Z3-attested optimal -> opt out
        # honestly (the Spec 0.5 seam tolerates any tuple length; only the mfg impl
        # asserts len==2). Task 9 binds the trust_boundary note.
        return False

    def compile(self, ir: FCIR, model: Any = None) -> tuple[cp_model.CpModel, DcVarIndex]:
        """Build the datacenter CP-SAT model + var index (Task 7). CODE-DISJOINT from
        the checker (this module never imports the checker's coverage_floor kernel; the
        checker never imports these CP-SAT vars). ``model`` is accepted for Protocol
        parity (the manufacturing seam takes a model); the datacenter path builds its
        own ``CpModel`` and returns it."""
        return _dc_build_model(ir)

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
