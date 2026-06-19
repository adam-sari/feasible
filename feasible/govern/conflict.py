"""Normative conflict detection (Z3 rule-vs-rule) + signed-policy resolution.

A PERMISSION (compile_mode CONFLICT_ONLY) is never a plan constraint; it enters
ONLY here. Detection is a rule-vs-rule Z3 UNSAT over an abstract scope (no plan)
GROUNDED on the instance: if the instance realizes the permission's scope, the
obligation ("cleanout required") and the permission ("cleanout not required")
are jointly UNSAT. Resolution is EXPLANATION-ONLY over that core: the signed
ConflictPolicy auto-resolves ONLY a different-class, no-exception clash (drop the
lower-priority clause, ``AUTO_BY_POLICY``); otherwise it ESCALATES to the gate.
``feasible verify`` replays this over the recorded core; it never re-derives.
"""
from __future__ import annotations

import z3
from pydantic import BaseModel, Field

from feasible.conflict.policy import ConflictPolicy
from feasible.ir.domain import ClauseKind, ExceptionMode, FCIR, Rule


class Conflict(BaseModel):
    obligation_id: str
    permission_id: str
    scope: dict
    z3_core: list[str]
    minimization_status: str = "not_minimized"


class Resolution(BaseModel):
    conflict: Conflict
    resolution_mode: str  # AUTO_BY_POLICY | ESCALATE
    dropped_rule_id: str | None = None
    rationale: str = ""


def _normative_unsat(obligation_id: str, permission_id: str) -> list[str] | None:
    """Z3: obligation says cleanout_required, permission says NOT — jointly UNSAT."""
    s = z3.Solver()
    s.set(unsat_core=True)
    required = z3.Bool("cleanout_required_over_scope_S")
    s.assert_and_track(required, obligation_id)  # obligation: required
    s.assert_and_track(z3.Not(required), permission_id)  # permission: not required
    if s.check() == z3.unsat:
        return [str(c) for c in s.unsat_core()]
    return None


def _scope_realizable(ir: FCIR, permission: Rule) -> bool:
    """Does the instance realize the permission's scope (machine + priority + a
    real Allergen->non-allergen transition)?"""
    machine = permission.params.get("scope_machine")
    priority = permission.params.get("scope_priority")
    inst = ir.instance
    # is there a priority-`priority` job whose fill op can run on `machine` and is
    # Allergen, plus a non-allergen job that can follow it there?
    allergen_here = [
        o for o in inst.operations
        if machine in o.eligible_machines
        and inst.job(o.job_id).family == "Allergen"
        and (priority is None or inst.job(o.job_id).priority == priority)
    ]
    nonallergen_here = [
        o for o in inst.operations
        if machine in o.eligible_machines and inst.job(o.job_id).family != "Allergen"
    ]
    return bool(allergen_here) and bool(nonallergen_here)


def detect_normative_conflicts(ir: FCIR) -> list[Conflict]:
    conflicts: list[Conflict] = []
    permissions = [r for r in ir.rules if r.clause_kind == ClauseKind.PERMISSION]
    for p in permissions:
        target = p.params.get("target_rule")
        obligation = ir.rule(target) if target else None
        if obligation is None:
            continue
        if not _scope_realizable(ir, p):
            continue
        core = _normative_unsat(obligation.rule_id, p.rule_id)
        if core is not None:
            conflicts.append(Conflict(
                obligation_id=obligation.rule_id,
                permission_id=p.rule_id,
                scope={"machine": p.params.get("scope_machine"), "priority": p.params.get("scope_priority")},
                z3_core=core,
            ))
    return conflicts


def resolve_conflicts(ir: FCIR, conflicts: list[Conflict], policy: ConflictPolicy) -> list[Resolution]:
    resolutions: list[Resolution] = []
    for c in conflicts:
        o = ir.rule(c.obligation_id)
        p = ir.rule(c.permission_id)
        assert o is not None and p is not None
        pa = policy.priority(o.resolution_class) if o.resolution_class else None
        pb = policy.priority(p.resolution_class) if p.resolution_class else None
        has_exception = (
            o.exception_mode != ExceptionMode.NONE or p.exception_mode != ExceptionMode.NONE
            or bool(o.overrides) or bool(p.overrides)
        )
        if pa is not None and pb is not None and pa != pb and not has_exception:
            loser, winner = (p, o) if pa > pb else (o, p)
            win_label = policy.label(winner.resolution_class) or winner.resolution_class
            lose_label = policy.label(loser.resolution_class) or loser.resolution_class
            resolutions.append(Resolution(
                conflict=c, resolution_mode="AUTO_BY_POLICY", dropped_rule_id=loser.rule_id,
                rationale=(f"{winner.resolution_class}({max(pa, pb)}) > {loser.resolution_class}"
                           f"({min(pa, pb)}) under {policy.policy_id}@{policy.digest()[:12]}: "
                           f"{win_label} wins over {lose_label}"),
            ))
        else:
            resolutions.append(Resolution(
                conflict=c, resolution_mode="ESCALATE", dropped_rule_id=None,
                rationale="equal priority or an exception/override marker is present -> human gate",
            ))
    return resolutions


def active_after_resolution(ir: FCIR, resolutions: list[Resolution]) -> FCIR:
    """Drop AUTO_BY_POLICY losers -> the active rule set used for the plan
    (instance stays feasible; the dropped clause is inactive-for-plan, NOT
    rejected-from-pack)."""
    dropped = {r.dropped_rule_id for r in resolutions if r.resolution_mode == "AUTO_BY_POLICY"}
    kept = [r for r in ir.rules if r.rule_id not in dropped]
    return FCIR(rules=kept, instance=ir.instance)
