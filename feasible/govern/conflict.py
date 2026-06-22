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

from pydantic import BaseModel, Field

import feasible.domains.manufacturing  # noqa: F401  (registers the manufacturing domain)
from feasible.conflict.policy import ConflictPolicy
from feasible.domains import get_domain
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


def _normative_unsat(
    obligation_id: str, permission_id: str, domain_id: str = "manufacturing"
) -> list[str] | None:
    """The rule-vs-rule Z3 UNSAT core, now a per-domain hook
    (``DomainVerifier.conflict_unsat_core``). ``detect_normative_conflicts``
    threads the IR's signed ``domain_id``; the rule-only default keeps the
    manufacturing surface unchanged."""
    _, verifier = get_domain(domain_id)
    return verifier.conflict_unsat_core(obligation_id, permission_id)


def _scope_realizable(ir: FCIR, permission: Rule) -> bool:
    """Scope realizability, now a per-domain hook
    (``DomainVerifier.conflict_realizable``) dispatched on the IR's signed
    ``domain_id`` (fail-closed on an unknown domain)."""
    _, verifier = get_domain(ir.domain_id)
    return verifier.conflict_realizable(ir, permission)


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
        core = _normative_unsat(obligation.rule_id, p.rule_id, ir.domain_id)
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
        # AUTO-resolution may ONLY drop the conflict-only PERMISSION, and only when the
        # obligation's class strictly OUTRANKS the permission's. A clash where the
        # permission would override a HARD obligation is never auto-resolved — silently
        # disabling a hard rule always ESCALATES to the human gate.
        if pa is not None and pb is not None and pa > pb and not has_exception:
            win_label = policy.label(o.resolution_class or "") or o.resolution_class
            lose_label = policy.label(p.resolution_class or "") or p.resolution_class
            resolutions.append(Resolution(
                conflict=c, resolution_mode="AUTO_BY_POLICY", dropped_rule_id=p.rule_id,
                rationale=(f"{o.resolution_class}({pa}) > {p.resolution_class}"
                           f"({pb}) under {policy.policy_id}@{policy.digest()[:12]}: "
                           f"{win_label} wins over {lose_label}"),
            ))
        else:
            resolutions.append(Resolution(
                conflict=c, resolution_mode="ESCALATE", dropped_rule_id=None,
                rationale="equal/insufficient priority or an exception/override marker -> human gate",
            ))
    return resolutions


def active_after_resolution(ir: FCIR, resolutions: list[Resolution]) -> FCIR:
    """Drop AUTO_BY_POLICY losers -> the active rule set used for the plan
    (instance stays feasible; the dropped clause is inactive-for-plan, NOT
    rejected-from-pack)."""
    dropped = {r.dropped_rule_id for r in resolutions if r.resolution_mode == "AUTO_BY_POLICY"}
    kept = [r for r in ir.rules if r.rule_id not in dropped]
    return FCIR(rules=kept, instance=ir.instance, domain_id=ir.domain_id)
