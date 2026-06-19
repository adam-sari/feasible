"""The governance pipeline: take a 'messy' extracted pack and produce the
approved active rule set, recording the §5.2 scope correction and the §4.4
conflict resolution.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from feasible.conflict.policy import ConflictPolicy
from feasible.govern.backtranslate import back_translate, correct_scope, scope_is_overbroad
from feasible.govern.conflict import (
    Resolution,
    active_after_resolution,
    detect_normative_conflicts,
    resolve_conflicts,
)
from feasible.ir.domain import FCIR


class ScopeCorrection(BaseModel):
    rule_id: str
    before: str
    after: str


class GovernResult(BaseModel):
    active_ir: FCIR
    resolutions: list[Resolution] = Field(default_factory=list)
    corrections: list[ScopeCorrection] = Field(default_factory=list)


def govern_pack(extracted: FCIR, policy: ConflictPolicy) -> GovernResult:
    # 1) §5.2 — back-translation surfaces over-broad scope; the gate corrects it
    corrections: list[ScopeCorrection] = []
    corrected_rules = []
    for r in extracted.rules:
        if scope_is_overbroad(r):
            fixed = correct_scope(r)
            corrections.append(ScopeCorrection(
                rule_id=r.rule_id, before=back_translate(r), after=back_translate(fixed)))
            corrected_rules.append(fixed)
        else:
            corrected_rules.append(r)
    corrected = FCIR(rules=corrected_rules, instance=extracted.instance)

    # 2) §4.4 — detect the deontic clash and resolve via the signed policy
    conflicts = detect_normative_conflicts(corrected)
    resolutions = resolve_conflicts(corrected, conflicts, policy)
    active_ir = active_after_resolution(corrected, resolutions)

    return GovernResult(active_ir=active_ir, resolutions=resolutions, corrections=corrections)
