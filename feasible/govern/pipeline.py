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
    universe_ir: FCIR  # corrected (post-§5.2), R-4.4 RETAINED — the full approved universe
    active_ir: FCIR    # universe minus AUTO_BY_POLICY drops (R-4.4 removed)
    resolutions: list[Resolution] = Field(default_factory=list)
    corrections: list[ScopeCorrection] = Field(default_factory=list)
    dropped_rule_ids: list[str] = Field(default_factory=list)


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
    corrected = FCIR(
        rules=corrected_rules, instance=extracted.instance, domain_id=extracted.domain_id
    )

    # 2) §4.4 — detect the deontic clash and resolve via the signed policy
    conflicts = detect_normative_conflicts(corrected)
    resolutions = resolve_conflicts(corrected, conflicts, policy)
    active_ir = active_after_resolution(corrected, resolutions)
    dropped_rule_ids = [
        r.dropped_rule_id for r in resolutions
        if r.resolution_mode == "AUTO_BY_POLICY" and r.dropped_rule_id is not None
    ]

    return GovernResult(
        universe_ir=corrected,
        active_ir=active_ir,
        resolutions=resolutions,
        corrections=corrections,
        dropped_rule_ids=dropped_rule_ids,
    )
