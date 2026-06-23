"""The supported-rule registry — the executable, fail-closed trust guarantee.

Every active hard PLAN_CONSTRAINT rule is either evaluated by a predicate
(the domain verifier's ``evaluated_rule_ids``) or structurally guaranteed by the
model (its ``structural_rule_kinds`` — e.g. ``non_preemption``, subsumed by the
atomic-interval Plan model + no-overlap). Anything else fails closed: the
checker emits ``R-UNSUPPORTED-RULE`` and the compiler / cert emit raise.

Support is resolved **per domain**: the IR's signed ``domain_id`` selects the
``DomainVerifier`` whose ``evaluated_rule_ids`` / ``structural_rule_kinds`` define
what is supported. A rule_id from another domain (e.g. an ``R-*`` manufacturing
rule presented under ``domain_id="datacenter"``) is therefore unsupported and
fails closed — and an IR whose ``domain_id`` is not registered at all raises
``UnsupportedHardRuleError`` (an unknown domain supports nothing).

Support is sourced *only* through the per-domain ``DomainVerifier`` seam
(``evaluated_rule_ids`` / ``structural_rule_kinds``). The cert-reporting leaves in
``plan_cert`` read the same per-domain sets via ``_domain_formalization_sets`` — there
is no module-level manufacturing-only view (it was unused and removed post-v0.2).
"""
from __future__ import annotations

import feasible.domains.manufacturing  # noqa: F401  (registers the manufacturing domain)
from feasible.domains import UnknownDomainError, get_domain
from feasible.ir.domain import FCIR, Rule


class UnsupportedHardRuleError(ValueError):
    """An active hard PLAN_CONSTRAINT rule the engines do not evaluate."""


def is_supported(rule: Rule, ir: FCIR) -> bool:
    """Whether ``rule`` is supported under ``ir``'s domain. An unknown domain
    supports nothing (fail-closed)."""
    try:
        _, verifier = get_domain(ir.domain_id)
    except UnknownDomainError:
        return False
    return (
        rule.rule_id in verifier.evaluated_rule_ids
        or rule.kind in verifier.structural_rule_kinds
    )


def unsupported_hard_rules(ir: FCIR) -> list[Rule]:
    return [r for r in ir.hard_plan_rules() if not is_supported(r, ir)]


def assert_all_hard_rules_supported(ir: FCIR) -> None:
    bad = unsupported_hard_rules(ir)
    if bad:
        raise UnsupportedHardRuleError([r.rule_id for r in bad])
