"""The supported-rule registry — the executable, fail-closed trust guarantee.

Every active hard PLAN_CONSTRAINT rule is either evaluated by a predicate
(``EVALUATED_RULE_IDS``) or structurally guaranteed by the model
(``STRUCTURAL_RULE_KINDS`` — e.g. ``non_preemption``, subsumed by the
atomic-interval Plan model + no-overlap). Anything else fails closed: the
checker emits ``R-UNSUPPORTED-RULE`` and the compiler / cert emit raise.
"""
from __future__ import annotations

from feasible.ir.domain import FCIR, Rule

# rule_ids the checker / compiler / Z3 explicitly evaluate (1:1 with kind in v1)
EVALUATED_RULE_IDS: frozenset[str] = frozenset({
    "R-ROUTING", "R-NOOVERLAP", "R-SETUP", "R-MAINT", "R-SHIFT", "R-6.1-NIGHT-CLEANOUT",
})

# kinds that need no predicate — the interval model + no-overlap guarantee them
STRUCTURAL_RULE_KINDS: frozenset[str] = frozenset({"non_preemption"})


class UnsupportedHardRuleError(ValueError):
    """An active hard PLAN_CONSTRAINT rule the engines do not evaluate."""


def is_supported(rule: Rule) -> bool:
    return rule.rule_id in EVALUATED_RULE_IDS or rule.kind in STRUCTURAL_RULE_KINDS


def unsupported_hard_rules(ir: FCIR) -> list[Rule]:
    return [r for r in ir.hard_plan_rules() if not is_supported(r)]


def assert_all_hard_rules_supported(ir: FCIR) -> None:
    bad = unsupported_hard_rules(ir)
    if bad:
        raise UnsupportedHardRuleError([r.rule_id for r in bad])
