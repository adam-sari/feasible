"""Back-translation: render an IR rule to NL and confirm DEONTIC POLARITY.

Back-translation restates a rule and confirms its deontic operator (must /
must-not / may) matches ``clause_kind`` — so a permission silently re-typed as
an obligation fails even if the words restate faithfully. It also surfaces the
recorded §5.2 wrong-SCOPE extraction (a whole-line lock vs the intended fill-op
scope), which the human gate corrects. (Deterministic v1 stand-in for an
LLM/entailment check.)
"""
from __future__ import annotations

from feasible.ir.domain import ClauseKind, Rule

_DEONTIC = {
    ClauseKind.OBLIGATION: "must",
    ClauseKind.PROHIBITION: "must not",
    ClauseKind.PERMISSION: "may",
    ClauseKind.EXCEPTION_CANDIDATE: "may, by exception,",
}

_RENDER = {
    "routing_precedence": "operations of a job must run in Mix -> Fill -> Label order",
    "no_overlap": "a machine must not run two operations at once",
    "setup_cleanout": "a 90-minute cleanout must be performed when switching from an allergen product",
    "maintenance": "Filler-2 must not run during its Tuesday maintenance window",
    "shift": "the plant operates a day and a night shift",
    "night_cleanout": "a cleanout must not be performed during the night shift",
    "non_preemption": None,  # scope-dependent, see below
    "permission": "Filler-1 may change product family without a cleanout",
}


def deontic_operator(clause_kind: ClauseKind) -> str:
    return _DEONTIC[clause_kind]


def back_translate(rule: Rule) -> str:
    if rule.kind == "non_preemption":
        scope = rule.params.get("scope", "fill_op")
        if scope == "whole_line":
            return ("once an allergen order starts, NO other order may use ANY machine on its "
                    "route until it finishes (whole-line lock)")
        return "an allergen order's fill operation must run to completion without interruption"
    body = _RENDER.get(rule.kind) or f"rule {rule.rule_id}"
    return body


def polarity_matches_source(rule: Rule) -> bool:
    """Does the cited span's polarity agree with the rule's clause_kind?"""
    spans = [s for s in rule.provenance.spans if getattr(s, "role", "") == "primary_normative"]
    if not spans:
        return True  # modeling decision / no source to contradict
    text = " ".join(getattr(s, "quoted_text", "").lower() for s in spans)
    negative = any(k in text for k in ["only", "not", "no ", "never", "unavailable"])
    if rule.clause_kind == ClauseKind.PROHIBITION:
        return negative
    if rule.clause_kind == ClauseKind.OBLIGATION:
        return ("required" in text or "must" in text or "shall" in text or "expected" in text) or not negative
    if rule.clause_kind == ClauseKind.PERMISSION:
        return "may" in text
    return True


def scope_is_overbroad(rule: Rule) -> bool:
    """The §5.2 wrong-scope detector: a whole-line non-preemption lock is over-broad."""
    return rule.kind == "non_preemption" and rule.params.get("scope") == "whole_line"


def correct_scope(rule: Rule) -> Rule:
    """The human-gate correction: narrow a whole-line lock to the fill operation."""
    fixed = rule.model_copy(deep=True)
    fixed.params = {**rule.params, "scope": "fill_op"}
    return fixed
