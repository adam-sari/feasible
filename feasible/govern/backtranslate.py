"""Back-translation: render an IR rule to NL and confirm DEONTIC POLARITY.

Back-translation restates a rule and confirms its deontic operator (must /
must-not / may) matches ``clause_kind`` — so a permission silently re-typed as
an obligation fails even if the words restate faithfully. It also surfaces the
recorded §5.2 wrong-SCOPE extraction (a whole-line lock vs the intended fill-op
scope), which the human gate corrects. (Deterministic v1 stand-in for an
LLM/entailment check.)
"""
from __future__ import annotations

import feasible.domains.manufacturing  # noqa: F401  (registers the manufacturing domain)
from feasible.domains import get_domain
from feasible.ir.domain import ClauseKind, FCIR, Rule

_DEONTIC = {
    ClauseKind.OBLIGATION: "must",
    ClauseKind.PROHIBITION: "must not",
    ClauseKind.PERMISSION: "may",
    ClauseKind.EXCEPTION_CANDIDATE: "may, by exception,",
}


def deontic_operator(clause_kind: ClauseKind) -> str:
    return _DEONTIC[clause_kind]


def back_translate(rule: Rule, ir: FCIR | None = None) -> str:
    """Render a rule to NL via the domain renderer (relocated behind the seam).

    The renderer is per-domain: when ``ir`` is given the domain is selected by its
    signed ``domain_id``; without it (the rule-only callers / tests) we default to
    the manufacturing renderer, the only registered domain on this surface."""
    domain_id = ir.domain_id if ir is not None else "manufacturing"
    _, verifier = get_domain(domain_id)
    return verifier.back_translate(rule)


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
