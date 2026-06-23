"""Task 10: the coverage-RED guard — the omission-moat dual of the manufacturing
gotcha test.

A ``dc:redundancy_floor`` clause DROPPED from the pack goes RED in the coverage
ledger: its ``primary_normative`` span (the B-9 PINNED redundancy sentence) is now
uncovered, the classifier marks that sentence ``hard_obligation``, so
``build_coverage_ledger`` reports a RED finding and ``coverage.complete is False``.

This is exactly why B-9 pins the sentence to phrasing the classifier marks
``hard_obligation`` (the deontic ``must``/``shall`` wins over the ``shall not`` in the
same sentence): the omission moat must NOT fail OPEN on the hero rule. A redundancy
floor silently dropped from extraction is the worst-case omission — it MUST be caught.
"""
from __future__ import annotations

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
from feasible.conflict.policy import DATACENTER_POLICY
from feasible.domains import get_domain
from feasible.domains.datacenter.scenario import (
    CAPACITY_POLICY,
    REDUNDANCY_SENTENCE,
    build_dc_extracted_pack,
)
from feasible.govern.coverage import build_coverage_ledger
from feasible.govern.pipeline import govern_pack
from feasible.ingest.segment import segment
from feasible.ir.domain import FCIR


def _universe_ir() -> FCIR:
    return govern_pack(build_dc_extracted_pack(), DATACENTER_POLICY).universe_ir


def test_redundancy_sentence_classifies_hard_obligation() -> None:
    """B-9: the pinned redundancy sentence classifies ``hard_obligation`` (the deontic
    ``must``/``shall`` obligation operator wins even though the sentence also contains
    ``shall not``). If it classified soft/boilerplate the omission moat would fail OPEN."""
    _, verifier = get_domain("datacenter")
    segs = [s for s in segment(CAPACITY_POLICY) if "N+1 redundancy" in s.text]
    assert segs, "the pinned redundancy sentence must be a real segment of the SOP"
    assert verifier.classify_segment(segs[0]) == "hard_obligation"
    # the pinned constant is a verbatim substring of the policy text it is anchored to.
    assert REDUNDANCY_SENTENCE in CAPACITY_POLICY


def test_universe_coverage_is_complete_no_reds() -> None:
    """The approved UNIVERSE covers the policy — no RED findings (the redundancy clause
    is present and its hard-obligation sentence is covered)."""
    ledger = build_coverage_ledger(CAPACITY_POLICY, _universe_ir())
    assert ledger.complete is True
    assert ledger.red_findings == []


def test_coverage_red_when_redundancy_floor_dropped() -> None:
    """Dropping the ``dc:redundancy_floor`` rule leaves its hard-obligation redundancy
    sentence UNCOVERED -> a RED finding -> ``coverage.complete is False``. The omission
    moat catches a silently-dropped hero rule (it does NOT fail open)."""
    universe = _universe_ir()
    dropped = FCIR(
        rules=[r for r in universe.rules if r.rule_id != "dc:redundancy_floor"],
        instance=universe.instance,
        domain_id="datacenter",
    )
    ledger = build_coverage_ledger(CAPACITY_POLICY, dropped)
    assert ledger.complete is False
    # the RED finding is the hard-obligation redundancy sentence, now uncovered.
    reds = ledger.red_findings
    assert any(e.category == "hard_obligation" for e in reds)
    assert any("N+1 redundancy" in e.text for e in reds)


def test_dropping_a_non_redundancy_rule_does_not_red_the_floor_sentence() -> None:
    """Control: dropping a DIFFERENT rule (the structural ``dc:power_cap``) does NOT
    turn the redundancy sentence RED — only dropping the redundancy clause uncovers it,
    so the RED in the prior test is specifically attributable to the hero rule."""
    universe = _universe_ir()
    dropped = FCIR(
        rules=[r for r in universe.rules if r.rule_id != "dc:power_cap"],
        instance=universe.instance,
        domain_id="datacenter",
    )
    ledger = build_coverage_ledger(CAPACITY_POLICY, dropped)
    assert all("N+1 redundancy" not in e.text for e in ledger.red_findings)
