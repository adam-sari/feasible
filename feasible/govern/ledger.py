"""Trust ladder events on the append-only hash-chained ledger (T0->T5).

Each rule's promotion and each governance act (coverage, conflict resolution) is
a hash-chained event; the Merkle root summarises the pack's provenance. T3 has
two recorded sub-states: T3a (solver-free checker pass) and T3b (back-translation
meaning-alignment).
"""
from __future__ import annotations

from feasible.canon.canonical import LedgerEvent, append_event, merkle_root
from feasible.govern.backtranslate import back_translate, polarity_matches_source
from feasible.govern.conflict import Resolution
from feasible.govern.coverage import CoverageLedger
from feasible.ir.domain import FCIR

LADDER = ["T0", "T1", "T2", "T3", "T4", "T5"]


def build_trust_ledger(
    ir: FCIR, coverage: CoverageLedger, resolutions: list[Resolution]
) -> list[LedgerEvent]:
    events: list[LedgerEvent] = []
    events = append_event(events, {
        "event": "coverage_audited",
        "complete": coverage.complete,
        "denominator": coverage.denominator,
        "red_findings": [e.text for e in coverage.red_findings],
    })
    for r in sorted(ir.rules, key=lambda r: r.rule_id):
        events = append_event(events, {
            "event": "rule_approved",
            "rule_id": r.rule_id,
            "trust_tier": r.trust_tier.value,
            "clause_kind": r.clause_kind.value,
            "compile_mode": r.compile_mode.value,
            "resolution_class": r.resolution_class,
            "t3b_back_translation": back_translate(r),
            "t3b_polarity_ok": polarity_matches_source(r),
        })
    for res in resolutions:
        events = append_event(events, {
            "event": "conflict_resolved",
            "obligation": res.conflict.obligation_id,
            "permission": res.conflict.permission_id,
            "resolution_mode": res.resolution_mode,
            "dropped": res.dropped_rule_id,
            "rationale": res.rationale,
            "z3_core": res.conflict.z3_core,
        })
    return events


def ledger_merkle_root(events: list[LedgerEvent]) -> str:
    return merkle_root(events)
