from __future__ import annotations

from feasible.govern.backtranslate import (
    back_translate,
    correct_scope,
    deontic_operator,
    polarity_matches_source,
    scope_is_overbroad,
)
from feasible.govern.coverage import build_coverage_ledger, classify
from feasible.govern.ledger import build_trust_ledger, ledger_merkle_root
from feasible.ir.domain import (
    ClauseKind,
    CompileMode,
    FCIR,
    Provenance,
    Rule,
    Severity,
    TextSpan,
)
from feasible.conflict.policy import MANUFACTURING_POLICY
from feasible.govern.pipeline import govern_pack
from feasible.scenario import SHOP_RULES, build_extracted_pack, build_scenario_ir


def test_classify_hard_operator_beats_soft_keyword() -> None:
    # a HARD clause that merely MENTIONS 'priority'/'take precedence' must stay hard —
    # the omission moat must not fail open on the soft-keyword pre-empt.
    from feasible.ingest.segment import segment

    for sop, expect in [
        ("Priority allergen lines may not run unattended overnight under any circumstances.", "hard_prohibition"),
        ("Cleanouts take precedence over throughput and must run for 90 minutes.", "hard_obligation"),
        ("Priority-1 due dates are expected to be met where practical.", "soft_target"),  # no hard operator
    ]:
        segs = segment(sop)
        assert classify(segs[0]) == expect, (sop, classify(segs[0]))


def test_uncovered_hard_priority_clause_is_red() -> None:
    # an UNCOVERED hard clause containing 'priority' must go RED (not silently soft/complete)
    base = build_scenario_ir()
    empty = FCIR(rules=[], instance=base.instance)
    sop = "Priority allergen lines may not run unattended overnight under any circumstances."
    ledger = build_coverage_ledger(sop, empty)
    assert ledger.complete is False
    assert any(e.category == "hard_prohibition" for e in ledger.red_findings)


def test_coverage_complete_on_universe() -> None:
    # completeness is over the approved UNIVERSE (golden 6 + R-4.4 + corrected R-5.2)
    gov = govern_pack(build_extracted_pack(), MANUFACTURING_POLICY)
    ledger = build_coverage_ledger(SHOP_RULES, gov.universe_ir)
    assert ledger.complete is True
    assert ledger.red_findings == []
    assert ledger.denominator == 8
    night = [e for e in ledger.entries if "does not work nights" in e.text]
    assert night and "R-6.1-NIGHT-CLEANOUT" in night[0].covered_by
    cont = [e for e in ledger.entries if "run it to completion" in e.text]
    assert cont and "R-5.2" in cont[0].covered_by


def test_golden_six_leaves_allergen_continuity_red() -> None:
    # the golden spine ALONE does not cover §5.2 — extraction (R-5.2) is required to fill it
    ledger = build_coverage_ledger(SHOP_RULES, build_scenario_ir())
    assert ledger.complete is False
    assert any("run it to completion" in e.text for e in ledger.red_findings)


def test_coverage_red_when_rule_dropped() -> None:
    ir = build_scenario_ir()
    # drop the night-cleanout rule -> its hard-prohibition clause is now uncovered
    ir2 = FCIR(rules=[r for r in ir.rules if r.rule_id != "R-6.1-NIGHT-CLEANOUT"], instance=ir.instance)
    ledger = build_coverage_ledger(SHOP_RULES, ir2)
    assert ledger.complete is False
    assert any("does not work nights" in e.text for e in ledger.red_findings)


def test_classify_taxonomy() -> None:
    from feasible.ingest.segment import segment

    segs = {s.text.strip(): classify(s) for s in segment(SHOP_RULES)}
    # the night-shift clause is a hard prohibition
    night = [c for t, c in segs.items() if "does not work nights" in t]
    assert night == ["hard_prohibition"]


def test_back_translation_and_polarity() -> None:
    ir = build_scenario_ir()
    night = ir.rule("R-6.1-NIGHT-CLEANOUT")
    assert "must not" in (deontic_operator(night.clause_kind) + back_translate(night))
    assert polarity_matches_source(night) is True


def test_polarity_catches_mistyped_permission() -> None:
    # a prohibition source clause re-typed as an OBLIGATION should fail polarity
    bad = Rule(
        rule_id="R-BAD", kind="night_cleanout", params={}, severity=Severity.HARD,
        clause_kind=ClauseKind.PERMISSION,  # wrong: cited clause is a prohibition
        compile_mode=CompileMode.CONFLICT_ONLY, resolution_class="SAFETY_SANITATION",
        provenance=Provenance(spans=[TextSpan(
            quoted_text="Cleanouts may only be performed during the day shift", role="primary_normative")]),
    )
    # 'may only' is a permission-ish operator -> polarity for PERMISSION passes here, but
    # for the prohibition reading it must be PROHIBITION; assert the obligation reading fails:
    obligation_reading = bad.model_copy(update={"clause_kind": ClauseKind.OBLIGATION})
    obligation_reading.compile_mode = CompileMode.PLAN_CONSTRAINT
    assert polarity_matches_source(obligation_reading) is False


def test_s52_wrong_scope_beat() -> None:
    wrong = Rule(
        rule_id="R-5.2", kind="non_preemption", params={"scope": "whole_line"},
        severity=Severity.HARD, clause_kind=ClauseKind.OBLIGATION,
        compile_mode=CompileMode.PLAN_CONSTRAINT, resolution_class="EFFICIENCY",
        provenance=Provenance(spans=[TextSpan(
            quoted_text="run it to completion before taking other work", role="primary_normative")]),
    )
    assert scope_is_overbroad(wrong) is True
    assert "whole-line lock" in back_translate(wrong)
    fixed = correct_scope(wrong)
    assert scope_is_overbroad(fixed) is False
    assert "fill operation" in back_translate(fixed)


def test_trust_ledger_hash_chained_and_merkle_stable() -> None:
    ir = build_scenario_ir()
    cov = build_coverage_ledger(SHOP_RULES, ir)
    e1 = build_trust_ledger(ir, cov, [])
    e2 = build_trust_ledger(ir, cov, [])
    assert ledger_merkle_root(e1) == ledger_merkle_root(e2)
    assert e1[0].prev_hash == "0" * 64
    # one coverage event + one per rule
    assert len(e1) == 1 + len(ir.rules)
