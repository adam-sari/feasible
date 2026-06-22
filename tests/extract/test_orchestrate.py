from __future__ import annotations

import json
from pathlib import Path

import pytest

from feasible.extract.orchestrate import ExtractionReport, extract_policy
from feasible.extract.provider import MODEL, FixtureProvider, build_prompt, fixture_key
from feasible.ingest.segment import anchor, segment
from feasible.extract.schema import SCHEMA_DESCRIPTOR

# The COMMITTED, read-only store (C-7): only the real-sanitation fixtures live here,
# recorded ONCE by the happy-path test below. Tests that fabricate adversarial drafts
# write into a tmp_path scratch store instead (never this dir).
FIX = Path(__file__).parent / "fixtures"
SOP = (Path("feasible/scenario/data/shop_rules.md")).read_text(encoding="utf-8")
SAN_QUOTE = "a full 90-minute sanitation cleanout is required before the next product runs"


def _key_for(seg) -> str:
    # C-3/C-4: key on the STABLE descriptor, NOT RuleDraft.model_json_schema()
    return fixture_key(MODEL, build_prompt(seg.text.strip(), seg.heading_path), SCHEMA_DESCRIPTOR)


def _write_full_run(store: Path, *, sanitation: dict, others: dict | None = None) -> None:
    """Seed `store` with one fixture per segment: the sanitation segment gets the
    `sanitation` draft; every other segment gets `others` (default {} = no rule).
    This is the offline stand-in for a live --record pass (no network)."""
    store.mkdir(parents=True, exist_ok=True)
    for seg in segment(SOP):
        if "90-minute sanitation cleanout is required" in seg.text:
            (store / f"{_key_for(seg)}.json").write_text(json.dumps(sanitation), encoding="utf-8")
        else:
            (store / f"{_key_for(seg)}.json").write_text(json.dumps(others or {}), encoding="utf-8")


def test_extract_policy_grounds_real_quote_and_runs_llm_free_coverage():
    # records the COMMITTED sanitation fixtures into FIX (read-only thereafter)
    assert anchor(SAN_QUOTE, SOP) is not None
    _write_full_run(FIX, sanitation={
        "rule_id": "C-SANITATION", "kind": "setup_cleanout",
        "clause_kind": "OBLIGATION", "severity": "HARD",
        "verbatim_quote": SAN_QUOTE,
        "params_json": "{\"cleanout_minutes\": 90, \"trigger_family\": \"Allergen\"}",
        "rationale": "explicit sanitation obligation",
    })
    rep = extract_policy(SOP, domain_id="manufacturing",
                         provider=FixtureProvider(FIX), fixtures_dir=FIX)
    assert isinstance(rep, ExtractionReport)
    assert rep.n_segments == len(segment(SOP))
    ids = [d.rule.rule_id for d in rep.drafted]
    assert "C-SANITATION" in ids
    san = next(d for d in rep.drafted if d.rule.rule_id == "C-SANITATION")
    assert san.grounded is True
    assert san.char_start >= 0 and san.char_end > san.char_start
    assert san.back_translation                      # a non-empty NL rendering
    assert san.param_mismatch is False               # 90 appears in the cited span
    # the coverage ledger ran over the deterministic enumeration (LLM-free):
    assert rep.coverage.denominator > 0
    # the diff vs golden is by rule_id and the candidate is NOT golden:
    assert "C-SANITATION" in rep.golden_diff["only_in_draft"]
    assert rep.non_gating_note                        # the draft-not-certified banner


def test_fabricated_quote_is_dropped_not_grounded(tmp_path):
    """A draft whose verbatim_quote is NOT an exact substring is rejected by
    anchor() and never enters the candidate IR. (C-7: uses a tmp scratch store.)"""
    _write_full_run(tmp_path, sanitation={
        # the sanitation segment's fixture is fabricated (not a substring)
        "rule_id": "C-FAKE", "kind": "x", "clause_kind": "OBLIGATION", "severity": "HARD",
        "verbatim_quote": "this exact sentence is nowhere in the source document",
        "params_json": "", "rationale": "hallucinated",
    })
    rep = extract_policy(SOP, domain_id="manufacturing",
                         provider=FixtureProvider(tmp_path), fixtures_dir=tmp_path)
    assert all(d.rule.rule_id != "C-FAKE" for d in rep.drafted)   # never grounded
    u = next(u for u in rep.ungrounded if u["rule_id"] == "C-FAKE")
    assert "exact substring" in u["reason"]
    assert "C-FAKE" not in [r.rule_id for r in rep.candidate_ir.rules]


def test_cross_segment_quote_is_dropped_outside_its_segment(tmp_path):
    """[MAJOR C-1] verbatim-span-echo barrier: a quote that IS an exact substring of
    the document but was copied from a DIFFERENT segment than the one being drafted
    anchors against the full text yet falls OUTSIDE its source segment's char-range —
    it must be dropped with reason 'quote anchored outside its source segment'."""
    segs = segment(SOP)
    # find the sanitation segment (the draft target) and pick a quote from a DIFFERENT
    # segment that is a real substring of SOP but lies outside the sanitation range.
    san_seg = next(s for s in segs if "90-minute sanitation cleanout is required" in s.text)
    other_seg = next(
        s for s in segs
        if s.char_start != san_seg.char_start and len(s.text.strip()) > 20
        and SOP.find(s.text.strip()) >= 0
    )
    foreign_quote = other_seg.text.strip()
    # sanity: the foreign quote IS in the document but NOT inside the sanitation span
    assert anchor(foreign_quote, SOP) is not None
    fpos = anchor(foreign_quote, SOP)
    assert not (san_seg.char_start <= fpos[0] and fpos[1] <= san_seg.char_end)
    # the sanitation segment's fixture echoes the FOREIGN quote (a cross-segment leak)
    _write_full_run(tmp_path, sanitation={
        "rule_id": "C-CROSS", "kind": "x", "clause_kind": "OBLIGATION", "severity": "HARD",
        "verbatim_quote": foreign_quote, "params_json": "", "rationale": "cross-segment leak",
    })
    rep = extract_policy(SOP, domain_id="manufacturing",
                         provider=FixtureProvider(tmp_path), fixtures_dir=tmp_path)
    assert all(d.rule.rule_id != "C-CROSS" for d in rep.drafted)   # dropped
    u = next(u for u in rep.ungrounded if u["rule_id"] == "C-CROSS")
    assert u["reason"] == "quote anchored outside its source segment"
    assert "C-CROSS" not in [r.rule_id for r in rep.candidate_ir.rules]


def test_param_mismatch_is_flagged_on_real_span(tmp_path):
    """[MAJOR C-2] a draft cites the REAL sanitation span but carries a tampered
    numeric param (cleanout_minutes=1, not 90). The draft still grounds (the quote is
    real) but is FLAGGED param_mismatch=True for human review — the cited value '1'
    does not appear in the quoted span."""
    _write_full_run(tmp_path, sanitation={
        "rule_id": "C-TAMPER", "kind": "setup_cleanout",
        "clause_kind": "OBLIGATION", "severity": "HARD",
        "verbatim_quote": SAN_QUOTE,
        "params_json": "{\"cleanout_minutes\": 1}",   # tampered (span says 90)
        "rationale": "real quote, wrong number",
    })
    rep = extract_policy(SOP, domain_id="manufacturing",
                         provider=FixtureProvider(tmp_path), fixtures_dir=tmp_path)
    tam = next(d for d in rep.drafted if d.rule.rule_id == "C-TAMPER")
    assert tam.grounded is True                      # the quote is real -> grounded
    assert tam.param_mismatch is True                # but '1' is not in the span
    assert "cleanout_minutes" in tam.param_mismatch_note


def test_partial_draft_leaves_other_normative_spans_red(tmp_path):
    """[C-6] the omission moat on REAL extraction: when the model drafts ONLY the
    sanitation rule and {} for every other span, the deterministic coverage ledger
    surfaces the OTHER normative spans (incl. the gotcha) as RED — proving omission
    is caught LLM-free even on a partial extraction."""
    _write_full_run(tmp_path, sanitation={
        "rule_id": "C-SANITATION", "kind": "setup_cleanout",
        "clause_kind": "OBLIGATION", "severity": "HARD",
        "verbatim_quote": SAN_QUOTE,
        "params_json": "{\"cleanout_minutes\": 90}", "rationale": "obligation",
    })
    rep = extract_policy(SOP, domain_id="manufacturing",
                         provider=FixtureProvider(tmp_path), fixtures_dir=tmp_path)
    # only one rule drafted, but the ledger denominator counts ALL normative spans:
    assert len(rep.candidate_ir.rules) == 1
    assert rep.coverage.denominator > 1
    assert rep.coverage.complete is False
    assert len(rep.coverage.red_findings) > 0
    # the RED findings are OTHER normative spans the partial draft missed (not the
    # sanitation span, which is covered):
    red_texts = " ".join(r.text for r in rep.coverage.red_findings)
    assert "sanitation cleanout is required before the next product runs" not in red_texts
