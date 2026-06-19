from __future__ import annotations

from pathlib import Path

import pytest

from feasible.ingest.golden import NoSourceError, load_golden_ir
from feasible.ingest.segment import anchor, is_gapless, segment
from feasible.ingest.tabular import load_orders_xlsx, write_orders_xlsx
from feasible.ir.domain import CompileMode, Job, Severity

MINI = Path(__file__).resolve().parent.parent / "fixtures" / "mini"


def _mini_sources() -> dict[str, str]:
    return {"shop_rules.md": (MINI / "shop_rules.md").read_text(encoding="utf-8")}


def test_segmentation_is_gapless() -> None:
    text = (MINI / "shop_rules.md").read_text(encoding="utf-8")
    segs = segment(text)
    assert len(segs) > 1
    assert is_gapless(segs, text)
    # union reconstructs the text exactly
    assert "".join(s.text for s in segs) == text


def test_segmentation_gapless_on_tricky_text() -> None:
    text = "First sentence. Second one!\n\nA heading line\nThird? Done."
    segs = segment(text)
    assert is_gapless(segs, text)
    assert "".join(s.text for s in segs) == text


def test_anchor_locates_clause() -> None:
    text = "alpha. The night clause is here. omega."
    pos = anchor("The night clause is here.", text)
    assert pos is not None
    s, e = pos
    assert text[s:e] == "The night clause is here."


def test_anchor_missing_returns_none() -> None:
    assert anchor("not present", "some other text") is None


def test_golden_ir_loads_and_anchors() -> None:
    ir = load_golden_ir(MINI / "golden_ir.json", _mini_sources())
    assert len(ir.rules) == 6
    assert len(ir.instance.operations) == 9
    night = ir.rule("R-6.1-NIGHT-CLEANOUT")
    assert night is not None
    span = night.provenance.spans[0]
    # primary_normative span was anchored: offsets filled, sha256 filled
    assert span.char_start >= 0 and span.char_end > span.char_start
    assert len(span.source_sha256) == 64
    src = (MINI / "shop_rules.md").read_text(encoding="utf-8")
    assert src[span.char_start : span.char_end] == span.quoted_text


def test_golden_ir_modeling_decision_passthrough() -> None:
    ir = load_golden_ir(MINI / "golden_ir.json", _mini_sources())
    routing = ir.rule("R-ROUTING")
    assert routing is not None
    span = routing.provenance.spans[0]
    # modeling_decision span NOT re-anchored (offsets stay default -1)
    assert span.role == "modeling_decision"
    assert span.char_start == -1


def test_golden_ir_fabricated_quote_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(
        '{"rules":[{"rule_id":"R-X","kind":"x","params":{},"severity":"HARD",'
        '"clause_kind":"PROHIBITION","compile_mode":"PLAN_CONSTRAINT",'
        '"provenance":{"spans":[{"kind":"text","quoted_text":"this clause does not exist anywhere",'
        '"role":"primary_normative"}]}}],'
        '"instance":{"jobs":[],"operations":[],"machines":[],"setup_matrix":{},'
        '"maintenance":[],"horizon":100}}',
        encoding="utf-8",
    )
    with pytest.raises(NoSourceError):
        load_golden_ir(bad, _mini_sources())


def test_golden_rules_are_canonical_and_hard() -> None:
    ir = load_golden_ir(MINI / "golden_ir.json", _mini_sources())
    ids = {r.rule_id for r in ir.rules}
    assert {"R-ROUTING", "R-NOOVERLAP", "R-SETUP", "R-MAINT", "R-SHIFT", "R-6.1-NIGHT-CLEANOUT"} <= ids
    for rid in ("R-ROUTING", "R-NOOVERLAP", "R-SETUP", "R-MAINT", "R-SHIFT", "R-6.1-NIGHT-CLEANOUT"):
        r = ir.rule(rid)
        assert r.severity == Severity.HARD
        assert r.compile_mode == CompileMode.PLAN_CONSTRAINT


def test_orders_xlsx_roundtrip(tmp_path: Path) -> None:
    jobs = [
        Job(id="J1", product="PeanutSauce", family="Allergen", qty=10, due_date=600, priority=1),
        Job(id="J2", product="MildSauce", family="Standard", qty=5, due_date=900, priority=2),
    ]
    path = tmp_path / "orders.xlsx"
    write_orders_xlsx(path, jobs)
    loaded = load_orders_xlsx(path)
    assert len(loaded) == 2
    assert loaded[0].id == "J1" and loaded[0].family == "Allergen" and loaded[0].priority == 1
    assert loaded[1].due_date == 900
