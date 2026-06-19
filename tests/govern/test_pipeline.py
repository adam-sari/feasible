from __future__ import annotations

from feasible.checker.checker import check
from feasible.conflict.policy import MANUFACTURING_POLICY
from feasible.govern.backtranslate import scope_is_overbroad
from feasible.govern.pipeline import govern_pack
from feasible.scenario import build_extracted_pack
from feasible.solve.orchestrate import solve


def test_govern_pipeline_corrects_and_resolves() -> None:
    extracted = build_extracted_pack()
    assert len(extracted.rules) == 8  # golden 6 + R-4.4 + R-5.2
    gov = govern_pack(extracted, MANUFACTURING_POLICY)

    # §5.2 corrected
    assert len(gov.corrections) == 1
    assert gov.corrections[0].rule_id == "R-5.2"
    r52 = gov.active_ir.rule("R-5.2")
    assert r52 is not None and not scope_is_overbroad(r52)

    # §4.4 dropped by policy
    assert any(r.resolution_mode == "AUTO_BY_POLICY" and r.dropped_rule_id == "R-4.4" for r in gov.resolutions)
    assert gov.active_ir.rule("R-4.4") is None
    assert len(gov.active_ir.rules) == 7  # 6 golden + corrected R-5.2; R-4.4 dropped


def test_active_ir_solves_and_passes() -> None:
    gov = govern_pack(build_extracted_pack(), MANUFACTURING_POLICY)
    result = solve(gov.active_ir, max_seconds=20.0)
    assert result.status == "OPTIMAL"
    assert result.plan is not None
    assert check(result.plan, gov.active_ir).passed is True
    assert result.objective == (0, 90)
