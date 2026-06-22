"""Task 7 — coverage classifier / back-translation / conflict realizability are now
per-domain hooks dispatched on ``ir.domain_id``. This asserts the manufacturing
outputs are UNCHANGED after the relocation: the ``ManufacturingVerifier`` hooks
produce byte-identical results to the (former) inline ``govern/*`` implementations,
and the coverage-ledger / conflict-status surface still matches the frozen oracle.
"""
from __future__ import annotations

import json
from pathlib import Path

from feasible.conflict.policy import MANUFACTURING_POLICY
from feasible.domains import get_domain
from feasible.govern.backtranslate import back_translate
from feasible.govern.conflict import (
    _normative_unsat,
    _scope_realizable,
    detect_normative_conflicts,
    resolve_conflicts,
)
from feasible.govern.coverage import build_coverage_ledger, classify
from feasible.govern.pipeline import govern_pack
from feasible.ingest.segment import segment
from feasible.ir.domain import ClauseKind, CompileMode, FCIR, Provenance, Rule, Severity, TextSpan
from feasible.scenario import SHOP_RULES, build_extracted_pack, build_scenario_ir

ORACLE = Path(__file__).parent.parent / "regression" / "golden" / "manufacturing_oracle.json"


def _permission() -> Rule:
    return Rule(
        rule_id="R-4.4", kind="permission",
        params={"target_rule": "R-SETUP", "scope_machine": "Filler-1", "scope_priority": 1},
        severity=Severity.SOFT, clause_kind=ClauseKind.PERMISSION,
        compile_mode=CompileMode.CONFLICT_ONLY, resolution_class="CUSTOMER_PRIORITY",
        provenance=Provenance(spans=[TextSpan(
            quoted_text="Filler-1 may perform back-to-back family changes without an intervening cleanout",
            role="primary_normative")]),
    )


def test_classify_dispatches_to_manufacturing_verifier() -> None:
    _, v = get_domain("manufacturing")
    for seg in segment(SHOP_RULES):
        assert v.classify_segment(seg) == classify(seg)


def test_back_translate_dispatches_to_manufacturing_verifier() -> None:
    _, v = get_domain("manufacturing")
    ir = build_scenario_ir()
    for r in ir.rules:
        assert v.back_translate(r) == back_translate(r)


def test_conflict_realizable_dispatches_to_manufacturing_verifier() -> None:
    _, v = get_domain("manufacturing")
    base = build_scenario_ir()
    perm = _permission()
    ir = FCIR(rules=[*base.rules, perm], instance=base.instance)
    assert v.conflict_realizable(ir, perm) == _scope_realizable(ir, perm)
    assert _scope_realizable(ir, perm) is True


def test_conflict_unsat_core_dispatches_to_manufacturing_verifier() -> None:
    _, v = get_domain("manufacturing")
    core = v.conflict_unsat_core("R-SETUP", "R-4.4")
    assert core is not None and "R-SETUP" in core and "R-4.4" in core
    assert sorted(core) == sorted(_normative_unsat("R-SETUP", "R-4.4"))


def test_coverage_and_conflict_surface_match_oracle() -> None:
    gov = govern_pack(build_extracted_pack(), MANUFACTURING_POLICY)
    ledger = build_coverage_ledger(SHOP_RULES, gov.universe_ir)
    conflicts = detect_normative_conflicts(gov.universe_ir)
    resolutions = resolve_conflicts(gov.universe_ir, conflicts, MANUFACTURING_POLICY)
    golden = json.loads(ORACLE.read_text(encoding="utf-8"))

    assert ledger.complete == golden["coverage_ledger"]["complete"]
    assert ledger.denominator == golden["coverage_ledger"]["denominator"]
    assert [e.text for e in ledger.red_findings] == golden["coverage_ledger"]["red_findings"]
    # conflict resolution drops the permission exactly as the oracle records
    assert [r.dropped_rule_id for r in resolutions if r.resolution_mode == "AUTO_BY_POLICY"] == \
        [r["dropped"] for r in golden["conflict_status"]["resolutions"]
         if r["resolution_mode"] == "AUTO_BY_POLICY"]
