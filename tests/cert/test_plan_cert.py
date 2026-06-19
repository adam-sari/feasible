from __future__ import annotations

from pathlib import Path

from feasible.canon.canonical import new_signing_key
from feasible.cert.plan_cert import (
    ALLOWED_PROVENANCE,
    emit_plan_cert,
    iter_claim_leaves,
    render_html,
    verify_plan_cert,
)
from feasible.checker.checker import check
from feasible.ingest.golden import load_golden_ir
from feasible.ir.domain import FCIR, Plan
from feasible.smt.attest import attest_feasibility
from feasible.solve.orchestrate import solve

MINI = Path(__file__).resolve().parent.parent / "fixtures" / "mini"


def _mini_ir() -> FCIR:
    return load_golden_ir(MINI / "golden_ir.json", {"shop_rules.md": (MINI / "shop_rules.md").read_text(encoding="utf-8")})


def _make_cert():
    ir = _mini_ir()
    result = solve(ir, max_seconds=20.0)
    assert result.plan is not None
    plan = result.plan
    chk = check(plan, ir)
    att = attest_feasibility(plan, ir)
    # incumbent A: the optimized layout + an illegal 23:30 cleanout
    incumbent_a = Plan(assignments=dict(plan.assignments),
                       cleanouts=[("Filler-1", 1050, 1140, "cleanout J1->J2")])
    incumbent_b = plan  # KPI tie for the unit test; Task 10 crafts a worse B
    key = new_signing_key()
    cert = emit_plan_cert(ir, plan, result, chk, att, incumbent_a, incumbent_b, key)
    return ir, cert, key


def test_emit_verify_roundtrip() -> None:
    _ir, cert, key = _make_cert()
    res = verify_plan_cert(cert, key.public_key())
    assert res.ok, res.reasons


def test_tampered_plan_fails_verify() -> None:
    _ir, cert, key = _make_cert()
    # move an op to overlap something -> checker fails AND body no longer matches signature
    first_op = next(iter(cert["plan"]["assignments"]))
    cert["plan"]["assignments"][first_op][0] = 999999
    res = verify_plan_cert(cert, key.public_key())
    assert res.ok is False
    assert any("signed payload" in r or "checker FAIL" in r for r in res.reasons)


def test_wrong_key_fails_verify() -> None:
    _ir, cert, _key = _make_cert()
    other = new_signing_key()
    res = verify_plan_cert(cert, other.public_key())
    assert res.ok is False


def test_no_llm_fields_in_plan_cert_claims() -> None:
    _ir, cert, _key = _make_cert()
    leaves = list(iter_claim_leaves(cert["claims"]))
    assert len(leaves) > 0
    for leaf in leaves:
        assert leaf["provenance"] != "llm_generated"
        assert leaf["provenance"] in ALLOWED_PROVENANCE


def test_incumbent_a_gotcha_block() -> None:
    _ir, cert, _key = _make_cert()
    fail = cert["incumbent_A_failure"]
    assert fail["violated_rule_ref"] == "R-6.1-NIGHT-CLEANOUT"
    assert "Cleanouts may only be performed during the day shift" in fail["span"]["quoted_text"]
    assert fail["counter_witness"]["minute_of_day"] == 1050


def test_kpi_block_present() -> None:
    _ir, cert, _key = _make_cert()
    kpi = cert["kpi_vs_incumbent_B"]
    assert "weighted_tardiness" in kpi
    assert "optimized" in kpi["weighted_tardiness"]
    assert "incumbent_b" in kpi["total_changeover_time"]


def test_formalization_claim_grounded() -> None:
    _ir, cert, _key = _make_cert()
    form = cert["claims"]["formalization"]
    assert form["rule_pack_digest_ref"]["provenance"] == "rule_pack_digest_ref"
    assert form["n_hard_rules"]["value"] == 6


def test_render_html_contains_gotcha() -> None:
    _ir, cert, _key = _make_cert()
    html = render_html(cert)
    assert "Plan Certificate" in html
    assert "Cleanouts may only be performed during the day shift" in html
