from __future__ import annotations

from feasible.canon.canonical import new_signing_key
from feasible.cert.plan_cert import rule_pack_digest
from feasible.cert.rulepack_cert import emit_rulepack_cert, verify_rulepack_cert
from feasible.conflict.policy import MANUFACTURING_POLICY
from feasible.govern.conflict import detect_normative_conflicts, resolve_conflicts
from feasible.ir.domain import (
    ClauseKind,
    CompileMode,
    ExceptionMode,
    FCIR,
    Provenance,
    Rule,
    Severity,
    TextSpan,
)
from feasible.scenario import SHOP_RULES, build_scenario_ir


def _emit():
    ir = build_scenario_ir()
    key = new_signing_key()
    cert = emit_rulepack_cert(ir, SHOP_RULES, MANUFACTURING_POLICY, [], key)
    return ir, cert, key


def test_rulepack_emit_verify_roundtrip() -> None:
    _ir, cert, key = _emit()
    res = verify_rulepack_cert(cert, key.public_key())
    assert res.ok, res.reasons


def test_rulepack_digest_binds_to_plan_cert() -> None:
    ir, cert, _key = _emit()
    # the Rule-Pack Cert digest is exactly what a Plan Cert's rule_pack_ref binds to
    assert cert["rule_pack_digest"] == rule_pack_digest(ir)


def test_rulepack_coverage_complete() -> None:
    _ir, cert, _key = _emit()
    assert cert["coverage_ledger"]["complete"] is True
    assert cert["coverage_ledger"]["red_findings"] == []


def test_rulepack_tamper_fails() -> None:
    _ir, cert, key = _emit()
    cert["rules"][0]["rule_id"] = "R-TAMPERED"
    res = verify_rulepack_cert(cert, key.public_key())
    assert res.ok is False
    assert any("payload" in r or "digest" in r for r in res.reasons)


def test_rulepack_wrong_key_fails() -> None:
    _ir, cert, _key = _emit()
    other = new_signing_key()
    res = verify_rulepack_cert(cert, other.public_key())
    assert res.ok is False


def test_rulepack_records_conflict_resolution() -> None:
    base = build_scenario_ir()
    perm = Rule(
        rule_id="R-4.4", kind="permission",
        params={"target_rule": "R-SETUP", "scope_machine": "Filler-1", "scope_priority": 1},
        severity=Severity.SOFT, clause_kind=ClauseKind.PERMISSION,
        compile_mode=CompileMode.CONFLICT_ONLY, resolution_class="CUSTOMER_PRIORITY",
        exception_mode=ExceptionMode.NONE,
        provenance=Provenance(spans=[TextSpan(quoted_text="Filler-1 may do back-to-back changes",
                                              role="primary_normative")]),
    )
    ir = FCIR(rules=[*base.rules, perm], instance=base.instance)
    conflicts = detect_normative_conflicts(ir)
    resolutions = resolve_conflicts(ir, conflicts, MANUFACTURING_POLICY)
    key = new_signing_key()
    cert = emit_rulepack_cert(ir, SHOP_RULES, MANUFACTURING_POLICY, resolutions, key)
    cs = cert["conflict_status"]
    assert cs["internal_conflict"] is False  # auto-resolved, not escalated
    assert cs["resolutions"][0]["resolution_mode"] == "AUTO_BY_POLICY"
    assert cs["resolutions"][0]["dropped"] == "R-4.4"
    assert verify_rulepack_cert(cert, key.public_key()).ok
