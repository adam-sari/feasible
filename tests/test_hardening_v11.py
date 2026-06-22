"""v1.1 trust-hardening regression suite — the registry, plan-shape, predicate
totality, DSSE, two-cert universe/active, policy replay, and cert reporting.
"""
from __future__ import annotations

import copy

import pytest

from feasible.canon.canonical import new_signing_key, public_key_hex, sign_dsse, verify_dsse
from feasible.cert.plan_cert import (
    active_rule_set_digest,
    checked_rule_ids,
    emit_plan_cert,
    rule_pack_digest,
    structurally_enforced_rule_ids,
    verify_plan_cert,
)
from feasible.cert.rulepack_cert import (
    bundle_binding_reasons,
    emit_rulepack_cert,
    verify_rulepack_cert,
)
from feasible.checker.checker import check
from feasible.checker.plan_shape import validate_plan_shape
from feasible.compile.cpsat import build_model
from feasible.conflict.policy import MANUFACTURING_POLICY
from feasible.govern.pipeline import govern_pack
from feasible.ir.domain import (
    ClauseKind,
    CompileMode,
    ExceptionMode,
    FCIR,
    Plan,
    Provenance,
    Rule,
    Severity,
    TextSpan,
)
from feasible.registry import UnsupportedHardRuleError, unsupported_hard_rules
from feasible.scenario import (
    SHOP_RULES,
    build_extracted_pack,
    build_scenario_ir,
    generate_incumbent_b,
    make_incumbent_a,
)
from feasible.smt.attest import attest_feasibility
from feasible.solve.orchestrate import solve


def _unsupported_rule() -> Rule:
    # a 2nd setup_cleanout with a NOVEL rule_id — a known kind but not an evaluated id
    return Rule(rule_id="R-SETUP-2", kind="setup_cleanout", params={}, severity=Severity.HARD,
                clause_kind=ClauseKind.OBLIGATION, compile_mode=CompileMode.PLAN_CONSTRAINT,
                resolution_class="SAFETY_SANITATION", exception_mode=ExceptionMode.NONE,
                provenance=Provenance(spans=[TextSpan(quoted_text="a second cleanout rule")]))


# ---------------------------------------------------------------------------
# Registry — fail closed on anything not explicitly evaluated; non_preemption ok
# ---------------------------------------------------------------------------
def test_registry_flags_novel_ruleid_of_known_kind() -> None:
    ir = build_scenario_ir()
    ir2 = FCIR(rules=[*ir.rules, _unsupported_rule()], instance=ir.instance)
    assert [r.rule_id for r in unsupported_hard_rules(ir2)] == ["R-SETUP-2"]
    plan = solve(ir).plan
    res = check(plan, ir2)  # type: ignore[arg-type]
    assert res.passed is False
    assert any(v.rule_id == "R-UNSUPPORTED-RULE" for v in res.violations)
    with pytest.raises(UnsupportedHardRuleError):
        build_model(ir2)


def test_non_preemption_is_supported() -> None:
    active = govern_pack(build_extracted_pack(), MANUFACTURING_POLICY).active_ir
    assert "R-5.2" in [r.rule_id for r in active.hard_plan_rules()]
    assert unsupported_hard_rules(active) == []
    plan = solve(active).plan
    assert check(plan, active).passed is True  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Plan-shape — malformations flagged; an orphan cleanout is NOT a malformation
# ---------------------------------------------------------------------------
def _scenario_plan():
    ir = build_scenario_ir()
    return ir, solve(ir).plan


def test_plan_shape_clean_on_optimal() -> None:
    ir, plan = _scenario_plan()
    assert validate_plan_shape(plan, ir) == []


def test_plan_shape_catches_missing_unknown_ineligible() -> None:
    ir, plan = _scenario_plan()
    a = dict(plan.assignments)
    victim = next(iter(a))
    del a[victim]                      # missing_op
    a["GHOST"] = (0, "Filler-1")       # unknown_op
    a["J1-label"] = (0, "Mixer-A")     # ineligible_machine (label only on Labeler)
    toks = {v.counter_witness["predicate"] for v in validate_plan_shape(Plan(assignments=a, cleanouts=[]), ir)}
    assert {"missing_op", "unknown_op", "ineligible_machine"} <= toks


def test_plan_shape_catches_bad_cleanouts() -> None:
    ir, plan = _scenario_plan()
    bad = Plan(assignments=plan.assignments, cleanouts=[
        ("NoSuchMachine", 100, 190, "x"),   # cleanout_unknown_machine
        ("Filler-1", 200, 200, "x"),        # cleanout_nonpositive_duration
        ("Filler-1", 300, 390, ""),         # cleanout_empty_reason
    ])
    toks = {v.counter_witness["predicate"] for v in validate_plan_shape(bad, ir)}
    assert {"cleanout_unknown_machine", "cleanout_nonpositive_duration", "cleanout_empty_reason"} <= toks


def test_orphan_night_cleanout_is_r61_not_planshape() -> None:
    # the hero gotcha: incumbent-A's orphan night cleanout on Filler-1 -> exactly one R-6.1, no R-PLAN-SHAPE
    ir = build_scenario_ir()
    inc_b = generate_incumbent_b(ir)
    inc_a = make_incumbent_a(inc_b)  # Filler-1, 23:30
    res = check(inc_a, ir)
    assert [v.rule_id for v in res.violations if v.rule_id == "R-6.1-NIGHT-CLEANOUT"] == ["R-6.1-NIGHT-CLEANOUT"]
    assert not any(v.rule_id == "R-PLAN-SHAPE" for v in res.violations)


# ---------------------------------------------------------------------------
# Predicate totality — check() AND attest() must RETURN (not raise) on a ghost op
# ---------------------------------------------------------------------------
def test_check_and_attest_total_on_unknown_op() -> None:
    ir, plan = _scenario_plan()
    a = dict(plan.assignments)
    a["GHOST"] = (0, "Filler-1")  # a ghost forming a Filler-1 adjacency
    p = Plan(assignments=a, cleanouts=plan.cleanouts)
    res = check(p, ir)  # must not raise
    assert res.passed is False
    assert any(v.rule_id == "R-PLAN-SHAPE" for v in res.violations)
    att = attest_feasibility(p, ir)  # must not raise
    assert att.feasible is False
    assert res.passed == att.feasible  # parity on a malformed plan


# ---------------------------------------------------------------------------
# DSSE hardening
# ---------------------------------------------------------------------------
def _envelope():
    key = new_signing_key()
    return key, sign_dsse({"x": 1}, key)


def test_dsse_valid_roundtrip() -> None:
    key, env = _envelope()
    assert verify_dsse(env, key.public_key()) is True


@pytest.mark.parametrize("mutate", [
    lambda e: e.__setitem__("signatures", []),
    lambda e: e.__setitem__("signatures", "nope"),
    lambda e: e.__setitem__("signatures", ["nope"]),
    lambda e: e.__setitem__("payloadType", "application/evil"),
])
def test_dsse_fails_closed(mutate) -> None:
    key, env = _envelope()
    mutate(env)
    assert verify_dsse(env, key.public_key()) is False


def test_active_rule_set_digest_multi_dropped_no_crash() -> None:
    ir = build_scenario_ir()
    d = active_rule_set_digest(ir, [{"rule_id": "R-4.4"}, {"rule_id": "R-9.9"}])
    assert isinstance(d, str) and len(d) == 64


# ---------------------------------------------------------------------------
# Two-cert universe/active + reporting + policy replay (module-scoped certs)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def certs():
    gov = govern_pack(build_extracted_pack(), MANUFACTURING_POLICY)
    key = new_signing_key()
    rp = emit_rulepack_cert(gov.universe_ir, SHOP_RULES, MANUFACTURING_POLICY, gov.resolutions, key)
    res = solve(gov.active_ir)
    plan = res.plan
    inc_b = generate_incumbent_b(gov.active_ir)
    inc_a = make_incumbent_a(inc_b)
    dropped = [{"rule_id": rid, "drop_reason": "rule_inactive_for_plan_by_policy",
                "resolution_mode": "AUTO_BY_POLICY",
                "conflict_policy_ref": {"policy_id": MANUFACTURING_POLICY.policy_id, "digest": MANUFACTURING_POLICY.digest()}}
               for rid in gov.dropped_rule_ids]
    pc = emit_plan_cert(gov.active_ir, plan, res, check(plan, gov.active_ir),
                        attest_feasibility(plan, gov.active_ir), inc_a, inc_b, key,
                        dropped=dropped, rule_pack_digest_override=rule_pack_digest(gov.universe_ir))
    return {"gov": gov, "key": key, "rp": rp, "pc": pc}


def test_universe_has_r44_plan_cert_drops_it(certs) -> None:
    assert "R-4.4" in [r["rule_id"] for r in certs["rp"]["rules"]]
    assert [d["rule_id"] for d in certs["pc"]["active_rule_set_for_plan"]["dropped"]] == ["R-4.4"]


def test_dropped_plan_cert_verifies_standalone(certs) -> None:
    res = verify_plan_cert(certs["pc"], certs["key"].public_key())
    assert res.ok, res.reasons  # the opaque-token binding must NOT fail standalone


def test_two_cert_universe_binding(certs) -> None:
    assert certs["pc"]["rule_pack_ref"]["rule_pack_digest"] == certs["rp"]["rule_pack_digest"]


def test_cert_separates_structural_from_checked(certs) -> None:
    f = certs["pc"]["claims"]["formalization"]
    assert "R-5.2" in f["structurally_enforced_rule_ids"]["value"]
    assert "R-5.2" not in f["checked_rule_ids"]["value"]
    assert len(f["checked_rule_ids"]["value"]) == 6
    assert f["rule_pack_digest_ref"]["value"] == certs["pc"]["rule_pack_ref"]["rule_pack_digest"]


def test_rulepack_verifies(certs) -> None:
    assert verify_rulepack_cert(certs["rp"], certs["key"].public_key()).ok


def test_policy_replay_catches_dropping_safety(certs) -> None:
    # claim the SAFETY obligation (R-SETUP) was auto-dropped — contradicts "safety wins"
    bad = copy.deepcopy(certs["rp"])
    bad["conflict_status"]["resolutions"][0]["dropped"] = "R-SETUP"
    body = {k: v for k, v in bad.items() if k != "signature"}  # re-sign so only the REPLAY can catch it
    env = sign_dsse(body, certs["key"])
    env["public_key_hex"] = public_key_hex(certs["key"])
    bad["signature"] = env
    res = verify_rulepack_cert(bad, certs["key"].public_key())
    assert res.ok is False
    assert any("lower-priority" in r or "dropped" in r for r in res.reasons)


def _resign_rulepack(cert: dict, key) -> dict:
    body = {k: v for k, v in cert.items() if k != "signature"}
    env = sign_dsse(body, key)
    env["public_key_hex"] = public_key_hex(key)
    cert["signature"] = env
    return cert


def test_replay_flags_override_marker_on_auto(certs) -> None:
    # the real resolver ESCALATES when EITHER side carries a lex-specialis override.
    # Replay must mirror that: an AUTO_BY_POLICY resolution over an overridden rule is illegal.
    bad = copy.deepcopy(certs["rp"])
    for r in bad["rules"]:
        if r["rule_id"] == "R-4.4":
            r["overrides"] = ["R-SETUP"]
    ir_bad = FCIR(rules=[Rule.model_validate(r) for r in bad["rules"]],
                  instance=certs["gov"].universe_ir.instance)
    bad["rule_pack_digest"] = rule_pack_digest(ir_bad)  # keep the digest honest so ONLY replay can object
    _resign_rulepack(bad, certs["key"])
    res = verify_rulepack_cert(bad, certs["key"].public_key())
    assert res.ok is False
    assert any("exception/override" in r for r in res.reasons)


def test_replay_rejects_unknown_resolution_mode(certs) -> None:
    bad = copy.deepcopy(certs["rp"])
    bad["conflict_status"]["resolutions"][0]["resolution_mode"] = "MAGIC"
    _resign_rulepack(bad, certs["key"])
    res = verify_rulepack_cert(bad, certs["key"].public_key())
    assert res.ok is False
    assert any("unknown resolution_mode" in r for r in res.reasons)


def test_bundle_cross_checks_dropped(certs) -> None:
    assert bundle_binding_reasons(certs["pc"], certs["rp"]) == []
    # a Plan Cert that claims it dropped NOTHING while the rule-pack policy auto-dropped R-4.4
    bad_pc = copy.deepcopy(certs["pc"])
    bad_pc["active_rule_set_for_plan"]["dropped"] = []
    reasons = bundle_binding_reasons(bad_pc, certs["rp"])
    assert any("auto-dropped" in r for r in reasons)


def _resign_plan(cert: dict, key) -> dict:
    return _resign_rulepack(cert, key)  # identical envelope shape


@pytest.mark.parametrize("group,leaf,bad_value,token", [
    ("formalization", "n_hard_rules", 999, "n_hard_rules"),
    ("formalization", "checked_rule_ids", ["R-BOGUS"], "checked_rule_ids"),
    ("formalization", "structurally_enforced_rule_ids", [], "structurally_enforced_rule_ids"),
])
def test_plan_cert_rederives_formalization_leaves(certs, group, leaf, bad_value, token) -> None:
    bad = copy.deepcopy(certs["pc"])
    bad["claims"][group][leaf]["value"] = bad_value
    _resign_plan(bad, certs["key"])
    res = verify_plan_cert(bad, certs["key"].public_key())
    assert res.ok is False
    assert any(token in r for r in res.reasons)


# ---------------------------------------------------------------------------
# Task 1b — the formalization-leaf helpers source their id sets PER DOMAIN
# (not the module-level manufacturing-only EVALUATED_RULE_IDS/STRUCTURAL_RULE_KINDS).
# For a 2nd domain whose verifier declares non-empty evaluated/structural sets,
# the leaves must be NON-EMPTY (today they'd be [] — a materially-FALSE signed
# claim that 0 of the domain's hard rules are checked/structurally-enforced).
# ---------------------------------------------------------------------------
class _StubVerifier:
    """A minimal 2nd-domain verifier declaring non-empty formalization id sets."""

    domain_id = "stubdom"
    rule_kinds = frozenset({"sd_predicate", "sd_structural"})
    evaluated_rule_ids = frozenset({"sd:checked_a", "sd:checked_b"})
    structural_rule_kinds = frozenset({"sd_structural"})
    known_rule_ids = evaluated_rule_ids | frozenset({"sd:structural_x"})


def _stub_rule(rule_id: str, kind: str) -> Rule:
    from feasible.ir.domain import ClauseKind, CompileMode, ExceptionMode, Provenance, Severity, TextSpan
    return Rule(rule_id=rule_id, kind=kind, params={}, severity=Severity.HARD,
                clause_kind=ClauseKind.OBLIGATION, compile_mode=CompileMode.PLAN_CONSTRAINT,
                resolution_class="X", exception_mode=ExceptionMode.NONE,
                provenance=Provenance(spans=[TextSpan(quoted_text="stub")]))


@pytest.fixture
def stub_domain():
    from feasible.domains import _DOMAINS, register_domain
    register_domain("stubdom", object(), _StubVerifier())  # type: ignore[arg-type]
    try:
        yield
    finally:
        _DOMAINS.pop("stubdom", None)


def _stub_ir():
    inst = build_scenario_ir().instance  # any valid Instance; the helpers read rule_ids/kinds
    rules = [
        _stub_rule("sd:checked_a", "sd_predicate"),
        _stub_rule("sd:checked_b", "sd_predicate"),
        _stub_rule("sd:structural_x", "sd_structural"),
    ]
    return FCIR(rules=rules, instance=inst, domain_id="stubdom")


def test_formalization_leaves_manufacturing_unchanged() -> None:
    ir = govern_pack(build_extracted_pack(), MANUFACTURING_POLICY).active_ir
    # byte-identical to the module-level manufacturing view (the oracle's proof,
    # restated here as a direct unit assertion)
    active = {r.rule_id for r in ir.hard_plan_rules()}
    mfg_checked = {"R-ROUTING", "R-NOOVERLAP", "R-SETUP", "R-MAINT", "R-SHIFT", "R-6.1-NIGHT-CLEANOUT"}
    assert checked_rule_ids(ir) == sorted(mfg_checked & active)
    assert "R-5.2" in structurally_enforced_rule_ids(ir)
    assert "R-5.2" not in checked_rule_ids(ir)
    assert len(checked_rule_ids(ir)) == 6


def test_formalization_leaves_source_per_domain(stub_domain) -> None:
    ir = _stub_ir()
    # TODAY (module-level mfg sets) both resolve to [] for stubdom — the BUG.
    assert checked_rule_ids(ir) == ["sd:checked_a", "sd:checked_b"]
    assert structurally_enforced_rule_ids(ir) == ["sd:structural_x"]


def test_plan_cert_rederives_active_rule_ids(certs) -> None:
    bad = copy.deepcopy(certs["pc"])
    bad["active_rule_set_for_plan"]["active_rule_ids"] = ["R-ONLY"]
    _resign_plan(bad, certs["key"])
    res = verify_plan_cert(bad, certs["key"].public_key())
    assert res.ok is False
    assert any("active_rule_ids" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# GovernResult new fields
# ---------------------------------------------------------------------------
def test_govern_result_universe_active_dropped() -> None:
    gov = govern_pack(build_extracted_pack(), MANUFACTURING_POLICY)
    assert len(gov.universe_ir.rules) == 8
    assert gov.universe_ir.rule("R-4.4") is not None
    assert gov.active_ir.rule("R-4.4") is None
    assert len(gov.active_ir.rules) == 7
    assert gov.dropped_rule_ids == ["R-4.4"]
