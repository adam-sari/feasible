"""Task-10 forgery suite: the signed ``domain_id`` selector + the cross-domain
rule_id isolation guard.

Both cert bodies carry a top-level ``domain_id``. ``verify`` resolves
``get_domain(cert["domain_id"])`` (fail-closed on an unknown domain) and asserts
EVERY rule_id in the cert belongs to that domain's ``known_rule_ids`` — so a
re-signed cert cannot (a) point at an unregistered domain, nor (b) smuggle a
foreign-namespace rule_id (e.g. a ``dc:`` rule) under ``manufacturing``. The
re-sign always re-validates the signature, so only the new domain binding catches
the attack.
"""
from __future__ import annotations

import copy

import pytest

from feasible.canon.canonical import new_signing_key, public_key_hex, sign_dsse
from feasible.cert.plan_cert import emit_plan_cert, rule_pack_digest, verify_plan_cert
from feasible.cert.rulepack_cert import emit_rulepack_cert, verify_rulepack_cert
from feasible.checker.checker import check
from feasible.conflict.policy import MANUFACTURING_POLICY
from feasible.govern.pipeline import govern_pack
from feasible.scenario import (
    SHOP_RULES,
    build_extracted_pack,
    generate_incumbent_b,
    make_incumbent_a,
)
from feasible.smt.attest import attest_feasibility
from feasible.solve.orchestrate import solve


@pytest.fixture(scope="module")
def bundle():
    gov = govern_pack(build_extracted_pack(), MANUFACTURING_POLICY)
    key = new_signing_key()
    rp = emit_rulepack_cert(gov.universe_ir, SHOP_RULES, MANUFACTURING_POLICY, gov.resolutions, key)
    res = solve(gov.active_ir, workers=1, seed=1)
    plan = res.plan
    inc_b = generate_incumbent_b(gov.active_ir)
    inc_a = make_incumbent_a(inc_b)
    dropped = [{"rule_id": rid, "drop_reason": "rule_inactive_for_plan_by_policy",
                "resolution_mode": "AUTO_BY_POLICY",
                "conflict_policy_ref": {"policy_id": MANUFACTURING_POLICY.policy_id,
                                        "digest": MANUFACTURING_POLICY.digest()}}
               for rid in gov.dropped_rule_ids]
    pc = emit_plan_cert(gov.active_ir, plan, res, check(plan, gov.active_ir),
                        attest_feasibility(plan, gov.active_ir), inc_a, inc_b, key,
                        dropped=dropped, rule_pack_digest_override=rule_pack_digest(gov.universe_ir))
    return {"gov": gov, "key": key, "rp": rp, "pc": pc}


def _resign(cert: dict, key) -> dict:
    body = {k: v for k, v in cert.items() if k != "signature"}
    env = sign_dsse(body, key)
    env["public_key_hex"] = public_key_hex(key)
    cert["signature"] = env
    return cert


# ---------------------------------------------------------------------------
# Baseline: both honest certs carry the signed domain_id and verify
# ---------------------------------------------------------------------------
def test_honest_certs_carry_domain_id(bundle) -> None:
    assert bundle["pc"]["domain_id"] == "manufacturing"
    assert bundle["rp"]["domain_id"] == "manufacturing"
    assert verify_plan_cert(bundle["pc"], bundle["key"].public_key()).ok
    assert verify_rulepack_cert(bundle["rp"], bundle["key"].public_key()).ok


# ---------------------------------------------------------------------------
# D1 — re-point the PLAN cert at an unregistered domain
# ---------------------------------------------------------------------------
def test_plan_cert_unknown_domain_rejected(bundle) -> None:
    bad = copy.deepcopy(bundle["pc"])
    bad["domain_id"] = "datacenter"  # not registered
    _resign(bad, bundle["key"])
    res = verify_plan_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("domain" in r.lower() for r in res.reasons)


# ---------------------------------------------------------------------------
# D2 — re-point the RULE-PACK cert at an unregistered domain
# ---------------------------------------------------------------------------
def test_rulepack_cert_unknown_domain_rejected(bundle) -> None:
    bad = copy.deepcopy(bundle["rp"])
    bad["domain_id"] = "datacenter"
    _resign(bad, bundle["key"])
    res = verify_rulepack_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("domain" in r.lower() for r in res.reasons)


# ---------------------------------------------------------------------------
# D3 — smuggle a FOREIGN-namespace rule_id under the manufacturing domain (plan cert)
# ---------------------------------------------------------------------------
def test_plan_cert_foreign_rule_id_rejected(bundle) -> None:
    bad = copy.deepcopy(bundle["pc"])
    # inject a dc:-prefixed rule that no manufacturing known_rule_ids set owns
    bad["rules"].append({**bad["rules"][0], "rule_id": "dc:redundancy_floor"})
    _resign(bad, bundle["key"])
    res = verify_plan_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("dc:redundancy_floor" in r or "foreign" in r.lower()
               or "known_rule_ids" in r or "domain" in r.lower() for r in res.reasons)


# ---------------------------------------------------------------------------
# D4 — smuggle a FOREIGN-namespace rule_id under the manufacturing domain (rule-pack cert)
# ---------------------------------------------------------------------------
def test_rulepack_cert_foreign_rule_id_rejected(bundle) -> None:
    bad = copy.deepcopy(bundle["rp"])
    bad["rules"].append({**bad["rules"][0], "rule_id": "dc:redundancy_floor"})
    bad["rule_pack_digest"] = rule_pack_digest(
        __import__("feasible.ir.domain", fromlist=["FCIR"]).FCIR.model_validate(
            {"rules": bad["rules"], "instance": bad["instance"]}))
    _resign(bad, bundle["key"])
    res = verify_rulepack_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("dc:redundancy_floor" in r or "foreign" in r.lower()
               or "known_rule_ids" in r or "domain" in r.lower() for r in res.reasons)


# ---------------------------------------------------------------------------
# Determinism: two emits over the SAME inputs + key produce byte-identical
# conflict_status (the carried-forward z3_core ordering fix).
# ---------------------------------------------------------------------------
def test_emit_conflict_status_is_deterministic(bundle) -> None:
    gov = bundle["gov"]
    key = bundle["key"]
    rp1 = emit_rulepack_cert(gov.universe_ir, SHOP_RULES, MANUFACTURING_POLICY, gov.resolutions, key)
    rp2 = emit_rulepack_cert(gov.universe_ir, SHOP_RULES, MANUFACTURING_POLICY, gov.resolutions, key)
    assert rp1["conflict_status"] == rp2["conflict_status"]
    # z3_core is canonicalized (sorted) in the signed body
    core = rp1["conflict_status"]["resolutions"][0]["z3_core"]
    assert core == sorted(core)
    # and the signed bytes are identical (deterministic envelope over the same inputs+key)
    assert rp1["signature"]["payload"] == rp2["signature"]["payload"]
