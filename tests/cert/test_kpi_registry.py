"""Task-11 forgery suite: the verify-side ``KPI_REGISTRY`` + version-triple binding,
the gotcha-rule-id equality, and the variable-length objective.

A re-signed plan cert must not be able to:
  (a) change a KPI value AND its ``function_id`` to make the recompute "agree"
      under a swapped-in function name — ``verify`` re-derives every KPI by
      calling ``KPI_REGISTRY[domain_id][key]["fn"]`` (NEVER a cert-supplied
      callable) and asserts the cert's ``(function_id, function_version,
      input_schema_digest)`` triple equals the statically-registered one; and
  (b) cite a NON-gotcha rule as the incumbent-A failure — ``verify`` asserts the
      cited ``violated_rule_ref`` equals the domain verifier's ``gotcha_rule_id()``
      (the ``violations[0]`` fallback that previously let ANY hard-rule failure
      pose as the headline gotcha is removed).
"""
from __future__ import annotations

import copy

import pytest

from feasible.canon.canonical import new_signing_key, public_key_hex, sign_dsse
from feasible.cert.plan_cert import emit_plan_cert, rule_pack_digest, verify_plan_cert
from feasible.checker.checker import check
from feasible.conflict.policy import MANUFACTURING_POLICY
from feasible.domains import get_domain
from feasible.domains.base import KPI_REGISTRY
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
    return {"gov": gov, "key": key, "pc": pc}


def _resign(cert: dict, key) -> dict:
    body = {k: v for k, v in cert.items() if k != "signature"}
    env = sign_dsse(body, key)
    env["public_key_hex"] = public_key_hex(key)
    cert["signature"] = env
    return cert


# ---------------------------------------------------------------------------
# Baseline: the honest cert carries the version triple + verifies
# ---------------------------------------------------------------------------
def test_honest_cert_carries_kpi_function_refs(bundle) -> None:
    pc = bundle["pc"]
    refs = pc["kpi_function_refs"]
    registry = KPI_REGISTRY["manufacturing"]
    assert set(refs) == set(registry)
    for key, entry in registry.items():
        assert refs[key]["function_id"] == entry["function_id"]
        assert refs[key]["function_version"] == entry["function_version"]
        assert refs[key]["input_schema_digest"] == entry["input_schema_digest"]
    assert verify_plan_cert(pc, bundle["key"].public_key()).ok


# ---------------------------------------------------------------------------
# K1 — swap a KPI value AND its function_id so the recompute would "agree"
# ---------------------------------------------------------------------------
def test_kpi_fn_swap_rejected(bundle) -> None:
    bad = copy.deepcopy(bundle["pc"])
    # change a KPI value and rename its function_id to a fabricated one
    bad["kpi_vs_incumbent_B"]["weighted_tardiness"]["incumbent_b"] = 1
    bad["kpi_function_refs"]["weighted_tardiness"]["function_id"] = "mfg:fake_metric"
    _resign(bad, bundle["key"])
    res = verify_plan_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("kpi" in r.lower() or "function" in r.lower() for r in res.reasons)


# ---------------------------------------------------------------------------
# K2 — bump a function_version so the cert claims a different (unregistered) fn version
# ---------------------------------------------------------------------------
def test_kpi_version_bump_rejected(bundle) -> None:
    bad = copy.deepcopy(bundle["pc"])
    bad["kpi_function_refs"]["total_changeover_time"]["function_version"] = "v999"
    _resign(bad, bundle["key"])
    res = verify_plan_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("function_version" in r or "triple" in r or "kpi" in r.lower() for r in res.reasons)


# ---------------------------------------------------------------------------
# K3 — tamper the input_schema_digest in the triple
# ---------------------------------------------------------------------------
def test_kpi_input_schema_digest_tamper_rejected(bundle) -> None:
    bad = copy.deepcopy(bundle["pc"])
    bad["kpi_function_refs"]["late_priority_orders"]["input_schema_digest"] = "deadbeef"
    _resign(bad, bundle["key"])
    res = verify_plan_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("input_schema_digest" in r or "triple" in r or "kpi" in r.lower() for r in res.reasons)


# ---------------------------------------------------------------------------
# K4 — cite a NON-gotcha rule as the incumbent-A failure (the dropped fallback)
# ---------------------------------------------------------------------------
def test_nongotcha_violation_rejected(bundle) -> None:
    gov = bundle["gov"]
    key = bundle["key"]
    ir = gov.active_ir
    inst = ir.instance
    res_solve = solve(ir, workers=1, seed=1)
    plan = res_solve.plan
    inc_b = generate_incumbent_b(ir)
    # craft an incumbent_a that violates a NON-gotcha hard rule (R-SHIFT: an op past
    # the horizon) but NOT the night-cleanout gotcha — verify must reject it because
    # the cited gotcha rule is not the one actually violated.
    from feasible.ir.domain import Plan
    op0 = inst.operations[0]
    bad_assign = dict(plan.assignments)
    bad_assign[op0.op_id] = (inst.horizon + 100, plan.machine(op0.op_id))
    inc_a = Plan(assignments=bad_assign, cleanouts=[])
    gotcha = get_domain("manufacturing")[1].gotcha_rule_id()
    chk = check(inc_a, ir)
    assert not any(v.rule_id == gotcha for v in chk.violations)  # no night-cleanout violation
    assert chk.violations  # but it IS infeasible (a non-gotcha hard rule)
    dropped = [{"rule_id": rid, "drop_reason": "rule_inactive_for_plan_by_policy",
                "resolution_mode": "AUTO_BY_POLICY",
                "conflict_policy_ref": {"policy_id": MANUFACTURING_POLICY.policy_id,
                                        "digest": MANUFACTURING_POLICY.digest()}}
               for rid in gov.dropped_rule_ids]
    pc = emit_plan_cert(ir, plan, res_solve, check(plan, ir),
                        attest_feasibility(plan, ir), inc_a, inc_b, key,
                        dropped=dropped, rule_pack_digest_override=rule_pack_digest(gov.universe_ir))
    # the cert's incumbent_A_failure must report NO gotcha violation (fallback removed),
    # so verify rejects "the gotcha must be a real hard-rule failure".
    out = verify_plan_cert(pc, key.public_key())
    assert out.ok is False
    assert any("gotcha" in r.lower() or "incumbent_A_failure" in r for r in out.reasons)
