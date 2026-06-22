"""Forge-resistance suite — each test reconstructs an attack the adversarial review
found, RE-SIGNS the tampered certificate with a valid key (so the signature itself
always passes), and asserts the offline verifier now REJECTS it.

The threat model is the project's own: a skeptic who does NOT trust the signer
re-checks the cert offline. Anything the verifier does not RE-DERIVE, a self-signed
cert can fabricate — so every claim a demo leans on must be machine-checked here.
"""
from __future__ import annotations

import copy

import pytest

from feasible import api
from feasible.canon.canonical import digest_of, new_signing_key, public_key_hex, sign_dsse
from feasible.cert.plan_cert import rule_pack_digest, verify_plan_cert
from feasible.cert.rulepack_cert import (
    bundle_binding_reasons,
    verify_rulepack_cert,
)
from feasible.checker.checker import check
from feasible.conflict.policy import ConflictPolicy, DEFAULT_TRUSTED_POLICIES
from feasible.ir.domain import FCIR, Plan


# The forgery suite is parametrized over the registered DOMAINS (manufacturing
# only for Spec 0; the datacenter track adds "datacenter" in its own fork). Every
# attack runs against the bundle the FACADE builds — the same two-cert
# orchestration the CLI ships — so the forge-resistance guarantees are proven over
# the production path, not a test-local reconstruction.
@pytest.fixture(scope="module", params=["manufacturing"])
def domain_id(request):
    return request.param


@pytest.fixture(scope="module")
def bundle(domain_id):
    # build the honest two-cert bundle through the facade (single orchestration)
    key = new_signing_key()
    result = api.certify(domain_id, signer_key=key)
    pc, rp = result.plan_cert, result.rule_pack_cert
    # the governed ACTIVE instance (the surface incumbent_b is built/checked over);
    # surfaced so the A10 degenerate-incumbent attack can craft an infeasible plan.
    active_instance = FCIR.model_validate(  # reconstruct from the signed cert body
        {"rules": pc["rules"], "instance": pc["instance"], "domain_id": domain_id}).instance
    return {"domain_id": domain_id, "key": key, "rp": rp, "pc": pc,
            "active_instance": active_instance}


def _resign(cert: dict, key) -> dict:
    body = {k: v for k, v in cert.items() if k != "signature"}
    env = sign_dsse(body, key)
    env["public_key_hex"] = public_key_hex(key)
    cert["signature"] = env
    return cert


def _rp_digest(cert: dict) -> str:
    ir = FCIR.model_validate({"rules": cert["rules"], "instance": cert["instance"]})
    return rule_pack_digest(ir)


# ---------------------------------------------------------------------------
# Baseline: the honest bundle must verify and bind cleanly
# ---------------------------------------------------------------------------
def test_honest_bundle_verifies(bundle) -> None:
    assert verify_rulepack_cert(bundle["rp"], bundle["key"].public_key()).ok
    assert verify_plan_cert(bundle["pc"], bundle["key"].public_key()).ok
    assert bundle_binding_reasons(bundle["pc"], bundle["rp"]) == []


# ---------------------------------------------------------------------------
# A1 — a re-signed rule-pack forges an AUTO conflict to silently drop a hard rule
# ---------------------------------------------------------------------------
def test_forged_conflict_cannot_drop_hard_rule(bundle) -> None:
    bad = copy.deepcopy(bundle["rp"])
    # name two HARD plan rules (neither a permission) and "auto-drop" the lower one.
    # R-SETUP=SAFETY(100) vs R-MAINT=MAINTENANCE(90): the priority direction check is
    # satisfied (dropped == lower), so ONLY the pairing invariant can catch this.
    bad["conflict_status"]["resolutions"] = [{
        "obligation": "R-SETUP", "permission": "R-MAINT",
        "resolution_mode": "AUTO_BY_POLICY", "dropped": "R-MAINT",
        "rationale": "forged", "z3_core": [],
    }]
    _resign(bad, bundle["key"])
    res = verify_rulepack_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("PERMISSION" in r or "target obligation" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A2 — a plan cert silently OMITS a hard rule from its active set
# ---------------------------------------------------------------------------
def test_bundle_catches_silently_omitted_hard_rule(bundle) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["rules"] = [r for r in bad_pc["rules"] if r["rule_id"] != "R-SETUP"]
    bad_pc["active_rule_set_for_plan"]["active_rule_ids"] = [
        x for x in bad_pc["active_rule_set_for_plan"]["active_rule_ids"] if x != "R-SETUP"
    ]
    reasons = bundle_binding_reasons(bad_pc, bundle["rp"])
    assert any("universe minus auto-drops" in r or "active set" in r for r in reasons)


# ---------------------------------------------------------------------------
# A3 — a plan cert keeps a rule's id but WEAKENS its body
# ---------------------------------------------------------------------------
def test_bundle_catches_weakened_rule_body(bundle) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    for r in bad_pc["rules"]:
        if r["rule_id"] == "R-SETUP":
            r["params"] = {**r.get("params", {}), "sabotage": True}
    reasons = bundle_binding_reasons(bad_pc, bundle["rp"])
    assert any("differs from the certified universe rule body" in r for r in reasons)


# ---------------------------------------------------------------------------
# A4 — a plan is certified over a DIFFERENT instance under the same rule universe
# ---------------------------------------------------------------------------
def test_instance_swap_passes_standalone_but_bundle_binds(bundle) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["instance"]["horizon"] = 999999            # a different instance...
    bad_pc["instance_ref"]["instance_digest"] = digest_of(bad_pc["instance"])  # ...kept self-consistent
    _resign(bad_pc, bundle["key"])
    # standalone the plan cert is internally consistent (the swap is only catchable cross-cert)
    assert verify_plan_cert(bad_pc, bundle["key"].public_key()).ok
    reasons = bundle_binding_reasons(bad_pc, bundle["rp"])
    assert any("instance binding mismatch" in r for r in reasons)


# ---------------------------------------------------------------------------
# A5 — fabricate the "we beat the baseline" headline
# ---------------------------------------------------------------------------
def test_forged_kpi_is_rejected(bundle) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["kpi_vs_incumbent_B"]["weighted_tardiness"]["incumbent_b"] = 999999
    _resign(bad_pc, bundle["key"])
    res = verify_plan_cert(bad_pc, bundle["key"].public_key())
    assert res.ok is False
    assert any("kpi_vs_incumbent_B" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A6 — fabricate the gotcha (cited SOP clause / violated rule)
# ---------------------------------------------------------------------------
def test_forged_gotcha_is_rejected(bundle) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["incumbent_A_failure"]["violated_rule_ref"] = "R-TOTALLY-MADE-UP"
    _resign(bad_pc, bundle["key"])
    res = verify_plan_cert(bad_pc, bundle["key"].public_key())
    assert res.ok is False
    assert any("incumbent_A_failure" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A7 — inflate the source-grounding count
# ---------------------------------------------------------------------------
def test_forged_grounded_count_is_rejected(bundle) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["claims"]["formalization"]["rules_grounded_in_source"]["value"] = 999
    _resign(bad_pc, bundle["key"])
    res = verify_plan_cert(bad_pc, bundle["key"].public_key())
    assert res.ok is False
    assert any("rules_grounded_in_source" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A8 — class-swap: relabel rule resolution_classes to flip the drop direction
# ---------------------------------------------------------------------------
def test_class_swap_cannot_drop_hard_obligation(bundle) -> None:
    bad = copy.deepcopy(bundle["rp"])
    for r in bad["rules"]:
        if r["rule_id"] == "R-SETUP":
            r["resolution_class"] = "EFFICIENCY"            # demote the safety obligation
        elif r["rule_id"] == "R-4.4":
            r["resolution_class"] = "SAFETY_SANITATION"     # promote the permission
    bad["conflict_status"]["resolutions"] = [{
        "obligation": "R-SETUP", "permission": "R-4.4",
        "resolution_mode": "AUTO_BY_POLICY", "dropped": "R-SETUP",
        "rationale": "forged", "z3_core": [],
    }]
    bad["rule_pack_digest"] = _rp_digest(bad)  # keep the digest self-consistent
    _resign(bad, bundle["key"])
    res = verify_rulepack_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("strictly outrank" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A9 — policy-inversion: rewrite the embedded ConflictPolicy so customer > safety
# ---------------------------------------------------------------------------
def test_policy_inversion_cannot_drop_hard_obligation(bundle) -> None:
    bad = copy.deepcopy(bundle["rp"])
    for c in bad["conflict_policy"]["class_priorities"]:
        if c["class_id"] == "CUSTOMER_PRIORITY":
            c["priority"] = 200  # now outranks SAFETY_SANITATION(100)
    bad["conflict_policy_ref"]["digest"] = ConflictPolicy.model_validate(bad["conflict_policy"]).digest()
    bad["conflict_status"]["resolutions"][0]["dropped"] = "R-SETUP"
    _resign(bad, bundle["key"])
    res = verify_rulepack_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("strictly outrank" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A10 — infeasible incumbent_B inflates the KPI denominator
# ---------------------------------------------------------------------------
def test_infeasible_incumbent_b_rejected(bundle) -> None:
    inst = bundle["active_instance"]
    degenerate = Plan(
        assignments={o.op_id: (max(0, inst.horizon - o.duration), o.eligible_machines[0])
                     for o in inst.operations},
        cleanouts=[],
    )
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["incumbent_b"] = degenerate.model_dump(mode="json")
    _resign(bad_pc, bundle["key"])
    res = verify_plan_cert(bad_pc, bundle["key"].public_key())
    assert res.ok is False
    assert any("feasible baseline" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A11 — a degenerate (shape-invalid) incumbent_A strawman
# ---------------------------------------------------------------------------
def test_malformed_incumbent_a_rejected(bundle) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    a = dict(bad_pc["incumbent_a"]["assignments"])
    a["GHOST-OP"] = [0, "Filler-1"]   # an op not in the instance -> shape-invalid
    bad_pc["incumbent_a"]["assignments"] = a
    _resign(bad_pc, bundle["key"])
    res = verify_plan_cert(bad_pc, bundle["key"].public_key())
    assert res.ok is False
    assert any("well-formed" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A12 — fabricate the cited SOP clause at the root (rule provenance)
# ---------------------------------------------------------------------------
def test_forged_sop_clause_rejected(bundle) -> None:
    bad = copy.deepcopy(bundle["rp"])
    for r in bad["rules"]:
        if r["rule_id"] == "R-6.1-NIGHT-CLEANOUT":
            r["provenance"]["spans"][0]["quoted_text"] = \
                "night cleanouts cause a federal recall and criminal liability"
    bad["rule_pack_digest"] = _rp_digest(bad)
    _resign(bad, bundle["key"])
    res = verify_rulepack_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("not present in the SOP" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# Key pinning — a cert re-signed under ANY other key is rejected when authenticated
# ---------------------------------------------------------------------------
def test_pinned_wrong_key_rejected(bundle) -> None:
    other = new_signing_key()
    assert verify_plan_cert(bundle["pc"], other.public_key()).ok is False
    assert verify_rulepack_cert(bundle["rp"], other.public_key()).ok is False
    # ...but the genuine signer key authenticates
    assert verify_plan_cert(bundle["pc"], bundle["key"].public_key()).ok


# ---------------------------------------------------------------------------
# Policy pinning — an embedded policy not in the trusted store is rejected at the root
# ---------------------------------------------------------------------------
def test_untrusted_policy_rejected(bundle) -> None:
    assert verify_rulepack_cert(bundle["rp"], bundle["key"].public_key(),
                                trusted_policies=DEFAULT_TRUSTED_POLICIES).ok
    res = verify_rulepack_cert(bundle["rp"], bundle["key"].public_key(), trusted_policies=frozenset())
    assert res.ok is False
    assert any("trusted policy" in r for r in res.reasons)


def test_bundle_policy_ref_cross_check(bundle) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    for d in bad_pc["active_rule_set_for_plan"]["dropped"]:
        d["conflict_policy_ref"]["digest"] = "deadbeef"
    reasons = bundle_binding_reasons(bad_pc, bundle["rp"])
    assert any("different conflict policy" in r for r in reasons)


# ---------------------------------------------------------------------------
# A13 — record an auto-drop for a conflict that isn't realizable on the instance
# ---------------------------------------------------------------------------
def test_unrealizable_conflict_drop_rejected(bundle) -> None:
    bad = copy.deepcopy(bundle["rp"])
    # make every job Allergen -> there is no non-allergen follower, so the R-4.4 permission's
    # scope is no longer realizable and detection would have produced NO conflict at all.
    for j in bad["instance"]["jobs"]:
        j["family"] = "Allergen"
    bad["instance_ref"]["instance_digest"] = digest_of(bad["instance"])
    _resign(bad, bundle["key"])
    res = verify_rulepack_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("not realizable" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A14 — swap a KPI value AND its function_id so a naive recompute would "agree"
# (Task 11: verify re-derives every KPI from the STATIC KPI_REGISTRY fn — never a
# cert field — and binds the cert's (function_id, function_version,
# input_schema_digest) triple to the registry's, so a fn rename cannot launder a
# tampered KPI value).
# ---------------------------------------------------------------------------
def test_forged_kpi_function_id_is_rejected(bundle) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["kpi_vs_incumbent_B"]["weighted_tardiness"]["incumbent_b"] = 1
    bad_pc["kpi_function_refs"]["weighted_tardiness"]["function_id"] = "mfg:fabricated"
    _resign(bad_pc, bundle["key"])
    res = verify_plan_cert(bad_pc, bundle["key"].public_key())
    assert res.ok is False
    assert any("kpi" in r.lower() for r in res.reasons)


# ---------------------------------------------------------------------------
# A15 — cite a NON-gotcha hard-rule failure as the incumbent-A gotcha (Task 11:
# verify pins incumbent_A_failure.violated_rule_ref to the domain verifier's
# gotcha_rule_id() — the violations[0] fallback is removed, so an arbitrary hard
# failure cannot pose as the hero gotcha).
# ---------------------------------------------------------------------------
def test_nongotcha_incumbent_a_failure_rejected(bundle) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["incumbent_A_failure"]["violated_rule_ref"] = "R-SETUP"  # a real rule, but not the gotcha
    _resign(bad_pc, bundle["key"])
    res = verify_plan_cert(bad_pc, bundle["key"].public_key())
    assert res.ok is False
    assert any("gotcha" in r.lower() or "incumbent_A_failure" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A16 — the foreign-rule guard must FAIL CLOSED on a rule dict missing rule_id.
# A re-signed cert whose embedded ``rules`` carries a dict with NO ``rule_id``
# (-> None) alongside a string foreign id used to crash the guard's
# ``sorted([None, "x"])`` with a TypeError (a crash, not a clean rejection). The
# guard now coerces to str: the None/missing id is itself foreign, so both the
# plan-cert and rule-pack verifiers return ok=False with a reason and DO NOT raise.
# ---------------------------------------------------------------------------
def test_missing_rule_id_is_foreign_not_crash_plan_cert(bundle) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["rules"] = [*bad_pc["rules"],
                       {"kind": "no_overlap"},                    # missing rule_id -> None
                       {"rule_id": "dc:foreign-rule", "kind": "no_overlap"}]
    _resign(bad_pc, bundle["key"])
    res = verify_plan_cert(bad_pc, bundle["key"].public_key())  # must NOT raise
    assert res.ok is False
    assert any("foreign rule_id" in r for r in res.reasons)


def test_missing_rule_id_is_foreign_not_crash_rulepack_cert(bundle) -> None:
    bad_rp = copy.deepcopy(bundle["rp"])
    bad_rp["rules"] = [*bad_rp["rules"],
                       {"kind": "no_overlap"},                    # missing rule_id -> None
                       {"rule_id": "dc:foreign-rule", "kind": "no_overlap"}]
    _resign(bad_rp, bundle["key"])
    res = verify_rulepack_cert(bad_rp, bundle["key"].public_key())  # must NOT raise
    assert res.ok is False
    assert any("foreign rule_id" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A17 — re-label the (signed) objective_labels to a domain the cert never
# optimized (Task 3: objective_labels is a SIGNED, per-domain claim that
# ``verify`` RE-DERIVES from the domain verifier — a signed claim that isn't
# re-derived is forgeable under this project's re-sign threat model. The render
# reads these labels, so a fabricated pair would mislabel the headline objective
# in the demo). Parametrized over domain via the ``bundle`` fixture.
# ---------------------------------------------------------------------------
def test_forged_objective_labels_is_rejected(bundle) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["claims"]["optimality"]["objective_labels"]["value"] = ["cost_savings", "throughput"]
    _resign(bad_pc, bundle["key"])
    res = verify_plan_cert(bad_pc, bundle["key"].public_key())
    assert res.ok is False
    assert any("objective_labels" in r for r in res.reasons)
