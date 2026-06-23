"""Forge-resistance suite — each test reconstructs an attack the adversarial review
found, RE-SIGNS the tampered certificate with a valid key (so the signature itself
always passes), and asserts the offline verifier now REJECTS it.

The threat model is the project's own: a skeptic who does NOT trust the signer
re-checks the cert offline. Anything the verifier does not RE-DERIVE, a self-signed
cert can fabricate — so every claim a demo leans on must be machine-checked here.

The suite is parametrized over the registered DOMAINS (``manufacturing`` +
``datacenter``). Every attack runs against the bundle the FACADE builds — the same
two-cert orchestration the CLI ships — so the forge-resistance guarantees are proven
over the production path, not a test-local reconstruction, for BOTH verticals.

Manufacturing-specific attacks (A1/A2/A3/A4/A5/A8/A9/A10/A11/A12/A13/A14/A15) read
their rule-ids / KPI key / instance mutations from the per-domain ``_ATTACK``
descriptor. **B-7: the manufacturing descriptor reproduces the CURRENT literal ids
BYTE-FOR-BYTE** (so the manufacturing assertions are unchanged and the manufacturing
oracle is unperturbed), and **each datacenter attack must reach the SAME verify
branch its manufacturing counterpart hits** — pinned by a per-attack reason-string
assertion (not merely "does not crash").
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


# ---------------------------------------------------------------------------
# Per-domain attack descriptor (B-7). Each domain supplies the obligation/
# permission ids, the safety/conflict-only permission, the gotcha + a non-gotcha
# rule, the KPI key, the SOP-anchored rule, plus three domain-aware MUTATIONS (the
# A4 instance-swap, the A10 genuinely-infeasible incumbent_b, and the A13 make-
# unrealizable). The MANUFACTURING descriptor reproduces the CURRENT literal ids
# byte-for-byte, so the manufacturing assertions below are byte-identical.
# ---------------------------------------------------------------------------


def _mfg_a10_incumbent_b(inst) -> Plan:
    # the degenerate FJSP plan that drives every op to the END of the horizon:
    # shape-valid but NOT feasible (it violates a hard rule), so the "feasible
    # baseline" guard must reject it as a KPI denominator. (Current literal builder.)
    return Plan(
        assignments={o.op_id: (max(0, inst.horizon - o.duration), o.eligible_machines[0])
                     for o in inst.operations},
        cleanouts=[],
    )


def _dc_a10_incumbent_b(inst) -> Plan:
    # B-7/A10: a GENUINELY dc-INFEASIBLE incumbent_b — schedule the F1 cooling-path
    # maintenance task at start 0, so its [0,2) interval overlaps the posted
    # change-freeze (forbidden) window [0,2) on F1 -> a real dc:maintenance_window
    # breach (NOT a merely shape-valid plan that passes the checker). The "feasible
    # baseline" guard then rejects it as a KPI denominator.
    assignments: dict[str, tuple[int, str]] = {}
    for o in inst.operations:
        assignments[o.op_id] = (0, o.eligible_machines[0])
    return Plan(assignments=assignments, cleanouts=[])


def _mfg_a4_instance_swap(cert: dict) -> None:
    # a DIFFERENT instance under the same rule universe, kept self-consistent so the
    # plan cert verifies STANDALONE (the swap is catchable only cross-cert).
    cert["instance"]["horizon"] = 999999
    cert["instance_ref"]["instance_digest"] = digest_of(cert["instance"])


def _dc_a4_instance_swap(cert: dict) -> None:
    # B-7/A4: the dc convention copies ``horizon`` into the dc:redundancy_floor rule
    # params, so a swap that mutated ONLY instance.horizon would leave the rule's
    # horizon copy behind. RE-PACK the rule-embedded horizon together with
    # instance.horizon (keeping the objective + checker internally consistent), so the
    # plan cert verifies STANDALONE and the swap is catchable ONLY cross-cert via the
    # bundle's instance-binding mismatch — exactly the manufacturing A4 shape.
    cert["instance"]["horizon"] = 999999
    for r in cert["rules"]:
        if "horizon" in r.get("params", {}):
            r["params"]["horizon"] = 999999
    cert["instance_ref"]["instance_digest"] = digest_of(cert["instance"])


def _mfg_a13_make_unrealizable(cert: dict) -> None:
    # make every job Allergen -> there is no non-allergen follower, so the R-4.4
    # permission's scope is no longer realizable and detection would have produced NO
    # conflict at all. Only the instance is mutated (rules untouched).
    for j in cert["instance"]["jobs"]:
        j["family"] = "Allergen"
    cert["instance_ref"]["instance_digest"] = digest_of(cert["instance"])


def _dc_a13_make_unrealizable(cert: dict) -> None:
    # B-7/A13: re-scope the floored group so the dc:accel-skip-redundancy permission
    # (scope units F1/F2/F3) names NO member of any active dc:redundancy_floor group ->
    # the recorded auto-drop cites a conflict that is no longer realizable on the
    # instance. The dc "instance" topology lives in the rule params (delta #1), so the
    # rule body changes; recompute rule_pack_digest to keep the cert self-consistent
    # (the realizability replay, not a digest mismatch, is what must reject it).
    for r in cert["rules"]:
        if r["rule_id"] == "dc:redundancy_floor":
            r["params"]["units"] = ["X1", "X2", "X3"]
    cert["rule_pack_digest"] = _rp_digest(cert)


_ATTACK: dict[str, dict] = {
    "manufacturing": {
        # A1 — forge an AUTO drop of a lower HARD rule (neither a permission).
        "a1_obligation": "R-SETUP", "a1_permission": "R-MAINT", "a1_dropped": "R-MAINT",
        # A2/A3 — a HARD plan rule to silently omit / weaken.
        "a2_omit": "R-SETUP", "a3_weaken": "R-SETUP",
        # A5/A14 — the KPI key whose value/function-id is forged.
        "kpi_key": "weighted_tardiness",
        # A8 — class-swap: demote the safety obligation, promote the permission.
        "a8_obligation": "R-SETUP", "a8_permission": "R-4.4",
        "a8_safety_demote": "EFFICIENCY", "a8_perm_promote": "SAFETY_SANITATION",
        # A9 — policy-inversion: the class to lift over safety + the rule it then drops.
        "a9_invert_class": "CUSTOMER_PRIORITY", "a9_dropped": "R-SETUP",
        # A10 — a genuinely-infeasible incumbent_b builder (the KPI denominator).
        "a10_incumbent_b": _mfg_a10_incumbent_b,
        # A11 — a filler machine for the ghost (shape-invalid) incumbent_a op.
        "a11_filler": "Filler-1",
        # A12 — a rule whose primary_normative SOP quote is forged.
        "a12_sop_rule": "R-6.1-NIGHT-CLEANOUT",
        # A15 — a real NON-gotcha hard rule posing as the hero gotcha.
        "a15_nongotcha": "R-SETUP",
        # A4/A13 — domain-aware instance mutations.
        "a4_instance_swap": _mfg_a4_instance_swap,
        "a13_make_unrealizable": _mfg_a13_make_unrealizable,
    },
    "datacenter": {
        # A1 — two HARD PLAN_CONSTRAINT rules; the lower (dc:maintenance_window) is the
        # forged AUTO-drop. Neither is a CONFLICT_ONLY permission -> pairing invariant.
        "a1_obligation": "dc:redundancy_floor", "a1_permission": "dc:maintenance_window",
        "a1_dropped": "dc:maintenance_window",
        "a2_omit": "dc:redundancy_floor", "a3_weaken": "dc:redundancy_floor",
        "kpi_key": "stranded_power",
        # A8 — the floor (SAFETY_SANITATION, B-3) vs the pinned acceleration permission.
        "a8_obligation": "dc:redundancy_floor", "a8_permission": "dc:accel-skip-redundancy",
        "a8_safety_demote": "EFFICIENCY", "a8_perm_promote": "SAFETY_SANITATION",
        # A9 — lift ACCELERATION over the floor, then drop the floor.
        "a9_invert_class": "ACCELERATION", "a9_dropped": "dc:redundancy_floor",
        "a10_incumbent_b": _dc_a10_incumbent_b,
        "a11_filler": "F1",
        "a12_sop_rule": "dc:redundancy_floor",
        "a15_nongotcha": "dc:power_cap",
        "a4_instance_swap": _dc_a4_instance_swap,
        "a13_make_unrealizable": _dc_a13_make_unrealizable,
    },
}


@pytest.fixture(scope="module", params=["manufacturing", "datacenter"])
def domain_id(request):
    return request.param


@pytest.fixture(scope="module")
def attack(domain_id):
    return _ATTACK[domain_id]


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
def test_forged_conflict_cannot_drop_hard_rule(bundle, attack) -> None:
    bad = copy.deepcopy(bundle["rp"])
    # name two HARD plan rules (neither a permission) and "auto-drop" the lower one.
    # The priority direction check may be satisfied (dropped == lower), so ONLY the
    # pairing invariant (the dropped side must be a CONFLICT_ONLY PERMISSION whose
    # target_rule is the obligation) can catch this.
    bad["conflict_status"]["resolutions"] = [{
        "obligation": attack["a1_obligation"], "permission": attack["a1_permission"],
        "resolution_mode": "AUTO_BY_POLICY", "dropped": attack["a1_dropped"],
        "rationale": "forged", "z3_core": [],
    }]
    _resign(bad, bundle["key"])
    res = verify_rulepack_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("PERMISSION" in r or "target obligation" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A2 — a plan cert silently OMITS a hard rule from its active set
# ---------------------------------------------------------------------------
def test_bundle_catches_silently_omitted_hard_rule(bundle, attack) -> None:
    omit = attack["a2_omit"]
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["rules"] = [r for r in bad_pc["rules"] if r["rule_id"] != omit]
    bad_pc["active_rule_set_for_plan"]["active_rule_ids"] = [
        x for x in bad_pc["active_rule_set_for_plan"]["active_rule_ids"] if x != omit
    ]
    reasons = bundle_binding_reasons(bad_pc, bundle["rp"])
    assert any("universe minus auto-drops" in r or "active set" in r for r in reasons)


# ---------------------------------------------------------------------------
# A3 — a plan cert keeps a rule's id but WEAKENS its body
# ---------------------------------------------------------------------------
def test_bundle_catches_weakened_rule_body(bundle, attack) -> None:
    weaken = attack["a3_weaken"]
    bad_pc = copy.deepcopy(bundle["pc"])
    for r in bad_pc["rules"]:
        if r["rule_id"] == weaken:
            r["params"] = {**r.get("params", {}), "sabotage": True}
    reasons = bundle_binding_reasons(bad_pc, bundle["rp"])
    assert any("differs from the certified universe rule body" in r for r in reasons)


# ---------------------------------------------------------------------------
# A4 — a plan is certified over a DIFFERENT instance under the same rule universe
# ---------------------------------------------------------------------------
def test_instance_swap_passes_standalone_but_bundle_binds(bundle, attack) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    attack["a4_instance_swap"](bad_pc)                 # a different instance, kept self-consistent
    _resign(bad_pc, bundle["key"])
    # standalone the plan cert is internally consistent (the swap is only catchable cross-cert)
    assert verify_plan_cert(bad_pc, bundle["key"].public_key()).ok
    reasons = bundle_binding_reasons(bad_pc, bundle["rp"])
    assert any("instance binding mismatch" in r for r in reasons)


# ---------------------------------------------------------------------------
# A5 — fabricate the "we beat the baseline" headline
# ---------------------------------------------------------------------------
def test_forged_kpi_is_rejected(bundle, attack) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["kpi_vs_incumbent_B"][attack["kpi_key"]]["incumbent_b"] = 999999
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
def test_class_swap_cannot_drop_hard_obligation(bundle, attack) -> None:
    bad = copy.deepcopy(bundle["rp"])
    for r in bad["rules"]:
        if r["rule_id"] == attack["a8_obligation"]:
            r["resolution_class"] = attack["a8_safety_demote"]     # demote the safety obligation
        elif r["rule_id"] == attack["a8_permission"]:
            r["resolution_class"] = attack["a8_perm_promote"]      # promote the permission
    bad["conflict_status"]["resolutions"] = [{
        "obligation": attack["a8_obligation"], "permission": attack["a8_permission"],
        "resolution_mode": "AUTO_BY_POLICY", "dropped": attack["a8_obligation"],
        "rationale": "forged", "z3_core": [],
    }]
    bad["rule_pack_digest"] = _rp_digest(bad)  # keep the digest self-consistent
    _resign(bad, bundle["key"])
    res = verify_rulepack_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("strictly outrank" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A9 — policy-inversion: rewrite the embedded ConflictPolicy so a lower class > safety
# ---------------------------------------------------------------------------
def test_policy_inversion_cannot_drop_hard_obligation(bundle, attack) -> None:
    bad = copy.deepcopy(bundle["rp"])
    for c in bad["conflict_policy"]["class_priorities"]:
        if c["class_id"] == attack["a9_invert_class"]:
            c["priority"] = 200  # now outranks SAFETY_SANITATION(100)
    bad["conflict_policy_ref"]["digest"] = ConflictPolicy.model_validate(bad["conflict_policy"]).digest()
    bad["conflict_status"]["resolutions"][0]["dropped"] = attack["a9_dropped"]
    _resign(bad, bundle["key"])
    res = verify_rulepack_cert(bad, bundle["key"].public_key())
    assert res.ok is False
    assert any("strictly outrank" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A10 — infeasible incumbent_B inflates the KPI denominator
# ---------------------------------------------------------------------------
def test_infeasible_incumbent_b_rejected(bundle, attack) -> None:
    inst = bundle["active_instance"]
    degenerate = attack["a10_incumbent_b"](inst)
    # B-7 PRECONDITION: the crafted incumbent_b must be GENUINELY infeasible under a
    # domain hard rule (not merely shape-valid) — otherwise the "feasible baseline"
    # guard would have nothing to reject and the attack would be a no-op.
    ir = FCIR.model_validate(
        {"rules": bundle["pc"]["rules"], "instance": bundle["pc"]["instance"],
         "domain_id": bundle["domain_id"]})
    assert check(degenerate, ir).passed is False
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["incumbent_b"] = degenerate.model_dump(mode="json")
    _resign(bad_pc, bundle["key"])
    res = verify_plan_cert(bad_pc, bundle["key"].public_key())
    assert res.ok is False
    assert any("feasible baseline" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A11 — a degenerate (shape-invalid) incumbent_A strawman
# ---------------------------------------------------------------------------
def test_malformed_incumbent_a_rejected(bundle, attack) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    a = dict(bad_pc["incumbent_a"]["assignments"])
    a["GHOST-OP"] = [0, attack["a11_filler"]]   # an op not in the instance -> shape-invalid
    bad_pc["incumbent_a"]["assignments"] = a
    _resign(bad_pc, bundle["key"])
    res = verify_plan_cert(bad_pc, bundle["key"].public_key())
    assert res.ok is False
    assert any("well-formed" in r for r in res.reasons)


# ---------------------------------------------------------------------------
# A12 — fabricate the cited SOP clause at the root (rule provenance)
# ---------------------------------------------------------------------------
def test_forged_sop_clause_rejected(bundle, attack) -> None:
    bad = copy.deepcopy(bundle["rp"])
    for r in bad["rules"]:
        if r["rule_id"] == attack["a12_sop_rule"]:
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
def test_unrealizable_conflict_drop_rejected(bundle, attack) -> None:
    bad = copy.deepcopy(bundle["rp"])
    # mutate the instance/topology so the dropped permission's scope is no longer
    # realizable -> detection would have produced NO conflict at all -> the recorded
    # auto-drop cites a non-realizable conflict and the realizability replay rejects.
    attack["a13_make_unrealizable"](bad)
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
def test_forged_kpi_function_id_is_rejected(bundle, attack) -> None:
    key = attack["kpi_key"]
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["kpi_vs_incumbent_B"][key]["incumbent_b"] = 1
    bad_pc["kpi_function_refs"][key]["function_id"] = "mfg:fabricated"
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
def test_nongotcha_incumbent_a_failure_rejected(bundle, attack) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["incumbent_A_failure"]["violated_rule_ref"] = attack["a15_nongotcha"]  # real rule, not the gotcha
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


# ---------------------------------------------------------------------------
# A18 — the disjoint_solver_corroboration verdict is SOLVER-REPORTED at EMIT (same
# trust class as tripwire_passed). verify is solver-free + cannot replay a Z3 search,
# so it does NOT re-derive the verdict. This test PINS that honesty: a re-signed cert
# tampering the verdict is NOT rejected by verify (it would be FALSE to claim
# otherwise), AND the trust_boundary DOCUMENTS the leaf as solver-reported /
# not-verify-re-derived — consistent with the existing tripwire/optimal_per_cpsat/
# gap_bps leaves. The honest analogue of the forgery suite: where A1-A17 prove verify
# REJECTS a tamper, A18 proves the project is HONEST that a solver-reported leaf is
# NOT verify-re-derived (it does not pretend a closed check exists). Parametrized over
# domain via the ``bundle`` fixture.
# ---------------------------------------------------------------------------
def test_disjoint_solver_corroboration_is_documented_solver_reported(bundle) -> None:
    bad_pc = copy.deepcopy(bundle["pc"])
    bad_pc["claims"]["optimality"]["disjoint_solver_corroboration"]["value"]["verdict"] = "refuted"
    _resign(bad_pc, bundle["key"])
    res = verify_plan_cert(bad_pc, bundle["key"].public_key())
    assert res.ok is True                                    # solver-reported: verify leaves it alone
    tb = bad_pc["trust_boundary"]["optimality"].lower()
    assert "solver-reported" in tb and ("not re-checked" in tb or "not re-derived" in tb)
    assert bad_pc["claims"]["optimality"]["disjoint_solver_corroboration"]["provenance"] == "solver"
