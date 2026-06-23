"""Task 9: the datacenter scenario emits + verifies a REAL two-cert artifact through
the SINGLE frozen facade orchestration (``feasible.api``).

``api.certify("datacenter")`` runs the SAME branch-free loop the manufacturing path
runs (govern the extracted pack via the ``Domain.govern`` seam, emit the Rule-Pack
Cert over the universe, solve the active set via the ``Domain.solve`` seam — which
sets the REAL ``(stranded_power_kw, makespan)`` objective — emit the Plan Cert,
bind). ``api.verify`` re-checks the bundle offline (solver-free + LLM-free) and the
``TrustVector`` reflects the verify reasons + the domain's HONEST synthetic flag.

There is NO ``if domain_id == "datacenter"`` branch in ``certify`` — the datacenter
domain plugs in entirely behind the Spec 0.5 T6/T7/T8 seams.
"""
from __future__ import annotations

from feasible import api
from feasible.canon.canonical import new_signing_key


def test_datacenter_certify_produces_verifiable_bundle() -> None:
    key = new_signing_key()
    result = api.certify("datacenter", signer_key=key)
    view = api.verify(result.plan_cert, result.rule_pack_cert, signer_key=key)
    assert view.ok, view.reasons
    assert view.trust_vector.data == "synthetic"        # honest synthetic flag
    assert view.trust_vector.signature == "authenticated"
    assert view.trust_vector.signer_note                # Spec 0.5 T8 canonical sentence (non-empty)
    # the gotcha is the redundancy floor
    assert result.plan_cert["incumbent_A_failure"]["violated_rule_ref"] == "dc:redundancy_floor"
    # the signed objective labels are the REAL datacenter ones (Spec 0.5 T3)
    assert result.plan_cert["claims"]["optimality"]["objective_labels"]["value"] == ["stranded_power_kw", "makespan"]
    # bundle binds with empty reasons
    from feasible.cert.rulepack_cert import bundle_binding_reasons
    assert bundle_binding_reasons(result.plan_cert, result.rule_pack_cert) == []


def test_datacenter_listed_in_scenarios() -> None:
    ids = [s.domain_id for s in api.list_scenarios()]
    assert "datacenter" in ids and "manufacturing" in ids
