"""Frozen-schema contract test for the domain-agnostic facade (Task 12).

``feasible.api`` is the SINGLE two-cert orchestration the CLI and the three forked
tracks (console / datacenter / gemini) call. This pins the ``CertifyResult`` /
``TrustVector`` JSON shape and asserts the facade-built certs round-trip through
``api.verify`` cleanly — and that the ``TrustVector`` reflects the verify reasons
(self-described without a pinned key, authenticated with one).
"""
from __future__ import annotations

from feasible import api
from feasible.canon.canonical import new_signing_key
from feasible.domains.base import CertifyResult, ScenarioInfo, TrustVector, VerifyView


def test_list_scenarios_includes_manufacturing_first() -> None:
    # Task 9 appends datacenter to the facade scenario list; manufacturing stays
    # first (real data), datacenter follows (synthetic facility). Both are surfaced.
    scenarios = api.list_scenarios()
    ids = [s.domain_id for s in scenarios]
    assert ids[0] == "manufacturing"
    assert "datacenter" in ids
    assert all(isinstance(s, ScenarioInfo) for s in scenarios)
    assert scenarios[0].data == "real"


def test_certify_returns_frozen_certifyresult_that_verifies() -> None:
    key = new_signing_key()
    result = api.certify("manufacturing", signer_key=key)
    assert isinstance(result, CertifyResult)
    assert result.domain_id == "manufacturing"
    # the two facade-built certs must bind + verify cleanly through api.verify
    view = api.verify(result.plan_cert, result.rule_pack_cert, signer_key=key)
    assert isinstance(view, VerifyView)
    assert view.ok, view.reasons
    # the bundle binding is empty (no cross-cert mismatch)
    assert view.reasons == []


def test_trust_vector_signature_self_described_without_key() -> None:
    result = api.certify("manufacturing")  # no signer key -> ephemeral key, self-described
    tv = result.trust_vector
    assert isinstance(tv, TrustVector)
    assert tv.signature == "self_described"
    assert tv.checker == "pass"
    assert tv.data == "real"


def test_trust_vector_signature_authenticated_with_key() -> None:
    key = new_signing_key()
    result = api.certify("manufacturing", signer_key=key)
    # verifying WITH the pinned signer key authenticates the signature
    view = api.verify(result.plan_cert, result.rule_pack_cert, signer_key=key)
    assert view.trust_vector is not None
    assert view.trust_vector.signature == "authenticated"
    assert view.trust_vector.checker == "pass"

    # verifying WITHOUT a pinned key re-checks but cannot authenticate the signer
    view2 = api.verify(result.plan_cert, result.rule_pack_cert)
    assert view2.ok, view2.reasons
    assert view2.trust_vector is not None
    assert view2.trust_vector.signature == "self_described"
