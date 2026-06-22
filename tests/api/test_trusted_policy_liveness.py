"""Task 4 — the facade resolves the LIVE trusted-policy set per call.

``api.certify`` / ``api.verify`` must pass ``trusted_policies=None`` to
``verify_rulepack_cert`` so the trust store is resolved by re-scanning the
REGISTERED domains (``trusted_policy_set()``) at verify time — NOT the
import-time snapshot ``DEFAULT_TRUSTED_POLICIES`` captured when ``api`` was
first imported.

The showstopper this closes: a domain registered AFTER ``api`` import (the
datacenter track appends itself post-fork) contributes a safety-preserving
policy. Under the import-time snapshot a cert signed under that later policy
would be rejected at the root ("not in the trusted policy set") purely by import
ORDER. Resolving the live set per call admits it. With only manufacturing
registered the live set equals the snapshot, so manufacturing is byte-identical.
"""
from __future__ import annotations

import feasible.domains.manufacturing  # noqa: F401  (registers the manufacturing domain)
from feasible import api
from feasible.canon.canonical import new_signing_key
from feasible.conflict.policy import (
    DEFAULT_TRUSTED_POLICIES,
    ClassPriority,
    ConflictPolicy,
    SAFETY_CLASS_ID,
    trusted_policy_set,
)
from feasible.domains import _DOMAINS, register_domain


# A safety-preserving policy for a fake domain registered AFTER `api` import.
# It passes `no_permission_outranks_safety` (the safety class is top-priority),
# so the per-domain registry admits it — yet it is absent from the import-time
# snapshot, exactly modelling a track-added domain.
_LATER_POLICY = ConflictPolicy(
    policy_id="later_domain_v1",
    version=1,
    class_priorities=[
        ClassPriority(class_id=SAFETY_CLASS_ID, human_label="Safety", priority=100),
        ClassPriority(class_id="EFFICIENCY", human_label="Efficiency", priority=10),
    ],
)


class _LaterDomain:
    """A minimal safety-preserving fake domain — only ``policy()`` is exercised
    by the trusted-policy registry (``trusted_policy_set`` reads ``domain.policy()``)."""

    domain_id = "later_domain"
    display_name = "Later Domain"

    def policy(self):
        return _LATER_POLICY


def _register_later_domain():
    register_domain("later_domain", _LaterDomain(), object())


def _unregister_later_domain():
    _DOMAINS.pop("later_domain", None)


def test_later_policy_absent_from_import_snapshot_but_in_live_set():
    """Precondition: the later policy is NOT in the import-time snapshot but IS in
    the live ``trusted_policy_set()`` once its domain registers — so a facade that
    consults the snapshot would reject it purely by import order."""
    ref = (_LATER_POLICY.policy_id, _LATER_POLICY.digest())
    assert ref not in DEFAULT_TRUSTED_POLICIES  # the snapshot predates registration
    _register_later_domain()
    try:
        assert ref in trusted_policy_set()  # the live set admits it
    finally:
        _unregister_later_domain()


def _captured_store_from_verify(monkeypatch) -> "set[tuple[str, str]]":
    """Run ``api.verify`` on a manufacturing bundle, spying on
    ``verify_rulepack_cert`` to capture the EFFECTIVE trusted-policy store it
    resolves (``trusted_policies`` arg, or the live set when that arg is ``None``).
    """
    key = new_signing_key()
    result = api.certify("manufacturing", signer_key=key)

    captured: dict[str, frozenset] = {}
    import feasible.api as api_mod
    original = api_mod.verify_rulepack_cert

    def spy(cert, public_key, trusted_policies=None):
        store = trusted_policy_set() if trusted_policies is None else trusted_policies
        captured["store"] = store
        return original(cert, public_key, trusted_policies=trusted_policies)

    monkeypatch.setattr(api_mod, "verify_rulepack_cert", spy)
    view = api.verify(result.plan_cert, result.rule_pack_cert, signer_key=key)
    assert view.ok, view.reasons
    return captured["store"]


def test_api_verify_uses_live_trusted_policy_set(monkeypatch):
    """The store ``api.verify`` actually consults includes a domain registered
    AFTER ``api`` import — proving it resolves the live set, not the snapshot.
    Today this fails because ``api`` passes ``DEFAULT_TRUSTED_POLICIES``."""
    _register_later_domain()
    try:
        store = _captured_store_from_verify(monkeypatch)
        ref = (_LATER_POLICY.policy_id, _LATER_POLICY.digest())
        assert ref in store, (
            "api.verify consulted the import-time snapshot, not the live "
            "trusted_policy_set(): a later domain's policy is excluded by import order"
        )
    finally:
        _unregister_later_domain()


def test_api_certify_uses_live_trusted_policy_set(monkeypatch):
    """``api.certify``'s internal TrustVector verify pass must ALSO resolve the
    live set (it calls ``verify_rulepack_cert`` to derive ``checker``)."""
    _register_later_domain()
    captured: dict[str, frozenset] = {}
    import feasible.api as api_mod
    original = api_mod.verify_rulepack_cert

    def spy(cert, public_key, trusted_policies=None):
        store = trusted_policy_set() if trusted_policies is None else trusted_policies
        captured["store"] = store
        return original(cert, public_key, trusted_policies=trusted_policies)

    monkeypatch.setattr(api_mod, "verify_rulepack_cert", spy)
    try:
        key = new_signing_key()
        result = api.certify("manufacturing", signer_key=key)
        assert result.trust_vector.checker == "pass"
        ref = (_LATER_POLICY.policy_id, _LATER_POLICY.digest())
        assert ref in captured["store"], (
            "api.certify consulted the import-time snapshot, not the live set"
        )
    finally:
        _unregister_later_domain()


def test_manufacturing_byte_identical_live_equals_snapshot_when_alone():
    """With ONLY manufacturing registered the live set equals the snapshot — so
    the facade change is byte-identical for the manufacturing path."""
    # no later domain registered here
    assert trusted_policy_set() == DEFAULT_TRUSTED_POLICIES
