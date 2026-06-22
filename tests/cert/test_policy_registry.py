"""Task 8 — per-domain trusted-policy registry + the no-auto-drop-safety guard.

``DEFAULT_TRUSTED_POLICIES`` is no longer a hand-written global frozenset; it is
``trusted_policy_set()``, assembled from the policies of the *registered* domains.
Adding a domain policy is therefore a reviewed, tested act: the guard test asserts
that under each registered domain's policy NO permission class can ever strictly
outrank a safety obligation (so a safety obligation can never be the AUTO-dropped
side of a conflict — it must ESCALATE). This generalizes the manufacturing
"safety wins / permission dropped" invariant to every loaded domain.
"""
from __future__ import annotations

from feasible.conflict.policy import (
    MANUFACTURING_POLICY,
    no_permission_outranks_safety,
    trusted_policy_set,
)


def test_trusted_policy_set_includes_registered_manufacturing_policy():
    # importing the registry-bearing modules registers the manufacturing domain
    import feasible.domains.manufacturing  # noqa: F401

    s = trusted_policy_set()
    assert (MANUFACTURING_POLICY.policy_id, MANUFACTURING_POLICY.digest()) in s


def test_no_permission_auto_drops_safety():
    # under MANUFACTURING_POLICY there is no class that strictly outranks
    # SAFETY_SANITATION, so a safety obligation can never be auto-dropped.
    assert no_permission_outranks_safety(MANUFACTURING_POLICY) is True


def test_every_registered_domain_policy_protects_safety():
    import feasible.domains.manufacturing  # noqa: F401
    from feasible.domains import _DOMAINS

    seen = 0
    for _domain_id, (domain, _verifier) in _DOMAINS.items():
        policy = domain.policy()
        if policy is None:
            continue
        seen += 1
        assert no_permission_outranks_safety(policy) is True, (
            f"{_domain_id} policy lets a permission class outrank SAFETY_SANITATION"
        )
    assert seen >= 1  # at least manufacturing's policy is registered
