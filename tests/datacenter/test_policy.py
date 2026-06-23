"""Task 8: DATACENTER_POLICY (redundancy floor IS the SAFETY_SANITATION class, B-3).

The frozen ``no_permission_outranks_safety`` guard keys ONLY on
``SAFETY_CLASS_ID == "SAFETY_SANITATION"``. So the N+1/2N redundancy floor's
``resolution_class`` must literally BE ``SAFETY_SANITATION`` (not a bespoke
``REDUNDANCY`` id, which the guard would never inspect — a policy demoting
redundancy below acceleration would then be silently admitted). These tests pin:

  * ``no_permission_outranks_safety(DATACENTER_POLICY) is True``;
  * ``DATACENTER_POLICY`` is admitted into ``trusted_policy_set()`` once the
    datacenter domain registers;
  * the redundancy (``SAFETY_SANITATION``) priority strictly exceeds
    ``ACCELERATION`` + ``EFFICIENCY``;
  * (B-3 admission-failure) an inverted policy that DEMOTES redundancy below
    acceleration FAILS admission (caught precisely because the floor IS the
    safety class).
"""
from __future__ import annotations

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
from feasible.conflict.policy import (
    ClassPriority,
    ConflictPolicy,
    no_permission_outranks_safety,
    trusted_policy_set,
)
from feasible.conflict.policy import DATACENTER_POLICY


def test_datacenter_policy_protects_safety():
    assert no_permission_outranks_safety(DATACENTER_POLICY) is True


def test_datacenter_policy_in_trusted_set():
    s = trusted_policy_set()
    assert (DATACENTER_POLICY.policy_id, DATACENTER_POLICY.digest()) in s


def test_redundancy_strictly_outranks_acceleration_and_efficiency():
    safety = DATACENTER_POLICY.priority("SAFETY_SANITATION")
    accel = DATACENTER_POLICY.priority("ACCELERATION")
    eff = DATACENTER_POLICY.priority("EFFICIENCY")
    assert safety is not None and accel is not None and eff is not None
    assert safety > accel
    assert safety > eff


def test_inverted_redundancy_policy_fails_admission():
    inverted = ConflictPolicy(policy_id="dc_inverted", version=1, class_priorities=[
        ClassPriority(class_id="SAFETY_SANITATION", human_label="redundancy floor", priority=40),
        ClassPriority(class_id="ACCELERATION", human_label="accel", priority=90),  # outranks the floor!
    ])
    # the guard keys on SAFETY_SANITATION, so demoting the redundancy floor below
    # acceleration is CAUGHT (this is exactly why the floor's class IS SAFETY_SANITATION, B-3)
    assert no_permission_outranks_safety(inverted) is False
    assert (inverted.policy_id, inverted.digest()) not in trusted_policy_set()
