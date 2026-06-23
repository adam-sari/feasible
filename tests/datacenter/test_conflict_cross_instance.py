"""Design §4.4 cross-instance negative (Task 11): the datacenter conflict is
GROUNDED in the certified instance, not merely ASSERTED.

The honest datacenter rule-pack cert records an AUTO-drop of the
``dc:accel-skip-redundancy`` acceleration permission (the floor /
``SAFETY_SANITATION`` outranks ``ACCELERATION``). That auto-drop is only legitimate
because the permission's scope (group ``G1``, units ``F1/F2/F3``) is REALIZABLE on
the certified instance — i.e. it names real members of an ACTIVE
``dc:redundancy_floor`` group whose removal over the window could breach the floor.

This test re-signs the SAME recorded drop under a DIFFERENT datacenter instance —
one where the floored group has been re-scoped so it shares NO member with the
permission's scope. Under that instance the conflict ``detect_normative_conflicts``
would have produced NOTHING (the permission targets no real floored member), so the
recorded auto-drop is a fabricated governance narrative. ``verify_rulepack_cert``'s
realizability replay (``_scope_realizable`` -> ``DatacenterVerifier.conflict_realizable``)
must REJECT it with a "not realizable" reason — proving the conflict is grounded in
the certified instance, not asserted from the signer's word.
"""
from __future__ import annotations

import copy

from feasible import api
from feasible.canon.canonical import new_signing_key, public_key_hex, sign_dsse
from feasible.cert.plan_cert import rule_pack_digest
from feasible.cert.rulepack_cert import verify_rulepack_cert
from feasible.ir.domain import FCIR

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)


def _resign(cert: dict, key) -> dict:
    body = {k: v for k, v in cert.items() if k != "signature"}
    env = sign_dsse(body, key)
    env["public_key_hex"] = public_key_hex(key)
    cert["signature"] = env
    return cert


def _rp_digest(cert: dict) -> str:
    ir = FCIR.model_validate({"rules": cert["rules"], "instance": cert["instance"]})
    return rule_pack_digest(ir)


def test_honest_datacenter_conflict_is_realizable() -> None:
    """Sanity: the honest datacenter rule-pack cert verifies — its recorded
    acceleration-permission auto-drop IS realizable on the certified instance."""
    key = new_signing_key()
    rp = api.certify("datacenter", signer_key=key).rule_pack_cert
    res = verify_rulepack_cert(rp, key.public_key())
    assert res.ok, res.reasons
    # the recorded resolution is the floor-vs-acceleration auto-drop.
    resolutions = rp["conflict_status"]["resolutions"]
    assert any(r["permission"] == "dc:accel-skip-redundancy"
               and r["obligation"] == "dc:redundancy_floor"
               and r["resolution_mode"] == "AUTO_BY_POLICY"
               and r["dropped"] == "dc:accel-skip-redundancy"
               for r in resolutions)


def test_same_drop_under_different_instance_fails_realizability_replay() -> None:
    """The SAME dropped ``dc:accel-skip-redundancy`` permission, claimed under a
    DIFFERENT datacenter instance where the floored group shares NO member with the
    permission's scope, FAILS realizability replay in ``verify_rulepack_cert``."""
    key = new_signing_key()
    rp = api.certify("datacenter", signer_key=key).rule_pack_cert

    bad = copy.deepcopy(rp)
    # re-scope the floored group so NO member of the permission's scope (F1/F2/F3) is
    # a real installed member of any ACTIVE dc:redundancy_floor group -> the recorded
    # acceleration auto-drop cites a conflict that is no longer realizable on THIS
    # instance. (The dc topology lives in the rule params — delta #1 — so the
    # floored-group re-scope is the dc analogue of swapping the instance.)
    for r in bad["rules"]:
        if r["rule_id"] == "dc:redundancy_floor":
            r["params"]["units"] = ["Z1", "Z2", "Z3"]
    # keep the cert internally self-consistent so the rejection is the realizability
    # replay (NOT a digest mismatch).
    bad["rule_pack_digest"] = _rp_digest(bad)
    _resign(bad, key)

    res = verify_rulepack_cert(bad, key.public_key())
    assert res.ok is False
    assert any("not realizable" in r for r in res.reasons), res.reasons
