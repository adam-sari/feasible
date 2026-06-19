from __future__ import annotations

import pytest

from feasible.canon.canonical import (
    FloatInPayloadError,
    append_event,
    canonicalize,
    digest_of,
    merkle_root,
    new_signing_key,
    public_key_from_hex,
    public_key_hex,
    sha256_hex,
    sign_dsse,
    verify_chain,
    verify_dsse,
)
from feasible.conflict.policy import MANUFACTURING_POLICY, ConflictPolicy


def test_determinism_same_bytes() -> None:
    obj = {"b": 2, "a": 1, "nested": {"y": [1, 2, 3], "x": "hi"}}
    assert canonicalize(obj) == canonicalize(obj)


def test_key_order_independence() -> None:
    a = {"a": 1, "b": 2, "c": 3}
    b = {"c": 3, "b": 2, "a": 1}
    assert canonicalize(a) == canonicalize(b)


def test_compact_sorted_form() -> None:
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_float_rejected() -> None:
    with pytest.raises(FloatInPayloadError):
        canonicalize({"x": 1.5})
    with pytest.raises(FloatInPayloadError):
        canonicalize({"nested": [1, 2, 3.0]})


def test_nfc_equivalence() -> None:
    # "é" as single codepoint (NFC) vs "e" + combining acute (NFD) -> same hash.
    nfc = {"name": "café"}
    nfd = {"name": "café"}
    assert canonicalize(nfc) == canonicalize(nfd)


def test_sha256_hex_known() -> None:
    assert sha256_hex(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_ledger_chain_and_verify() -> None:
    events: list = []
    events = append_event(events, {"event": "extracted", "rule": "R-6.1-NIGHT-CLEANOUT"})
    events = append_event(events, {"event": "approved", "rule": "R-6.1-NIGHT-CLEANOUT"})
    assert len(events) == 2
    assert events[0].prev_hash == "0" * 64
    assert events[1].prev_hash == events[0].event_hash
    assert verify_chain(events) is True


def test_ledger_tamper_detected() -> None:
    events: list = []
    events = append_event(events, {"event": "a"})
    events = append_event(events, {"event": "b"})
    events[0].payload["event"] = "tampered"
    assert verify_chain(events) is False


def test_merkle_deterministic_and_order_sensitive() -> None:
    e1: list = []
    e1 = append_event(e1, {"x": 1})
    e1 = append_event(e1, {"x": 2})
    e2: list = []
    e2 = append_event(e2, {"x": 1})
    e2 = append_event(e2, {"x": 2})
    assert merkle_root(e1) == merkle_root(e2)
    # different order -> different root
    e3: list = []
    e3 = append_event(e3, {"x": 2})
    e3 = append_event(e3, {"x": 1})
    assert merkle_root(e3) != merkle_root(e1)


def test_dsse_sign_verify_roundtrip() -> None:
    key = new_signing_key()
    env = sign_dsse({"claim": "feasible", "objective": [12, 34]}, key)
    assert verify_dsse(env, key.public_key()) is True


def test_dsse_tamper_fails() -> None:
    key = new_signing_key()
    env = sign_dsse({"claim": "feasible"}, key)
    import base64

    body = bytearray(base64.b64decode(env["payload"]))
    body[5] ^= 0x01
    env["payload"] = base64.b64encode(bytes(body)).decode()
    assert verify_dsse(env, key.public_key()) is False


def test_dsse_wrong_key_fails() -> None:
    key = new_signing_key()
    other = new_signing_key()
    env = sign_dsse({"claim": "feasible"}, key)
    assert verify_dsse(env, other.public_key()) is False


def test_public_key_hex_roundtrip() -> None:
    key = new_signing_key()
    hexpk = public_key_hex(key)
    recovered = public_key_from_hex(hexpk)
    env = sign_dsse({"x": 1}, key)
    assert verify_dsse(env, recovered) is True


def test_conflict_policy_authority() -> None:
    p = MANUFACTURING_POLICY
    assert p.priority("SAFETY_SANITATION") == 100
    assert p.priority("CUSTOMER_PRIORITY") == 50
    assert p.priority("NOT_A_CLASS") is None
    assert "SAFETY_SANITATION" in p.class_ids()
    assert p.label("SAFETY_SANITATION").startswith("Safety")


def test_conflict_policy_digest_stable() -> None:
    assert MANUFACTURING_POLICY.digest() == MANUFACTURING_POLICY.digest()
    d1 = MANUFACTURING_POLICY.digest()
    p2 = ConflictPolicy.model_validate(MANUFACTURING_POLICY.model_dump())
    assert p2.digest() == d1


def test_digest_of_helper() -> None:
    assert digest_of({"a": 1}) == sha256_hex(b'{"a":1}')
