"""Deterministic serialization + hashing + ledger + DSSE/Ed25519 signing.

Determinism is sacred (it is what makes a certificate independently
re-checkable offline):
  * JCS-style canonical JSON: sorted keys, compact separators, UTF-8.
  * NO floats in any hashed payload (integer timeline + integer objective).
  * NFC-normalize every string before hashing.
  * Merkle / ledger leaves are taken in chained replay order (never sorted).
"""
from __future__ import annotations

import base64
import hashlib
import json
import unicodedata
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, Field

PAYLOAD_TYPE = "application/vnd.feasible.cert+json"
ZERO_HASH = "0" * 64


class FloatInPayloadError(ValueError):
    """Raised when a float reaches a hashed payload (would break determinism)."""


def _nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


def _enc_str(s: str) -> str:
    return json.dumps(_nfc(s), ensure_ascii=False, separators=(",", ":"))


def _canon(obj: Any) -> str:
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if obj is None:
        return "null"
    if isinstance(obj, float):
        raise FloatInPayloadError(f"float in hashed payload: {obj!r}")
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, str):
        return _enc_str(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_canon(x) for x in obj) + "]"
    if isinstance(obj, dict):
        items = sorted((_nfc(str(k)), v) for k, v in obj.items())
        return "{" + ",".join(_enc_str(k) + ":" + _canon(v) for k, v in items) + "}"
    raise TypeError(f"non-canonicalizable type: {type(obj).__name__}")


def canonicalize(obj: Any) -> bytes:
    """Canonical UTF-8 bytes for a dict / BaseModel (raises on any float)."""
    if isinstance(obj, BaseModel):
        obj = obj.model_dump(mode="json")
    return _canon(obj).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def digest_of(obj: Any) -> str:
    return sha256_hex(canonicalize(obj))


# --------------------------------------------------------------------------- #
# Hash-chained ledger
# --------------------------------------------------------------------------- #
class LedgerEvent(BaseModel):
    seq: int
    prev_hash: str
    payload: dict
    event_hash: str


def append_event(events: list[LedgerEvent], payload: dict) -> list[LedgerEvent]:
    seq = len(events)
    prev_hash = events[-1].event_hash if events else ZERO_HASH
    event_hash = sha256_hex(
        canonicalize({"seq": seq, "prev_hash": prev_hash, "payload": payload})
    )
    return [*events, LedgerEvent(seq=seq, prev_hash=prev_hash, payload=payload, event_hash=event_hash)]


def verify_chain(events: list[LedgerEvent]) -> bool:
    prev = ZERO_HASH
    for i, e in enumerate(events):
        if e.seq != i or e.prev_hash != prev:
            return False
        expect = sha256_hex(
            canonicalize({"seq": e.seq, "prev_hash": e.prev_hash, "payload": e.payload})
        )
        if expect != e.event_hash:
            return False
        prev = e.event_hash
    return True


def merkle_root(events: list[LedgerEvent]) -> str:
    """Binary Merkle root over event hashes in chained (replay) order."""
    nodes = [bytes.fromhex(e.event_hash) for e in events]
    if not nodes:
        return sha256_hex(b"")
    while len(nodes) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            nxt.append(hashlib.sha256(b"\x01" + left + right).digest())
        nodes = nxt
    return nodes[0].hex()


# --------------------------------------------------------------------------- #
# DSSE / Ed25519 signing
# --------------------------------------------------------------------------- #
def _pae(payload_type: str, body: bytes) -> bytes:
    pt = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(pt)).encode()
        + b" "
        + pt
        + b" "
        + str(len(body)).encode()
        + b" "
        + body
    )


def new_signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_hex(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes_raw().hex()


def sign_dsse(payload: dict, private_key: Ed25519PrivateKey) -> dict:
    body = canonicalize(payload)
    sig = private_key.sign(_pae(PAYLOAD_TYPE, body))
    return {
        "payload": base64.b64encode(body).decode(),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [{"keyid": "", "sig": base64.b64encode(sig).decode()}],
    }


def verify_dsse(envelope: dict, public_key: Ed25519PublicKey) -> bool:
    try:
        if envelope.get("payloadType") != PAYLOAD_TYPE:  # pin to the canonical type
            return False
        sigs = envelope.get("signatures")
        if not isinstance(sigs, list) or len(sigs) == 0:  # empty / non-list -> fail closed
            return False
        body = base64.b64decode(envelope["payload"])
        pae = _pae(PAYLOAD_TYPE, body)
        for s in sigs:
            public_key.verify(base64.b64decode(s["sig"]), pae)
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


def public_key_from_hex(hex_str: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))
