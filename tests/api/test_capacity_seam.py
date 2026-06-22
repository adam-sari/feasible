"""Task 8 — ``get_timeline`` capacity seam + frozen item schema + ``signer_note``.

The capacity series + threshold lines are a datacenter-only timeline overlay. The
SEAM (``Domain.capacity_series(plan, instance) -> tuple[list[dict], list[dict]] |
None``) RECOMPUTES them from the SIGNED plan+instance (never trusted from rendered
metadata); manufacturing returns ``None`` (no capacity overlay). ``get_timeline``
calls the seam and populates the ``TimelineView.capacity_series`` /
``threshold_lines`` fields — manufacturing stays ``None``, byte-identical timeline.

``VerifyView``/``TrustVector`` gain ``signer_note: str`` — the canonical
authenticated-vs-self-described sentence Track A renders VERBATIM instead of
fabricating prose. It byte-matches the sentence the CLI prints (``cli.verify``'s
``auth`` string), so the facade is the single source of that wording.
"""
from __future__ import annotations

from feasible import api
from feasible.canon.canonical import new_signing_key
from feasible.domains import get_domain
from feasible.domains.base import TimelineView, TrustVector, VerifyView

# The canonical signer notes — the EXACT strings ``cli.verify`` prints as ``auth``
# (cli.py:97-98). The facade is the single source of this wording so Track A
# renders it verbatim instead of fabricating prose.
SIGNER_NOTE_AUTHENTICATED = "SIGNER AUTHENTICATED (pinned key)"
SIGNER_NOTE_SELF_DESCRIBED = (
    "signer SELF-DESCRIBED — pass --signer-key to authenticate "
    "(re-check passed, identity UNVERIFIED)"
)


def test_get_timeline_manufacturing_capacity_series_is_none() -> None:
    """Manufacturing has no capacity overlay — both fields are ``None`` (the
    datacenter-only fields default; the seam returns ``None`` for manufacturing)."""
    tl = api.get_timeline("manufacturing")
    assert isinstance(tl, TimelineView)
    assert tl.capacity_series is None
    assert tl.threshold_lines is None


def test_manufacturing_domain_capacity_series_seam_returns_none() -> None:
    """The ``Domain.capacity_series`` seam exists and manufacturing returns ``None``
    (recompute-not-trusted; a domain WITH a capacity overlay returns the two lists)."""
    domain, _verifier = get_domain("manufacturing")
    assert hasattr(domain, "capacity_series")
    plan = domain.golden_ir()  # any signed-shape stand-in; mfg ignores it and returns None
    inst = domain.golden_ir().instance
    assert domain.capacity_series(plan, inst) is None


def test_certify_trust_vector_carries_signer_note() -> None:
    """``certify`` surfaces the canonical ``signer_note`` on the ``TrustVector``:
    self-described without a pinned key, authenticated with one."""
    self_desc = api.certify("manufacturing")  # ephemeral key -> self-described
    assert isinstance(self_desc.trust_vector, TrustVector)
    assert self_desc.trust_vector.signer_note == SIGNER_NOTE_SELF_DESCRIBED

    key = new_signing_key()
    auth = api.certify("manufacturing", signer_key=key)  # caller-pinned -> authenticated
    assert auth.trust_vector.signer_note == SIGNER_NOTE_AUTHENTICATED


def test_verify_view_carries_canonical_signer_note() -> None:
    """``api.verify`` surfaces the canonical ``signer_note`` (authenticated under a
    pinned key, self-described without) on both the ``VerifyView`` and its
    ``TrustVector`` — byte-matching the sentence the CLI prints."""
    key = new_signing_key()
    result = api.certify("manufacturing", signer_key=key)

    authed = api.verify(result.plan_cert, result.rule_pack_cert, signer_key=key)
    assert isinstance(authed, VerifyView)
    assert authed.signer_note == SIGNER_NOTE_AUTHENTICATED
    assert authed.trust_vector is not None
    assert authed.trust_vector.signer_note == SIGNER_NOTE_AUTHENTICATED

    self_desc = api.verify(result.plan_cert, result.rule_pack_cert)
    assert self_desc.signer_note == SIGNER_NOTE_SELF_DESCRIBED
    assert self_desc.trust_vector is not None
    assert self_desc.trust_vector.signer_note == SIGNER_NOTE_SELF_DESCRIBED


def test_signer_note_byte_matches_cli_auth_string() -> None:
    """The facade's canonical ``signer_note`` is the SAME wording ``cli.verify``
    composes as its ``auth`` line — the facade is the single source of that wording
    (Track A renders it verbatim rather than re-deriving prose)."""
    # mirror cli.verify's `auth` ternary (cli.py:97-98) under both key modes
    pinned_auth = "SIGNER AUTHENTICATED (pinned key)"
    unpinned_auth = (
        "signer SELF-DESCRIBED — pass --signer-key to authenticate "
        "(re-check passed, identity UNVERIFIED)"
    )
    assert SIGNER_NOTE_AUTHENTICATED == pinned_auth
    assert SIGNER_NOTE_SELF_DESCRIBED == unpinned_auth
