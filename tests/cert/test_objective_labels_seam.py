"""Task 3 — the objective LABELS are a SIGNED, per-domain claim, RE-DERIVED in
``verify`` (a signed claim that isn't re-derived is forgeable under this
project's re-sign threat model) and read by ``render_html`` from the cert (never
a hardcoded constant).

``DomainVerifier.objective_labels`` is the per-domain tuple (manufacturing
``("weighted_tardiness", "total_changeover")``). ``emit_plan_cert`` writes
``claims.optimality.objective_labels`` as a signed ledger leaf; ``verify``
asserts it equals the verifier's labels AND that its arity matches the objective
tuple; ``render_html`` sources the displayed terms from the signed field.

The bundle is built through the facade (``api.certify``) — the production
two-cert path — so the seam is exercised exactly as it ships.
"""
from __future__ import annotations

import copy

from feasible import api
from feasible.canon.canonical import new_signing_key, public_key_hex, sign_dsse
from feasible.cert.plan_cert import _fcir_from_cert, render_html, verify_plan_cert
from feasible.domains import get_domain
from feasible.domains.base import DomainVerifier


def _mfg_pc_key():
    key = new_signing_key()
    result = api.certify("manufacturing", signer_key=key)
    return result.plan_cert, key


def _resign(cert: dict, key) -> dict:
    body = {k: v for k, v in cert.items() if k != "signature"}
    env = sign_dsse(body, key)
    env["public_key_hex"] = public_key_hex(key)
    cert["signature"] = env
    return cert


def test_manufacturing_verifier_declares_objective_labels() -> None:
    """The ``DomainVerifier`` Protocol declares ``objective_labels`` and the
    manufacturing verifier carries the FJSP 2-tuple."""
    _domain, verifier = get_domain("manufacturing")
    assert isinstance(verifier, DomainVerifier)
    assert tuple(verifier.objective_labels) == ("weighted_tardiness", "total_changeover")


def test_cert_carries_signed_objective_labels() -> None:
    """A manufacturing cert carries the per-domain labels as a signed leaf whose
    value equals the verifier's labels and whose arity matches the objective."""
    pc, _key = _mfg_pc_key()
    _domain, verifier = get_domain(pc["domain_id"])
    leaf = pc["claims"]["optimality"]["objective_labels"]
    assert leaf["value"] == list(verifier.objective_labels)
    assert leaf["provenance"] == "ledger"
    assert len(leaf["value"]) == len(pc["claims"]["optimality"]["objective"]["value"])


def test_render_html_sources_labels_from_signed_cert() -> None:
    """``render_html`` reads the objective terms FROM the signed cert, not a
    hardcoded constant: tampering the labels in a deep-copy is reflected in the
    rendered HTML (proving the read is data-driven)."""
    pc, _key = _mfg_pc_key()
    honest_html = render_html(pc)
    assert "weighted_tardiness" in honest_html
    assert "total_changeover" in honest_html

    tampered = copy.deepcopy(pc)
    tampered["claims"]["optimality"]["objective_labels"]["value"] = ["cost_savings", "throughput"]
    tampered_html = render_html(tampered)
    assert "cost_savings" in tampered_html
    assert "throughput" in tampered_html


def test_verify_rederives_objective_labels() -> None:
    """``verify`` RE-DERIVES the labels from the per-domain verifier: a re-signed
    cert with tampered labels is rejected with an ``objective_labels`` reason; an
    honest cert verifies."""
    pc, key = _mfg_pc_key()
    assert verify_plan_cert(pc, key.public_key()).ok

    bad = copy.deepcopy(pc)
    bad["claims"]["optimality"]["objective_labels"]["value"] = ["cost_savings", "throughput"]
    _resign(bad, key)
    res = verify_plan_cert(bad, key.public_key())
    assert res.ok is False
    assert any("objective_labels" in r for r in res.reasons)


def test_verify_rejects_objective_labels_arity_mismatch() -> None:
    """``verify`` rejects an objective_labels whose arity disagrees with the
    objective tuple (the labels must name exactly the objective levels). We model
    a labels value that re-derives wrong AND has the wrong length."""
    pc, key = _mfg_pc_key()
    bad = copy.deepcopy(pc)
    # one label for a two-level objective: arity mismatch
    bad["claims"]["optimality"]["objective_labels"]["value"] = ["weighted_tardiness"]
    _resign(bad, key)
    res = verify_plan_cert(bad, key.public_key())
    assert res.ok is False
    assert any("objective_labels" in r for r in res.reasons)
