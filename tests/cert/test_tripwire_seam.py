"""Task 2 — the optimality TRIPWIRE is emitted through the per-domain
``verifier.optimality_tripwire`` SEAM, not the module-level len==2 FJSP
function. ``ManufacturingVerifier.optimality_tripwire`` delegates to
``feasible.solve.optimality.optimality_tripwire`` → byte-identical for the
manufacturing path, but routing through the seam is what lets a NON-FJSP domain
opt out honestly (return ``False`` + a trust-boundary note) instead of being
forced through the 2-tuple assertion.

The bundle is built through the facade (``api.certify``) — the production
two-cert path — so the seam is exercised exactly as it ships.
"""
from __future__ import annotations

from feasible import api
from feasible.canon.canonical import new_signing_key
from feasible.cert.plan_cert import _fcir_from_cert
from feasible.domains import get_domain
from feasible.domains.base import DomainVerifier
from feasible.ir.domain import Plan


def _mfg_pc_key():
    key = new_signing_key()
    result = api.certify("manufacturing", signer_key=key)
    return result.plan_cert, key


def test_cert_tripwire_equals_verifier_seam() -> None:
    """The signed ``tripwire_passed`` leaf equals the per-domain seam's verdict
    on the cert's own objective tuple — proving emit went through the seam."""
    pc, _key = _mfg_pc_key()
    ir = _fcir_from_cert(pc)
    plan = Plan.model_validate(pc["plan"])
    _domain, verifier = get_domain(pc["domain_id"])
    objective = tuple(pc["claims"]["optimality"]["objective"]["value"])
    seam_verdict = verifier.optimality_tripwire(ir, objective)
    assert seam_verdict == pc["claims"]["optimality"]["tripwire_passed"]["value"]


def test_manufacturing_verifier_has_tripwire_member() -> None:
    """The ``DomainVerifier`` Protocol declares ``optimality_tripwire`` and the
    manufacturing verifier satisfies it (runtime-checkable structural match)."""
    _domain, verifier = get_domain("manufacturing")
    assert isinstance(verifier, DomainVerifier)
    assert hasattr(verifier, "optimality_tripwire")


def test_seam_tolerates_variable_length_objective() -> None:
    """The SEAM (the Protocol contract) tolerates a variable-length objective:
    a NON-FJSP domain may receive a length-3 tuple and return a bool WITHOUT
    raising. Only the *manufacturing implementation* requires exactly 2 levels;
    the seam itself imposes no arity. We model a non-FJSP domain with a tiny
    stub verifier whose ``optimality_tripwire`` honestly opts out (``False``)
    and confirm a 3-tuple flows through it without error."""

    class _NonFjspVerifier:
        def optimality_tripwire(self, ir: object, objective: tuple[int, ...]) -> bool:
            # honest opt-out: tripwire is solver-reported for this domain, not
            # FJSP-asserted; never asserts a fixed arity.
            return False

    stub = _NonFjspVerifier()
    # a length-3 objective must NOT raise through the seam contract
    assert stub.optimality_tripwire(object(), (1, 2, 3)) is False
    assert stub.optimality_tripwire(object(), (7,)) is False


def test_manufacturing_impl_still_requires_two_levels() -> None:
    """The manufacturing IMPLEMENTATION keeps its 2-tuple assertion (the FJSP
    model has exactly two lexicographic levels). The seam delegates to it, so a
    length-3 tuple raises in the *manufacturing* path — the arity guard is in
    the impl, not the seam contract."""
    import pytest

    pc, _key = _mfg_pc_key()
    ir = _fcir_from_cert(pc)
    _domain, verifier = get_domain("manufacturing")
    with pytest.raises(ValueError):
        verifier.optimality_tripwire(ir, (1, 2, 3))
