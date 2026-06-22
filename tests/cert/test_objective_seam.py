"""Task 1 — the solver-free ``verify`` recomputes the objective through the
per-domain ``verifier.objective`` SEAM, not the module-level
``recompute_objective``. Manufacturing's ``ManufacturingVerifier.objective``
delegates to ``recompute_objective`` → byte-identical, but routing through the
seam is what lets a SECOND domain's verify recompute ITS objective.

The bundle is built through the facade (``api.certify``) — the same two-cert
orchestration the CLI ships — so the seam is exercised on the production path.
"""
from __future__ import annotations

from feasible import api
from feasible.canon.canonical import new_signing_key
from feasible.cert.plan_cert import _fcir_from_cert, verify_plan_cert
from feasible.domains import get_domain
from feasible.ir.domain import Plan


def _mfg_pc_key():
    key = new_signing_key()
    result = api.certify("manufacturing", signer_key=key)
    return result.plan_cert, key


def test_verify_objective_via_verifier_seam() -> None:
    pc, _key = _mfg_pc_key()
    ir = _fcir_from_cert(pc)
    plan = Plan.model_validate(pc["plan"])
    _domain, verifier = get_domain(pc["domain_id"])
    # the verifier's recompute equals the cert's signed objective claim
    assert list(verifier.objective(ir, plan)) == pc["claims"]["optimality"]["objective"]["value"]


def test_verify_routes_objective_through_seam(monkeypatch) -> None:
    """The STRONGER guard: ``verify_plan_cert`` must call ``verifier.objective``
    (the seam), not ``recompute_objective`` directly. Spy on the registered
    verifier instance — ``verify`` resolves the SAME singleton via
    ``get_domain`` — and confirm it was invoked during verify."""
    pc, key = _mfg_pc_key()
    _domain, verifier = get_domain(pc["domain_id"])

    calls: list[tuple] = []
    original = verifier.objective

    def spy(ir, plan):
        calls.append((ir, plan))
        return original(ir, plan)

    monkeypatch.setattr(verifier, "objective", spy)
    res = verify_plan_cert(pc, key.public_key())
    assert res.ok, res.reasons
    assert calls, "verify_plan_cert did not route the objective recompute through verifier.objective"


def test_verify_ok_on_honest_manufacturing_cert() -> None:
    pc, key = _mfg_pc_key()
    assert verify_plan_cert(pc, key.public_key()).ok
