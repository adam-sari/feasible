"""Task 7 — the facade ``api.certify`` routes the solve + govern steps through
the per-domain ``Domain.solve`` / ``Domain.govern`` SEAMS (branch-free), not the
module-level ``feasible.solve.orchestrate.solve`` / inlined
``govern_pack(...)``.

``ManufacturingDomain.solve`` delegates to ``feasible.solve.orchestrate.solve``
and ``ManufacturingDomain.govern`` delegates to
``govern_pack(self.build_extracted_pack(), self.policy())`` → byte-identical for
the manufacturing path (the deterministic-surface oracle proves it). Routing
through the seam is what lets a SECOND domain plug its own ``dc_solve`` / govern
behind ONE seam without ``api.certify`` branching on ``domain_id``.
"""
from __future__ import annotations

from feasible import api
from feasible.canon.canonical import new_signing_key
from feasible.domains import get_domain
from feasible.domains.base import CertifyResult, Domain, VerifyView
from feasible.govern.pipeline import GovernResult
from feasible.ir.domain import FCIR
from feasible.solve.orchestrate import SolveResult


def test_manufacturing_domain_has_solve_govern_seams() -> None:
    """The ``Domain`` Protocol declares ``solve``/``govern`` and the manufacturing
    domain satisfies it (runtime-checkable structural match)."""
    domain, _verifier = get_domain("manufacturing")
    assert isinstance(domain, Domain)
    assert hasattr(domain, "solve")
    assert hasattr(domain, "govern")


def test_domain_govern_delegates_to_govern_pack() -> None:
    """``ManufacturingDomain.govern()`` returns the SAME ``GovernResult`` as the
    inlined ``govern_pack(build_extracted_pack(), policy())`` — delegation, so the
    governed surface (universe/active digests, dropped ids) is byte-identical."""
    domain, _verifier = get_domain("manufacturing")
    gov = domain.govern()
    assert isinstance(gov, GovernResult)
    # delegation correctness: the governed surface equals the existing inline call
    from feasible.govern.pipeline import govern_pack

    direct = govern_pack(domain.build_extracted_pack(), domain.policy())
    assert gov.universe_ir.model_dump() == direct.universe_ir.model_dump()
    assert gov.active_ir.model_dump() == direct.active_ir.model_dump()
    assert gov.dropped_rule_ids == direct.dropped_rule_ids


def test_domain_solve_delegates_to_orchestrate_solve() -> None:
    """``ManufacturingDomain.solve(active_ir)`` returns a ``SolveResult`` with a
    plan — delegating to the existing ``feasible.solve.orchestrate.solve``."""
    domain, _verifier = get_domain("manufacturing")
    active_ir: FCIR = domain.govern().active_ir
    result = domain.solve(active_ir)
    assert isinstance(result, SolveResult)
    assert result.plan is not None


def test_certify_routes_through_domain_solve_and_govern(monkeypatch) -> None:
    """The STRONGER guard: ``api.certify`` must call ``domain.govern`` and
    ``domain.solve`` (the seams), not the module-level functions directly. Spy on
    the registered domain singleton — ``api.certify`` resolves the SAME instance
    via ``get_domain`` — and confirm both were invoked during certify."""
    domain, _verifier = get_domain("manufacturing")

    govern_calls: list[tuple] = []
    solve_calls: list[tuple] = []
    govern_orig = domain.govern
    solve_orig = domain.solve

    def govern_spy() -> GovernResult:
        govern_calls.append(())
        return govern_orig()

    def solve_spy(ir: FCIR) -> SolveResult:
        solve_calls.append((ir,))
        return solve_orig(ir)

    monkeypatch.setattr(domain, "govern", govern_spy)
    monkeypatch.setattr(domain, "solve", solve_spy)

    key = new_signing_key()
    result = api.certify("manufacturing", signer_key=key)
    assert isinstance(result, CertifyResult)
    assert govern_calls, "api.certify did not route governance through domain.govern"
    assert solve_calls, "api.certify did not route the solve through domain.solve"


def test_certified_bundle_verifies_through_facade() -> None:
    """The seam refactor keeps the production path green: the facade-built bundle
    binds + verifies cleanly through ``api.verify`` (the oracle proves the
    deterministic surface is byte-identical to the pre-seam certs)."""
    key = new_signing_key()
    result = api.certify("manufacturing", signer_key=key)
    view = api.verify(result.plan_cert, result.rule_pack_cert, signer_key=key)
    assert isinstance(view, VerifyView)
    assert view.ok, view.reasons
    assert view.reasons == []
