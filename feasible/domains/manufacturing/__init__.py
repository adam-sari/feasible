"""Manufacturing as a registered domain.

Task 5 lands the predicate bundle (``ManufacturingVerifier``) and registers it so
the top-level ``check`` / ``attest_feasibility`` dispatch through the seam. The
data/presentation half (``ManufacturingDomain``, wrapping ``feasible.scenario``)
lands in a later task and replaces the lightweight placeholder registered here.
Only the verifier is exercised by the Task-5 dispatch; the placeholder domain
object is a stand-in until the full ``Domain`` is wired.
"""
from __future__ import annotations

from typing import Any

from feasible.domains import register_domain
from feasible.domains.manufacturing.verifier import ManufacturingVerifier


class _ManufacturingDomainPlaceholder:
    """Minimal ``Domain`` stand-in (replaced by the full data-side Domain in a
    later task). Only attributes needed for registration are populated; the data
    methods are not yet exercised by the Task-5 verifier dispatch."""

    domain_id: str = "manufacturing"
    display_name: str = "Manufacturing (FJSP)"

    def policy_doc(self) -> Any: ...
    def build_extracted_pack(self) -> Any: ...
    def golden_ir(self) -> Any: ...
    def incumbents(self) -> Any: ...

    def policy(self) -> Any:
        # the signed conflict policy this domain certifies under; surfaced so the
        # per-domain trusted-policy registry (``trusted_policy_set``) can admit it.
        # Imported lazily to avoid a policy<->domain import cycle. The full
        # data-side Domain (a later task) returns the SAME policy object.
        from feasible.conflict.policy import MANUFACTURING_POLICY
        return MANUFACTURING_POLICY

    def viz_meta(self) -> Any: ...
    def trust_boundary_extra(self) -> Any: ...


register_domain("manufacturing", _ManufacturingDomainPlaceholder(), ManufacturingVerifier())

__all__ = ["ManufacturingVerifier"]
