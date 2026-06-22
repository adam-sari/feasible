"""Manufacturing as a registered domain.

Task 5 lands the predicate bundle (``ManufacturingVerifier``) so the top-level
``check`` / ``attest_feasibility`` dispatch through the seam. Task 9 lands the
data/presentation half (``ManufacturingDomain``) by **delegating to the existing
``feasible.scenario`` builders — no file move, no rename** — and registers it
alongside the verifier (replacing the Task-5 placeholder). The ``known_rule_ids``
on the verifier + the per-domain disjointness guard complete the cross-domain
isolation seam (signed ``domain_id`` + per-domain rule_id ownership).
"""
from __future__ import annotations

from feasible.domains import register_domain
import feasible.domains.manufacturing.kpi  # noqa: F401  (populates KPI_REGISTRY["manufacturing"])
from feasible.domains.manufacturing.domain import ManufacturingDomain
from feasible.domains.manufacturing.verifier import ManufacturingVerifier

# The id this package registers — read by ``bootstrap_domains`` to detect whether
# this package's bundle is currently registered (precise reload-on-cleared-registry).
DOMAIN_ID = "manufacturing"

register_domain(DOMAIN_ID, ManufacturingDomain(), ManufacturingVerifier())

__all__ = ["ManufacturingDomain", "ManufacturingVerifier", "DOMAIN_ID"]
