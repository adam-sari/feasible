from __future__ import annotations
from feasible.domains import register_domain
from feasible.domains.datacenter.domain import DatacenterDomain
from feasible.domains.datacenter.verifier import DatacenterVerifier

# The id this package registers — read by ``bootstrap_domains`` to detect whether
# this package's bundle is currently registered (precise reload-on-cleared-registry).
DOMAIN_ID = "datacenter"

# ``emit_plan_cert`` / ``verify_plan_cert`` resolve ``KPI_REGISTRY[domain_id]`` (never
# a cert callable). Task 8 populates the real stranded-power / makespan / SLA-penalty
# recompute fns + version triples (importing ``kpi`` registers
# ``KPI_REGISTRY["datacenter"]`` as an import side-effect).
import feasible.domains.datacenter.kpi  # noqa: E402,F401  (populates KPI_REGISTRY["datacenter"])

register_domain("datacenter", DatacenterDomain(), DatacenterVerifier())

__all__ = ["DatacenterDomain", "DatacenterVerifier", "DOMAIN_ID"]
