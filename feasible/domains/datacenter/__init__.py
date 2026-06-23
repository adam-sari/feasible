from __future__ import annotations
from feasible.domains import register_domain
from feasible.domains.base import KPI_REGISTRY


class _DatacenterDomainStub:
    domain_id = "datacenter"
    display_name = "Datacenter (capacity & maintenance planning)"

    def policy_doc(self):
        return ""

    def build_extracted_pack(self):
        raise NotImplementedError

    def golden_ir(self):
        raise NotImplementedError

    def incumbents(self):
        raise NotImplementedError

    def policy(self):
        return None

    def viz_meta(self):
        return {}

    # Spec 0.5 Domain seams (stubbed at the spike; Task 9 implements):
    def solve(self, ir):
        raise NotImplementedError

    def govern(self):
        raise NotImplementedError

    def capacity_series(self, plan, instance):
        return None

    def trust_boundary_extra(self):
        # honest synthetic flag + (B-2) the gotcha baseline-identity note: inc_a's
        # identity as a "real baseline an operator would run" is OUT-OF-BAND (a documented
        # degenerate-objective solve, not a hand-planted floor cleanout — see Task 10).
        return {
            "data": "synthetic",
            "incumbent_a_identity": "out-of-band: inc_a is a documented degenerate-objective "
                                    "solve (minimize-makespan ignoring the floor); the N+1 "
                                    "breach is EMERGENT, not hand-planted",
            "optimality": "tripwire opted out (objective solver-reported, not Z3-attested optimal)",
        }


from feasible.domains.datacenter.verifier import DatacenterVerifier

# The id this package registers — read by ``bootstrap_domains`` to detect whether
# this package's bundle is currently registered (precise reload-on-cleared-registry).
DOMAIN_ID = "datacenter"

# ``emit_plan_cert`` / ``verify_plan_cert`` resolve ``KPI_REGISTRY[domain_id]`` (never
# a cert callable). The spike registers an EMPTY (but present) datacenter KPI table so
# the frozen cert path resolves it without a KeyError; Task 8 populates the real
# stranded-power / makespan / SLA-penalty recompute fns + version triples.
KPI_REGISTRY.setdefault("datacenter", {})

register_domain("datacenter", _DatacenterDomainStub(), DatacenterVerifier())

__all__ = ["DatacenterVerifier", "DOMAIN_ID"]
