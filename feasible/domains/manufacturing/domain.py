"""The manufacturing ``Domain`` (data/presentation half) — Task 9.

This wraps the EXISTING ``feasible.scenario`` builders behind the ``Domain``
protocol by pure delegation: **no file move, no rename**. The crafted sauce
co-packer scenario, its golden IR, the two incumbents, the SOP text, and the
signed conflict policy stay exactly where they are; this class is a thin
adapter so the facade + trusted-policy registry can reach them through the seam.
A domain owns NO crypto.

It replaces the lightweight ``_ManufacturingDomainPlaceholder`` registered in
Task 5 — same ``domain_id``/``display_name``/``policy()`` (so the per-domain
trusted-policy registry still admits ``MANUFACTURING_POLICY``), now with the
data methods wired to the real builders.
"""
from __future__ import annotations

from typing import Any


class ManufacturingDomain:
    """The manufacturing ``Domain`` — delegates to ``feasible.scenario``."""

    domain_id: str = "manufacturing"
    display_name: str = "Manufacturing (FJSP)"

    def policy_doc(self) -> str:
        """The governing SOP text (the source the rule pack was extracted from)."""
        from feasible.scenario import SHOP_RULES

        return SHOP_RULES

    def build_extracted_pack(self) -> Any:
        """The 'messy extraction' candidate rule pack (golden + §4.4 + §5.2)."""
        from feasible.scenario import build_extracted_pack

        return build_extracted_pack()

    def golden_ir(self) -> Any:
        """The hand-verified golden IR (the trusted reference rule pack)."""
        from feasible.scenario import build_scenario_ir

        return build_scenario_ir()

    def incumbents(self) -> dict[str, Any]:
        """The two baselines: A (illegal night cleanout) and B (feasible-naive).

        Built off the golden IR's active surface so the incumbents match the
        plan-certified instance (identical to the Task-1 oracle construction)."""
        from feasible.scenario import (
            build_scenario_ir,
            generate_incumbent_b,
            make_incumbent_a,
        )

        ir = build_scenario_ir()
        inc_b = generate_incumbent_b(ir)
        inc_a = make_incumbent_a(inc_b)
        return {"A": inc_a, "B": inc_b}

    def policy(self) -> Any:
        """The signed conflict policy this domain certifies under.

        Surfaced so the per-domain trusted-policy registry (``trusted_policy_set``)
        admits it. Imported lazily to avoid a policy<->domain import cycle."""
        from feasible.conflict.policy import MANUFACTURING_POLICY

        return MANUFACTURING_POLICY

    def viz_meta(self) -> dict[str, Any]:
        """Presentation metadata for the timeline view (machine lanes)."""
        from feasible.scenario import MACHINES

        return {"machines": list(MACHINES)}

    def trust_boundary_extra(self) -> dict[str, Any]:
        """Domain-specific trust-boundary notes. Manufacturing has none beyond
        the substrate's, so this is empty (datacenter adds capacity-recompute)."""
        return {}
