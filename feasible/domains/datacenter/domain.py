"""The datacenter ``Domain`` (data/presentation half) — Task 9.

A thin adapter wrapping ``feasible.domains.datacenter.scenario`` (the synthetic
facility builders, the two incumbents, the SOP text, the signed conflict policy)
behind the ``Domain`` protocol by pure delegation — a domain owns NO crypto. It
replaces the lightweight ``_DatacenterDomainStub`` registered at the Task-0 spike,
now wired to the real builders + the Spec 0.5 ``solve``/``govern``/``capacity_series``
seams so ``api.certify`` reaches it BRANCH-FREE (no ``if domain_id == "datacenter"``).

The data is SYNTHETIC (the facility is a hand-built scenario, not a customer
facility), surfaced HONESTLY via ``trust_boundary_extra()["data"] == "synthetic"``;
the certs themselves are REAL (same frozen pipeline, same forgery suite). The B-2
gotcha-baseline-identity note (inc_a's identity-as-real-baseline is OUT-OF-BAND — a
documented degenerate-objective solve, not a hand-planted floor cleanout) rides in
``trust_boundary_extra`` too.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from feasible.govern.pipeline import GovernResult
    from feasible.ir.domain import FCIR, Instance, Plan
    from feasible.solve.orchestrate import SolveResult


class DatacenterDomain:
    """The datacenter ``Domain`` — delegates to ``feasible.domains.datacenter.scenario``."""

    domain_id: str = "datacenter"
    display_name: str = "Datacenter (capacity & maintenance planning)"

    def policy_doc(self) -> str:
        """The governing SOP text (``capacity_policy.md`` — the extraction source the
        rule pack's ``primary_normative`` spans anchor against)."""
        from feasible.domains.datacenter.scenario import CAPACITY_POLICY

        return CAPACITY_POLICY

    def build_extracted_pack(self) -> Any:
        """The 'messy extraction' candidate pack: the golden rules + the seeded
        conflict-only acceleration permission (B-6) + the over-broad mis-extraction."""
        from feasible.domains.datacenter.scenario import build_dc_extracted_pack

        return build_dc_extracted_pack()

    def golden_ir(self) -> Any:
        """The hand-verified golden datacenter IR (the trusted reference rule pack)."""
        from feasible.domains.datacenter.scenario import build_dc_scenario_ir

        return build_dc_scenario_ir()

    def incumbents(self) -> dict[str, Any]:
        """The two baselines over the GOVERNED active datacenter IR:

          * A spends the N+1 buffer — the HERO gotcha: a degenerate-makespan plan
            that schedules a redundancy-derating maintenance task overlapping a fixed
            outage, dropping a floored group below N+1 at a specific timestep (an
            EMERGENT breach, not a hand-planted cleanout — B-2);
          * B is feasible-naive — holds the floor everywhere (defers maintenance to a
            floor-holding slot, so a larger makespan).

        Built against the governed active IR (universe minus the auto-dropped
        permission) — the same constraint surface the plan certifies — so the
        incumbents are comparable to the certified plan. The dc incumbents are
        deterministic fixed plans (they ignore the IR arg), so the active IR is
        passed for parity with the manufacturing construction."""
        from feasible.domains.datacenter.scenario import (
            build_dc_scenario_active_ir,
            dc_incumbent_a,
            dc_incumbent_b,
        )

        active_ir = build_dc_scenario_active_ir()
        return {"A": dc_incumbent_a(active_ir), "B": dc_incumbent_b(active_ir)}

    def policy(self) -> Any:
        """The signed conflict policy this domain certifies under (``DATACENTER_POLICY``).

        Surfaced so the per-domain trusted-policy registry (``trusted_policy_set``)
        admits it. The redundancy floor IS the ``SAFETY_SANITATION`` class (B-3), so
        the frozen ``no_permission_outranks_safety`` guard protects it and an inverted
        policy is rejected. Lazy import to avoid a policy<->domain import cycle."""
        from feasible.conflict.policy import DATACENTER_POLICY

        return DATACENTER_POLICY

    def govern(self) -> GovernResult:
        """Run the §5.2/§4.4 governance pipeline over the extracted pack through the
        FROZEN ``govern_pack`` (Spec 0.5 T6 threads ``domain_id="datacenter"`` — NO
        ``dc_govern_pack`` mirror). Delegates VERBATIM to ``govern_pack(
        self.build_extracted_pack(), self.policy())`` — the exact call ``api.certify``
        reaches branch-free via this seam. Lazy import to avoid a govern<->domain
        import cycle."""
        from feasible.govern.pipeline import govern_pack

        return govern_pack(self.build_extracted_pack(), self.policy())

    def solve(self, ir: FCIR) -> SolveResult:  # noqa: A003  (the seam verb)
        """Solve the datacenter active set ``ir`` for the certified plan.

        Delegates to ``dc_solve(ir, workers=1, seed=1)`` — the datacenter CP-SAT path
        (via ``DatacenterVerifier.compile``) that sets ``result.objective`` to the REAL
        ``(stranded_power_kw, makespan)`` tuple (the Spec 0.5 objective seam ``verify``
        recomputes through). Single-worker + seeded so plan extraction is
        byte-deterministic (B-11). ``api.certify`` reaches this BRANCH-FREE. Lazy import
        to avoid a solve<->domain import cycle."""
        from feasible.domains.datacenter.solve import dc_solve

        return dc_solve(ir, workers=1, seed=1)

    def viz_meta(self) -> dict[str, Any]:
        """Presentation metadata for the timeline view: the feed lanes + the maintenance
        paths (recomputed from the golden facility — purely cosmetic, never trusted)."""
        from feasible.domains.datacenter.scenario import build_dc_scenario_dc_instance

        dc = build_dc_scenario_dc_instance()
        return {
            "feeds": [f.id for f in dc.feeds],
            "paths": sorted({t.path for t in dc.maintenance_tasks}),
            "machines": sorted({f.id for f in dc.feeds} | {r.id for r in dc.racks}),
        }

    def capacity_series(
        self, plan: Any, instance: Any
    ) -> tuple[list[dict], list[dict]] | None:
        """The datacenter timeline capacity overlay ``(capacity_series, threshold_lines)``.

        RECOMPUTED from the SIGNED plan + the reconstructed IR (Track B OWNS this
        producer — Spec 0.5 T8) — NEVER trusted from a rendered/cert metadata field, so
        the rendered overlay is exactly as trustworthy as the cert. ``get_timeline``
        passes the reconstructed ``FCIR`` (which carries the ``dc:redundancy_floor``
        rule params — the floor/units/maintenance topology lives there, not in the bare
        ``Instance``); a bare ``Instance`` (no ``.rules``) yields ``None`` (nothing to
        recompute). The series is the per-(group, timestep) AVAILABLE redundant-unit
        count; the threshold lines are each group's N+1 floor.

        Conforms to the FROZEN Spec 0.5 item schema:
          * ``capacity_series`` item ``{"t": int, "value": int, "group": str | None}``;
          * ``threshold_lines`` item ``{"label": str, "value": int}``.
        INTEGERS ONLY (the availability count + the floor); deterministic order
        (active-group order then timestep)."""
        rules = getattr(instance, "rules", None)
        if rules is None:
            # a bare Instance carries no redundancy topology -> nothing to recompute.
            return None
        ir = instance
        # reuse the SAME closed availability helpers the checker/objective use, so the
        # overlay agrees with the signed objective + the per-timestep witness.
        from feasible.domains.datacenter.verifier import (
            _active_redundancy_groups,
            _plan_outage_intervals,
            _task_outage_intervals,
        )

        task_outage = _task_outage_intervals(plan, ir)
        plan_outage = _plan_outage_intervals(plan)
        series: list[dict] = []
        lines: list[dict] = []
        for r in _active_redundancy_groups(ir):
            p = r.params
            gid = str(p.get("group_id", "?"))
            units = [str(u) for u in p.get("units", [])]
            floor = int(p.get("floor", 0))
            horizon = int(p.get("horizon", 0))
            maintenance = p.get("maintenance", {})
            for t in range(horizon):
                n = 0
                for u in units:
                    down = any(a <= t < b for (a, b) in maintenance.get(u, []))
                    down = down or any(a <= t < b for (a, b) in task_outage.get(u, []))
                    down = down or any(a <= t < b for (a, b) in plan_outage.get(u, []))
                    if not down:
                        n += 1
                series.append({"t": t, "value": n, "group": gid})
            lines.append({"label": "N+1 floor", "value": floor})
        return series, lines

    def trust_boundary_extra(self) -> dict[str, Any]:
        """The HONEST datacenter trust-boundary notes:

          * ``data == "synthetic"`` — the facility is a hand-built scenario (the certs
            are REAL; the DATA is synthetic). Surfaced on ``TrustVector.data``;
          * ``coverage == "preview"`` — the coverage ledger is a preview surface;
          * ``conflict_replay == "verified"`` — the §4.4 conflict replay is verified;
          * ``incumbent_a_identity`` (B-2) — inc_a's identity-as-real-baseline is
            OUT-OF-BAND (a documented degenerate-objective solve, not a claim that
            operators run exactly this plan; the N+1 breach is EMERGENT);
          * ``optimality`` — the dc objective is solver-reported (tripwire opted out)."""
        return {
            "data": "synthetic",
            "coverage": "preview",
            "conflict_replay": "verified",
            "incumbent_a_identity": (
                "out-of-band: inc_a is a documented degenerate-objective solve "
                "(minimize-makespan ignoring the floor); the N+1 breach is EMERGENT, "
                "not hand-planted"
            ),
            "optimality": "tripwire opted out (objective solver-reported, not Z3-attested optimal)",
        }
