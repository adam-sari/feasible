"""Task 10: the ``CoverageFloor`` mini-threat-model (design §2) as REAL asserts,
driven through the DATACENTER ``dc:redundancy_floor`` predicate (the frozen closed
per-timestep kernel ``coverage_floor_violations`` it reuses) + the
recompute-not-trusted ``capacity_series`` producer (the Spec 0.5 T8 seam Track B owns).

Each adversarial case is a plan/instance crafted to slip past a NAIVE redundancy
check; the closed per-timestep predicate must catch it:

  * off-by-one timestep omission (the whole horizon is enumerated; a missing t reads
    as 0 available -> fail-closed);
  * interval-endpoint inclusivity (half-open ``[a,b)`` — a unit down over ``[1,2)`` is
    down at t=1 ONLY, up at t=2);
  * maintenance derating ignored (a PLAN-scheduled outage derates availability, not
    just FIXED instance maintenance);
  * a unit double-counted across two groups (each group is evaluated INDEPENDENTLY — a
    shared unit counts down in BOTH);
  * installed-vs-available confusion (the floor is over AVAILABLE units, never
    installed — three installed but two down still breaches a floor-2 group);
  * floor-on-average-not-every-timestep (a horizon whose AVERAGE clears the floor but
    one timestep dips below is caught — the floor is per-timestep).

The ``capacity_series`` recompute-not-trusted case is load-bearing: the rendered
overlay is exactly the seam recomputed from the SIGNED bytes (never a trusted cert
metadata field), conforming to the FROZEN item schema.
"""
from __future__ import annotations

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
from feasible import api
from feasible.canon.canonical import new_signing_key
from feasible.cert.plan_cert import _fcir_from_cert
from feasible.checker.checker import check
from feasible.domains import get_domain
from feasible.domains.datacenter.instance import (
    DatacenterInstance,
    baseline_plan,
    pack_dc_instance,
)
from feasible.ir.domain import (
    ClauseKind,
    CompileMode,
    ExceptionMode,
    FCIR,
    Instance,
    Job,
    Operation,
    Plan,
    Provenance,
    Rule,
    Severity,
    TextSpan,
)


def _legacy_ir(units, floor, horizon, maintenance) -> FCIR:
    """A single-group ``dc:redundancy_floor`` IR (the Task-0 slice convention) over the
    given units/floor/horizon/fixed-maintenance — the cheapest way to drive a crafted
    availability profile through the REAL datacenter checker."""
    dc = DatacenterInstance(
        group_id="G", units=list(units), floor=floor, horizon=horizon,
        maintenance=maintenance,
    )
    inst, rules = pack_dc_instance(dc)
    return FCIR(rules=rules, instance=inst, domain_id="datacenter")


def _floor_witnesses(plan: Plan, ir: FCIR) -> list[dict]:
    res = check(plan, ir)
    return [v.counter_witness for v in res.violations if v.rule_id == "dc:redundancy_floor"]


# --------------------------------------------------------------------------- #
# §2 adversarial cases                                                        #
# --------------------------------------------------------------------------- #


def test_off_by_one_timestep_omission_fails_closed() -> None:
    """The whole horizon ``[0, horizon)`` is enumerated; a timestep with NO available
    unit (e.g. every unit in fixed maintenance over the LAST timestep) reads as 0
    available -> a violation at THAT t. A naive check that stopped one short would miss
    it."""
    # 2 units floor 1, horizon 3; both units down over [2,3) -> available[2] = 0 < 1.
    ir = _legacy_ir(["U1", "U2"], 1, 3, {"U1": [(2, 3)], "U2": [(2, 3)]})
    plan = baseline_plan(ir, {})
    ws = _floor_witnesses(plan, ir)
    assert any(w == {"group_id": "G", "timestep": 2, "available": 0, "floor": 1} for w in ws)


def test_interval_endpoint_inclusivity_is_half_open() -> None:
    """Half-open ``[a,b)``: a PLAN outage over ``[1,2)`` removes the unit at t=1 ONLY
    (it is back up at t=2). With U3 fixed-down over ``[1,3)``, at t=1 (U2 out, U3 out)
    available=1 < floor 2 (breach); at t=2 (U2 back, U3 still out) available=2 (held)."""
    ir = _legacy_ir(["U1", "U2", "U3"], 2, 4, {"U3": [(1, 3)]})
    plan = baseline_plan(ir, {"U2": (1, 2)})   # plan outage on U2 over [1,2) only
    ws = _floor_witnesses(plan, ir)
    timesteps = {w["timestep"] for w in ws}
    assert timesteps == {1}    # breach ONLY at t=1 — the endpoint is exclusive at t=2
    assert {"group_id": "G", "timestep": 1, "available": 1, "floor": 2} in ws


def test_maintenance_derating_not_ignored() -> None:
    """A PLAN-scheduled outage derates availability (not just FIXED instance
    maintenance). Without it the floor holds; WITH it the floor breaches — so a check
    that ignored plan-side derating would falsely pass."""
    ir = _legacy_ir(["U1", "U2", "U3"], 2, 4, {})  # no fixed maintenance -> always 3 up
    assert check(baseline_plan(ir, {}), ir).passed                  # floor holds
    plan = baseline_plan(ir, {"U1": (0, 4), "U2": (0, 4)})          # two units derated
    assert check(plan, ir).passed is False                          # derating caught
    ws = _floor_witnesses(plan, ir)
    assert all(w["available"] == 1 and w["floor"] == 2 for w in ws)


def test_unit_double_counted_across_two_groups() -> None:
    """A unit shared across TWO redundancy groups counts DOWN in BOTH — each group is
    evaluated INDEPENDENTLY. A FIXED outage on the shared unit breaches whichever group
    it tips below its floor (here both groups have the shared unit, both flagged)."""
    # Two groups GA={S, A} floor 2 and GB={S, B} floor 2 sharing unit S; S down over
    # [1,2) -> each group drops to 1 available at t=1 -> BOTH groups breach.
    inst = Instance(
        jobs=[Job(id=u, product=u, family="unit", qty=1, due_date=3, priority=3)
              for u in ("S", "A", "B")],
        operations=[Operation(op_id=u, job_id=u, seq=0, eligible_machines=[u], duration=1)
                    for u in ("S", "A", "B")],
        machines=["A", "B", "S"], setup_matrix={}, maintenance=[], horizon=3,
    )

    def _grp(gid: str, units: list[str]) -> Rule:
        return Rule(
            rule_id="dc:redundancy_floor", kind="redundancy_floor",
            params={"group_id": gid, "units": units, "floor": 2, "horizon": 3,
                    "maintenance": {"S": [[1, 2]]}},
            severity=Severity.HARD, clause_kind=ClauseKind.OBLIGATION,
            compile_mode=CompileMode.PLAN_CONSTRAINT, resolution_class="SAFETY_SANITATION",
            exception_mode=ExceptionMode.NONE,
            provenance=Provenance(spans=[TextSpan(quoted_text=f"floor {gid}", role="modeling_decision")]),
        )

    ir = FCIR(rules=[_grp("GA", ["S", "A"]), _grp("GB", ["S", "B"])],
              instance=inst, domain_id="datacenter")
    plan = baseline_plan(ir, {})
    ws = _floor_witnesses(plan, ir)
    groups_breached = {w["group_id"] for w in ws}
    assert groups_breached == {"GA", "GB"}            # the shared unit is down in BOTH
    assert all(w["timestep"] == 1 and w["available"] == 1 for w in ws)


def test_installed_vs_available_confusion() -> None:
    """The floor is over AVAILABLE units, NEVER installed. Three units installed but two
    down still breaches a floor-2 group (a check counting INSTALLED units would falsely
    pass at 3 >= 2)."""
    ir = _legacy_ir(["U1", "U2", "U3"], 2, 3, {"U1": [(0, 3)], "U2": [(0, 3)]})
    # installed = 3 (>= floor 2) but available = 1 everywhere -> breach every timestep.
    ws = _floor_witnesses(baseline_plan(ir, {}), ir)
    assert len(ws) == 3 and all(w["available"] == 1 and w["floor"] == 2 for w in ws)


def test_floor_on_average_not_every_timestep() -> None:
    """A horizon whose AVERAGE availability clears the floor but ONE timestep dips below
    is caught — the floor is per-timestep, never an average. Available = [3,1,3] avg 2.33
    but t=1 dips to 1 < floor 2."""
    # U2,U3 both down only over [1,2): available [3,1,3]. avg > floor but t=1 breaches.
    ir = _legacy_ir(["U1", "U2", "U3"], 2, 3, {"U2": [(1, 2)], "U3": [(1, 2)]})
    ws = _floor_witnesses(baseline_plan(ir, {}), ir)
    assert {w["timestep"] for w in ws} == {1}
    assert {"group_id": "G", "timestep": 1, "available": 1, "floor": 2} in ws


# --------------------------------------------------------------------------- #
# capacity_series recompute-not-trusted (Track B OWNS this producer)          #
# --------------------------------------------------------------------------- #


def test_capacity_series_equals_seam_recompute_from_signed_bytes() -> None:
    """(a) ``api.get_timeline("datacenter").capacity_series`` EQUALS
    ``DatacenterDomain.capacity_series(signed_plan, signed_ir)`` recomputed from the
    SIGNED plan+IR — the rendered overlay is exactly the seam recomputed, never a
    trusted cert/metadata field."""
    key = new_signing_key()
    result = api.certify("datacenter", signer_key=key)
    tl = api.get_timeline("datacenter", signer_key=key)
    domain, _verifier = get_domain("datacenter")
    signed_plan = Plan.model_validate(result.plan_cert["plan"])
    signed_ir = _fcir_from_cert(result.plan_cert)
    overlay = domain.capacity_series(signed_plan, signed_ir)
    assert overlay is not None
    series, lines = overlay
    assert tl.capacity_series == series
    assert tl.threshold_lines == lines


def test_capacity_series_conforms_to_frozen_item_schema() -> None:
    """(b) Every item conforms to the FROZEN Spec 0.5 item schema (keys + int types):
    ``capacity_series`` item ``{"t": int, "value": int, "group": str | None}``;
    ``threshold_lines`` item ``{"label": str, "value": int}``. INTEGERS ONLY."""
    key = new_signing_key()
    tl = api.get_timeline("datacenter", signer_key=key)
    assert tl.capacity_series and tl.threshold_lines
    for item in tl.capacity_series:
        assert set(item.keys()) == {"t", "value", "group"}
        assert isinstance(item["t"], int) and not isinstance(item["t"], bool)
        assert isinstance(item["value"], int) and not isinstance(item["value"], bool)
        assert item["group"] is None or isinstance(item["group"], str)
    for line in tl.threshold_lines:
        assert set(line.keys()) == {"label", "value"}
        assert isinstance(line["label"], str)
        assert isinstance(line["value"], int) and not isinstance(line["value"], bool)


def test_threshold_lines_carry_floor_recomputed_from_rule_params() -> None:
    """(c) The ``threshold_lines`` carry the N+1 floor as ``{"label": "N+1 floor",
    "value": <floor>}`` RECOMPUTED from the ``dc:redundancy_floor`` rule params (not a
    rendered constant)."""
    key = new_signing_key()
    result = api.certify("datacenter", signer_key=key)
    signed_ir = _fcir_from_cert(result.plan_cert)
    floor = next(
        int(r.params["floor"]) for r in signed_ir.rules if r.rule_id == "dc:redundancy_floor"
    )
    tl = api.get_timeline("datacenter", signer_key=key)
    assert {"label": "N+1 floor", "value": floor} in tl.threshold_lines


def test_rendered_series_is_never_load_bearing() -> None:
    """(d) A flattering rendered ``capacity_series`` is NEVER load-bearing:

      * the signed cert carries NO ``capacity_series`` field at all (so verify cannot
        read one — there is nothing to trust), AND any extra top-level field added to a
        cert trips the DSSE body-vs-payload guard (so a fabricated series cannot even
        ride along inside a signed cert);
      * ``verify``'s verdict comes from ``check`` over the SIGNED plan+IR, not a series;
      * ``get_timeline`` re-derives the series via the seam from the SIGNED bytes — and
        the real series reflects TRUE availability (a fabricated all-clear ``999`` is
        never what the seam returns)."""
    key = new_signing_key()
    result = api.certify("datacenter", signer_key=key)
    # the signed cert has NO capacity_series field — the overlay is never IN the cert,
    # so it cannot be a trusted load-bearing value.
    assert "capacity_series" not in result.plan_cert
    # any injected top-level field trips the body-vs-payload guard (the cert cannot smuggle
    # a fabricated flattering series inside a signed body).
    tampered = dict(result.plan_cert)
    tampered["capacity_series"] = [{"t": t, "value": 999, "group": "G1"} for t in range(8)]
    rejected = api.verify(tampered, result.rule_pack_cert, signer_key=key)
    assert rejected.ok is False
    assert any("does not match the signed payload" in r for r in rejected.reasons)
    # the HONEST bundle (no injection) verifies — its verdict is from check, not a series.
    assert api.verify(result.plan_cert, result.rule_pack_cert, signer_key=key).ok
    # the seam recompute reads SIGNED bytes only -> the real series is NOT the fabricated
    # all-clear; it reflects TRUE availability (<= installed 3, never 999).
    domain, _verifier = get_domain("datacenter")
    signed_plan = Plan.model_validate(result.plan_cert["plan"])
    signed_ir = _fcir_from_cert(result.plan_cert)
    series, _lines = domain.capacity_series(signed_plan, signed_ir)
    assert series != tampered["capacity_series"]
    assert all(item["value"] <= 3 for item in series)
