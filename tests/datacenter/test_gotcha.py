"""Task 10: the HERO gotcha end-to-end — "maintenance spends the N+1 buffer".

B-2: the gotcha is EMERGENT from a DOCUMENTED degenerate-objective SOLVE, NOT a
hand-planted floor cleanout. ``dc_incumbent_a`` is the OUTPUT of
``dc_degenerate_solve`` — the datacenter CP-SAT model run with the redundancy floor
RELAXED (``relax_redundancy=True``) and a degenerate "defer all maintenance to the
end of the horizon" objective. With the floor relaxed, the F1 cooling-path task
slides to its latest legal start [6,8), landing ON TOP of F3's FIXED outage [6,8) —
so a floored group drops below N+1 at a specific timestep as an EMERGENT consequence
of that objective. The optimized (certified) plan never drops below the floor (the
floor is HARD on the certify build).

``verify`` asserts ``incumbent_A_failure.violated_rule_ref == "dc:redundancy_floor"``
(equality with the domain gotcha rule — not merely non-None) and the per-timestep
``CoverageFloor`` witness re-derives solver-free.
"""
from __future__ import annotations

from feasible import api
from feasible.canon.canonical import new_signing_key
from feasible.checker.checker import check
from feasible.domains import get_domain
from feasible.domains.datacenter.scenario import (
    build_dc_scenario_active_ir,
    dc_incumbent_a,
    dc_incumbent_b,
)
from feasible.domains.datacenter.solve import dc_degenerate_solve


def test_incumbent_a_is_the_output_of_the_degenerate_solve_not_hand_built() -> None:
    """B-2 (a): ``dc_incumbent_a`` came from the DOCUMENTED degenerate solve — the test
    calls the degenerate-solve helper and asserts ``dc_incumbent_a`` IS its output (it
    is NOT a literal hand-built Plan with a planted cleanout). Byte-deterministic, so
    the two agree exactly."""
    active_ir = build_dc_scenario_active_ir()
    degenerate = dc_degenerate_solve(active_ir, workers=1, seed=1)
    inc_a = dc_incumbent_a(active_ir)
    assert inc_a.model_dump(mode="json") == degenerate.model_dump(mode="json")
    # the degenerate plan carries NO hand-planted floor cleanout — the breach is
    # EMERGENT from the (start-maximizing, floor-relaxed) objective, not a cleanout.
    assert inc_a.cleanouts == []
    # the F1 cooling-path task is deferred onto the F3 outage window [6,8) (the buffer-spend)
    assert inc_a.assignments["task:T1"][0] == 6


def test_degenerate_solve_is_byte_deterministic() -> None:
    """The degenerate solve is single-worker + seeded -> byte-deterministic, so the
    hero incumbent is a stable fixed plan (the Task-12 oracle precondition)."""
    active_ir = build_dc_scenario_active_ir()
    a = dc_degenerate_solve(active_ir, workers=1, seed=1)
    b = dc_degenerate_solve(active_ir, workers=1, seed=1)
    assert a.model_dump(mode="json") == b.model_dump(mode="json")


def test_optimized_plan_holds_floor_but_incumbent_a_breaches() -> None:
    """The CERTIFIED plan (floor HARD on the certify build) holds the floor everywhere;
    the degenerate incumbent A (floor relaxed) emergently breaches it."""
    active_ir = build_dc_scenario_active_ir()
    inc_a = dc_incumbent_a(active_ir)
    inc_b = dc_incumbent_b(active_ir)
    # the optimized (certified) plan never drops below the floor.
    key = new_signing_key()
    result = api.certify("datacenter", signer_key=key)
    from feasible.ir.domain import Plan

    certified_plan = Plan.model_validate(result.plan_cert["plan"])
    assert check(certified_plan, active_ir).passed
    # incumbent A emergently breaches; B (feasible-naive) holds the floor.
    assert check(inc_a, active_ir).passed is False
    assert check(inc_b, active_ir).passed is True


def test_gotcha_violated_rule_ref_equals_redundancy_floor() -> None:
    """B-2 (b): ``verify`` asserts ``incumbent_A_failure.violated_rule_ref ==
    "dc:redundancy_floor"`` — equality with the domain's signed ``gotcha_rule_id()``,
    not merely non-None. The bundle verifies green (the equality is enforced inside
    ``verify_plan_cert``)."""
    key = new_signing_key()
    result = api.certify("datacenter", signer_key=key)
    fa = result.plan_cert["incumbent_A_failure"]
    assert fa["violated_rule_ref"] == "dc:redundancy_floor"
    _, verifier = get_domain("datacenter")
    assert fa["violated_rule_ref"] == verifier.gotcha_rule_id()
    # the whole bundle verifies (verify_plan_cert enforces the gotcha-rule equality)
    view = api.verify(result.plan_cert, result.rule_pack_cert, signer_key=key)
    assert view.ok, view.reasons


def test_gotcha_per_timestep_witness_rederives_solverfree() -> None:
    """B-2 (c): the per-timestep ``CoverageFloor`` witness in the cert re-derives by
    re-running ``check(inc_a, ir)`` SOLVER-FREE — the FIRST floor violation's
    counter-witness matches the cert's ``incumbent_A_failure.counter_witness`` exactly
    (the cited timestep/available/floor are re-derivable, not trusted from the number)."""
    key = new_signing_key()
    result = api.certify("datacenter", signer_key=key)
    cert_witness = result.plan_cert["incumbent_A_failure"]["counter_witness"]
    # the cited gotcha is the redundancy floor with a per-timestep coverage_floor witness.
    assert cert_witness["group_id"] == "G1"
    assert cert_witness["available"] < cert_witness["floor"]

    # re-derive solver-free over the SAME incumbent A + active IR.
    active_ir = build_dc_scenario_active_ir()
    inc_a = dc_incumbent_a(active_ir)
    res = check(inc_a, active_ir)
    floor_v = [v for v in res.violations if v.rule_id == "dc:redundancy_floor"]
    assert floor_v and floor_v[0].witness_kind == "coverage_floor"
    # the cert cites the FIRST coverage_floor violation (the emitter takes night[0]).
    assert floor_v[0].counter_witness == cert_witness
    # the breach is at the F3-outage overlap (t=6), available 1 < floor 2.
    assert cert_witness == {"group_id": "G1", "timestep": 6, "available": 1, "floor": 2}


def test_trust_boundary_carries_b2_out_of_band_identity_note() -> None:
    """B-2: the domain's HONEST trust-boundary surface carries the out-of-band note —
    inc_a's identity-as-real-baseline is a DOCUMENTED degenerate-objective solve, NOT a
    claim that operators run exactly this plan; the N+1 breach is EMERGENT."""
    domain, _verifier = get_domain("datacenter")
    extra = domain.trust_boundary_extra()
    note = extra["incumbent_a_identity"]
    assert "out-of-band" in note.lower()
    assert "emergent" in note.lower()
    assert "degenerate" in note.lower()
