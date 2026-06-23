"""The datacenter anti-drift tripwire (Task 12): a frozen, signature-free projection
of the datacenter certs over the DETERMINISTIC surfaces only (body claims, digests,
ledger, verdicts) — never signature bytes (random key) and never raw plan assignments
(solver tie-breaks).

Mirrors ``tests/regression/test_manufacturing_oracle.py`` exactly, but routes through
the FROZEN ``govern_pack`` (Spec 0.5 T6 threads ``domain_id="datacenter"`` — NO
``dc_govern_pack`` mirror) + ``dc_solve(workers=1, seed=1)`` + the dc incumbents.

B-11 — the projected ``objective`` is the REAL signed ``(stranded_power_kw, makespan)``
tuple (``DatacenterVerifier.objective``), and ``objective_labels`` is
``["stranded_power_kw","makespan"]`` (the Spec 0.5 T3 signed leaf) — NOT an accidental
FJSP ``(0,0)`` regression. The precondition (``dc_solve`` plan-extraction byte
determinism — solve twice, byte-equal plan) is re-asserted here over the FULL scenario
before the golden is trusted.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from feasible.canon.canonical import new_signing_key
from feasible.cert.plan_cert import emit_plan_cert, rule_pack_digest, verify_plan_cert
from feasible.cert.rulepack_cert import emit_rulepack_cert, verify_rulepack_cert
from feasible.checker.checker import check
from feasible.conflict.policy import DATACENTER_POLICY
from feasible.govern.pipeline import govern_pack
from feasible.smt.attest import attest_feasibility

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
from feasible.domains.datacenter.scenario import (
    CAPACITY_POLICY,
    build_dc_extracted_pack,
    dc_incumbent_a,
    dc_incumbent_b,
)
from feasible.domains.datacenter.solve import dc_solve

GOLDEN = Path(__file__).parent / "golden" / "datacenter_oracle.json"


def _build_certs():
    """Build the two datacenter certs DETERMINISTICALLY (single-worker, seeded) through
    the FROZEN ``govern_pack`` + ``dc_solve`` (NOT ``dc_govern_pack``). Mirrors the
    manufacturing ``_build_certs`` shape (universe rule-pack cert, active plan cert with
    the universe ``rule_pack_digest_override`` + the policy-dropped[] list)."""
    gov = govern_pack(build_dc_extracted_pack(), DATACENTER_POLICY)
    key = new_signing_key()
    rp = emit_rulepack_cert(gov.universe_ir, CAPACITY_POLICY, DATACENTER_POLICY, gov.resolutions, key)
    res = dc_solve(gov.active_ir, workers=1, seed=1)
    plan = res.plan
    assert plan is not None, f"dc_solve produced no plan: status={res.status}"
    inc_b = dc_incumbent_b(gov.active_ir)
    inc_a = dc_incumbent_a(gov.active_ir)
    dropped = [{"rule_id": rid, "drop_reason": "rule_inactive_for_plan_by_policy",
                "resolution_mode": "AUTO_BY_POLICY",
                "conflict_policy_ref": {"policy_id": DATACENTER_POLICY.policy_id,
                                        "digest": DATACENTER_POLICY.digest()}}
               for rid in gov.dropped_rule_ids]
    pc = emit_plan_cert(gov.active_ir, plan, res, check(plan, gov.active_ir),
                        attest_feasibility(plan, gov.active_ir), inc_a, inc_b, key,
                        dropped=dropped, rule_pack_digest_override=rule_pack_digest(gov.universe_ir))
    return gov, key, rp, pc


def _normalize_conflict_status(conflict_status: dict) -> dict:
    """Make conflict_status solver-tie-break-free: the Z3 unsat-core (``z3_core``) is a
    SET whose element order is a solver tie-break (the cert keeps it verbatim; only this
    test projection canonicalizes ordering). Every other field is already deterministic."""
    cs = copy.deepcopy(conflict_status)
    for res in cs.get("resolutions", []):
        if "z3_core" in res:
            res["z3_core"] = sorted(res["z3_core"])
    return cs


def oracle_surface(rp: dict, pc: dict) -> dict:
    """Deterministic, signature-free projection (mirror of the manufacturing surface)."""
    return {
        "rule_pack_digest": rp["rule_pack_digest"],
        "instance_ref": rp["instance_ref"],
        "coverage_ledger": rp["coverage_ledger"],
        "conflict_status": _normalize_conflict_status(rp["conflict_status"]),
        "active_rule_set_for_plan": pc["active_rule_set_for_plan"],
        "claims_formalization": pc["claims"]["formalization"],
        "claims_feasibility": pc["claims"]["feasibility"],
        # B-11: the REAL signed datacenter objective (stranded_power_kw, makespan),
        # NOT an FJSP (0,0).
        "objective": pc["claims"]["optimality"]["objective"]["value"],
        # the per-domain objective LABELS (Spec 0.5 T3 signed leaf), re-derived in
        # verify + read by render_html.
        "objective_labels": pc["claims"]["optimality"]["objective_labels"]["value"],
        # T1.5: the additive disjoint-solver corroboration leaf (value object
        # {"solver":"z3-smt","verdict":...}) — for datacenter this is the HEADLINE
        # upgrade: where the same-engine tripwire OPTS OUT, a disjoint engine (Z3/SMT)
        # now gives REAL optimality backing. SOLVER-REPORTED at emit.
        "disjoint_solver_corroboration": pc["claims"]["optimality"]["disjoint_solver_corroboration"]["value"],
        "kpi_vs_incumbent_B": pc["kpi_vs_incumbent_B"],
        "kpi_function_refs": pc["kpi_function_refs"],
        "incumbent_A_failure": pc["incumbent_A_failure"],
        "rule_pack_ref": pc["rule_pack_ref"],
    }


def test_datacenter_dc_solve_extraction_is_byte_deterministic() -> None:
    """B-11 precondition (re-asserted over the FULL scenario): ``dc_solve`` plan
    extraction is byte-deterministic (solve twice, byte-equal plan) — so the golden is
    a stable fixed surface, not a solver tie-break."""
    gov = govern_pack(build_dc_extracted_pack(), DATACENTER_POLICY)
    a = dc_solve(gov.active_ir, workers=1, seed=1)
    b = dc_solve(gov.active_ir, workers=1, seed=1)
    assert a.plan is not None and b.plan is not None
    assert a.plan.model_dump(mode="json") == b.plan.model_dump(mode="json")


def test_datacenter_oracle_unchanged() -> None:
    gov, key, rp, pc = _build_certs()
    # certs must still verify (signature/binding round-trips even though bytes differ run-to-run)
    assert verify_rulepack_cert(rp, key.public_key(), trusted_policies=None).ok
    assert verify_plan_cert(pc, key.public_key()).ok
    got = oracle_surface(rp, pc)
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert got == golden, "datacenter deterministic surface drifted from golden"
    # B-11: the frozen objective is the REAL datacenter tuple, not an accidental FJSP (0,0).
    assert got["objective_labels"] == ["stranded_power_kw", "makespan"]
    assert got["objective"] != [0, 0]
