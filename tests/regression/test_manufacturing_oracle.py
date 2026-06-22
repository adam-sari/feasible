"""The anti-drift tripwire: a frozen projection of the manufacturing certs over the
DETERMINISTIC surfaces only (body claims, digests, ledger, verdicts) — never signature
bytes (random key) and never raw plan assignments (solver tie-breaks)."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from feasible.canon.canonical import new_signing_key
from feasible.cert.plan_cert import emit_plan_cert, rule_pack_digest, verify_plan_cert
from feasible.cert.rulepack_cert import emit_rulepack_cert, verify_rulepack_cert
from feasible.checker.checker import check
from feasible.conflict.policy import MANUFACTURING_POLICY
from feasible.govern.pipeline import govern_pack
from feasible.scenario import (
    SHOP_RULES, build_extracted_pack, generate_incumbent_b, make_incumbent_a,
)
from feasible.smt.attest import attest_feasibility
from feasible.solve.orchestrate import solve

GOLDEN = Path(__file__).parent / "golden" / "manufacturing_oracle.json"


def _build_certs():
    gov = govern_pack(build_extracted_pack(), MANUFACTURING_POLICY)
    key = new_signing_key()
    rp = emit_rulepack_cert(gov.universe_ir, SHOP_RULES, MANUFACTURING_POLICY, gov.resolutions, key)
    res = solve(gov.active_ir, max_seconds=30.0, workers=1, seed=1)
    plan = res.plan
    inc_b = generate_incumbent_b(gov.active_ir)
    inc_a = make_incumbent_a(inc_b)
    dropped = [{"rule_id": rid, "drop_reason": "rule_inactive_for_plan_by_policy",
                "resolution_mode": "AUTO_BY_POLICY",
                "conflict_policy_ref": {"policy_id": MANUFACTURING_POLICY.policy_id,
                                        "digest": MANUFACTURING_POLICY.digest()}}
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
    """Deterministic, signature-free projection."""
    return {
        "rule_pack_digest": rp["rule_pack_digest"],
        "instance_ref": rp["instance_ref"],
        "coverage_ledger": rp["coverage_ledger"],
        "conflict_status": _normalize_conflict_status(rp["conflict_status"]),
        "active_rule_set_for_plan": pc["active_rule_set_for_plan"],
        "claims_formalization": pc["claims"]["formalization"],
        "claims_feasibility": pc["claims"]["feasibility"],
        "objective": pc["claims"]["optimality"]["objective"]["value"],
        # the one additive signed field in Spec 0.5 (Task 3): the per-domain
        # objective LABELS, re-derived in verify + read by render_html.
        "objective_labels": pc["claims"]["optimality"]["objective_labels"]["value"],
        "kpi_vs_incumbent_B": pc["kpi_vs_incumbent_B"],
        "kpi_function_refs": pc["kpi_function_refs"],
        "incumbent_A_failure": pc["incumbent_A_failure"],
        "rule_pack_ref": pc["rule_pack_ref"],
    }


def test_manufacturing_oracle_unchanged():
    gov, key, rp, pc = _build_certs()
    # certs must still verify (signature/binding round-trips even though bytes differ run-to-run)
    assert verify_rulepack_cert(rp, key.public_key()).ok
    assert verify_plan_cert(pc, key.public_key()).ok
    got = oracle_surface(rp, pc)
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert got == golden, "manufacturing deterministic surface drifted from v0.1.1 golden"
