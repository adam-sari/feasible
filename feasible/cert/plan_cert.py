"""The signed Plan Certificate + a solver-free ``verify`` + an HTML projection.

The cert EMBEDS the instance and the active rule set, so ``verify_plan_cert`` is
fully self-contained (no file I/O): it reconstructs the FCIR from the cert,
re-runs the polynomial checker on the embedded plan, recomputes the objective,
and re-derives the rule-pack / active-set digests — then verifies the signature
and the embedded-key binding. Every claim leaf carries a ``provenance``
discriminator drawn ONLY from the non-LLM set (the LLM never touches a plan
cert's truth claims).
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from feasible.canon.canonical import (
    canonicalize,
    digest_of,
    public_key_from_hex,
    public_key_hex,
    sign_dsse,
    verify_dsse,
)
from feasible.checker.checker import CheckResult, check
from feasible.ir.domain import FCIR, Instance, Plan, Rule
from feasible.solve.optimality import optimality_tripwire
from feasible.solve.orchestrate import (
    SolveResult,
    late_priority_orders,
    recompute_objective,
    total_changeover_time,
    weighted_tardiness,
)
from feasible.smt.attest import AttestResult

SCHEMA_VERSION = "feasible.plan_cert.v1"
ALLOWED_PROVENANCE = {
    "checker", "solver", "objective_recompute", "ledger", "signature", "rule_pack_digest_ref",
}


class VerifyResult(BaseModel):
    ok: bool
    reasons: list[str] = Field(default_factory=list)


def _leaf(value, provenance: str) -> dict:
    assert provenance in ALLOWED_PROVENANCE, f"illegal claim provenance: {provenance}"
    return {"value": value, "provenance": provenance}


def rule_pack_digest(ir: FCIR) -> str:
    body = [r.model_dump(mode="json") for r in sorted(ir.rules, key=lambda r: r.rule_id)]
    return digest_of(body)


def active_rule_ids(ir: FCIR) -> list[str]:
    return sorted(r.rule_id for r in ir.hard_plan_rules())


def active_rule_set_digest(ir: FCIR, dropped: list[str]) -> str:
    return digest_of({"active": active_rule_ids(ir), "dropped": sorted(dropped)})


def _kpi(ir: FCIR, optimized: Plan, incumbent_b: Plan) -> dict:
    return {
        "weighted_tardiness": {
            "optimized": weighted_tardiness(ir, optimized),
            "incumbent_b": weighted_tardiness(ir, incumbent_b),
        },
        "late_priority_orders": {
            "optimized": late_priority_orders(ir, optimized),
            "incumbent_b": late_priority_orders(ir, incumbent_b),
        },
        "total_changeover_time": {
            "optimized": total_changeover_time(ir, optimized),
            "incumbent_b": total_changeover_time(ir, incumbent_b),
        },
    }


def _incumbent_a_failure(ir: FCIR, incumbent_a: Plan) -> dict:
    res = check(incumbent_a, ir)
    night = [v for v in res.violations if v.rule_id == "R-6.1-NIGHT-CLEANOUT"]
    v = night[0] if night else (res.violations[0] if res.violations else None)
    if v is None:
        return {"violated_rule_ref": None, "span": None, "counter_witness": {}}
    return {
        "violated_rule_ref": v.rule_id,
        "span": v.span.model_dump(mode="json") if v.span is not None else None,
        "counter_witness": v.counter_witness,
    }


def emit_plan_cert(
    ir: FCIR,
    plan: Plan,
    result: SolveResult,
    check_result: CheckResult,
    attest: AttestResult,
    incumbent_a: Plan,
    incumbent_b: Plan,
    private_key: Ed25519PrivateKey,
    plan_cert_id: str = "plan-cert-0001",
) -> dict:
    objective = list(result.objective) if result.objective else [0, 0]
    tripwire_ok = optimality_tripwire(ir, (objective[0], objective[1]))
    gap_bps = 0 if (result.gap == 0.0) else -1  # -1 = not proven optimal

    cert: dict = {
        "schema_version": SCHEMA_VERSION,
        "plan_cert_id": plan_cert_id,
        "rule_pack_ref": {
            "rule_pack_id": "rule-pack-golden",
            "rule_pack_digest": rule_pack_digest(ir),
            "rule_pack_cert_signature_ref": None,
        },
        "active_rule_set_for_plan": {
            "active_rule_ids": active_rule_ids(ir),
            "dropped": [],
            "active_rule_set_digest": active_rule_set_digest(ir, []),
        },
        "instance_ref": {"instance_digest": digest_of(ir.instance.model_dump(mode="json"))},
        # embedded for a self-contained, solver-free verify:
        "instance": ir.instance.model_dump(mode="json"),
        "rules": [r.model_dump(mode="json") for r in ir.rules],
        "plan": plan.model_dump(mode="json"),
        "claims": {
            "formalization": {
                "rule_pack_digest_ref": _leaf(rule_pack_digest(ir), "rule_pack_digest_ref"),
                "n_hard_rules": _leaf(len(active_rule_ids(ir)), "ledger"),
                "rules_grounded_in_source": _leaf(
                    sum(
                        1 for r in ir.hard_plan_rules()
                        if any(getattr(s, "role", "") == "primary_normative" for s in r.provenance.spans)
                    ),
                    "ledger",
                ),
            },
            "feasibility": {
                "checker": _leaf("PASS" if check_result.passed else "FAIL", "checker"),
                "z3_attest": _leaf("attested" if attest.feasible else "infeasible", "checker"),
            },
            "optimality": {
                "optimal_per_cpsat": _leaf(result.status == "OPTIMAL", "solver"),
                "gap_bps": _leaf(gap_bps, "solver"),
                "objective": _leaf(objective, "objective_recompute"),
                "tripwire_passed": _leaf(tripwire_ok, "solver"),
                "label": _leaf("optimal per CP-SAT, same-engine tripwire", "solver"),
            },
        },
        "kpi_vs_incumbent_B": _kpi(ir, plan, incumbent_b),
        "incumbent_A_failure": _incumbent_a_failure(ir, incumbent_a),
        "trust_boundary": {
            "verification": "IR-relative: the plan satisfies the approved IR; the source->IR edge "
                            "is closed by the extraction-independence layer + human gate (Build B).",
            "optimality": "CP-SAT self-reported gap + a SAME-ENGINE tripwire; not independently proven "
                          "(MiniZinc->Chuffed is the v1.1 upgrade).",
            "shared_convention": "compiler and checker share only the canonical (start, stable_op_id) order.",
            "semantic_correlation_residual": "a misreading shared by extraction + reviewer + checker is "
                                             "not caught by v1.",
        },
    }

    body = {k: v for k, v in cert.items() if k != "signature"}
    envelope = sign_dsse(body, private_key)
    envelope["public_key_hex"] = public_key_hex(private_key)
    cert["signature"] = envelope
    return cert


def iter_claim_leaves(claims: dict):
    for group in claims.values():
        for leaf in group.values():
            if isinstance(leaf, dict) and "provenance" in leaf:
                yield leaf


def _fcir_from_cert(cert: dict) -> FCIR:
    return FCIR(
        rules=[Rule.model_validate(r) for r in cert["rules"]],
        instance=Instance.model_validate(cert["instance"]),
    )


def verify_plan_cert(cert: dict, public_key: Ed25519PublicKey) -> VerifyResult:
    reasons: list[str] = []
    sig = cert.get("signature", {})

    # 1) signature + key binding
    envelope = {k: sig[k] for k in ("payload", "payloadType", "signatures") if k in sig}
    if not verify_dsse(envelope, public_key):
        reasons.append("signature invalid")
    if public_key_hex_of(public_key) != sig.get("public_key_hex"):
        reasons.append("embedded public-key binding mismatch")

    # 2) the visible body matches the signed bytes (tamper-evidence)
    body = {k: v for k, v in cert.items() if k != "signature"}
    import base64
    try:
        signed_bytes = base64.b64decode(envelope.get("payload", ""))
        if canonicalize(body) != signed_bytes:
            reasons.append("certificate body does not match the signed payload")
    except (ValueError, KeyError):
        reasons.append("malformed signature payload")

    # 3) reconstruct + re-check the embedded plan (solver-free)
    try:
        ir = _fcir_from_cert(cert)
        plan = Plan.model_validate(cert["plan"])
    except Exception as e:  # noqa: BLE001 - report any reconstruction failure
        reasons.append(f"cert reconstruction failed: {e}")
        return VerifyResult(ok=False, reasons=reasons)

    chk = check(plan, ir)
    if not chk.passed:
        reasons.append("checker FAIL on the embedded plan: " + "; ".join(v.message for v in chk.violations))

    # 4) recompute the canonical objective and match the cert's claim
    recomputed = list(recompute_objective(ir, plan))
    claimed = cert["claims"]["optimality"]["objective"]["value"]
    if recomputed != list(claimed):
        reasons.append(f"objective mismatch: recomputed {recomputed} != cert {claimed}")

    # 5) re-derive digests
    if rule_pack_digest(ir) != cert["rule_pack_ref"]["rule_pack_digest"]:
        reasons.append("rule_pack_digest mismatch")
    if active_rule_set_digest(ir, cert["active_rule_set_for_plan"]["dropped"]) != cert["active_rule_set_for_plan"]["active_rule_set_digest"]:
        reasons.append("active_rule_set_digest mismatch")

    return VerifyResult(ok=len(reasons) == 0, reasons=reasons)


def public_key_hex_of(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes_raw().hex()


def render_html(plan_cert: dict) -> str:
    import json

    obj = plan_cert["claims"]["optimality"]["objective"]["value"]
    feas = plan_cert["claims"]["feasibility"]["checker"]["value"]
    inc_a = plan_cert["incumbent_A_failure"]
    span_q = ""
    if inc_a.get("span"):
        span_q = inc_a["span"].get("quoted_text", "")
    payload_json = json.dumps(plan_cert, indent=2)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Feasible Plan Certificate</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:60rem}}
.claim{{border:1px solid #ccc;border-radius:8px;padding:1rem;margin:.5rem 0}}
.pass{{color:#0a0}} .fail{{color:#c00}} pre{{background:#f6f6f6;padding:1rem;overflow:auto}}</style>
</head><body>
<h1>Feasible — Plan Certificate</h1>
<div class="claim"><b>Feasibility:</b> <span class="{ 'pass' if feas=='PASS' else 'fail' }">{feas}</span>
(independently re-checkable offline via <code>feasible verify</code>)</div>
<div class="claim"><b>Optimality:</b> objective = {obj} — {plan_cert['claims']['optimality']['label']['value']}</div>
<div class="claim"><b>Gotcha (incumbent A):</b> violated {inc_a.get('violated_rule_ref')} —
cited clause: <i>"{span_q}"</i></div>
<h2>Signed canonical JSON (source of truth)</h2>
<pre>{payload_json}</pre>
</body></html>"""
