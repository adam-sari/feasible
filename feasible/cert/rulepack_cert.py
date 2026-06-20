"""The Rule-Pack Certificate — certifies the CONSTRAINTS (Build B).

The two-certificate split: this immutable, signed snapshot (keyed by
``rule_pack_digest``) certifies the extracted+approved rules, the coverage
ledger, and the conflict resolution; the Plan Certificate (cert/plan_cert.py)
binds to this pack ONLY by that digest. Verify is self-contained: it
re-derives the digest, recomputes coverage, confirms the policy digest, and
checks the signature + body binding.
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, Field

from feasible.canon.canonical import canonicalize, public_key_hex, sign_dsse, verify_dsse
from feasible.ingest.segment import sha256_text
from feasible.cert.plan_cert import VerifyResult, public_key_hex_of, rule_pack_digest
from feasible.conflict.policy import ConflictPolicy
from feasible.govern.backtranslate import back_translate, polarity_matches_source
from feasible.govern.conflict import Resolution
from feasible.govern.coverage import build_coverage_ledger
from feasible.govern.ledger import build_trust_ledger, ledger_merkle_root
from feasible.ir.domain import ExceptionMode, FCIR, Rule

SCHEMA_VERSION = "feasible.rule_pack_cert.v1"


def emit_rulepack_cert(
    ir: FCIR,
    sop_text: str,
    policy: ConflictPolicy,
    resolutions: list[Resolution],
    private_key: Ed25519PrivateKey,
    sources_name: str = "shop_rules.md",
    rule_pack_id: str = "rule-pack-golden",
) -> dict:
    coverage = build_coverage_ledger(sop_text, ir)
    events = build_trust_ledger(ir, coverage, resolutions)
    internal_conflict = any(r.resolution_mode == "ESCALATE" for r in resolutions)

    cert: dict = {
        "schema_version": SCHEMA_VERSION,
        "rule_pack_id": rule_pack_id,
        "sources": [{"name": sources_name, "sha256": sha256_text(sop_text)}],
        "sop_text": sop_text,
        "rules": [r.model_dump(mode="json") for r in ir.rules],
        "back_translations": {
            r.rule_id: {"text": back_translate(r), "polarity_ok": polarity_matches_source(r)}
            for r in ir.rules
        },
        "span_classification": [
            {"char_start": e.char_start, "char_end": e.char_end, "category": e.category,
             "status": e.status, "covered_by": e.covered_by}
            for e in coverage.entries
        ],
        "coverage_ledger": {
            "complete": coverage.complete,
            "denominator": coverage.denominator,
            "red_findings": [e.text for e in coverage.red_findings],
            "relative_to": "deterministic span enumeration + closed normativity taxonomy",
        },
        "conflict_status": {
            "internal_conflict": internal_conflict,
            "resolutions": [
                {"obligation": r.conflict.obligation_id, "permission": r.conflict.permission_id,
                 "resolution_mode": r.resolution_mode, "dropped": r.dropped_rule_id,
                 "rationale": r.rationale, "z3_core": r.conflict.z3_core}
                for r in resolutions
            ],
        },
        "conflict_policy_ref": {"policy_id": policy.policy_id, "digest": policy.digest()},
        "conflict_policy": policy.model_dump(mode="json"),  # embedded for deterministic replay
        "trust_ledger_merkle_root": ledger_merkle_root(events),
        "rule_pack_digest": rule_pack_digest(ir),
        "trust_boundary": {
            "coverage": "completeness is RELATIVE to the deterministic enumeration + classifier, "
                        "not absolute.",
            "conflict": "static class priority + explicit-override interlock; richer defeasible "
                        "resolution is roadmap.",
            "extraction": "the LLM authors/maintains rules; the golden approved set is what is "
                          "certified (extraction is non-gating).",
        },
    }

    body = {k: v for k, v in cert.items() if k != "signature"}
    envelope = sign_dsse(body, private_key)
    envelope["public_key_hex"] = public_key_hex(private_key)
    cert["signature"] = envelope
    return cert


def verify_rulepack_cert(cert: dict, public_key: Ed25519PublicKey) -> VerifyResult:
    reasons: list[str] = []
    sig = cert.get("signature", {})
    envelope = {k: sig[k] for k in ("payload", "payloadType", "signatures") if k in sig}
    if not verify_dsse(envelope, public_key):
        reasons.append("signature invalid")
    if public_key_hex_of(public_key) != sig.get("public_key_hex"):
        reasons.append("embedded public-key binding mismatch")

    body = {k: v for k, v in cert.items() if k != "signature"}
    try:
        if canonicalize(body) != base64.b64decode(envelope.get("payload", "")):
            reasons.append("certificate body does not match the signed payload")
    except (ValueError, KeyError):
        reasons.append("malformed signature payload")

    # reconstruct the rule pack and re-derive the digest
    try:
        ir = FCIR.model_validate({"rules": cert["rules"], "instance": _stub_instance()})
    except Exception as e:  # noqa: BLE001
        reasons.append(f"rule reconstruction failed: {e}")
        return VerifyResult(ok=False, reasons=reasons)
    if rule_pack_digest(ir) != cert["rule_pack_digest"]:
        reasons.append("rule_pack_digest mismatch")

    # recompute coverage over the embedded SOP + rules
    coverage = build_coverage_ledger(cert["sop_text"], ir)
    if coverage.complete != cert["coverage_ledger"]["complete"]:
        reasons.append("coverage completeness mismatch")
    if coverage.denominator != cert["coverage_ledger"]["denominator"]:
        reasons.append("coverage denominator mismatch")
    if sha256_text(cert["sop_text"]) != cert["sources"][0]["sha256"]:
        reasons.append("SOP digest mismatch")

    # replay the conflict policy deterministically (no Z3 re-run)
    try:
        policy = ConflictPolicy.model_validate(cert["conflict_policy"])
    except Exception as e:  # noqa: BLE001
        reasons.append(f"policy reconstruction failed: {e}")
        return VerifyResult(ok=False, reasons=reasons)
    if policy.digest() != cert["conflict_policy_ref"]["digest"]:
        reasons.append("conflict_policy digest mismatch")
    by_id = {r.rule_id: r for r in ir.rules}
    for res in cert["conflict_status"]["resolutions"]:
        obl, perm, mode = by_id.get(res["obligation"]), by_id.get(res["permission"]), res["resolution_mode"]
        if obl is None or perm is None:
            reasons.append(f"resolution references missing rule(s): {res['obligation']}/{res['permission']}")
            continue
        po, pp = policy.priority(obl.resolution_class or ""), policy.priority(perm.resolution_class or "")
        has_exc = obl.exception_mode != ExceptionMode.NONE or perm.exception_mode != ExceptionMode.NONE
        if mode == "AUTO_BY_POLICY":
            if po is None or pp is None:
                reasons.append(f"AUTO resolution {res['obligation']}/{res['permission']} cites an undeclared class")
            elif po == pp:
                reasons.append(f"AUTO resolution between equal-priority classes ({obl.resolution_class})")
            elif has_exc:
                reasons.append("AUTO resolution despite an exception/override marker")
            else:
                lower = obl.rule_id if po < pp else perm.rule_id
                if res["dropped"] != lower:
                    reasons.append(f"AUTO dropped {res['dropped']} != lower-priority {lower}")
        elif mode == "ESCALATE":
            if po is not None and pp is not None and po != pp and not has_exc:
                reasons.append("ESCALATE that should have auto-resolved (unequal priorities, no exception)")

    return VerifyResult(ok=len(reasons) == 0, reasons=reasons)


def _stub_instance() -> dict:
    # rule_pack_digest depends only on rules; FCIR needs an instance to validate.
    return {"jobs": [], "operations": [], "machines": [], "setup_matrix": {}, "maintenance": [], "horizon": 0}
