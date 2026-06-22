"""The Rule-Pack Certificate — certifies the CONSTRAINTS (Build B).

The two-certificate split: this immutable, signed snapshot (keyed by
``rule_pack_digest``) certifies the extracted+approved rules, the instance it was
detected over, the coverage ledger, and the conflict resolution; the Plan
Certificate (cert/plan_cert.py) binds to this pack by the digest AND the instance
ref. Verify is self-contained and solver-free: it re-derives the rule-pack +
instance digests, recomputes coverage, re-anchors every primary_normative quote to
the SOP, confirms the policy digest AND pins it to a trusted policy store, and
REPLAYS each conflict resolution against the signed policy — re-establishing that
every resolution is over a real CONFLICT_ONLY-PERMISSION→target pair and that
auto-resolution only ever drops the permission, so a forged pair / inverted policy
cannot silently drop a hard rule — then checks the signature + body binding.
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, Field

from feasible.canon.canonical import canonicalize, digest_of, public_key_hex, sign_dsse, verify_dsse
from feasible.ingest.segment import anchor, sha256_text
from feasible.cert.plan_cert import VerifyResult, active_rule_ids, public_key_hex_of, rule_pack_digest
from feasible.conflict.policy import ConflictPolicy, trusted_policy_set
from feasible.govern.backtranslate import back_translate, polarity_matches_source
from feasible.govern.conflict import Resolution, _scope_realizable
from feasible.govern.coverage import build_coverage_ledger
from feasible.govern.ledger import build_trust_ledger, ledger_merkle_root
from feasible.ir.domain import ClauseKind, CompileMode, ExceptionMode, FCIR, Rule

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
        # conflict detection is instance-grounded (scope realizability), so the pack
        # commits to the instance it certified over — the Plan Cert binds to this.
        "instance": ir.instance.model_dump(mode="json"),
        "instance_ref": {"instance_digest": digest_of(ir.instance.model_dump(mode="json"))},
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


def verify_rulepack_cert(
    cert: dict,
    public_key: Ed25519PublicKey,
    trusted_policies: frozenset[tuple[str, str]] | None = None,
) -> VerifyResult:
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

    # reconstruct the rule pack (over its committed instance) and re-derive the digests
    try:
        ir = FCIR.model_validate({"rules": cert["rules"], "instance": cert["instance"]})
    except Exception as e:  # noqa: BLE001
        reasons.append(f"rule reconstruction failed: {e}")
        return VerifyResult(ok=False, reasons=reasons)
    if rule_pack_digest(ir) != cert["rule_pack_digest"]:
        reasons.append("rule_pack_digest mismatch")
    if digest_of(ir.instance.model_dump(mode="json")) != cert.get("instance_ref", {}).get("instance_digest"):
        reasons.append("instance_ref digest mismatch")

    # recompute coverage over the embedded SOP + rules
    coverage = build_coverage_ledger(cert["sop_text"], ir)
    if coverage.complete != cert["coverage_ledger"]["complete"]:
        reasons.append("coverage completeness mismatch")
    if coverage.denominator != cert["coverage_ledger"]["denominator"]:
        reasons.append("coverage denominator mismatch")
    if sha256_text(cert["sop_text"]) != cert["sources"][0]["sha256"]:
        reasons.append("SOP digest mismatch")

    # re-anchor every primary_normative quote against the embedded SOP (the same gate the
    # builder runs at emit) — so a re-signed cert cannot fabricate a cited clause that does
    # not occur in the source. Combined with the auditor pinning sources[].sha256 to the
    # real SOP, the gotcha's cited clause is grounded in the document, not the signer's word.
    sop = cert["sop_text"]
    from feasible.ir.domain import TextSpan
    for r in ir.rules:
        for s in r.provenance.spans:
            if isinstance(s, TextSpan) and s.role == "primary_normative":
                pos = anchor(s.quoted_text, sop)
                if pos is None:
                    reasons.append(f"rule {r.rule_id}: quoted clause is not present in the SOP")
                elif s.char_start >= 0 and (s.char_start, s.char_end) != pos:
                    reasons.append(f"rule {r.rule_id}: quoted clause span [{s.char_start},{s.char_end}) "
                                   f"does not match its SOP position {pos}")

    # replay the conflict policy deterministically (no Z3 re-run)
    try:
        policy = ConflictPolicy.model_validate(cert["conflict_policy"])
    except Exception as e:  # noqa: BLE001
        reasons.append(f"policy reconstruction failed: {e}")
        return VerifyResult(ok=False, reasons=reasons)
    if policy.digest() != cert["conflict_policy_ref"]["digest"]:
        reasons.append("conflict_policy digest mismatch")
    # the trust store defaults to the per-domain registry (trusted_policy_set), assembled
    # from the registered domains' safety-preserving policies; pass an explicit frozenset
    # (e.g. frozenset()) only to pin/override it. A re-signed cert embedding an INVERTED
    # policy is rejected here at the root.
    store = trusted_policy_set() if trusted_policies is None else trusted_policies
    ref = (cert["conflict_policy_ref"].get("policy_id"), cert["conflict_policy_ref"].get("digest"))
    if ref not in store:
        reasons.append(f"conflict policy {ref[0]}@{(ref[1] or '')[:12]} is not in the trusted policy set")
    by_id = {r.rule_id: r for r in ir.rules}
    for res in cert["conflict_status"]["resolutions"]:
        obl, perm, mode = by_id.get(res["obligation"]), by_id.get(res["permission"]), res["resolution_mode"]
        if obl is None or perm is None:
            reasons.append(f"resolution references missing rule(s): {res['obligation']}/{res['permission']}")
            continue
        # A resolution is legitimate ONLY over a real detection pair: `perm` must be a
        # CONFLICT_ONLY PERMISSION whose params['target_rule'] is `obl` (exactly what
        # detect_normative_conflicts produces). Without this, a re-signed cert could name
        # any two hard plan rules, mark them AUTO_BY_POLICY, and silently drop the lower
        # one — disabling a safety/maintenance constraint with no visible permission.
        if perm.clause_kind != ClauseKind.PERMISSION or perm.compile_mode != CompileMode.CONFLICT_ONLY:
            reasons.append(f"resolution permission {perm.rule_id} is not a CONFLICT_ONLY PERMISSION")
        if perm.params.get("target_rule") != obl.rule_id:
            reasons.append(f"resolution permission {perm.rule_id} does not target obligation {obl.rule_id}")
        # the conflict must be REALIZABLE on the certified instance (detect_normative_conflicts
        # gates on this) — so a recorded auto-drop must correspond to a clash the detector would
        # actually have produced, not a fabricated governance narrative over a swapped instance.
        if not _scope_realizable(ir, perm):
            reasons.append(f"resolution {perm.rule_id}->{obl.rule_id} cites a conflict not realizable on the instance")
        po, pp = policy.priority(obl.resolution_class or ""), policy.priority(perm.resolution_class or "")
        # mirror resolve_conflicts EXACTLY: exception OR an explicit lex-specialis override
        # blocks auto-resolution (govern/conflict.py).
        has_exc = (
            obl.exception_mode != ExceptionMode.NONE or perm.exception_mode != ExceptionMode.NONE
            or bool(obl.overrides) or bool(perm.overrides)
        )
        if mode == "AUTO_BY_POLICY":
            if po is None or pp is None:
                reasons.append(f"AUTO resolution {res['obligation']}/{res['permission']} cites an undeclared class")
            elif po <= pp:
                # the ONLY direction the resolver auto-resolves: obligation strictly
                # outranks the permission, so the permission is dropped. A permission that
                # would override a hard obligation must ESCALATE — so a re-signed cert can't
                # invert the class lattice (or the policy) to silently drop a hard rule.
                reasons.append(f"AUTO requires the obligation class to strictly outrank the permission "
                               f"(po={po} <= pp={pp}); a clash the permission would win must ESCALATE")
            elif has_exc:
                reasons.append("AUTO resolution despite an exception/override marker")
            elif res["dropped"] != perm.rule_id:
                reasons.append(f"AUTO dropped {res['dropped']} but must drop the permission {perm.rule_id}")
        elif mode == "ESCALATE":
            if po is not None and pp is not None and po > pp and not has_exc:
                reasons.append("ESCALATE that should have auto-resolved (obligation outranks, no exception)")
        else:
            reasons.append(f"unknown resolution_mode {mode!r}")

    return VerifyResult(ok=len(reasons) == 0, reasons=reasons)


def bundle_binding_reasons(plan_cert: dict, rulepack_cert: dict) -> list[str]:
    """Cross-checks between an already-individually-verified Plan Cert and Rule-Pack
    Cert. The opaque ``rule_pack_digest`` deliberately does NOT let the Plan Cert
    re-derive the universe standalone, so these bindings must be enforced here:

    1. the Plan Cert's universe-digest binding equals the Rule-Pack Cert's digest;
    2. the two certs commit to the SAME instance (``instance_ref.instance_digest``);
    3. the rules the Plan Cert DROPPED exactly equal the Rule-Pack Cert's *replayed*
       policy auto-drops;
    4. the Plan Cert's ACTIVE set is exactly (universe hard-plan rules − auto-drops) —
       so a plan can't silently omit a hard rule it never recorded dropping; and
    5. every rule body the Plan Cert carries is byte-identical to the universe's
       (same rule_id ⇒ same object) — so a rule can't be silently *weakened*.

    Without (4)/(5) a Plan Cert could disable or weaken a hard safety rule while both
    certs still verify standalone and the dropped[] lists agree.
    """
    reasons: list[str] = []
    if plan_cert["rule_pack_ref"]["rule_pack_digest"] != rulepack_cert["rule_pack_digest"]:
        reasons.append("rule_pack binding mismatch (plan cert <-> rule-pack cert)")

    plan_inst = plan_cert.get("instance_ref", {}).get("instance_digest")
    rp_inst = rulepack_cert.get("instance_ref", {}).get("instance_digest")
    if plan_inst != rp_inst:
        reasons.append("instance binding mismatch (plan cert <-> rule-pack cert)")

    auto_dropped = sorted(
        r["dropped"] for r in rulepack_cert["conflict_status"]["resolutions"]
        if r["resolution_mode"] == "AUTO_BY_POLICY" and r["dropped"] is not None
    )
    plan_dropped = sorted(
        d["rule_id"] if isinstance(d, dict) else d
        for d in plan_cert["active_rule_set_for_plan"]["dropped"]
    )
    if auto_dropped != plan_dropped:
        reasons.append(f"plan-cert dropped {plan_dropped} != rule-pack auto-dropped {auto_dropped}")

    # (4) the active set must be exactly universe-hard-plan-rules minus the auto-drops
    try:
        universe = FCIR.model_validate({"rules": rulepack_cert["rules"], "instance": _stub_instance()})
        expected_active = sorted(set(active_rule_ids(universe)) - set(auto_dropped))
        if plan_cert["active_rule_set_for_plan"]["active_rule_ids"] != expected_active:
            reasons.append(
                f"plan-cert active set {plan_cert['active_rule_set_for_plan']['active_rule_ids']} "
                f"!= universe minus auto-drops {expected_active}"
            )
    except Exception as e:  # noqa: BLE001
        reasons.append(f"could not reconstruct universe for active-set binding: {e}")

    # (5) shared rule bodies must be byte-identical to the universe (no silent weakening)
    universe_by_id = {r["rule_id"]: r for r in rulepack_cert["rules"]}
    for pr in plan_cert.get("rules", []):
        rid = pr.get("rule_id")
        if rid not in universe_by_id:
            reasons.append(f"plan-cert rule {rid} is absent from the certified universe")
        elif pr != universe_by_id[rid]:
            reasons.append(f"plan-cert rule {rid} differs from the certified universe rule body")

    # (6) every drop the plan cert records must cite the SAME conflict policy the rule-pack
    # certified (so a drop can't be justified by a fabricated side-policy)
    rp_policy = rulepack_cert.get("conflict_policy_ref", {})
    for d in plan_cert["active_rule_set_for_plan"]["dropped"]:
        ref = d.get("conflict_policy_ref") if isinstance(d, dict) else None
        if ref is not None and ref.get("digest") != rp_policy.get("digest"):
            reasons.append(f"plan-cert drop {d.get('rule_id')} cites a different conflict policy than the rule-pack")
    return reasons


def _stub_instance() -> dict:
    # rule_pack_digest depends only on rules; FCIR needs an instance to validate.
    return {"jobs": [], "operations": [], "machines": [], "setup_matrix": {}, "maintenance": [], "horizon": 0}
