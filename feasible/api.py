"""The domain-agnostic facade — the SINGLE two-cert orchestration (Task 12).

Every consumer (the CLI, and the three forked tracks: React console, datacenter,
gemini) calls THESE functions instead of re-implementing the universe-rule-pack +
active-plan-cert loop. The loop is lifted verbatim out of ``cli.certify``: govern
the extracted pack, emit the Rule-Pack Cert over the UNIVERSE, solve the ACTIVE
set, emit the Plan Cert with the universe ``rule_pack_digest_override`` + the
policy-dropped[] list, then bind the two certs. The facade returns the frozen
view-model dataclasses from ``feasible.domains.base`` (the contract every track
forks against) plus a ``TrustVector`` derived from the verify reasons + the
domain's capability descriptor.

This module owns the crypto orchestration (a ``Domain`` owns NO crypto): it
resolves the domain bundle through the registry by ``domain_id``, but the signing
key, the DSSE envelope, and the two-cert binding live here.

``verify`` is solver-free + LLM-free: it calls only ``verify_plan_cert`` /
``verify_rulepack_cert`` / ``bundle_binding_reasons`` (which themselves dispatch
through the statically-registered domain bundle), never a cert-supplied callable.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from feasible.canon.canonical import new_signing_key, public_key_from_hex
from feasible.cert.plan_cert import (
    emit_plan_cert,
    rule_pack_digest,
    verify_plan_cert,
)
from feasible.cert.rulepack_cert import (
    bundle_binding_reasons,
    emit_rulepack_cert,
    verify_rulepack_cert,
)
from feasible.checker.checker import check
from feasible.conflict.policy import DEFAULT_TRUSTED_POLICIES
from feasible.domains import get_domain
from feasible.domains.base import (
    CertifyResult,
    CertsView,
    ConstraintsView,
    Domain,
    DomainVerifier,
    InputsView,
    ScenarioInfo,
    TimelineView,
    TrustVector,
    VerifyView,
)
from feasible.govern.pipeline import govern_pack
from feasible.ir.domain import FCIR, Plan
from feasible.smt.attest import attest_feasibility
from feasible.solve.orchestrate import solve

# The registered scenarios surfaced by the facade. Manufacturing only for Spec 0;
# the datacenter track appends its id here when it forks against this seam.
_SCENARIOS: list[str] = ["manufacturing"]


def _resolve(domain_id: str) -> tuple[Domain, DomainVerifier]:
    """Resolve the registered domain bundle (fail-closed on an unknown id). The
    import side-effect registers manufacturing; ``get_domain`` raises
    ``UnknownDomainError`` for anything unregistered."""
    import feasible.domains.manufacturing  # noqa: F401  (registers the manufacturing domain)

    return get_domain(domain_id)


def _govern(domain: Domain):
    """Run the §5.2/§4.4 governance pipeline over the domain's extracted pack."""
    return govern_pack(domain.build_extracted_pack(), domain.policy())


def list_scenarios() -> list[ScenarioInfo]:
    """The registered domains as ``ScenarioInfo`` view-models (manufacturing only)."""
    out: list[ScenarioInfo] = []
    for domain_id in _SCENARIOS:
        domain, _verifier = _resolve(domain_id)
        out.append(ScenarioInfo(domain_id=domain_id, display_name=domain.display_name, data="real"))
    return out


def load_inputs(domain_id: str) -> InputsView:
    """The instance (jobs / operations / machines) as the frozen ``InputsView``."""
    domain, _verifier = _resolve(domain_id)
    inst = domain.golden_ir().instance
    return InputsView(
        domain_id=domain_id,
        jobs=[j.model_dump(mode="json") for j in inst.jobs],
        operations=[o.model_dump(mode="json") for o in inst.operations],
        machines=list(inst.machines),
    )


def get_constraints(domain_id: str) -> ConstraintsView:
    """The approved universe rules + the policy-dropped rules as ``ConstraintsView``."""
    domain, _verifier = _resolve(domain_id)
    gov = _govern(domain)
    dropped = _dropped_from_gov(gov, domain)
    return ConstraintsView(
        domain_id=domain_id,
        rules=[r.model_dump(mode="json") for r in gov.universe_ir.rules],
        dropped=dropped,
    )


def _dropped_from_gov(gov, domain: Domain) -> list[dict]:
    """The rich ``dropped[]`` render metadata for the policy-auto-dropped rules —
    each citing the domain's signed conflict policy (so a drop can't be justified
    by a fabricated side-policy; ``bundle_binding_reasons`` cross-checks the ref)."""
    policy = domain.policy()
    return [
        {
            "rule_id": rid,
            "drop_reason": "rule_inactive_for_plan_by_policy",
            "resolution_mode": "AUTO_BY_POLICY",
            "conflict_policy_ref": {"policy_id": policy.policy_id, "digest": policy.digest()},
        }
        for rid in gov.dropped_rule_ids
    ]


def certify(domain_id: str, *, signer_key: Ed25519PrivateKey | None = None) -> CertifyResult:
    """The full two-cert loop for ``domain_id`` (the SINGLE orchestration).

    1. govern the extracted pack (§5.2 correction + §4.4 conflict resolution);
    2. emit the Rule-Pack Cert over the UNIVERSE (R-4.4 retained — coverage/replay
       need it), keyed by the universe ``rule_pack_digest``;
    3. solve the ACTIVE set (universe minus the policy auto-drops);
    4. emit the Plan Cert over the active set, binding to the universe digest via
       ``rule_pack_digest_override`` and recording the policy-dropped[] list.

    Both certs are signed by ``signer_key`` (a fresh ephemeral key when omitted —
    the self-described mode). Returns the certs + a ``TrustVector`` whose
    ``signature`` reflects whether the loop bound under a caller-pinned key.
    """
    domain, verifier = _resolve(domain_id)
    key = signer_key or new_signing_key()

    gov = _govern(domain)
    universe_ir: FCIR = gov.universe_ir
    active_ir: FCIR = gov.active_ir
    universe_digest = rule_pack_digest(universe_ir)
    dropped = _dropped_from_gov(gov, domain)

    rp_cert = emit_rulepack_cert(
        universe_ir, domain.policy_doc(), domain.policy(), gov.resolutions, key)

    result = solve(active_ir, max_seconds=30.0)
    if result.plan is None:
        raise RuntimeError(f"solve produced no plan for {domain_id!r}: status={result.status}")
    plan: Plan = result.plan

    incs = domain.incumbents()
    inc_a, inc_b = incs["A"], incs["B"]
    chk = check(plan, active_ir)
    att = attest_feasibility(plan, active_ir)
    plan_cert = emit_plan_cert(
        active_ir, plan, result, chk, att, inc_a, inc_b, key,
        dropped=dropped, rule_pack_digest_override=universe_digest)

    # derive the TrustVector from the loop's own verify reasons (a self-described
    # cert that fails to bind would surface here, not be silently asserted "pass").
    signature = "authenticated" if signer_key is not None else "self_described"
    trust_vector = _trust_vector(
        domain, verifier, plan_cert, rp_cert, key.public_key(), signature=signature)

    return CertifyResult(
        domain_id=domain_id,
        plan_cert=plan_cert,
        rule_pack_cert=rp_cert,
        trust_vector=trust_vector,
    )


def get_certificates(domain_id: str, *, signer_key: Ed25519PrivateKey | None = None) -> CertsView:
    """The two certs (re-running the loop) as a ``CertsView``."""
    result = certify(domain_id, signer_key=signer_key)
    return CertsView(
        domain_id=domain_id,
        plan_cert=result.plan_cert,
        rule_pack_cert=result.rule_pack_cert,
    )


def get_timeline(domain_id: str, *, signer_key: Ed25519PrivateKey | None = None) -> TimelineView:
    """The certified plan as a timeline view (machine lanes + op/cleanout intervals)."""
    result = certify(domain_id, signer_key=signer_key)
    plan = result.plan_cert["plan"]
    inst = result.plan_cert["instance"]
    domain, _verifier = _resolve(domain_id)
    lanes = [{"machine": mc} for mc in domain.viz_meta().get("machines", inst["machines"])]
    dur = {o["op_id"]: o["duration"] for o in inst["operations"]}
    intervals = [
        {"op_id": op, "machine": m, "start": s, "end": s + dur.get(op, 0)}
        for op, (s, m) in plan["assignments"].items()
    ]
    intervals += [
        {"op_id": "CLEANOUT", "machine": cm, "start": cs, "end": ce, "reason": reason}
        for (cm, cs, ce, reason) in plan["cleanouts"]
    ]
    return TimelineView(domain_id=domain_id, lanes=lanes, intervals=intervals)


def _public_key_for(cert: dict, signer_key_hex: str | None) -> Ed25519PublicKey:
    """The key the cert is checked against: the caller-pinned signer key (a
    re-signed forgery under any other key is then rejected) or the cert's own
    self-described key (re-checked, identity UNVERIFIED)."""
    return public_key_from_hex(signer_key_hex or cert["signature"]["public_key_hex"])


def _trust_vector(
    domain: Domain,
    verifier: DomainVerifier,
    plan_cert: dict,
    rule_pack_cert: dict,
    public_key: Ed25519PublicKey,
    *,
    signature: str,
) -> TrustVector:
    """The honesty descriptor derived from a real verify pass (never asserted blind).

    ``checker`` is ``pass`` only if both certs verify AND bind; ``data`` /
    ``coverage`` / ``conflict_replay`` come from the domain's capability descriptor
    (manufacturing: real data, calibrated coverage, verified conflict replay — its
    ``trust_boundary_extra`` is empty)."""
    pl_ok = verify_plan_cert(plan_cert, public_key).ok
    rp_ok = verify_rulepack_cert(
        rule_pack_cert, public_key, trusted_policies=DEFAULT_TRUSTED_POLICIES).ok
    bound = not bundle_binding_reasons(plan_cert, rule_pack_cert)
    checker = "pass" if (pl_ok and rp_ok and bound) else "fail"
    extra = domain.trust_boundary_extra()
    return TrustVector(
        signature=signature,
        checker=checker,
        coverage=extra.get("coverage", "calibrated"),
        conflict_replay=extra.get("conflict_replay", "verified"),
        data=extra.get("data", "real"),
    )


def verify(
    plan_cert: dict,
    rule_pack_cert: dict | None = None,
    signer_key: Ed25519PrivateKey | Ed25519PublicKey | str | None = None,
) -> VerifyView:
    """Independently re-check the bundle (solver-free + LLM-free) → ``VerifyView``.

    With ``rule_pack_cert`` the cross-cert binding is enforced too. ``signer_key``
    (a private key, a public key, or a 64-hex string) PINS the trusted signer: a
    re-signed forgery under any other key is rejected and the ``TrustVector``
    reports ``authenticated``; omit it for self-described mode (re-checked, signer
    UNVERIFIED). The verify-side resolves the domain bundle from the cert's signed
    ``domain_id`` — every check dispatches through the statically-registered
    verifier, never a cert callable.
    """
    signer_hex = _signer_hex(signer_key)
    pl_pubkey = _public_key_for(plan_cert, signer_hex)
    pl_res = verify_plan_cert(plan_cert, pl_pubkey)
    reasons = list(pl_res.reasons)
    ok = pl_res.ok

    if rule_pack_cert is not None:
        rp_pubkey = _public_key_for(rule_pack_cert, signer_hex)
        rp_res = verify_rulepack_cert(
            rule_pack_cert, rp_pubkey, trusted_policies=DEFAULT_TRUSTED_POLICIES)
        if not rp_res.ok:
            ok = False
            reasons += [f"rulepack: {r}" for r in rp_res.reasons]
        bundle = bundle_binding_reasons(plan_cert, rule_pack_cert)
        if bundle:
            ok = False
            reasons += bundle

    # the TrustVector mirrors verify's actual outcome: signature authenticated only
    # under a caller-pinned key; checker pass only if the (bundled) verify passed.
    domain, verifier = _resolve(plan_cert["domain_id"])
    signature = "authenticated" if signer_hex is not None else "self_described"
    extra = domain.trust_boundary_extra()
    trust_vector = TrustVector(
        signature=signature,
        checker="pass" if ok else "fail",
        coverage=extra.get("coverage", "calibrated"),
        conflict_replay=extra.get("conflict_replay", "verified"),
        data=extra.get("data", "real"),
    )
    return VerifyView(ok=ok, reasons=reasons, trust_vector=trust_vector)


def _signer_hex(
    signer_key: Ed25519PrivateKey | Ed25519PublicKey | str | None,
) -> str | None:
    """Normalize a pinned signer key (private/public/hex) to a 64-hex string, or
    ``None`` for self-described mode."""
    if signer_key is None:
        return None
    if isinstance(signer_key, str):
        return signer_key.strip()
    if isinstance(signer_key, Ed25519PrivateKey):
        return signer_key.public_key().public_bytes_raw().hex()
    return signer_key.public_bytes_raw().hex()
