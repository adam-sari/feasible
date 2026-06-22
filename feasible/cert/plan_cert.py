"""The signed Plan Certificate + a solver-free ``verify`` + an HTML projection.

The cert EMBEDS the instance, the active rule set, the plan, AND both incumbent
plans, so ``verify_plan_cert`` is fully self-contained (no file I/O): it
reconstructs the FCIR, re-runs the polynomial checker on the embedded plan,
recomputes the objective, re-derives the ACTIVE-rule-set digest, the visible
formalization claims, the instance_ref digest, the KPI table and the incumbent-A
gotcha (from the embedded incumbents), then verifies the signature + embedded-key
binding. The CP-SAT *optimality* leaves (``optimal_per_cpsat`` / ``gap_bps`` /
``tripwire_passed``) are solver-REPORTED and are NOT re-checked by this solver-free
verify — only the objective value itself is recomputed. The ``rule_pack_digest``
is an OPAQUE universe token (NOT re-derivable from the embedded active rules, which
are a subset of the universe); it — and the ``instance_ref`` — are bound to the
Rule-Pack Cert by the bundled ``verify --rulepack``, never standalone. Every claim
leaf carries a ``provenance`` discriminator drawn ONLY from the non-LLM set (the
LLM never touches a plan cert's truth claims).
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
from feasible.checker.plan_shape import validate_plan_shape
from feasible.domains import UnknownDomainError, get_domain
from feasible.domains.base import KPI_REGISTRY, DomainVerifier
from feasible.ir.domain import FCIR, Instance, Plan, Rule
from feasible.registry import EVALUATED_RULE_IDS, STRUCTURAL_RULE_KINDS, assert_all_hard_rules_supported
from feasible.solve.optimality import optimality_tripwire
from feasible.solve.orchestrate import SolveResult
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


def active_rule_set_digest(ir: FCIR, dropped: list) -> str:
    # hash only rule_ids — the rich `dropped` dicts are render metadata, never hashed
    ids = sorted(d["rule_id"] if isinstance(d, dict) else d for d in dropped)
    return digest_of({"active": active_rule_ids(ir), "dropped": ids})


def checked_rule_ids(ir: FCIR) -> list[str]:
    """Active hard rules an explicit predicate evaluates (excludes structural ones)."""
    return sorted(EVALUATED_RULE_IDS & set(active_rule_ids(ir)))


def structurally_enforced_rule_ids(ir: FCIR) -> list[str]:
    """Active hard rules guaranteed by the model (e.g. non_preemption) — NOT predicate-checked."""
    return sorted(r.rule_id for r in ir.hard_plan_rules() if r.kind in STRUCTURAL_RULE_KINDS)


def _kpi_registry_for(domain_id: str) -> dict:
    """The statically-registered, allow-listed KPI table for ``domain_id``.

    ``verify`` (and the emitter) resolve every KPI recompute ``fn`` from HERE —
    never from a cert field — so a re-signed cert cannot smuggle a callable. A
    domain with no registered KPIs fails closed (``KeyError``)."""
    return KPI_REGISTRY[domain_id]


def _kpi(ir: FCIR, optimized: Plan, incumbent_b: Plan) -> dict:
    """Per-KPI ``{optimized, incumbent_b}`` recomputed by the domain's registered
    fns (resolved from ``KPI_REGISTRY[ir.domain_id]``, never a cert callable)."""
    table = _kpi_registry_for(ir.domain_id)
    return {
        key: {
            "optimized": entry["fn"](ir, optimized),
            "incumbent_b": entry["fn"](ir, incumbent_b),
        }
        for key, entry in table.items()
    }


def _kpi_function_refs(domain_id: str) -> dict:
    """The per-KPI ``(function_id, function_version, input_schema_digest)`` version
    triples drawn from the registry. Echoed into the signed body; ``verify`` asserts
    byte-equality with the registry triple (a re-signed cert can't claim a different
    function for a KPI value). A plain dict (sorted-key canonicalization) — no float."""
    table = _kpi_registry_for(domain_id)
    return {
        key: {
            "function_id": entry["function_id"],
            "function_version": entry["function_version"],
            "input_schema_digest": entry["input_schema_digest"],
        }
        for key, entry in table.items()
    }


def _incumbent_a_failure(ir: FCIR, incumbent_a: Plan, verifier: DomainVerifier) -> dict:
    """The headline incumbent-A gotcha. The cited ``violated_rule_ref`` is the
    domain's ``gotcha_rule_id()`` ONLY — there is no ``violations[0]`` fallback, so
    an arbitrary hard-rule failure can never pose as the hero gotcha (``verify``
    asserts this equality)."""
    res = check(incumbent_a, ir)
    gotcha = verifier.gotcha_rule_id()
    night = [v for v in res.violations if v.rule_id == gotcha]
    v = night[0] if night else None
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
    dropped: list[dict] | None = None,
    rule_pack_digest_override: str | None = None,
) -> dict:
    assert_all_hard_rules_supported(ir)  # never certify a plan against an unevaluated hard rule
    # resolve the SIGNED domain bundle: the KPI recompute fns + the gotcha rule id
    # come from the statically-registered DomainVerifier, NOT from any cert field.
    _domain, verifier = get_domain(ir.domain_id)
    dropped = dropped or []
    rpd = rule_pack_digest_override or rule_pack_digest(ir)  # universe digest when called from certify
    objective = list(result.objective) if result.objective else [0, 0]
    # variable-length lexicographic objective tuple (manufacturing emits 2 levels)
    tripwire_ok = optimality_tripwire(ir, tuple(objective))
    gap_bps = 0 if (result.gap == 0.0) else -1  # -1 = not proven optimal

    cert: dict = {
        "schema_version": SCHEMA_VERSION,
        "plan_cert_id": plan_cert_id,
        # the SIGNED domain selector: verify resolves the DomainVerifier bundle from
        # this id (fail-closed on an unknown domain) and rejects any cert rule_id not
        # in that domain's known_rule_ids (cross-domain isolation; foreign rule rejected).
        "domain_id": ir.domain_id,
        "rule_pack_ref": {
            "rule_pack_id": "rule-pack-golden",
            "rule_pack_digest": rpd,
            "rule_pack_cert_signature_ref": None,
        },
        "active_rule_set_for_plan": {
            "active_rule_ids": active_rule_ids(ir),
            "dropped": dropped,
            "active_rule_set_digest": active_rule_set_digest(ir, dropped),
        },
        "instance_ref": {"instance_digest": digest_of(ir.instance.model_dump(mode="json"))},
        # embedded for a self-contained, solver-free verify:
        "instance": ir.instance.model_dump(mode="json"),
        "rules": [r.model_dump(mode="json") for r in ir.rules],
        "plan": plan.model_dump(mode="json"),
        # incumbents embedded so verify can RE-DERIVE the KPI table + the gotcha,
        # not merely trust the signed numbers:
        "incumbent_a": incumbent_a.model_dump(mode="json"),
        "incumbent_b": incumbent_b.model_dump(mode="json"),
        "claims": {
            "formalization": {
                "rule_pack_digest_ref": _leaf(rpd, "rule_pack_digest_ref"),
                "n_hard_rules": _leaf(len(active_rule_ids(ir)), "ledger"),
                "checked_rule_ids": _leaf(checked_rule_ids(ir), "ledger"),
                "structurally_enforced_rule_ids": _leaf(structurally_enforced_rule_ids(ir), "ledger"),
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
        # the per-KPI (function_id, function_version, input_schema_digest) version
        # triples — verify re-derives each KPI from KPI_REGISTRY[domain_id][key]["fn"]
        # and asserts the cert triple equals the registered one (no cert callable).
        "kpi_function_refs": _kpi_function_refs(ir.domain_id),
        "incumbent_A_failure": _incumbent_a_failure(ir, incumbent_a, verifier),
        "trust_boundary": {
            "verification": "IR-relative: the plan satisfies the approved IR; the source->IR edge "
                            "is closed by the extraction-independence layer + human gate (Build B). "
                            "Authenticity rests on the PINNED signer key (verify --signer-key); a rule's "
                            "formalization metadata (clause_kind/compile_mode/severity) is the signer's "
                            "human-gated attestation, not re-derivable from the SOP.",
            "optimality": "CP-SAT self-reported gap + a SAME-ENGINE tripwire; not independently proven "
                          "(MiniZinc->Chuffed is a post-v1.1 roadmap item). These optimality leaves are "
                          "solver-reported and NOT re-checked by the solver-free `verify`; the objective "
                          "value itself IS recomputed.",
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
        domain_id=cert.get("domain_id", "manufacturing"),
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

    # 2b) resolve the SIGNED domain bundle (fail-closed on an unknown domain) and assert
    # EVERY rule_id in the cert belongs to that domain's known_rule_ids. The signed
    # domain_id selects which DomainVerifier's predicates run; without this guard a
    # re-signed cert could (a) name an unregistered domain (whose verifier supports
    # nothing) or (b) smuggle a foreign-namespace rule_id (e.g. a dc:* rule) under
    # manufacturing — bypassing the per-domain isolation. (Fully reconstructed,
    # re-checked below; this is the cross-domain guard.)
    domain_id = cert.get("domain_id")
    if not isinstance(domain_id, str):
        reasons.append("missing or non-string domain_id")
        return VerifyResult(ok=False, reasons=reasons)
    try:
        _domain, verifier = get_domain(domain_id)
    except UnknownDomainError:
        reasons.append(f"unknown domain {domain_id!r} (no registered verifier bundle)")
        return VerifyResult(ok=False, reasons=reasons)
    known = verifier.known_rule_ids
    # Coerce to str so a rule dict missing rule_id (-> None) alongside a string
    # foreign id is reported as foreign (still "not in known") rather than crashing
    # sorted() on a mixed None/str list (TypeError). A None/missing rule_id is foreign.
    foreign = sorted(
        str(rid) for r in cert.get("rules", [])
        if (rid := r.get("rule_id")) not in known
    )
    if foreign:
        reasons.append(f"foreign rule_id(s) {foreign} not in domain {domain_id!r} known_rule_ids")

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

    # 4) recompute the canonical objective and match the cert's claim. Routed
    # through the per-domain SEAM (``verifier`` already resolved at the domain
    # guard above): ``ManufacturingVerifier.objective`` delegates to
    # ``recompute_objective`` → byte-identical, while a SECOND domain recomputes
    # ITS own objective behind the same seam.
    recomputed = list(verifier.objective(ir, plan))
    claimed = cert["claims"]["optimality"]["objective"]["value"]
    if recomputed != list(claimed):
        reasons.append(f"objective mismatch: recomputed {recomputed} != cert {claimed}")

    # 5) self-consistency. rule_pack_ref.rule_pack_digest is an OPAQUE universe token
    # (tamper-protected by the body-vs-signature binding above; NOT re-derivable from the
    # embedded ACTIVE rules) — it is confirmed against the Rule-Pack Cert by the bundled
    # `verify --rulepack`, not re-derived here. The active-rule-set digest IS re-derived,
    # and the rule_pack_digest_ref leaf must equal the ref binding.
    if active_rule_set_digest(ir, cert["active_rule_set_for_plan"]["dropped"]) != cert["active_rule_set_for_plan"]["active_rule_set_digest"]:
        reasons.append("active_rule_set_digest mismatch")
    leaf = cert["claims"]["formalization"]["rule_pack_digest_ref"]["value"]
    if leaf != cert["rule_pack_ref"]["rule_pack_digest"]:
        reasons.append("rule_pack_digest_ref leaf != rule_pack_ref binding")

    # 6) re-derive the visible formalization + active-set DISPLAY claims from the
    # embedded active rules. The emitter computes these; re-deriving makes them
    # machine-checked, not merely signed (a re-signed cert can't lie about them).
    f = cert["claims"]["formalization"]
    rederived = {
        "n_hard_rules": len(active_rule_ids(ir)),
        "checked_rule_ids": checked_rule_ids(ir),
        "structurally_enforced_rule_ids": structurally_enforced_rule_ids(ir),
        "rules_grounded_in_source": sum(
            1 for r in ir.hard_plan_rules()
            if any(getattr(s, "role", "") == "primary_normative" for s in r.provenance.spans)
        ),
    }
    for name, want in rederived.items():
        got = f.get(name, {}).get("value")
        if got != want:
            reasons.append(f"formalization.{name} claim {got} != re-derived {want}")
    if cert["active_rule_set_for_plan"]["active_rule_ids"] != active_rule_ids(ir):
        reasons.append("active_rule_ids claim != re-derived active set")

    # 7) the embedded instance must hash to the cert's instance_ref (the cross-cert
    # bundle binds THIS digest to the rule pack — so a plan can't be re-pointed at a
    # different/easier instance under the same rule universe).
    if digest_of(ir.instance.model_dump(mode="json")) != cert.get("instance_ref", {}).get("instance_digest"):
        reasons.append("instance_ref digest mismatch")

    # 8) re-derive the KPI table and the incumbent-A gotcha from the EMBEDDED incumbent
    # plans — the headline "we beat the baseline" and the cited SOP clause are otherwise
    # pure trust-me claims a re-signed cert could fabricate.
    try:
        inc_a = Plan.model_validate(cert["incumbent_a"])
        inc_b = Plan.model_validate(cert["incumbent_b"])
    except Exception as e:  # noqa: BLE001
        reasons.append(f"incumbent reconstruction failed: {e}")
        return VerifyResult(ok=False, reasons=reasons)
    # the incumbents are real scenario plans, not strawmen: B (the KPI denominator) must be
    # FEASIBLE + shape-valid, and A (the gotcha) must at least be shape-valid and exhibit a
    # genuine hard-rule violation. (Their IDENTITY as the customer's true baselines is bound
    # out-of-band by the scenario, exactly like the instance.)
    if not check(inc_b, ir).passed:
        reasons.append("incumbent_b is not a feasible baseline (the KPI denominator must be a real plan)")
    if validate_plan_shape(inc_a, ir):
        reasons.append("incumbent_a is not a well-formed plan over the certified instance")
    # the cited incumbent-A failure MUST be the domain's headline gotcha rule (there is
    # no longer a violations[0] fallback in the emitter): an arbitrary hard-rule failure
    # cannot pose as the hero gotcha. This both rejects a null/forged ref AND pins the
    # rule identity to the verifier's gotcha_rule_id().
    gotcha = verifier.gotcha_rule_id()
    if cert["incumbent_A_failure"].get("violated_rule_ref") != gotcha:
        reasons.append(
            f"incumbent_A_failure.violated_rule_ref "
            f"{cert['incumbent_A_failure'].get('violated_rule_ref')!r} != domain gotcha rule {gotcha!r} "
            f"(the gotcha must be a real failure of the certified gotcha rule)"
        )

    # the KPI value table must equal the table re-derived by the STATICALLY-REGISTERED
    # domain fns (resolved from KPI_REGISTRY[domain_id], never a cert callable) ...
    if _kpi(ir, plan, inc_b) != cert["kpi_vs_incumbent_B"]:
        reasons.append("kpi_vs_incumbent_B claim != re-derived KPI")
    # ... AND the cert's per-KPI (function_id, function_version, input_schema_digest)
    # version triple must equal the registry's triple byte-for-byte — so a re-signed cert
    # cannot pair a tampered KPI value with a fabricated/renamed function to look honest.
    if cert.get("kpi_function_refs") != _kpi_function_refs(domain_id):
        reasons.append(
            "kpi_function_refs claim != registered KPI version triple "
            "(function_id/function_version/input_schema_digest mismatch)"
        )

    if _incumbent_a_failure(ir, inc_a, verifier) != cert["incumbent_A_failure"]:
        reasons.append("incumbent_A_failure claim != re-derived failure")

    return VerifyResult(ok=len(reasons) == 0, reasons=reasons)


def public_key_hex_of(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes_raw().hex()


def _gantt_html(plan_cert: dict) -> str:
    inst = plan_cert["instance"]
    plan = plan_cert["plan"]
    dur = {o["op_id"]: o["duration"] for o in inst["operations"]}
    fam_of_job = {j["id"]: j["family"] for j in inst["jobs"]}
    job_of_op = {o["op_id"]: o["job_id"] for o in inst["operations"]}
    colors = {"Allergen": "#d9534f", "Standard": "#5bc0de", "Spicy": "#f0ad4e"}

    ends = [s + dur[o] for o, (s, _m) in plan["assignments"].items()]
    ends += [c[2] for c in plan["cleanouts"]]
    max_t = max(ends) if ends else 1
    span = max(max_t, 1)

    def pct(x: int) -> float:
        return round(100.0 * x / span, 3)

    # night shading bands [960,1440), [2400,2880), ...
    bands = ""
    k = 0
    while 960 + k * 1440 < span:
        a = 960 + k * 1440
        b = min(1440 + k * 1440, span)
        bands += f'<div class="night" style="left:{pct(a)}%;width:{pct(b - a)}%"></div>'
        k += 1

    rows = ""
    for mc in inst["machines"]:
        bars = ""
        for op, (s, m) in plan["assignments"].items():
            if m != mc:
                continue
            fam = fam_of_job[job_of_op[op]]
            bars += (f'<div class="bar" style="left:{pct(s)}%;width:{pct(dur[op])}%;'
                     f'background:{colors.get(fam, "#bbb")}" title="{op} [{s},{s + dur[op]})">{op}</div>')
        for (cm, cs, ce, reason) in plan["cleanouts"]:
            if cm == mc:
                bars += (f'<div class="bar clean" style="left:{pct(cs)}%;width:{pct(ce - cs)}%" '
                         f'title="{reason} [{cs},{ce})">CLEANOUT</div>')
        rows += f'<div class="row"><div class="mlabel">{mc}</div><div class="track">{bands}{bars}</div></div>'
    return rows


def render_html(plan_cert: dict) -> str:
    import json

    c = plan_cert["claims"]
    obj = c["optimality"]["objective"]["value"]
    feas = c["feasibility"]["checker"]["value"]
    z3 = c["feasibility"]["z3_attest"]["value"]
    opt_label = c["optimality"]["label"]["value"]
    tripwire = c["optimality"]["tripwire_passed"]["value"]
    inc_a = plan_cert["incumbent_A_failure"]
    span_q = inc_a["span"].get("quoted_text", "") if inc_a.get("span") else ""
    kpi = plan_cert["kpi_vs_incumbent_B"]

    def kpi_row(label: str, key: str) -> str:
        o, b = kpi[key]["optimized"], kpi[key]["incumbent_b"]
        win = "win" if o <= b else ""
        return f'<tr><td>{label}</td><td class="{win}">{o}</td><td>{b}</td></tr>'

    payload_json = json.dumps(plan_cert, indent=2)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Feasible Plan Certificate</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;max-width:64rem;color:#222}}
h1{{margin-bottom:0}} .sub{{color:#666;margin-top:.2rem}}
.claim{{border:1px solid #ddd;border-radius:8px;padding:.8rem 1rem;margin:.5rem 0;background:#fafafa}}
.pass{{color:#0a7a0a;font-weight:600}} .fail{{color:#c00;font-weight:600}}
.gotcha{{border-left:4px solid #d9534f;background:#fff5f5}}
table{{border-collapse:collapse;margin:.5rem 0}} td,th{{border:1px solid #ddd;padding:.3rem .7rem;text-align:right}}
th:first-child,td:first-child{{text-align:left}} .win{{color:#0a7a0a;font-weight:600}}
.gantt{{margin:1rem 0}} .row{{display:flex;align-items:center;margin:3px 0}}
.mlabel{{width:90px;font-size:.8rem;color:#444}} .track{{position:relative;flex:1;height:26px;background:#f0f0f0;border-radius:4px;overflow:hidden}}
.night{{position:absolute;top:0;height:100%;background:repeating-linear-gradient(45deg,#e6e6f5,#e6e6f5 6px,#dadaf0 6px,#dadaf0 12px)}}
.bar{{position:absolute;top:2px;height:22px;border-radius:3px;color:#fff;font-size:.65rem;line-height:22px;text-align:center;overflow:hidden;white-space:nowrap}}
.bar.clean{{background:repeating-linear-gradient(45deg,#444,#444 4px,#666 4px,#666 8px);color:#fff}}
details{{margin-top:1rem}} pre{{background:#f6f6f6;padding:1rem;overflow:auto;font-size:.7rem;max-height:30rem}}
.legend span{{display:inline-block;margin-right:1rem;font-size:.8rem}} .sw{{display:inline-block;width:12px;height:12px;border-radius:2px;vertical-align:middle;margin-right:3px}}
</style></head><body>
<h1>Feasible — Plan Certificate</h1>
<div class="sub">generate + verify + certify · independently re-checkable offline via <code>feasible verify</code></div>

<div class="claim"><b>① Formalization:</b> {c['formalization']['n_hard_rules']['value']} approved hard rules
(rule-pack digest <code>{plan_cert['rule_pack_ref']['rule_pack_digest'][:16]}…</code>)</div>
<div class="claim"><b>② Feasibility:</b> checker <span class="{'pass' if feas=='PASS' else 'fail'}">{feas}</span>
· Z3 {z3} (two independent verifiers)</div>
<div class="claim"><b>③ Optimality:</b> objective (weighted_tardiness, changeover) = {obj} — {opt_label}; tripwire_passed={tripwire}</div>

<div class="claim gotcha"><b>🎯 Gotcha — incumbent A rejected:</b> violated <code>{inc_a.get('violated_rule_ref')}</code><br>
cited SOP clause: <i>"{span_q}"</i><br>
counter-witness: {', '.join(f'{k}={v}' for k, v in (inc_a.get('counter_witness') or {}).items()) or '—'}</div>

<h3>KPI vs incumbent B (feasible-but-naive baseline)</h3>
<table><tr><th>metric</th><th>Feasible</th><th>incumbent B</th></tr>
{kpi_row('priority-weighted tardiness', 'weighted_tardiness')}
{kpi_row('late priority orders', 'late_priority_orders')}
{kpi_row('total changeover (min)', 'total_changeover_time')}
</table>

<h3>Optimized schedule</h3>
<div class="legend"><span><span class="sw" style="background:#d9534f"></span>Allergen</span>
<span><span class="sw" style="background:#5bc0de"></span>Standard</span>
<span><span class="sw" style="background:#f0ad4e"></span>Spicy</span>
<span><span class="sw" style="background:#555"></span>Cleanout</span>
<span><span class="sw night" style="width:24px"></span>night shift [22:00–06:00)</span></div>
<div class="gantt">{_gantt_html(plan_cert)}</div>

<details><summary>Signed canonical JSON (source of truth — what <code>feasible verify</code> re-checks)</summary>
<pre>{payload_json}</pre></details>
</body></html>"""
