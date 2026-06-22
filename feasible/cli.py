"""Feasible CLI: ``feasible run <scenario_dir>`` and ``feasible verify <cert>``."""
from __future__ import annotations

import json
from pathlib import Path

import typer

from feasible.canon.canonical import new_signing_key, public_key_from_hex, public_key_hex
from feasible.cert.plan_cert import emit_plan_cert, render_html, rule_pack_digest, verify_plan_cert
from feasible.cert.rulepack_cert import bundle_binding_reasons, emit_rulepack_cert, verify_rulepack_cert
from feasible.checker.checker import check
from feasible.conflict.policy import DEFAULT_TRUSTED_POLICIES, MANUFACTURING_POLICY
from feasible.govern.coverage import build_coverage_ledger
from feasible.govern.pipeline import govern_pack
from feasible.scenario import (
    SHOP_RULES,
    build_extracted_pack,
    late_priority_orders,
    load_scenario,
    total_changeover_time,
    weighted_tardiness,
)
from feasible.smt.attest import attest_feasibility
from feasible.solve.orchestrate import solve

app = typer.Typer(add_completion=False, help="Feasible — generate + verify + certify scheduling.")


@app.command()
def run(
    scenario_dir: str = typer.Argument(..., help="directory with golden_ir.json + incumbents"),
    out: str = typer.Option("plan_cert.json", help="output certificate path"),
) -> None:
    """Solve the scenario, verify it, and emit a signed Plan Certificate (+ HTML)."""
    ir, inc_a, inc_b = load_scenario(scenario_dir)
    result = solve(ir, max_seconds=30.0)
    if result.plan is None:
        typer.echo(f"solve status: {result.status} (no plan)")
        raise typer.Exit(1)
    plan = result.plan
    chk = check(plan, ir)
    att = attest_feasibility(plan, ir)
    key = new_signing_key()
    cert = emit_plan_cert(ir, plan, result, chk, att, inc_a, inc_b, key)

    out_path = Path(out)
    out_path.write_text(json.dumps(cert, indent=2), encoding="utf-8")
    html_path = out_path.with_suffix(".html")
    html_path.write_text(render_html(cert), encoding="utf-8")

    typer.echo("=== Feasible run ===")
    typer.echo(f"status: {result.status}  objective(wt,co)={result.objective}")
    typer.echo(f"feasibility: checker={'PASS' if chk.passed else 'FAIL'}  z3={'attested' if att.feasible else 'INFEASIBLE'}")
    typer.echo("KPI vs incumbent B (feasible-naive):")
    typer.echo(f"  weighted_tardiness : {weighted_tardiness(ir, plan)}  vs  {weighted_tardiness(ir, inc_b)}")
    typer.echo(f"  late_priority_ords : {late_priority_orders(ir, plan)}  vs  {late_priority_orders(ir, inc_b)}")
    typer.echo(f"  total_changeover   : {total_changeover_time(ir, plan)}  vs  {total_changeover_time(ir, inc_b)}")
    fa = cert["incumbent_A_failure"]
    typer.echo(f"GOTCHA — incumbent A violates {fa['violated_rule_ref']}: \"{fa['span']['quoted_text']}\"")
    typer.echo(f"wrote {out_path} and {html_path}")


def _resolve_signer_key(signer_key: str) -> str:
    """A --signer-key is either an inline 64-hex public key or a path to a .hex file."""
    p = Path(signer_key)
    return (p.read_text(encoding="utf-8").strip() if p.exists() else signer_key.strip())


@app.command()
def verify(
    cert_path: str = typer.Argument(..., help="a plan_cert.json to re-check offline"),
    rulepack: str = typer.Option(None, help="optional rule_pack_cert.json to also verify + bind"),
    signer_key: str = typer.Option(
        None, help="trusted signer public-key hex (or path to a .hex file) to AUTHENTICATE the "
                   "cert; omit for self-described mode (re-checked but signer UNVERIFIED)"),
) -> None:
    """Independently re-check a Plan Certificate (solver-free). With --rulepack, also verify
    the Rule-Pack Cert and the cross-cert binding; the conflict policy is pinned to the
    published trust store. With --signer-key, the cert is also AUTHENTICATED against a trusted
    key (a re-signed forgery under any other key is rejected)."""
    cert = json.loads(Path(cert_path).read_text(encoding="utf-8"))
    # pin to the supplied trusted key; otherwise fall back to the cert's self-described key
    pinned_hex = _resolve_signer_key(signer_key) if signer_key else None
    pubkey = public_key_from_hex(pinned_hex or cert["signature"]["public_key_hex"])
    res = verify_plan_cert(cert, pubkey)
    reasons = list(res.reasons)
    ok = res.ok

    if rulepack is not None:
        rp = json.loads(Path(rulepack).read_text(encoding="utf-8"))
        rp_pubkey = public_key_from_hex(pinned_hex or rp["signature"]["public_key_hex"])
        rp_res = verify_rulepack_cert(rp, rp_pubkey, trusted_policies=DEFAULT_TRUSTED_POLICIES)
        if not rp_res.ok:
            ok = False
            reasons += [f"rulepack: {r}" for r in rp_res.reasons]
        bundle = bundle_binding_reasons(cert, rp)  # digest + instance + active-set + rule-body + policy binding
        if bundle:
            ok = False
            reasons += bundle

    auth = "SIGNER AUTHENTICATED (pinned key)" if pinned_hex else \
        "signer SELF-DESCRIBED — pass --signer-key to authenticate (re-check passed, identity UNVERIFIED)"
    if ok:
        if rulepack is not None:
            typer.echo("VERIFY: OK — plan re-checked, objective + claims match + rule-pack bound "
                       f"(active set, instance, SOP clauses, policy all pinned); {auth}.")
        else:
            # the active-set→universe and clause→SOP bindings live in the rule-pack cert by
            # design (the plan cert's rule_pack_digest is an opaque token), so a bare plan-cert
            # verify CANNOT confirm a hard rule wasn't dropped or a clause reworded.
            typer.echo("VERIFY: OK — plan internally consistent (objective + KPI + gotcha re-derived); "
                       "but WITHOUT --rulepack the active rule set is NOT bound to a certified universe "
                       "and cited SOP clauses are UNVERIFIED — pass --rulepack to confirm no hard rule "
                       f"was dropped or reworded; {auth}.")
        raise typer.Exit(0)
    typer.echo("VERIFY: FAIL")
    for r in reasons:
        typer.echo(f"  - {r}")
    raise typer.Exit(1)


@app.command()
def certify(
    scenario_dir: str = typer.Argument(..., help="directory with golden_ir.json + incumbents"),
    out: str = typer.Option("plan_cert.json", help="output plan-cert path"),
    rulepack_out: str = typer.Option("rule_pack_cert.json", help="output rule-pack-cert path"),
) -> None:
    """The FULL loop: messy extraction -> governance -> Rule-Pack Cert -> solve -> Plan Cert -> verify both."""
    _golden, inc_a, inc_b = load_scenario(scenario_dir)

    # 1) messy extraction + governance
    extracted = build_extracted_pack()
    gov = govern_pack(extracted, MANUFACTURING_POLICY)
    universe_ir = gov.universe_ir  # full approved set (R-4.4 retained) — what the Rule-Pack Cert certifies
    active_ir = gov.active_ir      # minus policy-dropped rules — what the plan is solved/checked against
    coverage = build_coverage_ledger(SHOP_RULES, universe_ir)
    dropped = [
        {"rule_id": rid, "drop_reason": "rule_inactive_for_plan_by_policy",
         "resolution_mode": "AUTO_BY_POLICY",
         "conflict_policy_ref": {"policy_id": MANUFACTURING_POLICY.policy_id, "digest": MANUFACTURING_POLICY.digest()}}
        for rid in gov.dropped_rule_ids
    ]

    typer.echo("=== Feasible certify (full loop) ===")
    typer.echo(f"extraction: {len(extracted.rules)} candidate rules -> "
               f"{len(universe_ir.rules)} approved universe -> {len(active_ir.rules)} active after policy")
    typer.echo(f"coverage ledger: complete={coverage.complete} denominator={coverage.denominator} red={len(coverage.red_findings)}")
    for c in gov.corrections:
        typer.echo(f"§5.2 back-translation correction [{c.rule_id}]: '{c.before}' -> '{c.after}'")
    for r in gov.resolutions:
        typer.echo(f"§4.4 conflict [{r.conflict.obligation_id} vs {r.conflict.permission_id}]: "
                   f"{r.resolution_mode} -> {r.rationale}")

    # 2) Rule-Pack Certificate — over the UNIVERSE (R-4.4 present; coverage + replay need it)
    key = new_signing_key()
    rp_cert = emit_rulepack_cert(universe_ir, SHOP_RULES, MANUFACTURING_POLICY, gov.resolutions, key)
    Path(rulepack_out).write_text(json.dumps(rp_cert, indent=2), encoding="utf-8")
    universe_digest = rule_pack_digest(universe_ir)

    # 3) solve + Plan Certificate over the ACTIVE set (binds to the universe rule-pack digest)
    result = solve(active_ir, max_seconds=30.0)
    if result.plan is None:
        typer.echo(f"solve status: {result.status} (no plan)")
        raise typer.Exit(1)
    plan = result.plan
    chk = check(plan, active_ir)
    att = attest_feasibility(plan, active_ir)
    plan_cert = emit_plan_cert(active_ir, plan, result, chk, att, inc_a, inc_b, key,
                               dropped=dropped, rule_pack_digest_override=universe_digest)
    Path(out).write_text(json.dumps(plan_cert, indent=2), encoding="utf-8")
    Path(out).with_suffix(".html").write_text(render_html(plan_cert), encoding="utf-8")
    # publish the signer's PUBLIC key so an auditor can pin it: `verify --signer-key signer_pub.hex`
    signer_path = Path(out).with_name("signer_pub.hex")
    signer_path.write_text(public_key_hex(key), encoding="utf-8")

    # 4) verify both (policy pinned to the published trust store) + the cross-cert binding
    rp_ok = verify_rulepack_cert(rp_cert, key.public_key(), trusted_policies=DEFAULT_TRUSTED_POLICIES)
    pl_ok = verify_plan_cert(plan_cert, key.public_key())
    bundle = bundle_binding_reasons(plan_cert, rp_cert)  # digest + instance + active-set + rule-body + policy
    bound = not bundle and plan_cert["rule_pack_ref"]["rule_pack_digest"] == universe_digest

    typer.echo(f"plan: status={result.status} objective(wt,co)={result.objective} checker={'PASS' if chk.passed else 'FAIL'}")
    typer.echo("KPI vs incumbent B:")
    typer.echo(f"  weighted_tardiness : {weighted_tardiness(active_ir, plan)}  vs  {weighted_tardiness(active_ir, inc_b)}")
    typer.echo(f"  late_priority_ords : {late_priority_orders(active_ir, plan)}  vs  {late_priority_orders(active_ir, inc_b)}")
    typer.echo(f"  total_changeover   : {total_changeover_time(active_ir, plan)}  vs  {total_changeover_time(active_ir, inc_b)}")
    fa = plan_cert["incumbent_A_failure"]
    typer.echo(f"GOTCHA — incumbent A violates {fa['violated_rule_ref']}: \"{fa['span']['quoted_text']}\"")
    typer.echo(f"Rule-Pack Cert verify: {'OK' if rp_ok.ok else 'FAIL ' + str(rp_ok.reasons)}")
    typer.echo(f"Plan Cert verify     : {'OK' if pl_ok.ok else 'FAIL ' + str(pl_ok.reasons)}")
    typer.echo(f"two-cert digest binding: {'OK' if bound else 'MISMATCH ' + str(bundle)}")
    typer.echo(f"signer public key -> {signer_path} ({public_key_hex(key)[:16]}…)  "
               f"(auditor: verify --signer-key {signer_path.name})")
    typer.echo(f"wrote {rulepack_out}, {out}, {Path(out).with_suffix('.html')}")
    if not (rp_ok.ok and pl_ok.ok and bound and chk.passed):
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
