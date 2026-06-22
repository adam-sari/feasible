"""Feasible CLI: ``feasible run <scenario_dir>`` and ``feasible verify <cert>``."""
from __future__ import annotations

import json
from pathlib import Path

import typer

from feasible import api
from feasible.canon.canonical import new_signing_key, public_key_hex
from feasible.cert.plan_cert import emit_plan_cert, render_html
from feasible.checker.checker import check
from feasible.conflict.policy import MANUFACTURING_POLICY
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

# The manufacturing scenario the CLI certifies (the facade resolves the domain
# bundle by id; the CLI's scenario-dir argument selects the SOP/incumbent files
# for the bare ``run`` path and stays accepted for backward compatibility).
_DOMAIN_ID = "manufacturing"

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
    rp = json.loads(Path(rulepack).read_text(encoding="utf-8")) if rulepack is not None else None

    # route through the facade — the SINGLE solver-free verify orchestration
    view = api.verify(cert, rp, signer_key=pinned_hex)
    reasons = list(view.reasons)
    ok = view.ok

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
    # the two-cert orchestration is the facade's SINGLE source of truth; the CLI
    # signs under an explicit key (so it can publish signer_pub.hex), writes the
    # files, re-derives the governance + KPI narrative for display, and verifies
    # through the same facade. The scenario-dir argument is retained for backward
    # compatibility (it selects the SOP/incumbent files the demo loop reads).
    key = new_signing_key()
    cert_result = api.certify(_DOMAIN_ID, signer_key=key)
    plan_cert = cert_result.plan_cert
    rp_cert = cert_result.rule_pack_cert

    Path(rulepack_out).write_text(json.dumps(rp_cert, indent=2), encoding="utf-8")
    Path(out).write_text(json.dumps(plan_cert, indent=2), encoding="utf-8")
    Path(out).with_suffix(".html").write_text(render_html(plan_cert), encoding="utf-8")
    # publish the signer's PUBLIC key so an auditor can pin it: `verify --signer-key signer_pub.hex`
    signer_path = Path(out).with_name("signer_pub.hex")
    signer_path.write_text(public_key_hex(key), encoding="utf-8")

    # display narrative — re-derived from the governance run (NOT load-bearing; the
    # certs themselves are the source of truth, re-verified below).
    extracted = build_extracted_pack()
    gov = govern_pack(extracted, MANUFACTURING_POLICY)
    universe_ir = gov.universe_ir
    active_ir = gov.active_ir
    coverage = build_coverage_ledger(SHOP_RULES, universe_ir)
    _golden, _inc_a, inc_b = load_scenario(scenario_dir)
    from feasible.ir.domain import Plan as _Plan
    plan = _Plan.model_validate(plan_cert["plan"])

    typer.echo("=== Feasible certify (full loop) ===")
    typer.echo(f"extraction: {len(extracted.rules)} candidate rules -> "
               f"{len(universe_ir.rules)} approved universe -> {len(active_ir.rules)} active after policy")
    typer.echo(f"coverage ledger: complete={coverage.complete} denominator={coverage.denominator} red={len(coverage.red_findings)}")
    for c in gov.corrections:
        typer.echo(f"§5.2 back-translation correction [{c.rule_id}]: '{c.before}' -> '{c.after}'")
    for r in gov.resolutions:
        typer.echo(f"§4.4 conflict [{r.conflict.obligation_id} vs {r.conflict.permission_id}]: "
                   f"{r.resolution_mode} -> {r.rationale}")

    # verify both + the cross-cert binding THROUGH THE FACADE (the single solver-free path)
    view = api.verify(plan_cert, rp_cert, signer_key=key)
    chk = check(plan, active_ir)
    obj = plan_cert["claims"]["optimality"]["objective"]["value"]

    typer.echo(f"plan: status={plan_cert['claims']['optimality']['label']['value']} "
               f"objective(wt,co)={tuple(obj)} checker={'PASS' if chk.passed else 'FAIL'}")
    typer.echo("KPI vs incumbent B:")
    typer.echo(f"  weighted_tardiness : {weighted_tardiness(active_ir, plan)}  vs  {weighted_tardiness(active_ir, inc_b)}")
    typer.echo(f"  late_priority_ords : {late_priority_orders(active_ir, plan)}  vs  {late_priority_orders(active_ir, inc_b)}")
    typer.echo(f"  total_changeover   : {total_changeover_time(active_ir, plan)}  vs  {total_changeover_time(active_ir, inc_b)}")
    fa = plan_cert["incumbent_A_failure"]
    typer.echo(f"GOTCHA — incumbent A violates {fa['violated_rule_ref']}: \"{fa['span']['quoted_text']}\"")
    rp_ok_disp = "OK" if view.ok else "FAIL " + str([r for r in view.reasons if r.startswith("rulepack:")])
    pl_ok_disp = "OK" if view.ok else "FAIL " + str([r for r in view.reasons if not r.startswith("rulepack:")])
    typer.echo(f"Rule-Pack Cert verify: {rp_ok_disp}")
    typer.echo(f"Plan Cert verify     : {pl_ok_disp}")
    typer.echo(f"two-cert digest binding: {'OK' if view.ok else 'MISMATCH ' + str(view.reasons)}")
    typer.echo(f"signer public key -> {signer_path} ({public_key_hex(key)[:16]}…)  "
               f"(auditor: verify --signer-key {signer_path.name})")
    typer.echo(f"wrote {rulepack_out}, {out}, {Path(out).with_suffix('.html')}")
    if not view.ok:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
