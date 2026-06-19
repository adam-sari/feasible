"""Feasible CLI: ``feasible run <scenario_dir>`` and ``feasible verify <cert>``."""
from __future__ import annotations

import json
from pathlib import Path

import typer

from feasible.canon.canonical import new_signing_key, public_key_from_hex
from feasible.cert.plan_cert import emit_plan_cert, render_html, verify_plan_cert
from feasible.checker.checker import check
from feasible.scenario import load_scenario, weighted_tardiness, total_changeover_time, late_priority_orders
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


@app.command()
def verify(cert_path: str = typer.Argument(..., help="a plan_cert.json to re-check offline")) -> None:
    """Independently re-check a Plan Certificate (solver-free)."""
    cert = json.loads(Path(cert_path).read_text(encoding="utf-8"))
    pubkey = public_key_from_hex(cert["signature"]["public_key_hex"])
    res = verify_plan_cert(cert, pubkey)
    if res.ok:
        typer.echo("VERIFY: OK — signature valid, plan re-checked, objective + digests match.")
        raise typer.Exit(0)
    typer.echo("VERIFY: FAIL")
    for r in res.reasons:
        typer.echo(f"  - {r}")
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
