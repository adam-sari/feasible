"""The §3.2 CI gates: the crafted scenario must keep the demo's promises green.

If any gate fails the instance is mis-tuned and the demo is dishonest.
"""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from feasible.canon.canonical import new_signing_key, public_key_from_hex
from feasible.cert.plan_cert import emit_plan_cert, verify_plan_cert
from feasible.checker.checker import check
from feasible.cli import app
from feasible.scenario import (
    build_scenario_ir,
    late_priority_orders,
    load_scenario,
    total_changeover_time,
    weighted_tardiness,
)
from feasible.smt.attest import attest_feasibility
from feasible.solve.optimality import optimality_tripwire
from feasible.solve.orchestrate import solve

DATA = Path(__file__).resolve().parent.parent.parent / "feasible" / "scenario" / "data"


def test_ci_gates_full_loop() -> None:
    ir, inc_a, inc_b = load_scenario(DATA)
    result = solve(ir, max_seconds=30.0)
    assert result.plan is not None
    opt = result.plan

    # --- optimality gates ---
    assert result.status == "OPTIMAL"
    assert result.gap == 0.0
    assert optimality_tripwire(ir, result.objective) is True  # nothing beats the optimum

    # --- KPI gates vs the feasible-naive incumbent B ---
    assert weighted_tardiness(ir, inc_b) > 0  # B is genuinely beatable
    assert weighted_tardiness(ir, opt) < weighted_tardiness(ir, inc_b)
    assert late_priority_orders(ir, opt) <= late_priority_orders(ir, inc_b)
    assert total_changeover_time(ir, opt) <= total_changeover_time(ir, inc_b)

    # --- verification gates ---
    assert check(opt, ir).passed is True
    assert attest_feasibility(opt, ir).feasible is True
    assert check(inc_b, ir).passed is True  # B is a valid baseline

    # --- the HERO gotcha: incumbent A rejected with the §6.1 span ---
    a_res = check(inc_a, ir)
    assert a_res.passed is False
    night = [v for v in a_res.violations if v.rule_id == "R-6.1-NIGHT-CLEANOUT"]
    assert len(night) == 1
    assert "Cleanouts may only be performed during the day shift" in night[0].span.quoted_text

    # --- certificate emit + solver-free verify ---
    key = new_signing_key()
    cert = emit_plan_cert(ir, opt, result, check(opt, ir), attest_feasibility(opt, ir), inc_a, inc_b, key)
    vres = verify_plan_cert(cert, key.public_key())
    assert vres.ok, vres.reasons
    assert cert["claims"]["optimality"]["tripwire_passed"]["value"] is True


def test_scenario_ir_matches_frozen_golden() -> None:
    # the in-code builder and the frozen golden_ir.json describe the same rule set
    ir_code = build_scenario_ir()
    ir_disk, _a, _b = load_scenario(DATA)
    assert {r.rule_id for r in ir_code.rules} == {r.rule_id for r in ir_disk.rules}
    assert len(ir_code.instance.operations) == len(ir_disk.instance.operations) == 18


def test_cli_run_and_verify(tmp_path: Path) -> None:
    runner = CliRunner()
    cert_path = tmp_path / "plan_cert.json"
    res_run = runner.invoke(app, ["run", str(DATA), "--out", str(cert_path)])
    assert res_run.exit_code == 0, res_run.output
    assert "GOTCHA" in res_run.output
    assert cert_path.exists()
    assert cert_path.with_suffix(".html").exists()

    res_verify = runner.invoke(app, ["verify", str(cert_path)])
    assert res_verify.exit_code == 0, res_verify.output
    assert "OK" in res_verify.output


def test_cli_verify_detects_tamper(tmp_path: Path) -> None:
    runner = CliRunner()
    cert_path = tmp_path / "c.json"
    runner.invoke(app, ["run", str(DATA), "--out", str(cert_path)])
    cert = json.loads(cert_path.read_text(encoding="utf-8"))
    first = next(iter(cert["plan"]["assignments"]))
    cert["plan"]["assignments"][first][0] = 999999
    cert_path.write_text(json.dumps(cert), encoding="utf-8")
    res = runner.invoke(app, ["verify", str(cert_path)])
    assert res.exit_code == 1
    assert "FAIL" in res.output
