from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from feasible.cli import app
from feasible.extract.provider import MODEL, build_prompt, fixture_key
from feasible.extract.schema import SCHEMA_DESCRIPTOR
from feasible.ingest.segment import segment

runner = CliRunner()
SOP_PATH = Path("feasible/scenario/data/shop_rules.md")
FIX = Path("feasible/extract/fixtures")   # the CLI's committed offline store (read-only)


def _seed_cli_fixtures():
    """Pre-record CLI fixtures (one real rule, {} elsewhere) into the CLI store. This
    is the stand-in for a one-time live `--record` pass; thereafter the dir is the
    committed, read-only offline replay store the CLI default reads. Keys on the
    STABLE SCHEMA_DESCRIPTOR (C-3/C-4), never RuleDraft.model_json_schema()."""
    FIX.mkdir(parents=True, exist_ok=True)
    schema = SCHEMA_DESCRIPTOR
    sop = SOP_PATH.read_text(encoding="utf-8")
    for seg in segment(sop):
        key = fixture_key(MODEL, build_prompt(seg.text.strip(), seg.heading_path), schema)
        path = FIX / f"{key}.json"
        if "90-minute sanitation cleanout is required" in seg.text:
            path.write_text(json.dumps({
                "rule_id": "C-SANITATION", "kind": "setup_cleanout",
                "clause_kind": "OBLIGATION", "severity": "HARD",
                "verbatim_quote": "a full 90-minute sanitation cleanout is required before the next product runs",
                "params_json": "{\"cleanout_minutes\": 90}", "rationale": "obligation",
            }), encoding="utf-8")
        else:
            path.write_text(json.dumps({}), encoding="utf-8")


def test_extract_cli_writes_draft_and_report_offline(tmp_path):
    _seed_cli_fixtures()
    out = tmp_path / "draft.json"
    rep = tmp_path / "report.md"
    result = runner.invoke(app, [
        "extract", str(SOP_PATH), "--provider", "gemini",
        "--out", str(out), "--report", str(rep),
    ])
    assert result.exit_code == 0, result.output
    assert out.exists() and rep.exists()
    draft = json.loads(out.read_text(encoding="utf-8"))
    assert draft["non_gating_note"]                       # the DRAFT banner is in the file
    assert any(r["rule_id"] == "C-SANITATION" for r in draft["candidate_ir"]["rules"])
    md = rep.read_text(encoding="utf-8")
    assert "NOT CERTIFIED" in md                          # the report shouts non-gating
    assert "C-SANITATION" in md
    assert "Coverage" in md


def test_extract_cli_unknown_provider_errors(tmp_path):
    result = runner.invoke(app, [
        "extract", str(SOP_PATH), "--provider", "openai",
        "--out", str(tmp_path / "d.json"), "--report", str(tmp_path / "r.md"),
    ])
    assert result.exit_code != 0
