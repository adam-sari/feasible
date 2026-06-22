"""The non-gating audit (design §6, priority order):
  Barrier 1 — drafts are NEVER auto-promoted; only human-approved golden is certified.
  Barrier 2 — coverage completeness is deterministic + ZERO LLM input.
  Barrier 3 — anchor() rejects fabricated citations (exact-substring, fail-closed,
              segment-constrained — C-1).
PLUS — a real-quote-but-tampered-param draft does NOT silently become certifiable
       (proven by attempting api.certify and confirming it never admits the draft);
PLUS — NO code path feeds a draft into emit_*cert (extract-package AST isolation +
       dynamic-import scan + the extract CLI command's call-graph guard — C-5).
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

import feasible.cli  # noqa: F401  (so we can read its AST below)
from feasible.extract.orchestrate import _anchor_in_segment, extract_policy
from feasible.extract.provider import MODEL, FixtureProvider, build_prompt, fixture_key
from feasible.extract.schema import SCHEMA_DESCRIPTOR
from feasible.govern.coverage import build_coverage_ledger
from feasible.ingest.segment import anchor, segment
from feasible.ir.domain import FCIR

EXTRACT_DIR = Path("feasible/extract")
CLI_PATH = Path("feasible/cli.py")
SOP = Path("feasible/scenario/data/shop_rules.md").read_text(encoding="utf-8")


# ---- Barrier 1 + no-emit-path: the extract PACKAGE imports no cert (C-5) ----- #

def _cert_import_offenders(tree: ast.AST, label: str) -> list[str]:
    """Static (import/from) + dynamic (importlib/__import__ string-arg) cert imports."""
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("feasible.cert"):
            offenders.append(f"{label}: from {node.module}")
        if isinstance(node, ast.Import):
            for n in node.names:
                if n.name.startswith("feasible.cert"):
                    offenders.append(f"{label}: import {n.name}")
        # dynamic: importlib.import_module("feasible.cert...") / __import__("feasible.cert...")
        if isinstance(node, ast.Call):
            fn = node.func
            is_dynamic = (
                (isinstance(fn, ast.Attribute) and fn.attr == "import_module")
                or (isinstance(fn, ast.Name) and fn.id == "__import__")
            )
            if is_dynamic:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str) \
                            and arg.value.startswith("feasible.cert"):
                        offenders.append(f"{label}: dynamic import {arg.value!r}")
    return offenders


def test_barrier1_extract_package_imports_no_cert_static_or_dynamic():
    """C-5 (1): the whole extract PACKAGE must not import feasible.cert — neither
    statically (import/from) nor dynamically (importlib.import_module/__import__)."""
    offenders: list[str] = []
    for py in EXTRACT_DIR.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        offenders += _cert_import_offenders(tree, str(py))
    assert offenders == [], f"extract package must not touch cert/: {offenders}"


def test_no_emit_cert_symbol_referenced_anywhere_in_extract():
    """Belt-and-braces: the emit_* / cert symbols never appear in the extract source."""
    banned = ("emit_plan_cert", "emit_rulepack_cert", "rule_pack_digest")
    for py in EXTRACT_DIR.rglob("*.py"):
        src = py.read_text(encoding="utf-8")
        for sym in banned:
            assert sym not in src, f"{py} references cert symbol {sym!r}"


def test_extract_cli_command_call_graph_never_reaches_emit_cert():
    """C-5 (2): cli.py DOES import feasible.cert for run/certify — so we cannot claim
    'cli.py imports no cert'. Instead we scope the claim to the `extract` COMMAND: walk
    its function body and assert it references NO cert emitter symbol and calls only the
    extract entrypoints (extract_policy/make_provider/render_report), none of which
    import cert (proven by the package test above)."""
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    extract_fn = next(
        (n for n in ast.walk(tree)
         if isinstance(n, ast.FunctionDef) and n.name == "extract"),
        None,
    )
    if extract_fn is None:
        # The `extract` CLI command lands in Task 6 (this guard, Task 4, is sequenced
        # before it). With no `extract` command, the call-graph claim holds VACUOUSLY —
        # there is no command whose call graph could reach a cert emitter. The guard
        # engages automatically the moment Task 6 adds the command.
        pytest.skip("extract CLI command not yet added (Task 6); call-graph guard vacuous")
    banned = {"emit_plan_cert", "emit_rulepack_cert", "render_html", "rule_pack_digest"}
    referenced_names = {
        n.id for n in ast.walk(extract_fn) if isinstance(n, ast.Name)
    } | {
        n.attr for n in ast.walk(extract_fn) if isinstance(n, ast.Attribute)
    }
    assert not (referenced_names & banned), \
        f"extract command must not reference cert emitters: {referenced_names & banned}"
    # and it DOES route through the non-gating entrypoints:
    assert {"extract_policy", "make_provider", "render_report"} & referenced_names


# ---- Barrier 2: coverage is deterministic + LLM-free ------------------------- #

def test_barrier2_coverage_is_llm_free_and_deterministic():
    """build_coverage_ledger over the SAME inputs returns byte-identical ledgers
    and takes NO provider — its only inputs are sop_text + ir (no LLM)."""
    from feasible.domains import get_domain
    golden = get_domain("manufacturing")[0].golden_ir()
    empty = FCIR(rules=[], instance=golden.instance, domain_id="manufacturing")
    led1 = build_coverage_ledger(SOP, empty)
    led2 = build_coverage_ledger(SOP, empty)
    assert led1.model_dump() == led2.model_dump()       # deterministic
    # an empty candidate IR leaves every normative span RED (omission moat fires)
    assert led1.denominator > 0
    assert led1.complete is False and len(led1.red_findings) > 0


# ---- Barrier 3: anchor() rejects fabricated citations ------------------------ #

def test_barrier3_anchor_rejects_fabricated_quote():
    assert anchor("a full 90-minute sanitation cleanout is required", SOP) is not None
    assert anchor("the CEO personally approves every cleanout", SOP) is None   # fabricated


# ---- PLUS [C-2]: a real-quote-but-tampered-param draft is NOT certifiable ----- #

def test_real_quote_tampered_param_is_flagged_and_not_certifiable(tmp_path):
    """[MAJOR C-2] LOAD-BEARING tampered-param proof. A draft cites a REAL span but
    carries a wrong param (cleanout_minutes=1, span says 90). Two assertions make
    this load-bearing rather than a re-statement of barrier 1:
      (a) the ORCHESTRATOR flags the mismatch (param_mismatch=True) — the cited value
          is surfaced for human review, not silently passed; AND
      (b) NON-CERTIFIABILITY is PROVEN by running api.certify("manufacturing") and
          confirming no emitted cert carries the tampered identity/value — only the
          human-approved golden (R-SETUP=90) is certified; there is no api path that
          admits a draft, so a tampered param cannot ride into a certificate.
    """
    import json as _json

    import feasible.domains.manufacturing  # noqa: F401  (register the domain)
    from feasible import api
    from feasible.canon.canonical import new_signing_key
    from feasible.domains import get_domain

    real_quote = "a full 90-minute sanitation cleanout is required before the next product runs"

    # (a) drive the ORCHESTRATOR (where the flag lives) via a tmp scratch store:
    # the sanitation segment's fixture cites the REAL span but a tampered param.
    store = tmp_path / "fix"
    store.mkdir()
    for seg in segment(SOP):
        k = fixture_key(MODEL, build_prompt(seg.text.strip(), seg.heading_path), SCHEMA_DESCRIPTOR)
        if "90-minute sanitation cleanout is required" in seg.text:
            (store / f"{k}.json").write_text(_json.dumps({
                "rule_id": "C-TAMPER", "kind": "setup_cleanout",
                "clause_kind": "OBLIGATION", "severity": "HARD",
                "verbatim_quote": real_quote, "params_json": "{\"cleanout_minutes\": 1}",
                "rationale": "real quote, wrong number",
            }), encoding="utf-8")
        else:
            (store / f"{k}.json").write_text("{}", encoding="utf-8")
    rep = extract_policy(SOP, domain_id="manufacturing",
                         provider=FixtureProvider(store), fixtures_dir=store)
    tam = next(d for d in rep.drafted if d.rule.rule_id == "C-TAMPER")
    assert tam.grounded is True and tam.param_mismatch is True   # flagged for review
    assert tam.rule.params.get("cleanout_minutes") == 1          # candidate is just a draft

    # the golden is untouched (the human-approved source of truth)
    golden = get_domain("manufacturing")[0].golden_ir()
    golden_setup = next(r for r in golden.rules if r.rule_id == "R-SETUP")
    assert golden_setup.params.get("cleanout_minutes") == 90

    # (b) PROVE non-certifiability: api.certify certifies the GOLDEN ir; there is no
    # parameter by which a draft could be injected. Serialize the WHOLE bundle and
    # assert the tampered identity never appears while the golden rule does.
    key = new_signing_key()
    bundle = api.certify("manufacturing", signer_key=key)
    blob = _json.dumps(bundle.plan_cert) + _json.dumps(bundle.rule_pack_cert)
    assert "C-TAMPER" not in blob          # the draft's id never enters any cert
    assert "R-SETUP" in blob               # the golden rule is what was certified
    # and there is NO function in feasible.extract that turns a candidate into a cert:
    import feasible.extract as ex
    assert not hasattr(ex, "certify")
    assert not hasattr(ex, "emit_plan_cert")
