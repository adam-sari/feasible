"""Task 8: the synthetic 48 MW facility scenario + capacity_policy.md anchoring.

  * ``build_dc_scenario_ir()`` is a valid ``FCIR(domain_id="datacenter")`` whose
    every ``primary_normative`` span anchors (exact substring) in
    ``CAPACITY_POLICY``;
  * ``build_coverage_ledger(CAPACITY_POLICY, build_dc_scenario_ir())`` is
    ``complete`` (no RED) for the golden set;
  * the extracted pack carries ONE mis-extraction + ONE conflict-only permission;
  * B-6: the permission rule is ``clause_kind=PERMISSION``,
    ``compile_mode=CONFLICT_ONLY``, ``params["target_rule"] ==
    "dc:redundancy_floor"``, id ``"dc:accel-skip-redundancy"`` in
    ``DatacenterVerifier.known_rule_ids``;
  * B-9: ``classify_segment(<the pinned redundancy sentence>)`` returns
    ``hard_obligation`` (the deontic-wins invariant — the omission moat must not
    fail OPEN on the hero rule).
"""
from __future__ import annotations

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
from feasible.cert.plan_cert import checked_rule_ids, structurally_enforced_rule_ids
from feasible.domains import get_domain
from feasible.domains.datacenter.scenario import (
    CAPACITY_POLICY,
    REDUNDANCY_SENTENCE,
    build_dc_extracted_pack,
    build_dc_scenario_active_ir,
    build_dc_scenario_ir,
)
from feasible.govern.coverage import build_coverage_ledger
from feasible.ingest.segment import Segment, anchor
from feasible.ir.domain import ClauseKind, CompileMode, FCIR, Severity, TextSpan


def test_scenario_ir_is_datacenter_domain():
    ir = build_dc_scenario_ir()
    assert isinstance(ir, FCIR)
    assert ir.domain_id == "datacenter"
    assert any(r.rule_id == "dc:redundancy_floor" for r in ir.rules)


def test_every_primary_normative_span_anchors_in_capacity_policy():
    ir = build_dc_scenario_ir()
    anchored = 0
    for r in ir.rules:
        for s in r.provenance.spans:
            if isinstance(s, TextSpan) and s.role == "primary_normative":
                pos = anchor(s.quoted_text, CAPACITY_POLICY)
                assert pos is not None, f"{r.rule_id}: quote not in capacity_policy.md: {s.quoted_text!r}"
                assert (s.char_start, s.char_end) == pos
                anchored += 1
    assert anchored >= 1  # at least the redundancy floor cites the SOP


def test_coverage_ledger_complete_no_red():
    ir = build_dc_scenario_ir()
    ledger = build_coverage_ledger(CAPACITY_POLICY, ir)
    assert ledger.complete, [e.text for e in ledger.red_findings]
    assert ledger.denominator >= 1


def test_extracted_pack_carries_one_mis_extraction_and_one_permission():
    pack = build_dc_extracted_pack()
    assert pack.domain_id == "datacenter"
    permissions = [r for r in pack.rules if r.clause_kind == ClauseKind.PERMISSION]
    assert len(permissions) == 1
    perm = permissions[0]
    # B-6: the pinned conflict-only permission shape.
    assert perm.rule_id == "dc:accel-skip-redundancy"
    assert perm.compile_mode == CompileMode.CONFLICT_ONLY
    assert perm.params.get("target_rule") == "dc:redundancy_floor"
    _, verifier = get_domain("datacenter")
    assert "dc:accel-skip-redundancy" in verifier.known_rule_ids


def test_redundancy_sentence_classifies_hard_obligation():
    # B-9: the pinned redundancy sentence the dc:redundancy_floor rule anchors MUST
    # classify hard_obligation (deontic-wins invariant; the coverage-RED guard must
    # NOT fail OPEN on the hero rule).
    _, verifier = get_domain("datacenter")
    seg = Segment(char_start=0, char_end=len(REDUNDANCY_SENTENCE), text=REDUNDANCY_SENTENCE)
    assert verifier.classify_segment(seg) == "hard_obligation"


def test_structural_caps_are_active_hard_plan_rules_in_scenario():
    """The structural ``dc:power_cap``/``dc:anti_affinity`` are emitted HARD/
    PLAN_CONSTRAINT in the governed scenario active set: their KIND is in
    ``structural_rule_kinds`` (so they are SUPPORTED kind-wise, not as inert
    SOFT/CONFLICT_ONLY rules), and they are now active hard-plan guards whose closed
    predicates actually run on the certified plan. A 'structural' rule that is
    CONFLICT_ONLY would be contradictory + inert — this pins them honest."""
    ir = build_dc_scenario_active_ir()
    for rid in ("dc:power_cap", "dc:anti_affinity"):
        r = ir.rule(rid)
        assert r is not None
        assert r.severity == Severity.HARD
        assert r.compile_mode == CompileMode.PLAN_CONSTRAINT
        assert ir.has_active(rid)


def test_structurally_enforced_and_checked_rule_ids_partition_the_active_hard_rules():
    """The cert's formalization ledger now DEMONSTRATES the structural-enforcement
    guarantee: ``structurally_enforced_rule_ids`` is the two structural caps (no longer
    a vacuously-empty ``[]``) and ``checked_rule_ids`` stays the two predicate-evaluated
    plan-dependent rules. The two sets partition the active hard PLAN_CONSTRAINT rules."""
    ir = build_dc_scenario_active_ir()
    assert structurally_enforced_rule_ids(ir) == ["dc:anti_affinity", "dc:power_cap"]
    assert checked_rule_ids(ir) == ["dc:maintenance_window", "dc:redundancy_floor"]
    # the two ledger sets partition the active hard rules (no rule both checked and
    # structurally enforced; together they cover every active hard PLAN_CONSTRAINT rule).
    hard = {r.rule_id for r in ir.hard_plan_rules()}
    assert hard == set(structurally_enforced_rule_ids(ir)) | set(checked_rule_ids(ir))
    assert not (set(structurally_enforced_rule_ids(ir)) & set(checked_rule_ids(ir)))
