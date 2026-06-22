from __future__ import annotations

import pytest
from pydantic import ValidationError

from feasible.canon.canonical import digest_of
from feasible.extract.schema import SCHEMA_DESCRIPTOR, RuleDraft, draft_to_rule
from feasible.ir.domain import ClauseKind, CompileMode, Rule, Severity


def _draft(**over) -> RuleDraft:
    base = dict(
        rule_id="C-1", kind="setup_cleanout", clause_kind="OBLIGATION",
        severity="HARD", verbatim_quote="a full 90-minute sanitation cleanout is required",
        params_json='{"cleanout_minutes": 90}', rationale="cited sanitation requirement",
    )
    base.update(over)
    return RuleDraft(**base)


def test_ruledraft_validates_and_rejects_bad_enum():
    d = _draft()
    assert d.clause_kind == "OBLIGATION"
    with pytest.raises(ValidationError):
        _draft(clause_kind="MAYBE")          # not a ClauseKind value
    with pytest.raises(ValidationError):
        _draft(severity="MEDIUM")            # not HARD/SOFT


def test_ruledraft_rejects_empty_quote():
    with pytest.raises(ValidationError):
        _draft(verbatim_quote="   ")         # an empty/whitespace quote can't be anchored


def test_draft_to_rule_builds_candidate_rule_with_anchored_span():
    d = _draft()
    r = draft_to_rule(d, source_sha256="abc123", char_start=10, char_end=55)
    assert isinstance(r, Rule)
    assert r.rule_id == "C-1"
    assert r.severity == Severity.HARD
    assert r.clause_kind == ClauseKind.OBLIGATION
    assert r.compile_mode == CompileMode.PLAN_CONSTRAINT
    assert r.params == {"cleanout_minutes": 90}
    span = r.provenance.spans[0]
    assert span.char_start == 10 and span.char_end == 55
    assert span.source_sha256 == "abc123"
    assert span.role == "primary_normative"


def test_permission_draft_is_conflict_only():
    d = _draft(clause_kind="PERMISSION", severity="SOFT", params_json="")
    r = draft_to_rule(d, source_sha256="x", char_start=0, char_end=5)
    assert r.clause_kind == ClauseKind.PERMISSION
    assert r.compile_mode == CompileMode.CONFLICT_ONLY   # Rule validator requires this
    assert r.params == {}                                # empty params_json -> {}


def test_malformed_params_json_raises():
    with pytest.raises(ValueError):
        draft_to_rule(_draft(params_json="{not json"), source_sha256="x", char_start=0, char_end=5)


def test_schema_descriptor_is_stable_and_pydantic_independent():
    """C-3/C-4: the fixture key hashes SCHEMA_DESCRIPTOR (hand-authored), NOT
    RuleDraft.model_json_schema() (which Pydantic is free to reshape within 2.x).
    Pin the descriptor's digest so a fixture-orphaning drift fails LOUDLY here, and
    prove the descriptor is decoupled from the volatile generated schema."""
    # the descriptor enumerates exactly the wire fields + the two closed enums:
    assert set(SCHEMA_DESCRIPTOR["fields"]) == {
        "rule_id", "kind", "clause_kind", "severity",
        "verbatim_quote", "params_json", "rationale",
    }
    assert SCHEMA_DESCRIPTOR["clause_kind_enum"] == sorted(c.value for c in ClauseKind)
    assert SCHEMA_DESCRIPTOR["severity_enum"] == sorted(s.value for s in Severity)
    # SNAPSHOT PIN — if this digest changes, every committed fixture is orphaned;
    # that must be a DELIBERATE, reviewed bump (re-record fixtures), never a silent
    # Pydantic-driven drift. (Fill in the digest printed on first green run.)
    assert digest_of(SCHEMA_DESCRIPTOR) == "40fb819eaf85ab746a71ea7affcd269f340b796021acea4332aca40cd58781e2"
    # decoupled from the generated schema: the generated schema's digest is NOT the key
    assert digest_of(RuleDraft.model_json_schema()) != digest_of(SCHEMA_DESCRIPTOR)
