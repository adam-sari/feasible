"""The Gemini ``response_schema`` (``RuleDraft``) + the candidate-Rule adapter.

``RuleDraft`` is a CLOSED, JSON-scalar Pydantic model (no floats, no open dict) so
it is a stable ``response_schema`` for ``gemini-2.5-flash``. ``draft_to_rule``
maps a VALIDATED, ALREADY-ANCHORED draft into the frozen ``feasible.ir.domain.Rule``
— a CANDIDATE only. Nothing here certifies anything; the human gate promotes a
candidate into ``golden_ir`` before any cert is emitted (design §6 barrier 1).
"""
from __future__ import annotations

import json

from pydantic import BaseModel, field_validator

from feasible.ir.domain import (
    ClauseKind,
    CompileMode,
    Provenance,
    Rule,
    Severity,
    TextSpan,
)

_CLAUSE_KINDS = {c.value for c in ClauseKind}
_SEVERITIES = {s.value for s in Severity}


class RuleDraft(BaseModel):
    """A single Gemini-drafted candidate rule. JSON-scalar fields only."""

    rule_id: str
    kind: str
    clause_kind: str
    severity: str
    verbatim_quote: str
    params_json: str = ""
    rationale: str = ""

    @field_validator("clause_kind")
    @classmethod
    def _clause(cls, v: str) -> str:
        if v not in _CLAUSE_KINDS:
            raise ValueError(f"clause_kind must be one of {sorted(_CLAUSE_KINDS)}, got {v!r}")
        return v

    @field_validator("severity")
    @classmethod
    def _sev(cls, v: str) -> str:
        if v not in _SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(_SEVERITIES)}, got {v!r}")
        return v

    @field_validator("verbatim_quote")
    @classmethod
    def _quote(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("verbatim_quote must be a non-empty span the model echoes")
        return v


# C-3/C-4: the STABLE, hand-authored fixture-key descriptor. The fixture key hashes
# THIS dict (which we own and version), NOT RuleDraft.model_json_schema() (which
# Pydantic may reshape within 2.x — adding/relabeling `title`/`$defs` — silently
# orphaning every committed fixture). The LIVE GeminiProvider passes the RuleDraft
# CLASS to response_schema (the SDK introspects it); this descriptor is ONLY the
# deterministic fixture key. Bump `version` (and re-record fixtures) on a DELIBERATE
# wire-shape change; a snapshot test pins digest_of(SCHEMA_DESCRIPTOR).
SCHEMA_DESCRIPTOR: dict = {
    "version": 1,
    "model_name": "RuleDraft",
    "fields": {
        "rule_id": "str",
        "kind": "str",
        "clause_kind": "str",
        "severity": "str",
        "verbatim_quote": "str",
        "params_json": "str",
        "rationale": "str",
    },
    "clause_kind_enum": sorted(_CLAUSE_KINDS),
    "severity_enum": sorted(_SEVERITIES),
}


def _parse_params(params_json: str) -> dict:
    if not params_json.strip():
        return {}
    obj = json.loads(params_json)  # ValueError on malformed input -> draft dropped
    if not isinstance(obj, dict):
        raise ValueError(f"params_json must encode a JSON object, got {type(obj).__name__}")
    return obj


def draft_to_rule(
    draft: RuleDraft,
    *,
    source_sha256: str,
    char_start: int,
    char_end: int,
) -> Rule:
    """Map a validated, anchored ``RuleDraft`` to a CANDIDATE ``Rule``.

    ``char_start``/``char_end`` come from ``anchor()`` (exact-substring); this
    function never anchors itself. A ``PERMISSION`` compiles ``CONFLICT_ONLY``
    (the ``Rule`` model validator enforces it); everything else is a
    ``PLAN_CONSTRAINT`` candidate.
    """
    clause = ClauseKind(draft.clause_kind)
    compile_mode = (
        CompileMode.CONFLICT_ONLY
        if clause == ClauseKind.PERMISSION
        else CompileMode.PLAN_CONSTRAINT
    )
    span = TextSpan(
        source_sha256=source_sha256,
        char_start=char_start,
        char_end=char_end,
        quoted_text=draft.verbatim_quote,
        role="primary_normative",
    )
    return Rule(
        rule_id=draft.rule_id,
        kind=draft.kind,
        params=_parse_params(draft.params_json),
        severity=Severity(draft.severity),
        clause_kind=clause,
        compile_mode=compile_mode,
        provenance=Provenance(spans=[span]),
    )
