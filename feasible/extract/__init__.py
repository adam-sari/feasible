"""Track C — Gemini non-gating extraction (boundary A).

Gemini drafts a candidate FC-IR rule from a PRE-ENUMERATED span; deterministic
validators (Pydantic, ``anchor()``, the LLM-free coverage ledger) + the human
gate decide. A draft is NEVER auto-promoted — only a human-approved ``golden_ir``
is certified. This package imports NOTHING from ``feasible.cert`` (the non-gating
isolation barrier, asserted by ``tests/extract/test_non_gating.py``).
"""
from __future__ import annotations

from feasible.extract.orchestrate import ExtractionReport, extract_policy
from feasible.extract.provider import (
    FixtureProvider,
    GeminiProvider,
    Provider,
    make_provider,
)
from feasible.extract.report import render_report
from feasible.extract.schema import SCHEMA_DESCRIPTOR, RuleDraft, draft_to_rule

__all__ = [
    "extract_policy",
    "ExtractionReport",
    "RuleDraft",
    "SCHEMA_DESCRIPTOR",
    "draft_to_rule",
    "Provider",
    "FixtureProvider",
    "GeminiProvider",
    "make_provider",
    "render_report",
]
