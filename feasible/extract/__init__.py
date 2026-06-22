"""Track C — Gemini non-gating extraction (boundary A).

Gemini drafts a candidate FC-IR rule from a PRE-ENUMERATED span; deterministic
validators (Pydantic, ``anchor()``, the LLM-free coverage ledger) + the human
gate decide. A draft is NEVER auto-promoted — only a human-approved ``golden_ir``
is certified. This package imports NOTHING from ``feasible.cert`` (the non-gating
isolation barrier, asserted by ``tests/extract/test_non_gating.py``).
"""
from __future__ import annotations
