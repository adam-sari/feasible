"""JSON-Schema export for the FC-IR (the LLM-emission/wire form)."""
from __future__ import annotations

from feasible.ir.domain import FCIR


def export_json_schema() -> dict:
    return FCIR.model_json_schema()
