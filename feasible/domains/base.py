"""Domain seam: protocols, view-models, and the witness-schema registry."""
from __future__ import annotations
from pydantic import BaseModel

_WITNESS_SCHEMAS: dict[str, type[BaseModel]] = {}

def register_witness_schema(witness_kind: str, model: type[BaseModel]) -> None:
    _WITNESS_SCHEMAS[witness_kind] = model

def validate_witness(witness_kind: str, counter_witness: dict) -> BaseModel:
    return _WITNESS_SCHEMAS[witness_kind].model_validate(counter_witness)  # KeyError = fail-closed
