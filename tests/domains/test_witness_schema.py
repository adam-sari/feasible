from __future__ import annotations
import pytest
from pydantic import BaseModel
from feasible.checker.result import Violation
from feasible.domains.base import register_witness_schema, validate_witness


class _NightWitness(BaseModel):
    cleanout_start: int
    minute_of_day: int


def test_witness_roundtrips_through_registered_schema():
    register_witness_schema("night_cleanout", _NightWitness)
    v = Violation(rule_id="mfg:R-6.1-NIGHT-CLEANOUT", span=None,
                  message="x", counter_witness={"cleanout_start": 1050, "minute_of_day": 90},
                  witness_kind="night_cleanout", witness_version="v1")
    model = validate_witness(v.witness_kind, v.counter_witness)   # serialize->validate->equal
    assert model.model_dump() == v.counter_witness


def test_unregistered_witness_kind_fails_closed():
    with pytest.raises(KeyError):
        validate_witness("no_such_kind", {})
