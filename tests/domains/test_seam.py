from __future__ import annotations
import pytest
from feasible.domains import get_domain, register_domain, UnknownDomainError, active_rule_ids_from_dicts

def test_unknown_domain_fails_closed():
    with pytest.raises(UnknownDomainError):
        get_domain("no_such_domain")

def test_active_rule_ids_from_dicts_is_instance_independent():
    rules = [
        {"rule_id": "mfg:R-SETUP", "severity": "HARD", "compile_mode": "PLAN_CONSTRAINT"},
        {"rule_id": "mfg:R-4.4", "severity": "SOFT", "compile_mode": "CONFLICT_ONLY"},
    ]
    assert active_rule_ids_from_dicts(rules) == ["mfg:R-SETUP"]   # only HARD+PLAN_CONSTRAINT, no instance built
