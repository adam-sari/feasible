import pytest
from feasible.registry import assert_all_hard_rules_supported, UnsupportedHardRuleError
from feasible.scenario import build_scenario_ir
from feasible.ir.domain import FCIR


def test_cross_domain_rule_id_is_unsupported_failclosed():
    ir = build_scenario_ir()
    bad = FCIR(rules=ir.rules, instance=ir.instance, domain_id="datacenter")  # mfg rules under dc domain
    with pytest.raises(UnsupportedHardRuleError):
        assert_all_hard_rules_supported(bad)


def test_registry_membership_implies_predicate():
    # every evaluated id must be produced by SOME violation path / have a Z3 branch (smoke)
    from feasible.domains import get_domain
    _, v = get_domain("manufacturing")
    assert v.evaluated_rule_ids   # non-empty; full predicate-existence asserted in checker tests
