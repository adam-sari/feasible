from __future__ import annotations

import feasible.domains.manufacturing  # noqa: F401  (import = register the domain)
from feasible.domains import get_domain, register_domain
from feasible.domains.base import domains_known_rule_ids_disjoint


def test_manufacturing_known_rule_ids():
    _, v = get_domain("manufacturing")
    assert "R-SETUP" in v.known_rule_ids and "R-4.4" in v.known_rule_ids


def test_registered_domains_are_disjoint():
    assert domains_known_rule_ids_disjoint() is True
