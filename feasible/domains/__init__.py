from __future__ import annotations
from feasible.domains.base import Domain, DomainVerifier

class UnknownDomainError(KeyError): ...

_DOMAINS: dict[str, tuple[Domain, DomainVerifier]] = {}

def register_domain(domain_id: str, domain: Domain, verifier: DomainVerifier) -> None:
    _DOMAINS[domain_id] = (domain, verifier)

def get_domain(domain_id: str) -> tuple[Domain, DomainVerifier]:
    if domain_id not in _DOMAINS:
        raise UnknownDomainError(domain_id)
    return _DOMAINS[domain_id]

def active_rule_ids_from_dicts(rules: list[dict]) -> list[str]:
    return sorted(r["rule_id"] for r in rules
                  if r.get("severity") == "HARD" and r.get("compile_mode") == "PLAN_CONSTRAINT")
