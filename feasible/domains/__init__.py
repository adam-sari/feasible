from __future__ import annotations

import importlib
import sys

from feasible.domains.base import Domain, DomainVerifier

class UnknownDomainError(KeyError): ...

_DOMAINS: dict[str, tuple[Domain, DomainVerifier]] = {}

# The EXPLICIT registered-domain package import-paths the facade bootstraps. Each
# package registers its bundle via a ``register_domain`` import side-effect.
# Manufacturing is the only registered domain in Spec 0.5; the datacenter track
# APPENDS its package path here (one line) when it forks against this seam, so the
# facade/verify path resolves it in a fresh process without the caller having
# imported the package directly. Order is irrelevant (registration is keyed by id).
_DOMAIN_PACKAGES: tuple[str, ...] = (
    "feasible.domains.manufacturing",
    "feasible.domains.datacenter",
)


def register_domain(domain_id: str, domain: Domain, verifier: DomainVerifier) -> None:
    _DOMAINS[domain_id] = (domain, verifier)


def bootstrap_domains() -> None:
    """Import every registered-domain package so ``get_domain`` /
    ``trusted_policy_set`` resolve in a fresh process regardless of import order.

    Called on the facade/verify entry paths (offline verify must resolve all
    domain bundles without the caller having imported a domain package). This is
    idempotent: importing an already-imported package is a no-op, so manufacturing
    stays byte-identical. If a package is already in ``sys.modules`` but its bundle
    is absent from ``_DOMAINS`` (e.g. the registry was cleared mid-process), the
    module is reloaded so its ``register_domain`` side-effect re-runs — the
    registration is re-derived from the package, never from cert bytes.
    """
    for pkg in _DOMAIN_PACKAGES:
        module = sys.modules.get(pkg)
        if module is None:
            importlib.import_module(pkg)
        elif not _package_registered(module):
            importlib.reload(module)


def _package_registered(module: object) -> bool:
    """Whether ``module``'s declared domain bundle is currently registered.

    A domain package may expose ``DOMAIN_ID`` to name the id it registers; absent
    that, fall back to "is the registry non-empty" (the import side-effect ran)."""
    domain_id = getattr(module, "DOMAIN_ID", None)
    if domain_id is not None:
        return domain_id in _DOMAINS
    return bool(_DOMAINS)

def get_domain(domain_id: str) -> tuple[Domain, DomainVerifier]:
    if domain_id not in _DOMAINS:
        raise UnknownDomainError(domain_id)
    return _DOMAINS[domain_id]

def active_rule_ids_from_dicts(rules: list[dict]) -> list[str]:
    return sorted(r["rule_id"] for r in rules
                  if r.get("severity") == "HARD" and r.get("compile_mode") == "PLAN_CONSTRAINT")
