"""Task 6 — ``govern_pack`` / ``active_after_resolution`` must thread the IR's
signed ``domain_id`` through the FCIR reconstructions, not silently reset it to
the ``"manufacturing"`` default. Manufacturing packs carry ``domain_id``
``"manufacturing"`` (the default) so this is byte-identical for manufacturing;
a second domain governs through the SINGLE frozen pipeline without a mirror.
"""
from __future__ import annotations

from feasible.conflict.policy import MANUFACTURING_POLICY
from feasible.domains import _DOMAINS, register_domain
from feasible.govern.conflict import active_after_resolution
from feasible.govern.pipeline import govern_pack
from feasible.ir.domain import FCIR
from feasible.scenario import build_extracted_pack

_OTHER_DOMAIN = "other_domain"


class _OtherVerifier:
    """A minimal second-domain verifier. ``govern_pack`` dispatches conflict
    detection on ``ir.domain_id``; this verifier reports NO realizable permission
    scope, so detection yields no conflicts — isolating the test on the
    ``domain_id``-threading reconstructions (it never touches manufacturing Z3)."""

    domain_id = _OTHER_DOMAIN

    def conflict_realizable(self, ir: object, permission: object) -> bool:
        return False

    def conflict_unsat_core(
        self, obligation_id: str, permission_id: str
    ) -> list[str] | None:
        return None


def _register_other_domain() -> None:
    register_domain(_OTHER_DOMAIN, object(), _OtherVerifier())


def _unregister_other_domain() -> None:
    _DOMAINS.pop(_OTHER_DOMAIN, None)


def _pack_with_domain_id(domain_id: str) -> FCIR:
    base = build_extracted_pack()
    return FCIR(rules=base.rules, instance=base.instance, domain_id=domain_id)


def test_govern_pack_threads_domain_id() -> None:
    _register_other_domain()
    try:
        pack = _pack_with_domain_id(_OTHER_DOMAIN)
        gov = govern_pack(pack, MANUFACTURING_POLICY)
        assert gov.universe_ir.domain_id == _OTHER_DOMAIN
        assert gov.active_ir.domain_id == _OTHER_DOMAIN
    finally:
        _unregister_other_domain()


def test_active_after_resolution_threads_domain_id() -> None:
    pack = _pack_with_domain_id(_OTHER_DOMAIN)
    # no resolutions -> all rules kept; domain_id must survive the reconstruction
    out = active_after_resolution(pack, [])
    assert out.domain_id == _OTHER_DOMAIN


def test_manufacturing_domain_id_unchanged() -> None:
    gov = govern_pack(build_extracted_pack(), MANUFACTURING_POLICY)
    assert gov.universe_ir.domain_id == "manufacturing"
    assert gov.active_ir.domain_id == "manufacturing"
