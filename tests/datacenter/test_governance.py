"""Task 8: datacenter governance through the FROZEN govern_pack (Spec 0.5 T6).

Routing the datacenter pack through ``govern_pack(build_dc_extracted_pack(),
DATACENTER_POLICY)`` (NOT a ``dc_govern_pack`` mirror):

  * produces a ``universe_ir``/``active_ir`` BOTH with ``domain_id ==
    "datacenter"`` (the Spec 0.5 T6 guarantee — ``govern_pack`` threads
    ``extracted.domain_id`` through both reconstructions);
  * records the §5.2-equivalent scope correction (the over-broad mis-extraction
    narrowed at the gate);
  * records the §4.4-equivalent ``AUTO_BY_POLICY`` drop of the
    ``dc:accel-skip-redundancy`` permission (the floor — ``SAFETY_SANITATION``/100
    — strictly outranks ``ACCELERATION``/50, so the permission is dropped, the
    floor kept).
"""
from __future__ import annotations

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
from feasible.conflict.policy import DATACENTER_POLICY
from feasible.domains.datacenter.scenario import build_dc_extracted_pack
from feasible.govern.pipeline import govern_pack


def test_domain_id_survives_govern_pack():
    gov = govern_pack(build_dc_extracted_pack(), DATACENTER_POLICY)
    assert gov.universe_ir.domain_id == "datacenter"
    assert gov.active_ir.domain_id == "datacenter"


def test_govern_records_auto_drop_of_permission():
    gov = govern_pack(build_dc_extracted_pack(), DATACENTER_POLICY)
    # the floor (SAFETY_SANITATION/100) strictly outranks ACCELERATION/50 -> the
    # permission is AUTO-dropped, the redundancy floor kept.
    assert "dc:accel-skip-redundancy" in gov.dropped_rule_ids
    assert any(r.rule_id == "dc:redundancy_floor" for r in gov.active_ir.rules)
    assert all(r.rule_id != "dc:accel-skip-redundancy" for r in gov.active_ir.rules)
    auto = [r for r in gov.resolutions if r.resolution_mode == "AUTO_BY_POLICY"]
    assert auto and auto[0].dropped_rule_id == "dc:accel-skip-redundancy"


def test_govern_records_scope_correction():
    gov = govern_pack(build_dc_extracted_pack(), DATACENTER_POLICY)
    # the §5.2-equivalent mis-extraction is surfaced + corrected at the gate.
    assert gov.corrections, "expected a recorded scope correction"
