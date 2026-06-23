"""The synthetic datacenter facility builder.

Task 1 lands a SMALL but representative facility (every dc:* rule kind present,
every structural sub-model populated) so the pack/unpack convention is exercised
over the full surface. Task 8 fleshes this into the hero scenario (capacity policy,
governance, KPIs, the N+1-buffer gotcha). The facility is INTEGERS-ONLY and
normalized (sorted intervals) so pack/unpack is exact identity.

Task 8 adds the source-anchored layer:

  * ``CAPACITY_POLICY`` — the synthetic SOP (``data/capacity_policy.md``); every
    ``primary_normative`` span the dc rules cite is a VERBATIM substring of it
    (exact-substring ``anchor()``), exactly as manufacturing rules are anchored
    against ``shop_rules.md``;
  * ``build_dc_scenario_ir`` — the GOLDEN datacenter IR (the rules anchored +
    activated), valid ``FCIR(domain_id="datacenter")``;
  * ``build_dc_extracted_pack`` — the 'messy extraction' pack: the golden IR plus
    ONE replayable mis-extraction (an over-broad scope corrected at the gate) and
    ONE conflict-only acceleration permission (``dc:accel-skip-redundancy``, B-6)
    the §4.4-equivalent govern step AUTO-drops because the floor
    (``SAFETY_SANITATION``) outranks ``ACCELERATION``;
  * ``build_dc_scenario_active_ir`` — the governed active set (universe minus the
    auto-dropped permission), the surface the plan certifies + the incumbents run
    against;
  * ``dc_incumbent_a`` / ``dc_incumbent_b`` — the two baselines: A spends the N+1
    buffer (an EMERGENT redundancy-floor breach), B is feasible-naive (holds the
    floor, defers maintenance -> a larger makespan).
"""
from __future__ import annotations

from pathlib import Path

from feasible.domains.datacenter.instance import (
    AntiAffinityGroup,
    DatacenterInstance,
    FaultDomain,
    Feed,
    Hall,
    MaintenanceTask,
    MaintenanceWindow,
    PowerCap,
    Rack,
    RedundancyGroup,
    pack_dc_instance,
)
from feasible.ingest.segment import anchor, sha256_text
from feasible.ir.domain import (
    ClauseKind,
    CompileMode,
    ExceptionMode,
    FCIR,
    Plan,
    Provenance,
    Rule,
    Severity,
    TextSpan,
)

HORIZON = 8  # 8 integer timesteps

# --------------------------------------------------------------------------- #
# The synthetic SOP (the extraction source the dc rules anchor against).      #
# --------------------------------------------------------------------------- #
_DATA = Path(__file__).resolve().parent / "data"
CAPACITY_POLICY = (_DATA / "capacity_policy.md").read_text(encoding="utf-8")

# B-9: the PINNED redundancy sentence. It (a) anchors the dc:redundancy_floor rule's
# primary_normative span (exact substring of CAPACITY_POLICY) and (b) classifies
# ``hard_obligation`` under ``DatacenterVerifier.classify_segment`` (the deontic
# "must"/"shall" + redundancy keywords drive it), so the coverage-RED guard (Task 10)
# dropping this clause provably goes RED — the omission moat must NOT fail OPEN on
# the hero rule.
REDUNDANCY_SENTENCE = (
    "The facility must at all times maintain N+1 redundancy on every cooling path "
    "and 2N on every UPS feed; maintenance shall not reduce available redundant "
    "capacity below the N+1 floor."
)

# The verbatim quotes the other dc rules cite (each an exact substring of the SOP).
_POWER_CAP_QUOTE = "Every feed must keep its aggregate rack draw within the certified feed cap"
_MAINTENANCE_WINDOW_QUOTE = (
    "Maintenance tasks must not be scheduled inside a posted change-freeze window"
)
_ANTI_AFFINITY_QUOTE = (
    "Replicas of a redundant service must not be placed in the same power or cooling "
    "fault domain"
)


def build_dc_scenario_dc_instance() -> DatacenterInstance:
    """A small representative facility: 1 hall, 4 feeds (one N+1 redundant group of
    3 + a spare), 4 racks across 2 fault domains, one power cap, one anti-affinity
    pair, two maintenance tasks (one on a redundant feed -> the buffer mechanism),
    one forbidden maintenance window."""
    halls = [Hall(id="H1")]
    fault_domains = [FaultDomain(id="FD-A"), FaultDomain(id="FD-B")]
    feeds = [
        Feed(id="F1", hall_id="H1", capacity_kw=500),
        Feed(id="F2", hall_id="H1", capacity_kw=500),
        Feed(id="F3", hall_id="H1", capacity_kw=500),
        Feed(id="F4", hall_id="H1", capacity_kw=500),
    ]
    racks = [
        Rack(id="R1", hall_id="H1", feed_id="F1", fault_domain_id="FD-A", draw_kw=60),
        Rack(id="R2", hall_id="H1", feed_id="F2", fault_domain_id="FD-A", draw_kw=60),
        Rack(id="R3", hall_id="H1", feed_id="F3", fault_domain_id="FD-B", draw_kw=70),
        Rack(id="R4", hall_id="H1", feed_id="F4", fault_domain_id="FD-B", draw_kw=70),
    ]
    redundancy_groups = [
        RedundancyGroup(
            group_id="G1", units=["F1", "F2", "F3"], floor=2,
            maintenance={"F3": [(6, 8)]},  # a FIXED outage near horizon end (sorted)
        ),
    ]
    power_caps = [
        PowerCap(
            cap_id="CAP-H1", scope_units=["R1", "R2", "R3", "R4"], cap_kw=300,
            per_member_pct=40, draws={"R1": 60, "R2": 60, "R3": 70, "R4": 70},
        ),
    ]
    anti_affinity_groups = [
        AntiAffinityGroup(
            group_id="AA1", replicas=["R1", "R3"],
            fault_domain_of={"R1": "FD-A", "R3": "FD-B"},
        ),
    ]
    maintenance_tasks = [
        MaintenanceTask(id="T1", path="F1", duration=2, unit="F1"),
        MaintenanceTask(id="T2", path="F4", duration=1, unit=None),
    ]
    maintenance_windows = [
        MaintenanceWindow(
            path_id="F1", forbidden=[(0, 2)], derate_kw={"F1": 100},
        ),
    ]
    return DatacenterInstance(
        horizon=HORIZON,
        halls=halls, feeds=feeds, racks=racks, fault_domains=fault_domains,
        redundancy_groups=redundancy_groups, power_caps=power_caps,
        anti_affinity_groups=anti_affinity_groups,
        maintenance_tasks=maintenance_tasks, maintenance_windows=maintenance_windows,
    )


# --------------------------------------------------------------------------- #
# Source anchoring + rule activation (Task 8)                                 #
# --------------------------------------------------------------------------- #

# The primary_normative quote each dc rule kind cites (verbatim SOP substring).
_RULE_QUOTE: dict[str, str] = {
    "dc:redundancy_floor": REDUNDANCY_SENTENCE,
    "dc:power_cap": _POWER_CAP_QUOTE,
    "dc:maintenance_window": _MAINTENANCE_WINDOW_QUOTE,
    "dc:anti_affinity": _ANTI_AFFINITY_QUOTE,
}

# The rule kinds promoted to ACTIVE (HARD/PLAN_CONSTRAINT) in the golden scenario.
# redundancy_floor is already HARD/PLAN_CONSTRAINT from the packer; maintenance_window
# is PLAN-DEPENDENT and is promoted here so the solver respects the forbidden windows.
# The STRUCTURAL power_cap/anti_affinity stay instance invariants (SOFT/CONFLICT_ONLY),
# checked by their closed predicates but not plan-scheduled.
_ACTIVE_RULE_IDS: frozenset[str] = frozenset({"dc:redundancy_floor", "dc:maintenance_window"})


def _anchor_dc_rules(rules: list[Rule], sop_text: str) -> None:
    """Anchor every primary_normative span against ``sop_text`` (validates the quote
    exists + pins its char range). Mirror ``feasible.scenario._anchor_rules``."""
    digest = sha256_text(sop_text)
    for r in rules:
        for s in r.provenance.spans:
            if isinstance(s, TextSpan) and s.role == "primary_normative":
                pos = anchor(s.quoted_text, sop_text)
                assert pos is not None, f"{r.rule_id}: quote not in capacity_policy.md: {s.quoted_text!r}"
                s.char_start, s.char_end, s.source_sha256 = pos[0], pos[1], digest


def _golden_rules() -> list[Rule]:
    """Pack the synthetic facility, then attach the SOURCE-ANCHORED primary_normative
    span + promote the active plan-dependent rules. The packer already encodes the
    topology into params (re-derivable); here we only set provenance + activation."""
    dc = build_dc_scenario_dc_instance()
    _inst, rules = pack_dc_instance(dc)
    for r in rules:
        quote = _RULE_QUOTE.get(r.rule_id)
        if quote is not None:
            # replace the packer's modeling-decision span with a SOURCE quote (the
            # facility structural block, carried on the first redundancy rule's params,
            # is untouched — it lives in params, not provenance).
            r.provenance = Provenance(spans=[TextSpan(quoted_text=quote, role="primary_normative")])
        if r.rule_id in _ACTIVE_RULE_IDS:
            r.severity = Severity.HARD
            r.compile_mode = CompileMode.PLAN_CONSTRAINT
    _anchor_dc_rules(rules, CAPACITY_POLICY)
    return rules


def build_dc_scenario_ir() -> FCIR:
    """The GOLDEN datacenter IR (the hand-verified reference rule pack): the
    source-anchored, activated dc rules over the packed synthetic facility instance.
    A valid ``FCIR(domain_id="datacenter")``."""
    dc = build_dc_scenario_dc_instance()
    inst, _rules = pack_dc_instance(dc)
    return FCIR(rules=_golden_rules(), instance=inst, domain_id="datacenter")


# --------------------------------------------------------------------------- #
# The 'messy extraction' pack: golden + one mis-extraction + one permission   #
# --------------------------------------------------------------------------- #

def _span(quoted: str, role: str = "primary_normative") -> TextSpan:
    return TextSpan(quoted_text=quoted, role=role)


def make_dc_permission() -> Rule:
    """B-6: the PINNED conflict-only acceleration permission
    (``dc:accel-skip-redundancy``) — a recorded extraction the §4.4-equivalent
    govern step AUTO-drops (the floor / ``SAFETY_SANITATION`` outranks
    ``ACCELERATION``). Its shape is exactly what ``detect_normative_conflicts``
    produces + ``verify_rulepack_cert``'s pairing invariant admits:
    ``clause_kind=PERMISSION``, ``compile_mode=CONFLICT_ONLY``,
    ``params['target_rule'] == 'dc:redundancy_floor'``, plus the scope keys
    ``conflict_realizable`` reads (``group_id``/``units``/``window``)."""
    return Rule(
        rule_id="dc:accel-skip-redundancy", kind="permission",
        params={
            "target_rule": "dc:redundancy_floor",
            "group_id": "G1",
            "units": ["F1", "F2", "F3"],
            "window": [6, 8],
        },
        severity=Severity.SOFT, clause_kind=ClauseKind.PERMISSION,
        compile_mode=CompileMode.CONFLICT_ONLY, resolution_class="ACCELERATION",
        exception_mode=ExceptionMode.NONE,
        provenance=Provenance(spans=[_span(
            "Commissioning acceleration", role="primary_normative")]),
    )


def make_dc_mis_extraction() -> Rule:
    """The replayable §5.2-equivalent mis-extraction: an over-broad scope the LLM
    produced (``scope='whole_line'``), narrowed to ``fill_op`` at the gate by the
    frozen ``scope_is_overbroad``/``correct_scope`` back-translation hook. It carries
    NO primary_normative span (a modeling artifact, not a source clause) so coverage
    is unaffected; it is dropped/corrected, never plan-active."""
    return Rule(
        rule_id="dc:over-broad-maintenance", kind="non_preemption",
        params={"scope": "whole_line"},
        severity=Severity.SOFT, clause_kind=ClauseKind.OBLIGATION,
        compile_mode=CompileMode.CONFLICT_ONLY, resolution_class="EFFICIENCY",
        exception_mode=ExceptionMode.NONE,
        provenance=Provenance(spans=[_span(
            "over-broad maintenance lock (mis-extraction)", role="modeling_decision")]),
    )


def build_dc_extracted_pack() -> FCIR:
    """The 'messy extraction' candidate pack: the golden rules + the seeded
    conflict-only permission (B-6) and the over-broad mis-extraction. Routed through
    the FROZEN ``govern_pack`` (Spec 0.5 T6 threads ``domain_id``) — NO mirror."""
    base = build_dc_scenario_ir()
    extracted = [make_dc_permission(), make_dc_mis_extraction()]
    return FCIR(rules=[*base.rules, *extracted], instance=base.instance, domain_id="datacenter")


def build_dc_scenario_active_ir() -> FCIR:
    """The GOVERNED active set: the extracted pack run through the frozen
    ``govern_pack`` under ``DATACENTER_POLICY`` — universe minus the AUTO-dropped
    ``dc:accel-skip-redundancy`` permission (and the corrected mis-extraction). This
    is the surface the plan certifies + the incumbents run against. Lazy import of
    the policy to avoid a scenario<->policy import cycle."""
    from feasible.conflict.policy import DATACENTER_POLICY
    from feasible.govern.pipeline import govern_pack

    return govern_pack(build_dc_extracted_pack(), DATACENTER_POLICY).active_ir


# --------------------------------------------------------------------------- #
# The two incumbents (Task 8) — A spends the N+1 buffer; B is feasible-naive   #
# --------------------------------------------------------------------------- #

def dc_incumbent_b(ir: FCIR | None = None) -> Plan:
    """A FEASIBLE-NAIVE baseline: hold the N+1 floor everywhere (no buffer spent) but
    DEFER maintenance — schedule each task at a later floor-holding slot, so the
    makespan is larger than the optimized plan. Deterministic (fixed scenario).

    T1 (path F1, dur 2, derates redundancy unit F1) is placed at [4,6) — legal vs the
    forbidden window [0,2) on F1 AND clear of F3's fixed outage [6,8), so the floor
    holds; T2 (path F4, dur 1, no redundancy linkage) is placed at [5,6). makespan 6."""
    return Plan(assignments={"task:T1": (4, "F1"), "task:T2": (5, "F4")}, cleanouts=[])


def dc_incumbent_a(ir: FCIR | None = None) -> Plan:
    """The HERO baseline (B-2): a degenerate-makespan-minimizing plan that SPENDS the
    N+1 buffer. It schedules T1 (which derates redundancy unit F1) at [6,8) — exactly
    overlapping F3's FIXED outage [6,8) — so at t=6,7 only F2 is available (1 < floor
    2): an EMERGENT redundancy-floor breach, not a hand-planted cleanout. T2 at [0,1).

    The breach is the maintenance-spends-the-buffer gotcha: a planner minimizing
    makespan (run the F1 task as late/short as possible) walks straight into the floor
    violation the certificate catches."""
    return Plan(assignments={"task:T1": (6, "F1"), "task:T2": (0, "F4")}, cleanouts=[])
