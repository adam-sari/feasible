"""The crafted sauce co-packer scenario: in-code instance, golden IR, and the two
incumbents (A illegal / B feasible-naive). Numbers are TUNED so the §3.2 CI gates
pass. KPI helpers are re-exported from ``feasible.solve.orchestrate`` (single
source of truth — never redefined here).
"""
from __future__ import annotations

import json
from pathlib import Path

from ortools.sat.python import cp_model

from feasible.compile.cpsat import build_model, extract_plan
from feasible.ingest.golden import load_golden_ir
from feasible.ingest.segment import anchor, sha256_text
from feasible.ingest.tabular import write_orders_xlsx
from feasible.ir.domain import (
    ClauseKind,
    CompileMode,
    ExceptionMode,
    FCIR,
    Instance,
    Job,
    Operation,
    OpClass,
    Provenance,
    Rule,
    Severity,
    TextSpan,
)
from feasible.solve.orchestrate import (  # re-exported single source of truth
    late_priority_orders,
    recompute_objective,
    total_changeover_time,
    weighted_tardiness,
)

DATA = Path(__file__).resolve().parent / "data"
SHOP_RULES = (DATA / "shop_rules.md").read_text(encoding="utf-8")

MACHINES = ["Mixer-A", "Mixer-B", "Filler-1", "Filler-2", "Labeler"]

# job_id, product, family, priority, due_date  (tuned so naive B is tardy, optimum is not)
JOBS = [
    ("J1", "PeanutGold", "Allergen", 1, 360),
    ("J2", "MildClassic", "Standard", 1, 380),
    ("J3", "GardenHerb", "Standard", 2, 760),
    ("J4", "FieryChipotle", "Spicy", 2, 800),
    ("J5", "SesameSwirl", "Allergen", 3, 1300),
    ("J6", "PlainTable", "Standard", 3, 1340),
]
# per-job (mix, fill, label) durations — distinct/co-prime-ish; the Labeler is the bottleneck
DUR = {
    "J1": (31, 17, 110), "J2": (29, 13, 100), "J3": (37, 19, 90),
    "J4": (23, 11, 80), "J5": (41, 23, 130), "J6": (19, 7, 70),
}
HORIZON = 4320  # 3 days


def _span(quoted: str, role: str = "primary_normative") -> TextSpan:
    return TextSpan(quoted_text=quoted, role=role)


def _rule(rule_id, kind, clause, resclass, quoted, params=None, role="primary_normative") -> Rule:
    return Rule(
        rule_id=rule_id, kind=kind, params=params or {}, severity=Severity.HARD,
        clause_kind=clause, compile_mode=CompileMode.PLAN_CONSTRAINT, resolution_class=resclass,
        exception_mode=ExceptionMode.NONE, provenance=Provenance(spans=[_span(quoted, role)]),
    )


def build_scenario_ir() -> FCIR:
    jobs = [Job(id=j, product=p, family=f, qty=100, due_date=d, priority=pr) for (j, p, f, pr, d) in JOBS]
    operations: list[Operation] = []
    for (j, _p, _f, _pr, _d) in JOBS:
        md, fd, ld = DUR[j]
        operations.append(Operation(op_id=f"{j}-mix", job_id=j, seq=0, eligible_machines=["Mixer-A", "Mixer-B"], duration=md))
        operations.append(Operation(op_id=f"{j}-fill", job_id=j, seq=1, eligible_machines=["Filler-1", "Filler-2"], duration=fd))
        operations.append(Operation(op_id=f"{j}-label", job_id=j, seq=2, eligible_machines=["Labeler"], duration=ld))
    inst = Instance(
        jobs=jobs, operations=operations, machines=MACHINES,
        setup_matrix={"Allergen|Standard": 90, "Allergen|Spicy": 90},
        maintenance=[("Filler-2", 1200, 1440)], horizon=HORIZON,
    )
    rules = [
        _rule("R-ROUTING", "routing_precedence", ClauseKind.OBLIGATION, "EFFICIENCY",
              "Mix -> Fill -> Label routing (structural)", role="modeling_decision"),
        _rule("R-NOOVERLAP", "no_overlap", ClauseKind.PROHIBITION, "EFFICIENCY",
              "Per-machine no-overlap (structural)", role="modeling_decision"),
        _rule("R-SETUP", "setup_cleanout", ClauseKind.OBLIGATION, "SAFETY_SANITATION",
              "a full 90-minute sanitation cleanout is required before the next product runs",
              {"cleanout_minutes": 90, "trigger_family": "Allergen"}),
        _rule("R-MAINT", "maintenance", ClauseKind.PROHIBITION, "HARD_AVAILABILITY_MAINTENANCE",
              "Filler-2 is unavailable for scheduled maintenance every Tuesday 02:00-06:00"),
        _rule("R-SHIFT", "shift", ClauseKind.OBLIGATION, "EFFICIENCY",
              "The plant runs two shifts: day 06:00-22:00 and night 22:00-06:00",
              {"day_start": 0, "day_end": 960, "night_start": 960, "night_end": 1440}),
        _rule("R-6.1-NIGHT-CLEANOUT", "night_cleanout", ClauseKind.PROHIBITION, "SAFETY_SANITATION",
              "Cleanouts may only be performed during the day shift; the sanitation crew does not work nights",
              {"day_start": 0, "day_end": 960, "night_start": 960, "night_end": 1440}),
    ]
    # anchor spans against the SOP (validates the primary_normative quotes exist)
    digest = sha256_text(SHOP_RULES)
    for r in rules:
        for s in r.provenance.spans:
            if s.role == "primary_normative":
                pos = anchor(s.quoted_text, SHOP_RULES)
                assert pos is not None, f"{r.rule_id}: quote not in SOP: {s.quoted_text!r}"
                s.char_start, s.char_end, s.source_sha256 = pos[0], pos[1], digest
    return FCIR(rules=rules, instance=inst)


def generate_incumbent_b(ir: FCIR, max_seconds: float = 30.0):
    """A feasible-but-naive baseline: force the priority-1 labels LAST (so they
    ship late) and pay the resulting allergen cleanouts."""
    m, vi = build_model(ir)
    p1_labels = [o for o in ir.instance.operations if o.seq == 2 and ir.instance.job(o.job_id).priority == 1]
    other_labels = [o for o in ir.instance.operations if o.seq == 2 and ir.instance.job(o.job_id).priority != 1]
    for pl in p1_labels:
        for ol in other_labels:
            m.add(vi.starts[pl.op_id] >= vi.ends[ol.op_id])
    m.minimize(vi.total_changeover)
    solver = cp_model.CpSolver()
    solver.parameters.num_search_workers = 1
    solver.parameters.max_time_in_seconds = max_seconds
    solver.solve(m)
    return extract_plan(solver, vi)


def make_incumbent_a(incumbent_b, machine: str = "Labeler"):
    """The planner's baseline with a manually-placed 23:30 (illegal) cleanout."""
    from feasible.ir.domain import Plan

    cleanouts = list(incumbent_b.cleanouts) + [(machine, 1050, 1140, "manual cleanout J1->J2 (23:30)")]
    return Plan(assignments=dict(incumbent_b.assignments), cleanouts=cleanouts)


def load_scenario(scenario_dir: str | Path):
    """Load (ir, incumbent_a, incumbent_b) from a written scenario directory."""
    from feasible.ir.domain import Plan

    d = Path(scenario_dir)
    sources = {"shop_rules.md": (d / "shop_rules.md").read_text(encoding="utf-8")}
    ir = load_golden_ir(d / "golden_ir.json", sources)
    inc_a = Plan.model_validate(json.loads((d / "incumbent_a.json").read_text(encoding="utf-8")))
    inc_b = Plan.model_validate(json.loads((d / "incumbent_b.json").read_text(encoding="utf-8")))
    return ir, inc_a, inc_b


def write_scenario(scenario_dir: str | Path) -> None:
    """Freeze the scenario data files (golden IR, SOP, xlsx, both incumbents)."""
    d = Path(scenario_dir)
    d.mkdir(parents=True, exist_ok=True)
    ir = build_scenario_ir()
    (d / "shop_rules.md").write_text(SHOP_RULES, encoding="utf-8")
    (d / "golden_ir.json").write_text(
        json.dumps({"rules": [r.model_dump(mode="json") for r in ir.rules],
                    "instance": ir.instance.model_dump(mode="json")}, indent=2),
        encoding="utf-8",
    )
    write_orders_xlsx(d / "orders_week_34.xlsx", ir.instance.jobs)
    inc_b = generate_incumbent_b(ir)
    inc_a = make_incumbent_a(inc_b)
    (d / "incumbent_b.json").write_text(json.dumps(inc_b.model_dump(mode="json"), indent=2), encoding="utf-8")
    (d / "incumbent_a.json").write_text(json.dumps(inc_a.model_dump(mode="json"), indent=2), encoding="utf-8")


__all__ = [
    "build_scenario_ir", "generate_incumbent_b", "make_incumbent_a", "load_scenario",
    "write_scenario", "weighted_tardiness", "late_priority_orders", "total_changeover_time",
    "recompute_objective", "DATA",
]
