"""Ugly-but-honest text certificate (the walking-skeleton output).

Superseded by the signed Plan Certificate (cert/plan_cert.py); kept as a simple
human-readable render of a solved + checked plan.
"""
from __future__ import annotations

from feasible.checker.checker import CheckResult, machine_sequence
from feasible.ir.domain import FCIR, Plan
from feasible.solve.orchestrate import SolveResult


def text_certificate(ir: FCIR, plan: Plan, result: SolveResult, check: CheckResult) -> str:
    lines: list[str] = []
    lines.append("=== Feasible plan certificate (text) ===")
    lines.append(f"status: {result.status}")
    if result.objective is not None:
        lines.append(
            f"objective: weighted_tardiness={result.objective[0]}, "
            f"total_changeover={result.objective[1]} (gap={result.gap})"
        )
    lines.append("")
    lines.append("schedule (per machine):")
    for mc in ir.instance.machines:
        seq = machine_sequence(plan, mc)
        cleans = [c for c in plan.cleanouts if c[0] == mc]
        if not seq and not cleans:
            continue
        lines.append(f"  {mc}:")
        for op_id in seq:
            start = plan.start(op_id)
            end = start + ir.instance.operation(op_id).duration
            lines.append(f"    [{start:>5}, {end:>5}) {op_id}")
        for (_, cs, ce, reason) in cleans:
            lines.append(f"    [{cs:>5}, {ce:>5}) CLEANOUT ({reason})")
    lines.append("")
    lines.append(f"verification: {'PASS' if check.passed else 'FAIL'}")
    for v in check.violations:
        cite = ""
        if v.span is not None and hasattr(v.span, "quoted_text"):
            cite = f'  [cite: "{v.span.quoted_text}"]'
        lines.append(f"  - {v.rule_id}: {v.message}{cite}")
    lines.append("")
    lines.append("incumbent comparison: see signed Plan Certificate (Task 9 KPI-vs-B).")
    return "\n".join(lines)
