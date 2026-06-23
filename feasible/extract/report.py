"""Markdown renderer for an ``ExtractionReport`` (the human-review artifact).

The report SHOUTS its non-gating status: nothing here is certified. It surfaces the
drafted candidate rules, the dropped (ungrounded) citations, the LLM-free coverage
summary (the omission moat), and the rule_id diff vs the trusted golden IR.
"""
from __future__ import annotations

from feasible.extract.orchestrate import ExtractionReport


def render_report(report: ExtractionReport) -> str:
    lines: list[str] = []
    lines.append(f"# Extraction Report — {report.domain_id}")
    lines.append("")
    lines.append(f"> **{report.non_gating_note}**")
    lines.append("")
    lines.append(f"- source sha256: `{report.source_sha256}`")
    lines.append(f"- segments enumerated (deterministic, pre-LLM): {report.n_segments}")
    lines.append(f"- drafted candidate rules: {len(report.drafted)}")
    lines.append(f"- dropped (ungrounded citations): {len(report.ungrounded)}")
    lines.append("")

    lines.append("## Drafted candidate rules (NOT certified)")
    lines.append("")
    lines.append("| rule_id | kind | clause | param flag | back-translation | verbatim quote |")
    lines.append("|---|---|---|---|---|---|")
    for d in report.drafted:
        q = d.verbatim_quote.replace("|", "\\|")
        bt = d.back_translation.replace("|", "\\|")
        flag = "⚠ PARAM MISMATCH" if d.param_mismatch else ""
        lines.append(
            f"| {d.rule.rule_id} | {d.rule.kind} | {d.rule.clause_kind.value} | "
            f"{flag} | {bt} | {q} |"
        )
    lines.append("")

    # C-2: surface every param-vs-span mismatch explicitly for human review.
    mismatches = [d for d in report.drafted if d.param_mismatch]
    if mismatches:
        lines.append("## ⚠ Param-vs-span mismatches (human review required)")
        lines.append("")
        for d in mismatches:
            lines.append(f"- **{d.rule.rule_id}**: {d.param_mismatch_note} "
                         f"(cited span: {d.verbatim_quote!r})")
        lines.append("")

    if report.ungrounded:
        lines.append("## Dropped — ungrounded citations (anchor() fail-closed)")
        lines.append("")
        for u in report.ungrounded:
            lines.append(f"- **{u['rule_id']}**: {u['reason']} — quote: {u['verbatim_quote']!r}")
        lines.append("")

    cov = report.coverage
    lines.append("## Coverage (deterministic, LLM-free)")
    lines.append("")
    lines.append(f"- normative denominator: {cov.denominator}")
    lines.append(f"- complete: {cov.complete}")
    lines.append(f"- RED (uncovered normative spans): {len(cov.red_findings)}")
    for r in cov.red_findings:
        lines.append(f"  - [{r.category}] {r.text!r}")
    lines.append("")

    lines.append("## Diff vs trusted golden_ir (by rule_id)")
    lines.append("")
    lines.append(f"- only in golden (the draft MISSED): {report.golden_diff['only_in_golden']}")
    lines.append(f"- only in draft (NEW candidate, human-review): {report.golden_diff['only_in_draft']}")
    lines.append(f"- common: {report.golden_diff['common']}")
    lines.append("")
    return "\n".join(lines)
