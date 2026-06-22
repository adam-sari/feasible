"""Coverage / omission ledger — the extraction-independence moat.

Over a DETERMINISTIC, gapless span enumeration (segments produced before any
LLM), every segment is classified into a CLOSED normativity taxonomy and mapped
to >=1 rule (by span overlap) or tagged non-normative with a reason. An unmapped
hard prohibition/obligation is a RED finding — the only mechanism that catches a
silently dropped rule (including the gotcha). Completeness is RELATIVE to this
enumeration + classifier, not absolute.

The classifier here is a deterministic keyword heuristic (the v1 stand-in for an
LLM classifier that only ever *classifies* pre-enumerated units, never selects
which spans exist).
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from feasible.ingest.segment import Segment, segment
from feasible.ir.domain import FCIR, TextSpan

TAXONOMY = [
    "hard_prohibition", "hard_obligation", "conditional_obligation",
    "soft_target", "definition", "boilerplate", "metadata",
]
# A conditional obligation (e.g. "when switching off an allergen product, a
# cleanout is required") is still a HARD requirement when it applies — an
# uncovered one is a silently-dropped rule and must be RED.
NORMATIVE_RED = {"hard_prohibition", "hard_obligation", "conditional_obligation"}


def classify(seg: Segment) -> str:
    text = seg.text.strip().lower()
    if seg.text.lstrip().startswith("#"):
        return "metadata"
    if not text:
        return "boilerplate"
    # A HARD deontic operator ALWAYS wins over the soft-target keywords: a clause that
    # both mentions 'priority' AND says 'may not' / 'must' is a hard rule, never a soft
    # target. Testing the soft keywords first (as a pre-empt) would let any hard clause
    # containing the word 'priority' slip through uncovered without going RED — the
    # omission moat must not fail open.
    prohibition = any(k in text for k in ["may only", "may not", "does not", "not work", "unavailable", "no filler"])
    obligation = any(k in text for k in ["is required", "must ", "shall"])
    conditional = "when" in text or "if " in text
    if prohibition:
        return "hard_prohibition"
    if obligation and conditional:
        return "conditional_obligation"
    if obligation:
        return "hard_obligation"
    # only with NO hard operator present are priority/precedence/expectation soft (§3.1/§3.4)
    if "take precedence" in text or "are expected" in text or "priority" in text:
        return "soft_target"
    return "boilerplate"


class CoverageEntry(BaseModel):
    char_start: int
    char_end: int
    category: str
    text: str
    covered_by: list[str] = Field(default_factory=list)
    status: str  # COVERED | RED | NON_NORMATIVE


class CoverageLedger(BaseModel):
    entries: list[CoverageEntry] = Field(default_factory=list)
    red_findings: list[CoverageEntry] = Field(default_factory=list)
    complete: bool = True
    denominator: int = 0  # number of normative segments


def _overlaps(a0: int, a1: int, b0: int, b1: int) -> bool:
    return a0 < b1 and b0 < a1


def _rule_spans(ir: FCIR) -> list[tuple[str, TextSpan]]:
    out: list[tuple[str, TextSpan]] = []
    for r in ir.rules:
        for s in r.provenance.spans:
            if isinstance(s, TextSpan) and s.role == "primary_normative" and s.char_start >= 0:
                out.append((r.rule_id, s))
    return out


def build_coverage_ledger(sop_text: str, ir: FCIR) -> CoverageLedger:
    segments = segment(sop_text)
    spans = _rule_spans(ir)
    entries: list[CoverageEntry] = []
    reds: list[CoverageEntry] = []
    denom = 0
    for seg in segments:
        category = classify(seg)
        covered_by = [
            rid for (rid, s) in spans if _overlaps(seg.char_start, seg.char_end, s.char_start, s.char_end)
        ]
        if category in NORMATIVE_RED:
            denom += 1
            status = "COVERED" if covered_by else "RED"
        elif category == "soft_target":
            # soft targets (e.g. §3.1/§3.4, reclassified soft) need no rule
            denom += 1
            status = "COVERED" if covered_by else "NON_NORMATIVE"
        else:
            status = "NON_NORMATIVE"
        entry = CoverageEntry(
            char_start=seg.char_start, char_end=seg.char_end, category=category,
            text=seg.text.strip(), covered_by=covered_by, status=status,
        )
        entries.append(entry)
        if status == "RED":
            reds.append(entry)
    return CoverageLedger(
        entries=entries, red_findings=reds, complete=len(reds) == 0, denominator=denom
    )
