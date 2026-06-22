"""``extract_policy``: the deterministic non-gating extraction pipeline.

segment (deterministic, pre-LLM) -> per-span Gemini draft -> Pydantic-validate ->
anchor() the verbatim quote (exact-substring, FAIL-CLOSED) -> assemble a CANDIDATE
FCIR -> run the LLM-free coverage ledger + back-translation + a rule_id diff vs the
domain's golden_ir. The result is a REPORT, never a certificate (design §6).

Barrier 1 (no auto-promote): the candidate IR is never passed to any cert emitter
— this module imports nothing from ``feasible.cert``.
Barrier 2 (coverage LLM-free): ``build_coverage_ledger`` runs over ``segment()``'s
deterministic enumeration; no provider call is in its call graph.
Barrier 3 [C-1] (anchor fail-closed, segment-constrained): a quote that is not an
exact substring of the source — OR that exact-matches only OUTSIDE the segment it
was drafted from (a cross-segment leak) — is dropped to ``ungrounded`` and never
enters the candidate IR. PLUS [C-2]: a grounded draft whose numeric param value is
absent from the cited span is FLAGGED ``param_mismatch`` for human review.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from feasible.domains import get_domain
from feasible.extract.provider import MODEL, Provider, build_prompt, fixture_key
from feasible.extract.schema import SCHEMA_DESCRIPTOR, RuleDraft, draft_to_rule
from feasible.govern.backtranslate import back_translate
from feasible.govern.coverage import CoverageLedger, build_coverage_ledger
from feasible.ingest.segment import Segment, anchor, segment, sha256_text
from feasible.ir.domain import FCIR, Rule

NON_GATING_NOTE = (
    "DRAFT — NOT CERTIFIED. These candidate rules are LLM-drafted from "
    "pre-enumerated spans. Only a human-approved golden_ir is ever certified; this "
    "report gates nothing. Coverage is deterministic + LLM-free; every quote is "
    "exact-anchored (fail-closed)."
)


@dataclass
class DraftedRule:
    rule: Rule
    verbatim_quote: str
    char_start: int
    char_end: int
    back_translation: str
    grounded: bool = True
    param_mismatch: bool = False        # C-2: a numeric param value not present in the cited span
    param_mismatch_note: str = ""       # human-review explanation (empty when no mismatch)


@dataclass
class ExtractionReport:
    domain_id: str
    source_sha256: str
    n_segments: int
    drafted: list[DraftedRule]
    ungrounded: list[dict]
    candidate_ir: FCIR
    coverage: CoverageLedger
    golden_diff: dict
    non_gating_note: str = NON_GATING_NOTE


def _golden_diff(candidate: FCIR, golden: FCIR) -> dict:
    cand = {r.rule_id for r in candidate.rules}
    gold = {r.rule_id for r in golden.rules}
    return {
        "only_in_golden": sorted(gold - cand),
        "only_in_draft": sorted(cand - gold),
        "common": sorted(cand & gold),
    }


def _anchor_in_segment(
    quote: str, policy_text: str, seg: Segment
) -> tuple[int, int] | None:
    """[MAJOR C-1] EXACT-substring anchor CONSTRAINED to the originating segment.

    Returns the (char_start, char_end) of the FIRST occurrence of ``quote`` that
    lies wholly within ``[seg.char_start, seg.char_end)``, or ``None`` if the quote
    is absent OR only occurs outside this segment (a cross-segment leak). We search
    within the segment's char-window so a quote that legitimately repeats elsewhere
    in the document is still anchored to THIS segment when echoed honestly, and a
    foreign quote (present elsewhere but not here) returns None.
    """
    idx = policy_text.find(quote, seg.char_start, seg.char_end)
    if idx < 0:
        return None
    end = idx + len(quote)
    if end > seg.char_end:          # straddles the segment boundary -> reject
        return None
    return (idx, end)


def _param_mismatch(params: dict, span_text: str) -> str:
    """C-2: return a human-review note if a NUMERIC param value is not present
    (as a substring) in the cited span text, else "". Non-numeric params are not
    checked (they are not cross-checkable against the verbatim span this way)."""
    misses = [
        f"{k}={v}"
        for k, v in params.items()
        if isinstance(v, (int,)) and not isinstance(v, bool)
        and str(v) not in span_text
    ]
    if not misses:
        return ""
    return "param value(s) not found in cited span: " + ", ".join(sorted(misses))


def extract_policy(
    policy_text: str,
    *,
    domain_id: str,
    provider: Provider,
    fixtures_dir: Path,
) -> ExtractionReport:
    domain, _verifier = get_domain(domain_id)          # fail-closed on unknown domain
    golden = domain.golden_ir()
    source_sha = sha256_text(policy_text)
    # C-3/C-4: the fixture key hashes the STABLE descriptor; the LIVE provider (Task 5)
    # forwards the RuleDraft CLASS as the wire response_schema separately.
    schema = SCHEMA_DESCRIPTOR

    segments: list[Segment] = segment(policy_text)
    drafted: list[DraftedRule] = []
    ungrounded: list[dict] = []

    for seg in segments:
        if seg.is_blank():
            continue
        prompt = build_prompt(seg.text.strip(), seg.heading_path)
        key = fixture_key(MODEL, prompt, schema)
        raw = provider.draft(prompt=prompt, response_schema=schema, fixture_key=key)
        if not raw:                                    # {} = the model saw no rule here
            continue
        draft = RuleDraft.model_validate(raw)          # ValidationError -> caller sees it
        # BARRIER 3 [C-1]: anchor the echoed quote by EXACT substring, CONSTRAINED to
        # THIS segment's char-range (fail-closed; no fuzzy tier, no cross-segment leak).
        full_pos = anchor(draft.verbatim_quote, policy_text)
        in_seg = _anchor_in_segment(draft.verbatim_quote, policy_text, seg)
        if in_seg is None:
            # distinguish "nowhere in the document" from "elsewhere but not here"
            reason = (
                "quote anchored outside its source segment"
                if full_pos is not None
                else "verbatim_quote not an exact substring of the source "
                     "(fabricated/paraphrased citation)"
            )
            ungrounded.append({
                "rule_id": draft.rule_id,
                "verbatim_quote": draft.verbatim_quote,
                "reason": reason,
            })
            continue
        pos = in_seg
        rule = draft_to_rule(draft, source_sha256=source_sha,
                             char_start=pos[0], char_end=pos[1])
        span_text = policy_text[pos[0]:pos[1]]
        note = _param_mismatch(rule.params, span_text)   # C-2
        drafted.append(DraftedRule(
            rule=rule, verbatim_quote=draft.verbatim_quote,
            char_start=pos[0], char_end=pos[1],
            back_translation=back_translate(rule),
            param_mismatch=bool(note),
            param_mismatch_note=note,
        ))

    # Assemble a CANDIDATE FCIR (instance borrowed from golden purely so the IR is
    # constructible; never solved, never certified). The coverage ledger reads only
    # spans + domain_id; the diff reads only rule_ids.
    candidate_ir = FCIR(
        rules=[d.rule for d in drafted],
        instance=golden.instance,
        domain_id=domain_id,
    )
    # BARRIER 2: coverage is deterministic + LLM-free (segment() + keyword classifier).
    coverage = build_coverage_ledger(policy_text, candidate_ir)
    golden_diff = _golden_diff(candidate_ir, golden)

    return ExtractionReport(
        domain_id=domain_id,
        source_sha256=source_sha,
        n_segments=len(segments),
        drafted=drafted,
        ungrounded=ungrounded,
        candidate_ir=candidate_ir,
        coverage=coverage,
        golden_diff=golden_diff,
    )
