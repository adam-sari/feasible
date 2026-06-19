"""Deterministic span enumeration — runs BEFORE any LLM sees the document.

Produces a *gapless* span tree: the union of segment char-ranges is exactly
``[0, len(text))`` with no overlaps. The LLM (Build B) only ever *classifies*
these pre-enumerated units; it never decides which spans exist. This is what
lets the coverage ledger prove completeness over a known denominator.
"""
from __future__ import annotations

import hashlib
import re

from pydantic import BaseModel

from feasible.ir.domain import TextSpan

# Break after a sentence terminator + trailing whitespace, or after a newline.
_BREAK = re.compile(r"[.!?:][)\"']?\s+|\n+")


class Segment(BaseModel):
    char_start: int
    char_end: int
    text: str
    heading_path: str = ""

    def is_blank(self) -> bool:
        return not self.text.strip()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _heading_path(line: str) -> str:
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return stripped.lstrip("#").strip()
    return ""


def segment(text: str, source_sha256: str | None = None) -> list[Segment]:
    """Split ``text`` into a contiguous, gapless list of segments."""
    segments: list[Segment] = []
    pos = 0
    heading = ""
    for m in _BREAK.finditer(text):
        end = m.end()
        chunk = text[pos:end]
        if chunk.strip():
            hp = _heading_path(chunk) or heading
            if _heading_path(chunk):
                heading = _heading_path(chunk)
            segments.append(Segment(char_start=pos, char_end=end, text=chunk, heading_path=hp))
        elif segments:
            # whitespace-only chunk: fold into the previous segment to stay gapless
            prev = segments[-1]
            segments[-1] = Segment(
                char_start=prev.char_start,
                char_end=end,
                text=text[prev.char_start : end],
                heading_path=prev.heading_path,
            )
        # else: leading whitespace before any content — absorbed by next segment via pos
        pos = end
    if pos < len(text):
        chunk = text[pos:]
        if chunk.strip():
            segments.append(
                Segment(char_start=pos, char_end=len(text), text=chunk, heading_path=heading)
            )
        elif segments:
            prev = segments[-1]
            segments[-1] = Segment(
                char_start=prev.char_start,
                char_end=len(text),
                text=text[prev.char_start :],
                heading_path=prev.heading_path,
            )
    # Re-anchor the very first segment to char 0 to guarantee full coverage even
    # when leading whitespace preceded the first content chunk.
    if segments and segments[0].char_start != 0:
        first = segments[0]
        segments[0] = Segment(
            char_start=0,
            char_end=first.char_end,
            text=text[0 : first.char_end],
            heading_path=first.heading_path,
        )
    return segments


def is_gapless(segments: list[Segment], text: str) -> bool:
    if not segments:
        return len(text) == 0
    if segments[0].char_start != 0 or segments[-1].char_end != len(text):
        return False
    for a, b in zip(segments, segments[1:]):
        if a.char_end != b.char_start:
            return False
    return True


def anchor(quoted_text: str, source_text: str) -> tuple[int, int] | None:
    """Locate ``quoted_text`` in ``source_text`` by exact substring; None if absent."""
    idx = source_text.find(quoted_text)
    if idx < 0:
        return None
    return (idx, idx + len(quoted_text))


def to_text_span(seg: Segment, source_sha256: str, role: str = "primary_normative") -> TextSpan:
    return TextSpan(
        source_sha256=source_sha256,
        char_start=seg.char_start,
        char_end=seg.char_end,
        quoted_text=seg.text.strip(),
        heading_path=seg.heading_path,
        role=role,
    )
