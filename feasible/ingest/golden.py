"""Load a hand-authored golden FC-IR and anchor its provenance to source text.

Only ``role == "primary_normative"`` TextSpans are re-anchored (their
char_start/char_end/source_sha256 are filled by exact-substring match). Spans
with role in {modeling_decision, supporting} and all CellRefs pass through
unchanged. A missing primary_normative quoted_text raises ``NoSourceError``.
"""
from __future__ import annotations

import json
from pathlib import Path

from feasible.canon.canonical import sha256_hex
from feasible.ingest.segment import anchor
from feasible.ir.domain import FCIR


class NoSourceError(ValueError):
    """A primary_normative span's quoted_text was not found in any source."""


def load_golden_ir(ir_json_path: str | Path, sources: dict[str, str]) -> FCIR:
    raw = json.loads(Path(ir_json_path).read_text(encoding="utf-8"))
    digests = {name: sha256_hex(text.encode("utf-8")) for name, text in sources.items()}

    for rule in raw.get("rules", []):
        for span in rule.get("provenance", {}).get("spans", []):
            if span.get("kind", "text") != "text":
                continue
            if span.get("role", "primary_normative") != "primary_normative":
                continue
            quoted = span.get("quoted_text", "")
            located: tuple[str, tuple[int, int]] | None = None
            for name, text in sources.items():
                pos = anchor(quoted, text)
                if pos is not None:
                    located = (name, pos)
                    break
            if located is None:
                raise NoSourceError(
                    f"rule {rule.get('rule_id')}: primary_normative quoted_text "
                    f"not found in any source: {quoted!r}"
                )
            name, (start, end) = located
            span["char_start"] = start
            span["char_end"] = end
            span["source_sha256"] = digests[name]

    return FCIR.model_validate(raw)
