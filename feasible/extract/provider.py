"""Provider seam: ``FixtureProvider`` (offline default) + the pinned knobs.

The fixture key ``sha256(canonical({model, prompt, schema_descriptor}))`` keys a
stored JSON reply, where ``schema_descriptor`` is the STABLE hand-authored
``SCHEMA_DESCRIPTOR`` (NOT ``RuleDraft.model_json_schema()``, which Pydantic may
reshape within 2.x — C-3/C-4). The same (model, prompt, descriptor) always replays
the same draft offline — no network, no key. Live Gemini (``GeminiProvider``,
Task 5) passes the ``RuleDraft`` CLASS to the SDK's ``response_schema`` and records
into the same store only when ``GEMINI_API_KEY`` is set AND ``--record`` is passed.
A fixture miss is FAIL-CLOSED (``FixtureMissingError``) — never a silent live
fallthrough.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Protocol, runtime_checkable

from feasible.canon.canonical import digest_of

# Pinned determinism knobs (design §6): one model, temperature 0, a fixed seed.
MODEL = "gemini-2.5-flash"
TEMPERATURE = 0
SEED = 7


class FixtureMissingError(FileNotFoundError):
    """An offline draft was requested but no recorded fixture exists for the key."""


def fixture_key(model: str, prompt: str, schema_descriptor: dict) -> str:
    """Stable filename stem: sha256 over the JCS-canonical request triple. The
    ``schema_descriptor`` is the STABLE ``SCHEMA_DESCRIPTOR`` (C-3/C-4), not the
    volatile Pydantic-generated ``model_json_schema()``."""
    return digest_of({"model": model, "prompt": prompt, "schema": schema_descriptor})


def build_prompt(segment_text: str, heading_path: str) -> str:
    """The deterministic per-span drafting prompt. The model is told to draft AT
    MOST one rule for THIS span and to echo the span VERBATIM as ``verbatim_quote``
    (no fuzzy tier — an un-echoed quote fails ``anchor()`` and is dropped)."""
    return (
        "You convert ONE policy segment into AT MOST ONE candidate scheduling rule.\n"
        "Rules: (1) Use ONLY this segment; do not invent facts. (2) Set "
        "`verbatim_quote` to an EXACT substring of this segment (copy it character-"
        "for-character) — it will be checked by exact match. (3) If the segment is "
        "boilerplate/definition/metadata with no normative rule, return an empty "
        "object {}.\n"
        f"Heading: {heading_path}\n"
        f"Segment: {segment_text}"
    )


@runtime_checkable
class Provider(Protocol):
    def draft(self, *, prompt: str, response_schema: dict, fixture_key: str) -> dict:
        """Return the raw Gemini JSON object for one span ({} = no rule)."""
        ...


class FixtureProvider:
    """Offline replay (the default). Reads ``{fixtures_dir}/{fixture_key}.json``."""

    def __init__(self, fixtures_dir: Path) -> None:
        self.fixtures_dir = Path(fixtures_dir)

    def draft(self, *, prompt: str, response_schema: dict, fixture_key: str) -> dict:
        path = self.fixtures_dir / f"{fixture_key}.json"
        if not path.exists():
            raise FixtureMissingError(
                f"no recorded fixture {path.name} for this (model, prompt, schema); "
                f"re-run with a live GEMINI_API_KEY and --record to record it"
            )
        return json.loads(path.read_text(encoding="utf-8"))


def load_env() -> str | None:
    """Load ``.env`` (python-dotenv) and return ``GEMINI_API_KEY`` (or ``None``).

    C-9: ``override=False`` so an API key ALREADY in ``os.environ`` (e.g. set by a
    test via monkeypatch, or by the caller's shell) is NOT clobbered by a stale
    ``.env`` — the process env wins. The import guard is narrowed to ``ImportError``
    (python-dotenv is a declared dep; only a genuinely missing module is tolerated,
    so a real dotenv bug surfaces instead of being swallowed by a bare ``except``).
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return os.environ.get("GEMINI_API_KEY") or None
    load_dotenv(override=False)
    return os.environ.get("GEMINI_API_KEY") or None


class MissingApiKeyError(RuntimeError):
    """Live recording was requested but GEMINI_API_KEY is not set."""


class GeminiProvider:
    """Live google-genai drafting. The SDK is imported LAZILY (the offline default
    never needs it). With ``record=True`` (the only mode the CLI uses for live) the
    reply is written to the fixture store for deterministic offline replay."""

    def __init__(self, api_key: str, fixtures_dir: Path, *, record: bool = True) -> None:
        from google import genai  # lazy: offline path never imports the SDK

        self.fixtures_dir = Path(fixtures_dir)
        self.record = record
        self._client = genai.Client(api_key=api_key)

    def draft(self, *, prompt: str, response_schema: dict, fixture_key: str) -> dict:
        from google.genai import types

        from feasible.extract.schema import RuleDraft  # lazy: the SDK introspects this CLASS

        # C-3: pass the RuleDraft Pydantic CLASS (the SDK builds the closed wire schema
        # from it) — NOT the volatile RuleDraft.model_json_schema() dict, and NOT the
        # `response_schema` arg (which keys only the offline fixture, hashed elsewhere).
        resp = self._client.models.generate_content(
            model=MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=RuleDraft,
                temperature=TEMPERATURE,
                seed=SEED,
            ),
        )
        text = resp.text
        if text is None:
            raise RuntimeError(
                "Gemini returned an empty response (no JSON text) — likely a blocked "
                "or truncated reply; cannot draft a rule for this span"
            )
        out = json.loads(text)
        if self.record:
            self.fixtures_dir.mkdir(parents=True, exist_ok=True)
            (self.fixtures_dir / f"{fixture_key}.json").write_text(
                json.dumps(out, indent=2), encoding="utf-8"
            )
        return out


def make_provider(*, record: bool, fixtures_dir: Path) -> Provider:
    """The CLI's provider factory. Default (record=False) is the offline
    ``FixtureProvider``. Live recording (record=True) fails FAST when no key is
    present (no silent self-described drafting)."""
    if not record:
        return FixtureProvider(fixtures_dir)
    api_key = load_env()
    if not api_key:
        raise MissingApiKeyError(
            "live --record needs GEMINI_API_KEY (set it in .env, see .env.example); "
            "omit --record to replay recorded fixtures offline"
        )
    return GeminiProvider(api_key, fixtures_dir, record=True)
