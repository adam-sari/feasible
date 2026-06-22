from __future__ import annotations

import json

import pytest

from feasible.extract.provider import (
    FixtureMissingError,
    FixtureProvider,
    MODEL,
    SEED,
    TEMPERATURE,
    build_prompt,
    fixture_key,
    load_env,
)
from feasible.extract.schema import SCHEMA_DESCRIPTOR


def test_pinned_determinism_knobs():
    assert MODEL == "gemini-2.5-flash"
    assert TEMPERATURE == 0
    assert isinstance(SEED, int)


def test_fixture_key_is_deterministic_and_schema_sensitive():
    k1 = fixture_key(MODEL, "prompt A", SCHEMA_DESCRIPTOR)
    k2 = fixture_key(MODEL, "prompt A", SCHEMA_DESCRIPTOR)
    assert k1 == k2 and len(k1) == 64                      # sha256 hex
    assert fixture_key(MODEL, "prompt A", {"v": 99}) != k1            # schema-sensitive
    assert fixture_key(MODEL, "prompt B", SCHEMA_DESCRIPTOR) != k1    # prompt-sensitive


def test_build_prompt_is_deterministic_and_includes_span():
    p1 = build_prompt("a 90-minute cleanout is required", "Sanitation")
    p2 = build_prompt("a 90-minute cleanout is required", "Sanitation")
    assert p1 == p2
    assert "a 90-minute cleanout is required" in p1
    assert "Sanitation" in p1


def test_fixture_provider_replays_stored_json(tmp_path):
    # C-7: write the probe fixture into a TMP scratch store, never the committed dir
    key = fixture_key(MODEL, "REPLAY_PROBE", SCHEMA_DESCRIPTOR)
    (tmp_path / f"{key}.json").write_text(
        json.dumps({"rule_id": "C-FIX", "kind": "x", "clause_kind": "OBLIGATION",
                    "severity": "HARD", "verbatim_quote": "q", "params_json": "", "rationale": ""}),
        encoding="utf-8",
    )
    prov = FixtureProvider(tmp_path)
    out = prov.draft(prompt="REPLAY_PROBE", response_schema={}, fixture_key=key)
    assert out["rule_id"] == "C-FIX"


def test_fixture_provider_miss_fails_closed(tmp_path):
    prov = FixtureProvider(tmp_path)
    with pytest.raises(FixtureMissingError) as ei:
        prov.draft(prompt="NEVER_RECORDED", response_schema={}, fixture_key="deadbeef" * 8)
    assert "--record" in str(ei.value)   # the message tells you how to record it


def test_load_env_does_not_clobber_existing_process_env(monkeypatch, tmp_path):
    """C-9 isolation: load_env() must NOT overwrite a key already in os.environ,
    and (since it has a global side effect on os.environ) a test must be able to
    drive it deterministically. We set a sentinel, point dotenv at an empty dir,
    and assert load_env returns the sentinel unchanged (override=False)."""
    monkeypatch.setenv("GEMINI_API_KEY", "SENTINEL_FROM_PROCESS_ENV")
    monkeypatch.chdir(tmp_path)            # no .env here -> dotenv loads nothing
    assert load_env() == "SENTINEL_FROM_PROCESS_ENV"   # process env NOT clobbered


def test_load_env_returns_none_when_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)            # empty dir, no .env
    assert load_env() is None
