"""Backend contract test (Track A executable oracle).

Pins that every route maps 1:1 onto the frozen facade and serializes its view-model
VERBATIM — the /certify + /verify JSON carry the engine's labels/verify-reasons
unmodified, and a /certify result round-trips through /verify cleanly. The console is
a pure consumer; if the backend ever re-summarized a verdict, this fails.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from feasible import api
from web.server import app

client = TestClient(app)


def test_scenarios_route_matches_facade_verbatim() -> None:
    got = client.get("/api/scenarios").json()
    want = [
        {"domain_id": s.domain_id, "display_name": s.display_name, "data": s.data}
        for s in api.list_scenarios()
    ]
    assert got == want
    assert got[0]["domain_id"] == "manufacturing"
    assert got[0]["data"] == "synthetic"


def test_inputs_route_carries_facade_fields() -> None:
    got = client.get("/api/inputs/manufacturing").json()
    want = api.load_inputs("manufacturing")
    assert got["domain_id"] == "manufacturing"
    assert got["machines"] == list(want.machines)
    assert len(got["jobs"]) == len(want.jobs)
    # datacenter-only fields are null until Track B lands
    assert got["units"] is None and got["groups"] is None


def test_constraints_route_carries_rules_and_dropped() -> None:
    got = client.get("/api/constraints/manufacturing").json()
    want = api.get_constraints("manufacturing")
    assert [r["rule_id"] for r in got["rules"]] == [r["rule_id"] for r in want.rules]
    assert got["dropped"] == want.dropped
    assert got["draft"] is None  # Gemini draft is Track C; null today


def test_certify_then_verify_round_trips_with_verbatim_labels() -> None:
    cert = client.post("/api/certify/manufacturing", json={}).json()
    # the engine's optimality label is carried VERBATIM (not re-summarized)
    label = cert["plan_cert"]["claims"]["optimality"]["label"]["value"]
    assert label == "optimal per CP-SAT, same-engine tripwire"
    # the gotcha rule ref + counter-witness are carried verbatim
    assert cert["plan_cert"]["incumbent_A_failure"]["violated_rule_ref"] == "R-6.1-NIGHT-CLEANOUT"
    # the trust vector is the honesty descriptor (self-described, no pinned key)
    tv = cert["trust_vector"]
    assert tv["signature"] == "self_described"
    assert tv["checker"] == "pass"
    # Spec 0.5 added signer_note — the CANONICAL self-described/authenticated sentence
    assert set(tv.keys()) == {
        "signature", "checker", "coverage", "conflict_replay", "data", "signer_note"
    }
    # the signer_note is carried VERBATIM (Track A renders it, never fabricates it)
    assert "UNVERIFIED" in tv["signer_note"]  # self-described path
    # round-trip the OPAQUE certs back to /verify (byte-identical JSON in)
    vr = client.post(
        "/api/verify",
        json={"plan_cert": cert["plan_cert"], "rule_pack_cert": cert["rule_pack_cert"]},
    ).json()
    assert vr["ok"] is True
    assert vr["reasons"] == []
    assert vr["trust_vector"]["checker"] == "pass"


def test_verify_route_carries_engine_reasons_verbatim() -> None:
    """A tampered plan_cert surfaces the engine's OWN reason strings — the backend
    forwards them unmodified (it never authors a reason of its own)."""
    cert = client.post("/api/certify/manufacturing", json={}).json()
    bad = cert["plan_cert"]
    # corrupt a hashed body field so verify fails; the reason must be the engine's
    bad["claims"]["optimality"]["objective"]["value"] = [999, 999]
    vr = client.post("/api/verify", json={"plan_cert": bad}).json()
    facade_view = api.verify(bad)
    assert vr["ok"] is facade_view.ok
    assert vr["reasons"] == facade_view.reasons  # VERBATIM, not paraphrased
    assert vr["ok"] is False


def test_timeline_route_carries_lanes_and_intervals() -> None:
    got = client.get("/api/timeline/manufacturing").json()
    want = api.get_timeline("manufacturing")
    assert got["lanes"] == want.lanes
    assert len(got["intervals"]) == len(want.intervals)
    # datacenter-only capacity fields null until Track B
    assert got["capacity_series"] is None and got["threshold_lines"] is None


# --- [MAJOR A-2/A-3] the capacity render has a REAL producer; pin its key shape --- #
# Manufacturing returns capacity_series=None, so to pin the FROZEN capacity item keys
# against the TS mirror we assert the LIVE item dataclasses (CapacitySeriesItem /
# ThresholdLine) — NOT a hand-written set against itself. (Track B's datacenter
# populates real rows against THIS shape.)
from feasible.domains.base import (  # noqa: E402
    CapacitySeriesItem,
    ThresholdLine,
    TimelineView,
)


def test_timeline_view_dataclass_keys_match_ts_mirror() -> None:
    """The emitted TimelineView dict keys equal the TS-mirrored TimelineView keys —
    so the frontend's `TimelineView` interface cannot drift from the facade. The
    capacity item schema is FROZEN in the facade doc; Track A mirrors it 1:1."""
    from dataclasses import fields
    emitted = {f.name for f in fields(TimelineView)}
    # the exact key set the TS `TimelineView` interface declares (see types.ts)
    assert emitted == {
        "domain_id", "lanes", "intervals", "capacity_series", "threshold_lines"
    }


def test_capacity_item_frozen_schema_matches_ts() -> None:
    """The FROZEN capacity-series + threshold-line item keys equal the TS
    `CapacityPoint`/`ThresholdLine` interface keys. This is a LIVE cross-check, not a
    tautology: the key sets are read off the actual `CapacitySeriesItem`/`ThresholdLine`
    dataclasses via `dataclasses.fields()`, so renaming `t`/`value`/`group`/`label` on
    those item dataclasses FAILS this test (and, via schema_fixture.py, the frontend
    typesync test too). A real datacenter get_timeline emits dicts with EXACTLY these
    keys; the console renders them with no transform."""
    from dataclasses import fields
    # LIVE item-schema keys (feasible/domains/base.py), NOT a hand-written mirror:
    capacity_point_keys = {f.name for f in fields(CapacitySeriesItem)}
    threshold_line_keys = {f.name for f in fields(ThresholdLine)}
    # the exact key sets the TS `CapacityPoint`/`ThresholdLine` interfaces declare
    # (see types.ts) and that typesync.test.ts asserts against schema_fixture.json:
    assert capacity_point_keys == {"t", "value", "group"}  # group optional/None
    assert threshold_line_keys == {"label", "value"}


# --- [MAJOR A-4] REAL Python<->TS drift tripwire: emit the live key sets to a fixture --- #
def test_schema_fixture_matches_live_dataclasses(tmp_path) -> None:
    """`web/schema_fixture.py` emits set(field-names) per view-model from the LIVE
    `feasible/domains/base.py` dataclasses. The committed fixture the frontend asserts
    against MUST equal a freshly-emitted one — a Python field add/rename fails here AND
    in the frontend typesync test (the tripwire is REAL, not pure-TypeScript)."""
    import json
    from pathlib import Path
    from web.schema_fixture import emit_schema

    fresh = emit_schema()  # dict[str, sorted list[str]]
    committed = json.loads(
        Path("web/app/src/api/__tests__/schema_fixture.json").read_text(encoding="utf-8")
    )
    assert fresh == committed, (
        "schema drift: re-run `.venv/Scripts/python.exe -m web.schema_fixture` and "
        "update the TS types.ts + typesync expectations to match."
    )
    # spot-check the seam-critical surfaces
    assert "signer_note" in fresh["TrustVector"]
    assert set(fresh["TimelineView"]) == {
        "domain_id", "lanes", "intervals", "capacity_series", "threshold_lines"
    }
    # the FROZEN capacity item sub-schemas are LIVE in the tripwire (not just the
    # top-level views): renaming a field on CapacitySeriesItem/ThresholdLine drifts
    # the fixture and fails the frontend typesync too.
    assert set(fresh["CapacitySeriesItem"]) == {"t", "value", "group"}
    assert set(fresh["ThresholdLine"]) == {"label", "value"}


def test_routes_fixture_matches_live_routes() -> None:
    """The committed routes_fixture.json (the A-8 client<->server source of truth)
    equals the LIVE registered /api routes — a renamed/added route fails here AND in
    the frontend routes.test.ts."""
    import json
    from pathlib import Path
    from web.schema_fixture import emit_routes

    committed = json.loads(
        Path("web/app/src/api/__tests__/routes_fixture.json").read_text(encoding="utf-8")
    )
    assert sorted(emit_routes()) == sorted(committed)
    # the introspection route serves the SAME list to the frontend at runtime
    assert client.get("/api/_routes").json() == emit_routes()
