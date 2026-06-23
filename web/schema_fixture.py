"""Emit the per-view-model field-key sets from the LIVE feasible/domains/base.py
dataclasses. The committed `web/app/src/api/__tests__/schema_fixture.json` is the
oracle the frontend `typesync.test.ts` asserts the TS interfaces against — a Python
field add/rename changes this fixture and fails BOTH the backend and frontend suites.

Run `.venv/Scripts/python.exe -m web.schema_fixture` to regenerate the JSON.
"""
from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path

from feasible.domains import base

# the view-models the TS client mirrors 1:1 (the frozen facade surface)
_VIEW_MODELS = [
    base.ScenarioInfo, base.InputsView, base.ConstraintsView, base.TrustVector,
    base.CertifyResult, base.TimelineView, base.CertsView, base.VerifyView,
]

_FIXTURES = Path(__file__).resolve().parent / "app" / "src" / "api" / "__tests__"
_SCHEMA = _FIXTURES / "schema_fixture.json"
_ROUTES = _FIXTURES / "routes_fixture.json"


def emit_schema() -> dict[str, list[str]]:
    """name -> sorted field-name list, for every frozen facade view-model."""
    return {m.__name__: sorted(f.name for f in fields(m)) for m in _VIEW_MODELS}


def emit_routes() -> list[str]:
    """The registered /api route templates (excluding the introspection route) —
    the A-8 source of truth the client URL templates are diff-checked against."""
    from starlette.routing import Route as _Route
    from web.server import app

    return sorted(
        r.path for r in app.routes
        if isinstance(r, _Route) and r.path.startswith("/api") and r.path != "/api/_routes"
    )


def main() -> None:
    _FIXTURES.mkdir(parents=True, exist_ok=True)
    _SCHEMA.write_text(json.dumps(emit_schema(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _ROUTES.write_text(json.dumps(emit_routes(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {_SCHEMA} and {_ROUTES}")


if __name__ == "__main__":
    main()
