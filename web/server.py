"""Thin FastAPI adapter over the FROZEN ``feasible.api`` facade (Track A console).

Every route calls EXACTLY ONE facade function and serializes its frozen view-model
dataclass to JSON verbatim. The backend owns no business logic, no recompute, no
re-summary: it is a pure transport so the SPA renders engine truth unmodified. It
NEVER constructs/mutates/re-signs a cert — certs are opaque JSON forwarded as-is.
"""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from feasible import api

app = FastAPI(title="Feasible Console", version="0.2-demo")


def _view_to_dict(view: Any) -> Any:
    """Frozen-view-model -> plain JSON dict (recurses into nested dataclasses like
    TrustVector). Lists of dataclasses map elementwise. Plain dicts/lists/scalars
    (the opaque cert payloads, the jobs/rules dicts) pass through untouched."""
    if is_dataclass(view) and not isinstance(view, type):
        return asdict(view)
    if isinstance(view, list):
        return [_view_to_dict(v) for v in view]
    return view


class VerifyBody(BaseModel):
    plan_cert: dict
    rule_pack_cert: dict | None = None
    signer_key: str | None = None


@app.get("/api/scenarios")
def scenarios() -> Any:
    return _view_to_dict(api.list_scenarios())


@app.get("/api/inputs/{domain_id}")
def inputs(domain_id: str) -> Any:
    return _view_to_dict(api.load_inputs(domain_id))


@app.get("/api/constraints/{domain_id}")
def constraints(domain_id: str) -> Any:
    return _view_to_dict(api.get_constraints(domain_id))


@app.post("/api/certify/{domain_id}")
def certify(domain_id: str) -> Any:
    # self-described (ephemeral key) — the console never holds a signing key
    return _view_to_dict(api.certify(domain_id))


@app.get("/api/timeline/{domain_id}")
def timeline(domain_id: str) -> Any:
    return _view_to_dict(api.get_timeline(domain_id))


@app.get("/api/certificates/{domain_id}")
def certificates(domain_id: str) -> Any:
    return _view_to_dict(api.get_certificates(domain_id))


@app.post("/api/verify")
def verify(body: VerifyBody) -> Any:
    return _view_to_dict(
        api.verify(body.plan_cert, body.rule_pack_cert, signer_key=body.signer_key)
    )


@app.get("/api/_routes")
def routes() -> list[str]:
    """The registered API route templates (introspected from the app). The frontend's
    `routes.test.ts` fetches this and asserts every client URL template matches a
    registered route — a non-mocked A-8 tripwire so a renamed route breaks the client."""
    from starlette.routing import Route as _Route

    return sorted(
        r.path for r in app.routes
        if isinstance(r, _Route) and r.path.startswith("/api") and r.path != "/api/_routes"
    )
