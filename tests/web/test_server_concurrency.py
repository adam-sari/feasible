"""Overlapping console requests must not race inside the engine.

FastAPI runs the sync routes on a threadpool and the SPA fires several requests at
once (React StrictMode double-invokes effects). Z3's global context is not
thread-safe, so without the server's engine lock these calls fail with Z3Exceptions
or crash the process outright.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from web.server import app


def _hit(req: tuple[str, str]) -> int:
    method, path = req
    with TestClient(app) as client:
        return client.request(method, path).status_code


def test_overlapping_engine_requests_all_succeed() -> None:
    reqs = [
        ("POST", "/api/certify/manufacturing"),
        ("GET", "/api/timeline/manufacturing"),
        ("POST", "/api/certify/datacenter"),
        ("GET", "/api/timeline/datacenter"),
    ] * 2
    with ThreadPoolExecutor(max_workers=len(reqs)) as pool:
        codes = list(pool.map(_hit, reqs))
    assert codes == [200] * len(reqs)
