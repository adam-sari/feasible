"""Task 9: the datacenter domain through the domain-agnostic facade.

The datacenter scenario certifies + verifies a REAL two-cert artifact through the
SAME ``feasible.api`` orchestration manufacturing uses — there is NO ``if domain_id
== "datacenter"`` branch in ``api.certify`` (the Spec 0.5 T6/T7/T8 seams make it
branch-free). This pins the facade-level datacenter contract:

  * ``list_scenarios`` surfaces datacenter as a SYNTHETIC scenario (honest flag);
  * ``certify`` builds a bundle that ``verify`` re-checks green offline, with the
    ``TrustVector`` carrying the synthetic data flag + the canonical signer_note;
  * ``get_timeline`` recomputes the datacenter capacity overlay from the SIGNED
    plan+instance (the Spec 0.5 T8 ``Domain.capacity_series`` seam — Track B owns
    the producer), conforming to the frozen item schema; and
  * the bundle verifies in a fresh process (the bootstrap import-list resolves the
    datacenter bundle on the offline-verify path).
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

from feasible import api
from feasible.canon.canonical import new_signing_key
from feasible.domains.base import CertifyResult, ScenarioInfo, TimelineView, TrustVector, VerifyView


def test_list_scenarios_carries_datacenter_as_synthetic() -> None:
    """The datacenter scenario is surfaced with the HONEST synthetic data flag (the
    facility is synthetic; manufacturing stays ``real``)."""
    scenarios = api.list_scenarios()
    by_id = {s.domain_id: s for s in scenarios}
    assert "manufacturing" in by_id and "datacenter" in by_id
    assert all(isinstance(s, ScenarioInfo) for s in scenarios)
    assert by_id["manufacturing"].data == "real"
    assert by_id["datacenter"].data == "synthetic"


def test_certify_datacenter_returns_frozen_certifyresult_that_verifies() -> None:
    key = new_signing_key()
    result = api.certify("datacenter", signer_key=key)
    assert isinstance(result, CertifyResult)
    assert result.domain_id == "datacenter"
    # the two facade-built certs bind + verify cleanly through api.verify
    view = api.verify(result.plan_cert, result.rule_pack_cert, signer_key=key)
    assert isinstance(view, VerifyView)
    assert view.ok, view.reasons
    assert view.reasons == []


def test_certify_datacenter_trust_vector_is_synthetic_and_authenticated() -> None:
    key = new_signing_key()
    result = api.certify("datacenter", signer_key=key)
    view = api.verify(result.plan_cert, result.rule_pack_cert, signer_key=key)
    assert view.trust_vector is not None
    tv: TrustVector = view.trust_vector
    assert tv.signature == "authenticated"
    assert tv.checker == "pass"
    assert tv.data == "synthetic"          # honest: the facility is synthetic
    assert tv.signer_note                   # the canonical sentence (non-empty)


def test_certify_datacenter_self_described_without_key() -> None:
    result = api.certify("datacenter")      # ephemeral key -> self-described
    assert isinstance(result.trust_vector, TrustVector)
    assert result.trust_vector.signature == "self_described"
    assert result.trust_vector.checker == "pass"
    assert result.trust_vector.data == "synthetic"


def test_get_timeline_datacenter_recomputes_capacity_overlay() -> None:
    """The datacenter timeline carries a capacity overlay RECOMPUTED from the signed
    plan+instance (the Spec 0.5 T8 seam), conforming to the frozen item schema:
    ``capacity_series`` item ``{"t": int, "value": int, "group": str | None}``;
    ``threshold_lines`` item ``{"label": str, "value": int}``. Recompute-not-trusted:
    ``get_timeline``'s series equals the seam recomputed from the signed bytes."""
    key = new_signing_key()
    tl = api.get_timeline("datacenter", signer_key=key)
    assert isinstance(tl, TimelineView)
    assert tl.capacity_series is not None and tl.threshold_lines is not None
    # frozen item schema (keys + int types)
    for item in tl.capacity_series:
        assert set(item.keys()) == {"t", "value", "group"}
        assert isinstance(item["t"], int) and isinstance(item["value"], int)
        assert item["group"] is None or isinstance(item["group"], str)
    for line in tl.threshold_lines:
        assert set(line.keys()) == {"label", "value"}
        assert isinstance(line["label"], str) and isinstance(line["value"], int)
    # the N+1 floor threshold line is present (recomputed from the rule params)
    assert any(line["label"] == "N+1 floor" for line in tl.threshold_lines)


def test_get_timeline_datacenter_overlay_equals_seam_recompute() -> None:
    """The rendered overlay is exactly the ``Domain.capacity_series`` seam recomputed
    from the SIGNED plan+instance — never a trusted cert/metadata field."""
    from feasible.cert.plan_cert import _fcir_from_cert
    from feasible.domains import get_domain
    from feasible.ir.domain import Plan

    key = new_signing_key()
    result = api.certify("datacenter", signer_key=key)
    tl = api.get_timeline("datacenter", signer_key=key)
    domain, _verifier = get_domain("datacenter")
    signed_plan = Plan.model_validate(result.plan_cert["plan"])
    # the FULL IR carries the dc:redundancy_floor rule params (the redundancy topology
    # lives there, not in the bare Instance) — the seam recomputes from the SIGNED IR.
    signed_ir = _fcir_from_cert(result.plan_cert)
    overlay = domain.capacity_series(signed_plan, signed_ir)
    assert overlay is not None
    series, lines = overlay
    assert tl.capacity_series == series
    assert tl.threshold_lines == lines


def test_offline_verify_datacenter_in_subprocess_importing_only_api(tmp_path: Path) -> None:
    """A subprocess that imports ONLY ``feasible.api`` (never the datacenter package)
    verifies the datacenter bundle green — the facade bootstrap resolves the
    datacenter bundle on the verify path."""
    key = new_signing_key()
    result = api.certify("datacenter", signer_key=key)
    bundle = {
        "plan_cert": result.plan_cert,
        "rule_pack_cert": result.rule_pack_cert,
        "signer_hex": key.public_key().public_bytes_raw().hex(),
    }
    bundle_path = tmp_path / "dc_bundle.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    script = textwrap.dedent(
        f"""
        import json
        from feasible import api
        from feasible.domains import _DOMAINS
        _DOMAINS.clear()
        assert "datacenter" not in _DOMAINS
        bundle = json.loads(open(r"{bundle_path}", encoding="utf-8").read())
        view = api.verify(bundle["plan_cert"], bundle["rule_pack_cert"], bundle["signer_hex"])
        assert view.ok, view.reasons
        assert view.trust_vector is not None
        assert view.trust_vector.signature == "authenticated"
        assert view.trust_vector.checker == "pass"
        assert view.trust_vector.data == "synthetic"
        print("DC_OFFLINE_VERIFY_OK")
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parents[2]),
    )
    assert proc.returncode == 0, f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    assert "DC_OFFLINE_VERIFY_OK" in proc.stdout, proc.stdout
