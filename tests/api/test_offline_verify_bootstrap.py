"""Task 5 — domain registry bootstrap on the facade/verify path.

Offline verify must resolve EVERY registered-domain bundle in a fresh process,
regardless of which domain modules a caller happened to import. The facade owns
an explicit ``bootstrap_domains()`` (an import-list of the registered-domain
packages — manufacturing now; the datacenter track appends itself post-fork)
that the facade/verify entry paths call, so ``get_domain`` /
``trusted_policy_set`` resolve without the caller having imported the domain
package directly.

The subprocess test is the load-bearing one: a process that imports ONLY
``feasible.api`` (never ``feasible.domains.manufacturing``) verifies a
manufacturing bundle green — proving the bootstrap registers domains on the
verify path, not by luck of a prior import in the test session.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import feasible.domains.manufacturing  # noqa: F401  (registers manufacturing in THIS process)
from feasible import api
from feasible.canon.canonical import new_signing_key


def test_bootstrap_domains_exists_and_registers_manufacturing() -> None:
    """The facade exposes ``bootstrap_domains()`` which imports every
    registered-domain package; after calling it (even on a clean ``_DOMAINS``)
    manufacturing resolves through ``get_domain``."""
    from feasible.domains import _DOMAINS, bootstrap_domains, get_domain

    # Drop manufacturing from the live registry, then re-bootstrap from the
    # facade's explicit import-list (NOT a direct `import ...manufacturing`).
    saved = _DOMAINS.pop("manufacturing", None)
    try:
        bootstrap_domains()
        domain, verifier = get_domain("manufacturing")
        assert verifier.domain_id == "manufacturing"
    finally:
        if saved is not None:
            _DOMAINS["manufacturing"] = saved


def test_offline_verify_in_subprocess_importing_only_api(tmp_path: Path) -> None:
    """A subprocess that imports ONLY ``feasible.api`` verifies a manufacturing
    bundle green — the bootstrap registers the domain on the verify path."""
    key = new_signing_key()
    result = api.certify("manufacturing", signer_key=key)
    bundle = {
        "plan_cert": result.plan_cert,
        "rule_pack_cert": result.rule_pack_cert,
        "signer_hex": key.public_key().public_bytes_raw().hex(),
    }
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    script = textwrap.dedent(
        f"""
        import json, sys
        # Import ONLY the facade — never `import feasible.domains.manufacturing`.
        from feasible import api
        # Clear whatever the facade's import chain happened to register, so the
        # ONLY thing that can re-register manufacturing on the verify path is the
        # facade's own bootstrap (called from api.verify). This proves the verify
        # path bootstraps, not luck-of-a-prior-import.
        from feasible.domains import _DOMAINS
        _DOMAINS.clear()
        assert "manufacturing" not in _DOMAINS
        bundle = json.loads(open(r"{bundle_path}", encoding="utf-8").read())
        view = api.verify(
            bundle["plan_cert"], bundle["rule_pack_cert"], bundle["signer_hex"]
        )
        assert view.ok, view.reasons
        assert view.trust_vector is not None
        assert view.trust_vector.signature == "authenticated"
        assert view.trust_vector.checker == "pass"
        print("OFFLINE_VERIFY_OK")
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parents[2]),
    )
    assert proc.returncode == 0, f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    assert "OFFLINE_VERIFY_OK" in proc.stdout, proc.stdout
