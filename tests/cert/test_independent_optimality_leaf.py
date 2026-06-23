"""T1.4 — the signed ``disjoint_solver_corroboration`` leaf.

The leaf is SOLVER-REPORTED at EMIT (provenance ``"solver"``, same trust class as
``tripwire_passed``): a disjoint second solver (Z3/SMT) re-runs the
strict-improvement query and the orchestrator's ``Verdict`` is written into
``claims.optimality`` as an OBJECT ``{"solver": "z3-smt", "verdict": …}`` (the
mechanism named alongside the verdict so a bare "corroborated" never travels
alone). The solver-free + LLM-free ``verify`` does NOT re-derive it (it cannot
replay a Z3 search) — exactly as it does not re-check ``tripwire_passed`` /
``optimal_per_cpsat`` / ``gap_bps`` — and the ``trust_boundary`` documents that
honestly.
"""
import copy

from feasible import api
from feasible.canon.canonical import new_signing_key, sign_dsse, public_key_hex
from feasible.cert.plan_cert import verify_plan_cert, render_html
from feasible.solve.independent_optimality import SOLVER_IDENTITY


def _pc(domain):
    key = new_signing_key()
    return api.certify(domain, signer_key=key).plan_cert, key


def test_leaf_present_and_corroborated_both_domains():
    for dom in ("manufacturing", "datacenter"):
        pc, key = _pc(dom)
        leaf = pc["claims"]["optimality"]["disjoint_solver_corroboration"]
        assert leaf["provenance"] == "solver"
        assert leaf["value"]["solver"] == SOLVER_IDENTITY    # mechanism travels WITH the verdict
        assert leaf["value"]["verdict"] == "corroborated"    # both optima are disjoint-corroborated
        assert verify_plan_cert(pc, key.public_key()).ok     # additive leaf doesn't break verify


def test_trust_boundary_documents_independence_and_residual():
    pc, _ = _pc("manufacturing")
    tb = pc["trust_boundary"]["optimality"].lower()
    assert "disjoint" in tb or "different solver" in tb
    assert "correlated" in tb and "no closed oracle" in tb
    assert "solver-reported" in tb                          # honest: NOT re-checked by verify


def test_render_qualifies_the_verdict_and_reads_the_signed_field():
    # render must print an INLINE qualifier naming the mechanism + residual — never a bare word.
    pc, _ = _pc("manufacturing")
    html = render_html(pc)
    assert "z3" in html.lower() and "different solver" in html.lower()  # mechanism named inline
    bad = copy.deepcopy(pc)
    bad["claims"]["optimality"]["disjoint_solver_corroboration"]["value"]["verdict"] = "refuted"
    assert "refuted" in render_html(bad)                    # render reflects the SIGNED field


def test_verify_does_not_re_derive_the_verdict():
    # honest: verify is solver-free; a tampered verdict is NOT rejected by verify (it is
    # solver-reported, same class as tripwire_passed).
    pc, key = _pc("manufacturing")
    bad = copy.deepcopy(pc)
    bad["claims"]["optimality"]["disjoint_solver_corroboration"]["value"]["verdict"] = "refuted"
    body = {k: v for k, v in bad.items() if k != "signature"}
    env = sign_dsse(body, key)
    env["public_key_hex"] = public_key_hex(key)
    bad["signature"] = env
    assert verify_plan_cert(bad, key.public_key()).ok        # NOT rejected — solver-reported leaf
