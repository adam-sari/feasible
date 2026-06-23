from feasible.solve.independent_optimality import (
    Verdict, SOLVER_IDENTITY, independent_optimality_check,
)
from feasible.domains import get_domain
from feasible.domains.base import DomainVerifier
from feasible.scenario import build_scenario_ir


def test_orchestrator_skips_when_domain_opts_out():
    # both domains stub-return None in T1.1 -> honest skip (never falsely corroborated)
    ir = build_scenario_ir()
    assert independent_optimality_check(ir, (0, 90)) is Verdict.skipped


def test_seam_member_present_and_tolerates_variable_length():
    _d, verifier = get_domain("manufacturing")
    assert isinstance(verifier, DomainVerifier)
    assert hasattr(verifier, "independent_optimality_encode")
    # the SEAM imposes no arity: a 3-tuple must not raise through the contract
    assert verifier.independent_optimality_encode(build_scenario_ir(), (1, 2, 3)) is None  # stub


def test_solver_identity_is_z3():
    assert SOLVER_IDENTITY == "z3-smt"
