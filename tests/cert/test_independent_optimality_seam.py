from feasible.solve.independent_optimality import (
    Verdict, SOLVER_IDENTITY, independent_optimality_check,
)
from feasible.domains import get_domain
from feasible.domains.base import DomainVerifier
from feasible.scenario import build_scenario_ir


def test_orchestrator_skips_when_domain_opts_out():
    # When a domain opts out of the free-search encoding (the seam returns None),
    # the orchestrator returns skipped -> NEVER falsely corroborated. In T1.1 BOTH
    # domains stubbed None for every V; from T1.2 the manufacturing impl is real for
    # the 2-level FJSP objective but honestly opts out (None) for a NON-FJSP arity —
    # so a 3-tuple is the durable opt-out path that exercises None -> skipped on the
    # REAL manufacturing domain (unchanged by T1.3 landing the dc encoding).
    ir = build_scenario_ir()
    assert independent_optimality_check(ir, (1, 2, 3)) is Verdict.skipped


def test_seam_member_present_and_tolerates_variable_length():
    _d, verifier = get_domain("manufacturing")
    assert isinstance(verifier, DomainVerifier)
    assert hasattr(verifier, "independent_optimality_encode")
    # the SEAM imposes no arity: a 3-tuple must not raise through the contract. The
    # manufacturing impl honestly opts out (returns None) for a non-2-level objective
    # rather than forcing the FJSP arity — the seam's documented None opt-out.
    assert verifier.independent_optimality_encode(build_scenario_ir(), (1, 2, 3)) is None


def test_solver_identity_is_z3():
    assert SOLVER_IDENTITY == "z3-smt"
