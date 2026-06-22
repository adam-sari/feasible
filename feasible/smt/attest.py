"""Independent Z3 feasibility attestation of a final plan + UNSAT core.

A SEPARATE arithmetic encoding (Z3) of the SAME hard predicates the polynomial
checker evaluates — reconstructing the per-machine sequence solely from start
times, re-deriving setup obligations from the setup matrix, never importing
CP-SAT arc literals. Independence is at the code level (Z3 vs Python); it is
correlated with the checker on setup attribution, so golden fixtures + the spike
property test are the real guard there.

Z3 is a feasibility attestor ONLY — it never bounds optimality. An UNSAT core
is NOT globally minimal and NOT a proof object; ``minimization_status`` records
this honestly (``feasible`` is the SAT-path sentinel).
"""
from __future__ import annotations

import z3
from pydantic import BaseModel, Field

import feasible.domains.manufacturing  # noqa: F401  (registers the manufacturing domain)
from feasible.checker.plan_shape import validate_plan_shape
from feasible.domains import get_domain
from feasible.ir.domain import FCIR, Plan
from feasible.registry import unsupported_hard_rules


class AttestResult(BaseModel):
    feasible: bool
    unsat_core: list[str] = Field(default_factory=list)
    minimization_status: str = "feasible"  # feasible | not_minimized | locally_minimized


def attest_feasibility(plan: Plan, ir: FCIR) -> AttestResult:
    # Mirror the checker's structural + fail-closed registry gate so the pair agrees
    # on malformed / unsupported plans (and so the Z3 encoding never sees a ghost op).
    gate = [f"R-PLAN-SHAPE:{v.counter_witness['predicate']}" for v in validate_plan_shape(plan, ir)]
    gate += [f"R-UNSUPPORTED-RULE:{r.rule_id}" for r in unsupported_hard_rules(ir)]
    if gate:
        return AttestResult(feasible=False, unsat_core=gate, minimization_status="not_minimized")

    # The parallel Z3 encoding (pinned plan vars + tracked per-rule constraints)
    # is built by the IR's domain verifier — a behavior-identical relocation of
    # the inline manufacturing encoding.
    _, verifier = get_domain(ir.domain_id)
    s = verifier.z3_encode(plan, ir)

    result = s.check()
    if result == z3.sat:
        return AttestResult(feasible=True, unsat_core=[], minimization_status="feasible")
    core = [str(c) for c in s.unsat_core()]
    return AttestResult(feasible=False, unsat_core=core, minimization_status="not_minimized")
