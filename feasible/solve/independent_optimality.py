"""Independent-optimality orchestration via a DISJOINT second solver (Z3/SMT).

The same-engine optimality tripwire (``feasible.solve.optimality``) re-solves the
strict-improvement query with the SAME engine (CP-SAT) that produced the optimum,
so it shares CP-SAT's solver-bug class (optimal-but-wrong / wrong-bound /
false-INFEASIBLE). This module re-runs the SAME query — "does a feasible plan
STRICTLY BETTER than the achieved objective V exist?" — through a DIFFERENT engine
(Z3, an SMT solver), via the per-domain ``independent_optimality_encode`` seam. If
Z3 also reports UNSAT then no plan beats V, so the optimum is corroborated by a
disjoint engine, defending exactly the CP-SAT solver-bug class the same-engine
tripwire structurally cannot.

This orchestrator owns the verdict semantics + the timeout + the fail-honest
mapping. It dispatches through the seam exactly as ``feasible.smt.attest``
dispatches through ``z3_encode`` (resolve domain, call the verifier's z3 seam, run
``s.check()``). Determinism: integers only; the solver object is NEVER hashed; the
only thing that reaches the signed body is the ``Verdict`` enum string +
``SOLVER_IDENTITY``.
"""
from __future__ import annotations

from enum import Enum

import z3

import feasible.domains.manufacturing  # noqa: F401  (registers the manufacturing domain)
from feasible.domains import get_domain
from feasible.ir.domain import FCIR


class Verdict(str, Enum):
    corroborated = "corroborated"   # Z3 UNSAT: no plan beats V
    refuted = "refuted"             # Z3 SAT: a strictly-better plan exists (a real bug signal)
    skipped = "skipped"             # Z3 unknown/timeout, or domain has no encoding -> fail-honest


SOLVER_IDENTITY = "z3-smt"          # the disjoint engine name carried in the leaf


def independent_optimality_check(ir: FCIR, V: tuple[int, ...],
                                 timeout_ms: int = 10_000) -> Verdict:
    """Re-run the strict-improvement query through a disjoint engine (Z3).

    Resolves the domain via ``get_domain(ir.domain_id)`` (mirroring
    ``attest.py``), calls the ``independent_optimality_encode`` seam, sets the Z3
    wall-clock timeout, and maps ``unsat -> corroborated``, ``sat -> refuted``,
    ``unknown/None -> skipped`` (fail-honest — NEVER falsely corroborated on a
    timeout or an honest domain opt-out)."""
    _, verifier = get_domain(ir.domain_id)
    s = verifier.independent_optimality_encode(ir, V)
    if s is None:                        # domain opts out -> honest skip
        return Verdict.skipped
    s.set("timeout", timeout_ms)         # z3 wall-clock bound (ms)
    r = s.check()
    if r == z3.unsat:
        return Verdict.corroborated
    if r == z3.sat:
        return Verdict.refuted
    return Verdict.skipped                # z3.unknown / timeout -> NEVER falsely corroborated
