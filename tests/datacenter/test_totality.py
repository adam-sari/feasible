"""Task 6 (B-5, CRITICAL): the executable totality contract for datacenter.

A self-signed cert is an adversary input: a missing/foreign/unknown param must
NEVER crash ``check`` (an uncaught ``KeyError`` in ``check_predicates`` is a
crash-DoS in ``verify_plan_cert``) and must NEVER pass silently (fail-closed).

This module pins four faces of the contract:

  (a) unknown domain → ``verify_plan_cert`` rejects (the frozen domain_id guard);
  (b) unknown rule_id within datacenter → ``assert_all_hard_rules_supported``
      raises ``UnsupportedHardRuleError``;
  (c) per-predicate param totality: for EACH ``dc:*`` predicate, over a DC IR with
      EACH required param removed in turn, ``check(plan, ir)`` returns
      ``passed=False`` WITHOUT raising (no ``KeyError`` escapes) AND never passes
      silently;
  (d) BOTH the checker and Z3 reject an unsupported ``dc:`` kind (the registry
      gate emits ``R-UNSUPPORTED-RULE`` and ``attest_feasibility`` is infeasible).
"""
from __future__ import annotations

import copy

import pytest

import feasible.domains.datacenter  # noqa: F401  (registers the datacenter domain)
from feasible.canon.canonical import new_signing_key
from feasible.cert.plan_cert import emit_plan_cert, rule_pack_digest, verify_plan_cert
from feasible.checker.checker import check
from feasible.domains import get_domain
from feasible.ir.domain import (
    ClauseKind,
    CompileMode,
    ExceptionMode,
    FCIR,
    Instance,
    Job,
    Operation,
    Plan,
    Provenance,
    Rule,
    Severity,
    TextSpan,
)
from feasible.registry import UnsupportedHardRuleError, assert_all_hard_rules_supported
from feasible.smt.attest import attest_feasibility


def _rule(rule_id: str, kind: str, params: dict) -> Rule:
    return Rule(
        rule_id=rule_id, kind=kind, params=params,
        severity=Severity.HARD, clause_kind=ClauseKind.OBLIGATION,
        compile_mode=CompileMode.PLAN_CONSTRAINT,
        resolution_class="SAFETY_SANITATION" if rule_id == "dc:redundancy_floor" else "EFFICIENCY",
        exception_mode=ExceptionMode.NONE,
        provenance=Provenance(spans=[TextSpan(quoted_text=f"{rule_id} (test)", role="modeling_decision")]),
    )


def _dc_active_ir_and_plan() -> tuple[FCIR, Plan]:
    """A shape-valid datacenter IR with ALL FOUR dc:* rules ACTIVE
    (HARD/PLAN_CONSTRAINT), plus a shape-valid plan."""
    units = ["U1", "U2", "U3", "U4"]
    horizon = 4
    jobs = [Job(id=u, product=u, family="unit", qty=1, due_date=horizon, priority=3) for u in units]
    ops = [Operation(op_id=u, job_id=u, seq=0, eligible_machines=[u], duration=1) for u in units]
    inst = Instance(jobs=jobs, operations=ops, machines=list(units),
                    setup_matrix={}, maintenance=[], horizon=horizon)
    rules = [
        _rule("dc:redundancy_floor", "redundancy_floor", {
            "group_id": "G1", "units": ["U1", "U2", "U3"], "floor": 2, "horizon": horizon,
            "maintenance": {},
        }),
        _rule("dc:maintenance_window", "maintenance_window", {
            "path_id": "U4", "forbidden": [[0, 1]], "derate_kw": {},
        }),
        _rule("dc:power_cap", "power_cap", {
            "cap_id": "CAP", "scope_units": ["U1", "U2"], "cap_kw": 100,
            "per_member_pct": 80, "draws": {"U1": 40, "U2": 40},
        }),
        _rule("dc:anti_affinity", "anti_affinity", {
            "group_id": "AA", "replicas": ["U1", "U3"],
            "fault_domain_of": {"U1": "FD-A", "U3": "FD-B"},
        }),
    ]
    ir = FCIR(rules=rules, instance=inst, domain_id="datacenter")
    plan = Plan(assignments={op.op_id: (0, op.eligible_machines[0]) for op in ir.instance.operations})
    return ir, plan


# --------------------------------------------------------------------------- #
# (a) unknown domain → verify_plan_cert rejects (frozen domain_id guard)        #
# --------------------------------------------------------------------------- #


def test_unknown_domain_rejected_by_verify():
    ir, plan = _dc_active_ir_and_plan()
    key = new_signing_key()
    _, verifier = get_domain("datacenter")
    from feasible.solve.orchestrate import SolveResult

    result = SolveResult(plan=plan, status="OPTIMAL",
                         objective=verifier.objective(ir, plan), gap=0.0)
    cert = emit_plan_cert(
        ir, plan, result, check(plan, ir), attest_feasibility(plan, ir),
        plan, plan, key, rule_pack_digest_override=rule_pack_digest(ir))
    # tamper the SIGNED domain_id to an unregistered domain → fail-closed.
    bad = copy.deepcopy(cert)
    bad["domain_id"] = "no_such_domain"
    res = verify_plan_cert(bad, key.public_key())
    assert res.ok is False
    assert any("no_such_domain" in r or "unknown domain" in r for r in res.reasons)


# --------------------------------------------------------------------------- #
# (b) unknown rule_id within datacenter → UnsupportedHardRuleError              #
# --------------------------------------------------------------------------- #


def test_unknown_dc_rule_id_is_unsupported_raises():
    ir, _ = _dc_active_ir_and_plan()
    bad = copy.deepcopy(ir)
    # a dc:* id NOT in the datacenter known/evaluated/structural sets, HARD/PLAN_CONSTRAINT.
    bad.rules.append(_rule("dc:not_a_real_rule", "not_a_real_kind", {}))
    with pytest.raises(UnsupportedHardRuleError):
        assert_all_hard_rules_supported(bad)


# --------------------------------------------------------------------------- #
# (c) per-predicate param totality (the crash-DoS B-5 closes)                   #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("rule_id,param", [
    ("dc:redundancy_floor", "group_id"), ("dc:redundancy_floor", "units"),
    ("dc:redundancy_floor", "floor"), ("dc:redundancy_floor", "horizon"),
    ("dc:power_cap", "cap_kw"), ("dc:power_cap", "scope_units"),
    ("dc:maintenance_window", "path_id"), ("dc:maintenance_window", "forbidden"),
    ("dc:anti_affinity", "replicas"),
])
def test_missing_param_fails_closed_without_raising(rule_id, param):
    ir, plan = _dc_active_ir_and_plan()
    del ir.rule(rule_id).params[param]
    res = check(plan, ir)              # MUST NOT raise (uncaught KeyError == crash-DoS)
    assert res.passed is False         # fail-closed, never a silent pass
    assert any(v.rule_id == rule_id for v in res.violations)


def test_no_bare_subscript_in_verifier_source():
    """Defense in depth: no bare ``params[...]`` / ``p[...]`` subscript reads a
    rule param inside verifier.py (every read is a TOTAL ``p.get(...)``). A bare
    subscript on an adversary-omitted param is the crash-DoS this guards."""
    import re

    import feasible.domains.datacenter.verifier as v

    src = inspect_source = __import__("inspect").getsource(v)
    # forbid `<name>[` indexing where <name> is a params alias (p / params / r.params).
    # we conservatively flag `p[` and `params[` and `.params[` subscripts.
    offenders = re.findall(r"(?<![\w.])(?:p|params)\[", src)
    offenders += re.findall(r"\.params\[", src)
    assert offenders == [], f"bare param subscript(s) found in verifier.py: {offenders}"


# --------------------------------------------------------------------------- #
# (d) BOTH engines reject an unsupported dc: kind (registry gate fail-closed)   #
# --------------------------------------------------------------------------- #


def test_unsupported_dc_kind_rejected_by_checker_and_z3():
    ir, plan = _dc_active_ir_and_plan()
    bad = copy.deepcopy(ir)
    bad.rules.append(_rule("dc:not_a_real_rule", "not_a_real_kind", {}))
    res = check(plan, bad)
    assert res.passed is False
    assert any(v.rule_id == "R-UNSUPPORTED-RULE" for v in res.violations)
    att = attest_feasibility(plan, bad)
    assert att.feasible is False
    assert any("R-UNSUPPORTED-RULE" in c for c in att.unsat_core)
