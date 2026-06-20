"""Adversarial red-team suite — actively tries to BREAK each core invariant.

Every test here is an *attack* that must FAIL to land (the guarantee must hold).
Kept as a permanent regression suite.
"""
from __future__ import annotations

import base64
import random

import pytest

from feasible.canon.canonical import (
    FloatInPayloadError,
    append_event,
    canonicalize,
    new_signing_key,
    public_key_hex,
    sign_dsse,
    verify_chain,
)
from feasible.cert.plan_cert import emit_plan_cert, rule_pack_digest, verify_plan_cert
from feasible.checker.checker import check
from feasible.conflict.policy import MANUFACTURING_POLICY
from feasible.govern.conflict import detect_normative_conflicts, resolve_conflicts
from feasible.govern.coverage import build_coverage_ledger
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
from feasible.scenario import SHOP_RULES, build_extracted_pack, build_scenario_ir
from feasible.smt.attest import attest_feasibility
from feasible.solve.optimality import optimality_tripwire
from feasible.solve.orchestrate import solve


def _rule(rid: str, kind: str, clause: ClauseKind, params=None) -> Rule:
    return Rule(
        rule_id=rid, kind=kind, params=params or {}, severity=Severity.HARD, clause_kind=clause,
        compile_mode=CompileMode.PLAN_CONSTRAINT, resolution_class="SAFETY_SANITATION",
        provenance=Provenance(spans=[TextSpan(quoted_text=f"{rid} clause")]),
    )


def _two_op_ir() -> FCIR:
    inst = Instance(
        jobs=[Job(id="JA", product="P", family="Allergen", qty=1, due_date=5000, priority=1),
              Job(id="JS", product="Q", family="Standard", qty=1, due_date=5000, priority=3)],
        operations=[Operation(op_id="JA-op", job_id="JA", seq=0, eligible_machines=["M"], duration=100),
                    Operation(op_id="JS-op", job_id="JS", seq=0, eligible_machines=["M"], duration=100)],
        machines=["M"], setup_matrix={"Allergen|Standard": 90}, maintenance=[("M", 2000, 2100)], horizon=5000,
    )
    return FCIR(rules=[_rule("R-ROUTING", "routing_precedence", ClauseKind.OBLIGATION),
                       _rule("R-NOOVERLAP", "no_overlap", ClauseKind.PROHIBITION),
                       _rule("R-SETUP", "setup_cleanout", ClauseKind.OBLIGATION),
                       _rule("R-MAINT", "maintenance", ClauseKind.PROHIBITION),
                       _rule("R-6.1-NIGHT-CLEANOUT", "night_cleanout", ClauseKind.PROHIBITION,
                             {"day_start": 0, "day_end": 960, "night_start": 960, "night_end": 1440})],
                instance=inst)


# ---------------------------------------------------------------------------
# 1) CERTIFICATE FORGERY — re-signing a bad plan with the attacker's own key
#    is still caught, because verify RE-CHECKS the plan (not just the signature).
# ---------------------------------------------------------------------------
def _valid_cert(key):
    ir = build_scenario_ir()
    result = solve(ir, max_seconds=20.0)
    plan = result.plan
    chk = check(plan, ir)
    att = attest_feasibility(plan, ir)
    inc_a = Plan(assignments=dict(plan.assignments), cleanouts=[("Filler-1", 1050, 1140, "x")])
    return ir, emit_plan_cert(ir, plan, result, chk, att, inc_a, plan, key)


def test_forge_by_resigning_bad_plan_is_caught() -> None:
    victim = new_signing_key()
    ir, cert = _valid_cert(victim)
    # ATTACK: overlap two ops, then re-sign the tampered body with the ATTACKER's key
    op = next(iter(cert["plan"]["assignments"]))
    other = [o for o in cert["plan"]["assignments"] if o != op][0]
    cert["plan"]["assignments"][other] = list(cert["plan"]["assignments"][op])  # identical start+machine -> overlap
    attacker = new_signing_key()
    body = {k: v for k, v in cert.items() if k != "signature"}
    env = sign_dsse(body, attacker)
    env["public_key_hex"] = public_key_hex(attacker)
    cert["signature"] = env
    res = verify_plan_cert(cert, attacker.public_key())  # self-consistent signature + key
    assert res.ok is False  # the checker re-run catches the violation
    assert any("checker FAIL" in r for r in res.reasons)


def test_flip_a_claim_value_is_caught() -> None:
    key = new_signing_key()
    _ir, cert = _valid_cert(key)
    cert["claims"]["feasibility"]["checker"]["value"] = "PASS-FORGED"
    res = verify_plan_cert(cert, key.public_key())
    assert res.ok is False  # body no longer matches the signed payload


def test_swap_objective_is_caught() -> None:
    key = new_signing_key()
    _ir, cert = _valid_cert(key)
    cert["claims"]["optimality"]["objective"]["value"] = [0, 0]  # claim a better objective
    res = verify_plan_cert(cert, key.public_key())
    assert res.ok is False


# ---------------------------------------------------------------------------
# 2) CHECKER BYPASS — boundary-time and wrong-machine attacks must be rejected.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cstart,should_pass", [
    (870, True),    # ends 960 exactly at day boundary (half-open) -> legal
    (871, False),   # ends 961 -> into night
    (960, False),   # starts at night boundary
    (959, False),   # 959+90=1049 -> crosses into night
    (1050, False),  # 23:30 -> deep night
    (1439, False),  # late night
    (1440, True),   # next day 06:00 -> legal day again
])
def test_night_cleanout_boundaries(cstart: int, should_pass: bool) -> None:
    ir = _two_op_ir()
    plan = Plan(assignments={"JA-op": (max(0, cstart - 100), "M"), "JS-op": (cstart + 90, "M")},
                cleanouts=[("M", cstart, cstart + 90, "c")])
    night = [v for v in check(plan, ir).violations if v.rule_id == "R-6.1-NIGHT-CLEANOUT"]
    assert (len(night) == 0) == should_pass


def test_cleanout_on_wrong_machine_does_not_satisfy_setup() -> None:
    inst = Instance(
        jobs=[Job(id="JA", product="P", family="Allergen", qty=1, due_date=5000, priority=1),
              Job(id="JS", product="Q", family="Standard", qty=1, due_date=5000, priority=2)],
        operations=[Operation(op_id="JA-op", job_id="JA", seq=0, eligible_machines=["M1", "M2"], duration=100),
                    Operation(op_id="JS-op", job_id="JS", seq=0, eligible_machines=["M1", "M2"], duration=100)],
        machines=["M1", "M2"], setup_matrix={"Allergen|Standard": 90}, maintenance=[], horizon=5000)
    ir = FCIR(rules=[_rule("R-NOOVERLAP", "no_overlap", ClauseKind.PROHIBITION),
                     _rule("R-SETUP", "setup_cleanout", ClauseKind.OBLIGATION)], instance=inst)
    # both ops on M1 (allergen->standard), but the cleanout is parked on M2 -> must NOT count
    plan = Plan(assignments={"JA-op": (0, "M1"), "JS-op": (100, "M1")},
                cleanouts=[("M2", 100, 190, "misplaced")])
    setup = [v for v in check(plan, ir).violations if v.rule_id == "R-SETUP"]
    assert len(setup) == 1


def test_maintenance_half_open_edge() -> None:
    ir = _two_op_ir()  # maintenance [2000, 2100)
    abut = Plan(assignments={"JA-op": (1900, "M"), "JS-op": (2100, "M")},  # JA ends 2000 == maint start
                cleanouts=[("M", 2000, 2090, "c")] if False else [])
    # JA-op ends exactly at 2000 (maint start) -> half-open, no overlap
    assert not any(v.rule_id == "R-MAINT" for v in check(abut, ir).violations)
    overlap = Plan(assignments={"JA-op": (1901, "M"), "JS-op": (3000, "M")})  # ends 2001 -> overlaps
    assert any(v.rule_id == "R-MAINT" for v in check(overlap, ir).violations)


# ---------------------------------------------------------------------------
# 3) CHECKER <-> Z3 PARITY — 250 random plans over a 3-family instance.
# ---------------------------------------------------------------------------
def test_checker_z3_parity_randomized() -> None:
    inst = Instance(
        jobs=[Job(id="JA", product="P", family="Allergen", qty=1, due_date=9000, priority=1),
              Job(id="JS", product="Q", family="Standard", qty=1, due_date=9000, priority=2),
              Job(id="JP", product="R", family="Spicy", qty=1, due_date=9000, priority=3)],
        operations=[Operation(op_id="A", job_id="JA", seq=0, eligible_machines=["M"], duration=60),
                    Operation(op_id="S", job_id="JS", seq=0, eligible_machines=["M"], duration=50),
                    Operation(op_id="P", job_id="JP", seq=0, eligible_machines=["M"], duration=40)],
        machines=["M"], setup_matrix={"Allergen|Standard": 90, "Allergen|Spicy": 90}, maintenance=[], horizon=9000)
    ir = FCIR(rules=[_rule("R-NOOVERLAP", "no_overlap", ClauseKind.PROHIBITION),
                     _rule("R-SETUP", "setup_cleanout", ClauseKind.OBLIGATION),
                     _rule("R-6.1-NIGHT-CLEANOUT", "night_cleanout", ClauseKind.PROHIBITION,
                           {"day_start": 0, "day_end": 960, "night_start": 960, "night_end": 1440})],
              instance=inst)
    rng = random.Random(0xFEA51B1E)
    for _ in range(250):
        assigns = {o: (rng.randint(0, 1600), "M") for o in ("A", "S", "P")}
        cleans = []
        for _c in range(rng.randint(0, 2)):
            cs = rng.randint(0, 1600)
            cleans.append(("M", cs, cs + 90, "c"))
        plan = Plan(assignments=assigns, cleanouts=cleans)
        assert check(plan, ir).passed == attest_feasibility(plan, ir).feasible


# ---------------------------------------------------------------------------
# 4) OPTIMALITY TRIPWIRE SOUNDNESS
# ---------------------------------------------------------------------------
def test_tripwire_sound_at_optimum_and_below() -> None:
    ir = _two_op_ir()
    res = solve(ir, max_seconds=20.0)
    v0, v1 = res.objective
    assert optimality_tripwire(ir, (v0, v1)) is True       # nothing beats the optimum
    assert optimality_tripwire(ir, (v0 + 1, v1)) is False  # a worse bound IS beatable
    assert optimality_tripwire(ir, (v0, v1 + 1)) is False


# ---------------------------------------------------------------------------
# 5) COVERAGE LEDGER — dropping a hard rule must turn its clause RED.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("dropped", ["R-6.1-NIGHT-CLEANOUT", "R-MAINT", "R-SETUP"])
def test_dropping_any_hard_rule_yields_red(dropped: str) -> None:
    ir = build_scenario_ir()
    ir2 = FCIR(rules=[r for r in ir.rules if r.rule_id != dropped], instance=ir.instance)
    ledger = build_coverage_ledger(SHOP_RULES, ir2)
    assert ledger.complete is False
    assert len(ledger.red_findings) >= 1


# ---------------------------------------------------------------------------
# 6) CONFLICT POLICY — never drops the higher-priority (safety) rule;
#    escalates on equal-class / exception markers.
# ---------------------------------------------------------------------------
def _ir_with_perm(resclass="CUSTOMER_PRIORITY", exc=ExceptionMode.NONE) -> FCIR:
    base = build_scenario_ir()
    perm = Rule(rule_id="R-4.4", kind="permission",
                params={"target_rule": "R-SETUP", "scope_machine": "Filler-1", "scope_priority": 1},
                severity=Severity.SOFT, clause_kind=ClauseKind.PERMISSION, compile_mode=CompileMode.CONFLICT_ONLY,
                resolution_class=resclass, exception_mode=exc,
                provenance=Provenance(spans=[TextSpan(quoted_text="Filler-1 may skip cleanout")]))
    return FCIR(rules=[*base.rules, perm], instance=base.instance)


def test_policy_never_drops_safety() -> None:
    ir = _ir_with_perm()
    res = resolve_conflicts(ir, detect_normative_conflicts(ir), MANUFACTURING_POLICY)
    assert all(r.dropped_rule_id != "R-SETUP" for r in res)  # never drop the safety obligation
    assert res[0].dropped_rule_id == "R-4.4"


def test_policy_escalates_equal_class_and_exceptions() -> None:
    for kw in [dict(resclass="SAFETY_SANITATION"), dict(exc=ExceptionMode.HUMAN_OVERRIDE),
               dict(exc=ExceptionMode.EXPLICIT_OVERRIDE)]:
        ir = _ir_with_perm(**kw)
        res = resolve_conflicts(ir, detect_normative_conflicts(ir), MANUFACTURING_POLICY)
        assert res[0].resolution_mode == "ESCALATE"
        assert res[0].dropped_rule_id is None


# ---------------------------------------------------------------------------
# 7) DETERMINISM / CANON — no float sneaks in; tamper-evident ledger.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("payload", [
    {"x": 1.5}, {"x": [1, 2, 3.0]}, {"a": {"b": float("nan")}}, {"ok": True, "bad": 1.0},
    {"t": (1, 2.5)},
])
def test_float_cannot_sneak_into_hashed_payload(payload) -> None:
    with pytest.raises(FloatInPayloadError):
        canonicalize(payload)


def test_canon_is_deterministic_and_bool_is_not_int() -> None:
    o = {"z": 1, "a": [3, 2, 1], "m": {"k": "v"}}
    assert canonicalize(o) == canonicalize(dict(reversed(list(o.items()))))
    assert canonicalize({"x": True}) != canonicalize({"x": 1})  # bool handled before int


def test_ledger_tamper_is_detected() -> None:
    events = []
    events = append_event(events, {"e": "a"})
    events = append_event(events, {"e": "b"})
    assert verify_chain(events) is True
    events[0].payload["e"] = "evil"
    assert verify_chain(events) is False


# ---------------------------------------------------------------------------
# 8) TWO-CERT BINDING — different rule sets -> different digests.
# ---------------------------------------------------------------------------
def test_rule_pack_digest_distinguishes_rule_sets() -> None:
    a = build_scenario_ir()
    b = build_extracted_pack()  # +R-4.4 +R-5.2
    assert rule_pack_digest(a) != rule_pack_digest(b)


def test_tampered_rule_pack_ref_in_plan_cert_is_caught() -> None:
    key = new_signing_key()
    _ir, cert = _valid_cert(key)
    cert["rule_pack_ref"]["rule_pack_digest"] = "deadbeef" * 8  # repoint to a different pack
    res = verify_plan_cert(cert, key.public_key())
    assert res.ok is False  # body-vs-signature mismatch + digest mismatch
