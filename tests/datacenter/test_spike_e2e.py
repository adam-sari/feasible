from __future__ import annotations

from feasible.canon.canonical import new_signing_key
from feasible.cert.plan_cert import emit_plan_cert, verify_plan_cert, rule_pack_digest
from feasible.checker.checker import check
from feasible.smt.attest import attest_feasibility
from feasible.solve.orchestrate import SolveResult
from feasible.domains import get_domain
from feasible.ir.domain import FCIR, Plan
import feasible.domains.datacenter  # registers the datacenter domain
from feasible.domains.datacenter.instance import DatacenterInstance, pack_dc_instance, unpack_dc_instance


def _minimal_dc_ir() -> FCIR:
    # 3 units, floor=2, horizon=4. One unit (U3) in maintenance over [1,3): available = [3,2,2,3] -> floor held.
    dc = DatacenterInstance(
        group_id="feedA", units=["U1", "U2", "U3"], floor=2, horizon=4,
        maintenance={"U3": [(1, 3)]},
    )
    inst, rules = pack_dc_instance(dc)
    return FCIR(rules=rules, instance=inst, domain_id="datacenter")


def _plan_over(ir: FCIR, extra_outage: dict | None = None) -> Plan:
    # the optimized plan schedules NO extra outage; assignments mirror the packed ops (shape-valid)
    from feasible.domains.datacenter.instance import baseline_plan
    return baseline_plan(ir, extra_outage or {})


def test_spike_emit_and_verify_real_cert():
    ir = _minimal_dc_ir()
    plan = _plan_over(ir)
    # the floor holds -> checker passes
    assert check(plan, ir).passed
    att = attest_feasibility(plan, ir)
    assert att.feasible
    # honest incumbents: B == optimized (floor held); A drops U2 ALSO into maintenance at t=1,2 -> available[1]=1 < floor 2
    inc_b = plan
    inc_a = _plan_over(ir, extra_outage={"U2": (1, 3)})
    assert check(inc_a, ir).passed is False  # the gotcha incumbent violates the floor
    key = new_signing_key()
    # the REAL datacenter objective is signed via the Spec 0.5 objective seam
    # (verifier.objective), NOT the FJSP recompute_objective. verify_plan_cert
    # recomputes through verifier.objective (Spec 0.5 T1) -> equal by construction.
    _, verifier = get_domain("datacenter")
    result = SolveResult(plan=plan, status="OPTIMAL", objective=verifier.objective(ir, plan), gap=0.0)
    cert = emit_plan_cert(ir, plan, result, check(plan, ir), att, inc_a, inc_b, key,
                          rule_pack_digest_override=rule_pack_digest(ir))
    # the FROZEN verify accepts a REAL datacenter cert offline
    res = verify_plan_cert(cert, key.public_key())
    assert res.ok, res.reasons
    # the signed objective is the REAL (stranded_power_kw, makespan); labels are signed
    assert cert["claims"]["optimality"]["objective_labels"]["value"] == ["stranded_power_kw", "makespan"]
    assert verifier.objective(ir, plan) == tuple(cert["claims"]["optimality"]["objective"]["value"])
    # the gotcha is the redundancy floor, with a per-timestep witness
    fa = cert["incumbent_A_failure"]
    assert fa["violated_rule_ref"] == "dc:redundancy_floor"
    assert fa["counter_witness"]["timestep"] == 1
    assert fa["counter_witness"]["available"] == 1 and fa["counter_witness"]["floor"] == 2


def test_spike_witness_rederivable_solverfree():
    # verify RE-DERIVES the gotcha from the embedded incumbent_a (not the signed number)
    ir = _minimal_dc_ir()
    plan = _plan_over(ir)
    inc_a = _plan_over(ir, extra_outage={"U2": (1, 3)})
    vs = check(inc_a, ir).violations
    floor_v = [v for v in vs if v.rule_id == "dc:redundancy_floor"]
    assert floor_v and floor_v[0].witness_kind == "coverage_floor"
    assert floor_v[0].counter_witness == {"group_id": "feedA", "timestep": 1, "available": 1, "floor": 2}


def test_spike_param_reads_are_total_failclosed():
    # B-5 (CRITICAL): a self-signed cert that OMITS a required param must NOT crash
    # check() (a KeyError in check_predicates is uncaught in verify_plan_cert -> crash-DoS).
    # Each required param removed -> passed=False, NO raise, NO silent pass.
    import copy
    ir = _minimal_dc_ir()
    plan = _plan_over(ir)
    for key in ("group_id", "units", "floor", "horizon"):
        bad = copy.deepcopy(ir)
        del bad.rule("dc:redundancy_floor").params[key]
        res = check(plan, bad)              # must NOT raise
        assert res.passed is False          # fail-closed (never a silent pass)
        assert any(v.rule_id == "dc:redundancy_floor" for v in res.violations)


def govern_pack_from_ir(ir: FCIR, policy=None):
    """The spike's thin shim: wrap the already-built IR as an extracted pack and
    route it through the SINGLE frozen ``govern_pack`` (Task 8 routes the real pack
    directly). The point of B-8 is to PIN — at the spike — that ``domain_id`` survives
    the frozen govern threading (Spec 0.5 T6 reconstructs ``FCIR(..., domain_id=...)``).
    A ``None`` policy collapses to the reviewed datacenter policy whose SAFETY class is
    literally ``SAFETY_SANITATION`` (B-3)."""
    from feasible.conflict.policy import ConflictPolicy, ClassPriority
    from feasible.govern.pipeline import govern_pack
    if policy is None:
        policy = ConflictPolicy(
            policy_id="datacenter_spike_v1",
            version=1,
            class_priorities=[
                ClassPriority(class_id="SAFETY_SANITATION",
                              human_label="N+1/2N redundancy floor (this domain's safety floor)",
                              priority=100),
                ClassPriority(class_id="EFFICIENCY", human_label="Acceleration / efficiency", priority=10),
            ],
        )
    return govern_pack(ir, policy), policy


def test_spike_rulepack_cert_and_domain_id_survives_govern():
    # B-8: the spike also emits+verifies a REAL Rule-Pack Cert, and asserts the signed
    # domain_id == "datacenter" SURVIVES the frozen govern_pack (Spec 0.5 T6 threads it).
    from feasible.cert.rulepack_cert import emit_rulepack_cert, verify_rulepack_cert
    from feasible.domains.datacenter.instance import DatacenterInstance, pack_dc_instance
    # a minimal extracted pack carrying domain_id="datacenter"
    dc = DatacenterInstance(group_id="feedA", units=["U1", "U2", "U3"], floor=2, horizon=4,
                            maintenance={"U3": [(1, 3)]})
    inst, rules = pack_dc_instance(dc)
    ir = FCIR(rules=rules, instance=inst, domain_id="datacenter")
    # Spec 0.5 T6: govern_pack reconstructs FCIR(..., domain_id=ir.domain_id)
    gov, policy = govern_pack_from_ir(ir, policy=None)
    assert gov.universe_ir.domain_id == "datacenter"
    assert gov.active_ir.domain_id == "datacenter"
    key = new_signing_key()
    rp = emit_rulepack_cert(gov.active_ir, sop_text="redundancy floor (spike)",
                            policy=policy, resolutions=[], private_key=key)
    # pin the spike policy explicitly (Task 8 registers the datacenter policy in the
    # live trusted_policy_set; the spike only pins the round-trip + domain_id survival).
    trusted = frozenset({(policy.policy_id, policy.digest())})
    assert verify_rulepack_cert(rp, key.public_key(), trusted_policies=trusted).ok
