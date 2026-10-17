"""FC-IR -> OR-Tools CP-SAT model.

Reuses the spike-zero AddCircuit idioms verbatim: optional intervals per
(op, machine), a per-machine circuit with the FULL self-loop biconditional
(self_loop <=> NOT machine_presence), sequence-dependent setup gaps, and a
MATERIALIZED day-shift cleanout interval for every Allergen -> non-Allergen
transition. Maintenance windows are fixed blocking intervals; the night-cleanout
ban (R-6.1) is a modular constraint. Only ``compile_mode == PLAN_CONSTRAINT``
rules are compiled (parity with the checker; permissions never appear here).

Objective is STAGED lexicographic: minimize priority-weighted tardiness (weight
= 4 - priority), freeze it as a hard bound, then minimize total changeover.
"""
from __future__ import annotations

from dataclasses import dataclass

from ortools.sat.cp_model_pb2 import CpSolverStatus
from ortools.sat.python import cp_model

from feasible.ir.domain import FCIR
from feasible.registry import assert_all_hard_rules_supported

DEPOT = 0
DAY_DEFAULT = {"day_start": 0, "day_end": 960, "night_start": 960, "night_end": 1440}


@dataclass
class VarIndex:
    starts: dict[str, cp_model.IntVar]
    ends: dict[str, cp_model.IntVar]
    presence: dict[str, cp_model.IntVar]  # op-level (== 1; every op is scheduled)
    machine_presence: dict[tuple[str, str], cp_model.IntVar]
    arcs: dict[tuple[str, str, str], cp_model.IntVar]
    cleanout_intervals: list[tuple[str, str, str, cp_model.IntVar, cp_model.IntVar]]
    tardiness: dict[str, cp_model.IntVar]
    weighted_tardiness: cp_model.IntVar
    total_changeover: cp_model.IntVar
    horizon: int
    ir: FCIR


def _family_of(ir: FCIR, op_id: str) -> str:
    op = ir.instance.operation(op_id)
    return ir.instance.job(op.job_id).family


def build_model(ir: FCIR) -> tuple[cp_model.CpModel, VarIndex]:
    assert_all_hard_rules_supported(ir)  # fail closed: never optimize against an unevaluated hard rule
    m = cp_model.CpModel()
    inst = ir.instance
    H = inst.horizon

    night_rule = ir.rule("R-6.1-NIGHT-CLEANOUT")
    night_active = ir.has_active("R-6.1-NIGHT-CLEANOUT")
    night = {**DAY_DEFAULT, **(night_rule.params if night_rule else {})}

    starts: dict[str, cp_model.IntVar] = {}
    ends: dict[str, cp_model.IntVar] = {}
    presence: dict[str, cp_model.IntVar] = {}
    machine_presence: dict[tuple[str, str], cp_model.IntVar] = {}
    intervals_by_machine: dict[str, list[cp_model.IntervalVar]] = {mc: [] for mc in inst.machines}

    # --- optional intervals, one per (op, eligible machine); exactly one machine
    for op in inst.operations:
        s = m.new_int_var(0, H, f"start_{op.op_id}")
        e = m.new_int_var(0, H, f"end_{op.op_id}")
        m.add(e == s + op.duration)
        starts[op.op_id], ends[op.op_id] = s, e
        pres = m.new_bool_var(f"present_{op.op_id}")
        m.add(pres == 1)  # every op must be scheduled
        presence[op.op_id] = pres
        machine_lits = []
        for mc in op.eligible_machines:
            mp = m.new_bool_var(f"mp_{op.op_id}_{mc}")
            machine_presence[(op.op_id, mc)] = mp
            iv = m.new_optional_interval_var(s, op.duration, e, mp, f"iv_{op.op_id}_{mc}")
            intervals_by_machine[mc].append(iv)
            machine_lits.append(mp)
        m.add(sum(machine_lits) == 1)

    # --- routing precedence within each job (Mix -> Fill -> Label)
    if ir.has_active("R-ROUTING"):
        by_job: dict[str, list] = {}
        for o in inst.operations:
            by_job.setdefault(o.job_id, []).append(o)
        for ops_j in by_job.values():
            ordered = sorted(ops_j, key=lambda o: o.seq)
            for a, b in zip(ordered, ordered[1:]):
                m.add(starts[b.op_id] >= ends[a.op_id])

    # --- per-machine circuit (sequencing + setups + materialized cleanouts)
    arcs: dict[tuple[str, str, str], cp_model.IntVar] = {}
    cleanout_intervals: list[tuple[str, str, str, cp_model.IntVar, cp_model.IntVar]] = []
    changeover_terms = []

    for mc in inst.machines:
        ops_here = [o for o in inst.operations if mc in o.eligible_machines]
        if not ops_here:
            continue
        # op nodes are 1..n; the depot node is 0 (used as a literal below)
        node: dict[str, int] = {o.op_id: idx + 1 for idx, o in enumerate(ops_here)}
        circuit: list[tuple[int, int, cp_model.IntVar]] = []

        depot_loop = m.new_bool_var(f"depotloop_{mc}")
        circuit.append((0, 0, depot_loop))
        for o in ops_here:
            mp = machine_presence[(o.op_id, mc)]
            loop = m.new_bool_var(f"loop_{o.op_id}_{mc}")
            # FULL biconditional: self-loop true  <=>  NOT present-on-machine
            m.add(mp == 0).only_enforce_if(loop)
            m.add(mp == 1).only_enforce_if(loop.Not())
            circuit.append((node[o.op_id], node[o.op_id], loop))
            en = m.new_bool_var(f"enter_{o.op_id}_{mc}")
            ex = m.new_bool_var(f"exit_{o.op_id}_{mc}")
            circuit.append((0, node[o.op_id], en))
            circuit.append((node[o.op_id], 0, ex))

        for op_i in ops_here:
            for op_j in ops_here:
                if op_i.op_id == op_j.op_id:
                    continue
                a = m.new_bool_var(f"arc_{op_i.op_id}_{op_j.op_id}_{mc}")
                arcs[(op_i.op_id, op_j.op_id, mc)] = a
                circuit.append((node[op_i.op_id], node[op_j.op_id], a))
                gap = inst.setup(_family_of(ir, op_i.op_id), _family_of(ir, op_j.op_id))
                m.add(starts[op_j.op_id] >= ends[op_i.op_id] + gap).only_enforce_if(a)
                if gap > 0:
                    changeover_terms.append(gap * a)
                    # materialized cleanout interval between op_i and op_j on mc
                    cs = m.new_int_var(0, H, f"cleanstart_{op_i.op_id}_{op_j.op_id}_{mc}")
                    ci = m.new_optional_interval_var(cs, gap, cs + gap, a, f"cleaniv_{op_i.op_id}_{op_j.op_id}_{mc}")
                    intervals_by_machine[mc].append(ci)
                    m.add(cs >= ends[op_i.op_id]).only_enforce_if(a)
                    m.add(cs + gap <= starts[op_j.op_id]).only_enforce_if(a)
                    if night_active:
                        # cleanout must sit fully inside a day window [day_start, day_end)
                        mod = m.new_int_var(0, 1439, f"cleanmod_{op_i.op_id}_{op_j.op_id}_{mc}")
                        m.add_modulo_equality(mod, cs, 1440)
                        m.add(mod >= night["day_start"]).only_enforce_if(a)
                        m.add(mod + gap <= night["day_end"]).only_enforce_if(a)
                    cleanout_intervals.append((op_i.op_id, op_j.op_id, mc, a, cs))

        m.add_circuit(circuit)

    # --- maintenance windows: fixed blocking intervals
    if ir.has_active("R-MAINT"):
        for k, (mc, mstart, mend) in enumerate(inst.maintenance):
            if mc in intervals_by_machine:
                mv = m.new_interval_var(mstart, mend - mstart, mend, f"maint_{mc}_{k}")
                intervals_by_machine[mc].append(mv)

    # --- per-machine no-overlap
    for mc in inst.machines:
        ivs = intervals_by_machine[mc]
        if ivs:
            m.add_no_overlap(ivs)

    # --- objective vars
    tardiness: dict[str, cp_model.IntVar] = {}
    wt_terms = []
    for job in inst.jobs:
        last_op = max((o for o in inst.operations if o.job_id == job.id), key=lambda o: o.seq)
        t = m.new_int_var(0, H, f"tard_{job.id}")
        m.add(t >= ends[last_op.op_id] - job.due_date)
        tardiness[job.id] = t
        wt_terms.append((4 - job.priority) * t)

    wt_ub = sum(4 - j.priority for j in inst.jobs) * H + 1
    weighted_tardiness = m.new_int_var(0, wt_ub, "weighted_tardiness")
    m.add(weighted_tardiness == sum(wt_terms))

    co_ub = 90 * len(inst.operations) * len(inst.machines) + 1
    total_changeover = m.new_int_var(0, co_ub, "total_changeover")
    m.add(total_changeover == (sum(changeover_terms) if changeover_terms else 0))

    vi = VarIndex(
        starts=starts,
        ends=ends,
        presence=presence,
        machine_presence=machine_presence,
        arcs=arcs,
        cleanout_intervals=cleanout_intervals,
        tardiness=tardiness,
        weighted_tardiness=weighted_tardiness,
        total_changeover=total_changeover,
        horizon=H,
        ir=ir,
    )
    return m, vi


def freeze_l1_and_minimize_changeover(
    m: cp_model.CpModel, solver: cp_model.CpSolver, vi: VarIndex
) -> CpSolverStatus:
    """Staged lexicographic solve. Returns the final CP-SAT status."""
    m.minimize(vi.weighted_tardiness)
    status1 = solver.solve(m)
    if status1 not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        return status1
    best_wt = int(solver.value(vi.weighted_tardiness))
    m.add(vi.weighted_tardiness == best_wt)  # freeze level 1
    m.minimize(vi.total_changeover)  # replaces the objective
    return solver.solve(m)


def extract_plan(solver: cp_model.CpSolver, vi: VarIndex):
    from feasible.ir.domain import Plan

    assignments: dict[str, tuple[int, str]] = {}
    for op in vi.ir.instance.operations:
        machine = next(
            mc
            for mc in op.eligible_machines
            if solver.boolean_value(vi.machine_presence[(op.op_id, mc)])
        )
        assignments[op.op_id] = (int(solver.value(vi.starts[op.op_id])), machine)

    cleanouts: list[tuple[str, int, int, str]] = []
    for i, j, mc, present, cs in vi.cleanout_intervals:
        if solver.boolean_value(present):
            start = int(solver.value(cs))
            dur = vi.ir.instance.setup(_family_of(vi.ir, i), _family_of(vi.ir, j))
            cleanouts.append((mc, start, start + dur, f"cleanout {i}->{j}"))
    return Plan(assignments=assignments, cleanouts=cleanouts)
