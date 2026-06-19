"""Spike-zero GATE + retained regression fixture.

A tiny hand-built CP-SAT model proving the six load-bearing modeling idioms the
whole Feasible spine depends on. DECOUPLED from FC-IR: imports nothing from
``feasible/``. If an OR-Tools upgrade ever changes circuit / optional-interval
semantics, this file goes red before any real code does.

Epoch (pinned once, reused everywhere): integer MINUTES, Mon 06:00 = 0.
    day shift = [0, 960)      (06:00 - 22:00)
    night     = [960, 1440)   (22:00 Mon -> 06:00 Tue)
Intervals are half-open [start, end). Setup Allergen -> non-Allergen = 90.
23:30 = minute 1050 (inside the night window). No floats anywhere.

Six facts proven:
  (a) CP-SAT sequences optional ops on a machine via AddCircuit + optional intervals.
  (b) FULL biconditional self_loop[o] <=> NOT present[o]; every present op has
      exactly one real in-arc + one real out-arc (vacuous-permissiveness => INFEASIBLE).
  (c) arc[i,j] => start[j] >= end[i] + setup(fam_i, fam_j).
  (d) the Allergen->Standard cleanout is a MATERIALIZED interval in AddNoOverlap
      with a pinned start, flowing into the plan (no op overlaps it).
  (e) per-machine sequence by sort key (start, stable_op_id) == the arc-chain order.
  (f) the illegal 23:30 cleanout (start = 1050) is rejected by the night ban.
"""
from __future__ import annotations

from ortools.sat.python import cp_model

HORIZON = 4320  # 3 days of minutes
NIGHT_START, NIGHT_END = 960, 1440
DAY_START, DAY_END = 0, 960
CLEANOUT_MIN = 90
ILLEGAL_CLEANOUT_START = 1050  # 23:30 -> night
LEGAL_CLEANOUT_START = 600  # 16:00 -> day

OPS = ["o0", "o1", "o2"]  # stable ids, lexicographic
FAMILY = {"o0": "Allergen", "o1": "Standard", "o2": "Standard"}
DURATION = {"o0": 40, "o1": 30, "o2": 20}  # co-prime-ish, distinct
DEPOT = 0


def setup_minutes(from_op: str, to_op: str) -> int:
    if FAMILY[from_op] == "Allergen" and FAMILY[to_op] != "Allergen":
        return CLEANOUT_MIN
    return 0


class SpikeBuild:
    """One single-machine optional-ops circuit model + an optional cleanout."""

    def __init__(
        self,
        ops: list[str],
        *,
        force_present: dict[str, bool] | None = None,
        force_self_loop: dict[str, bool] | None = None,
        with_cleanout_pair: tuple[str, str] | None = None,
        cleanout_start: int | None = None,
        night_ban: bool = False,
    ) -> None:
        m = cp_model.CpModel()
        self.model = m
        self.ops = ops
        self.node = {o: i + 1 for i, o in enumerate(ops)}  # depot is 0
        self.start: dict[str, cp_model.IntVar] = {}
        self.end: dict[str, cp_model.IntVar] = {}
        self.present: dict[str, cp_model.IntVar] = {}
        self.self_loop: dict[str, cp_model.IntVar] = {}
        self.enter: dict[str, cp_model.IntVar] = {}
        self.exit: dict[str, cp_model.IntVar] = {}
        self.arc: dict[tuple[str, str], cp_model.IntVar] = {}
        self.interval: dict[str, cp_model.IntervalVar] = {}

        for o in ops:
            self.start[o] = m.new_int_var(0, HORIZON, f"start_{o}")
            self.end[o] = m.new_int_var(0, HORIZON, f"end_{o}")
            self.present[o] = m.new_bool_var(f"present_{o}")
            m.add(self.end[o] == self.start[o] + DURATION[o])
            # optional interval, present iff the op runs on this machine
            self.interval[o] = m.new_optional_interval_var(
                self.start[o], DURATION[o], self.end[o], self.present[o], f"iv_{o}"
            )
            if force_present is not None and o in force_present:
                m.add(self.present[o] == int(force_present[o]))

        # --- circuit arcs ---
        arcs: list[tuple[int, int, cp_model.IntVar]] = []
        for o in ops:
            sl = m.new_bool_var(f"selfloop_{o}")
            self.self_loop[o] = sl
            # FULL biconditional: self_loop true  <=>  NOT present
            m.add(self.present[o] == sl.Not())
            if force_self_loop is not None and o in force_self_loop:
                m.add(sl == int(force_self_loop[o]))
            arcs.append((self.node[o], self.node[o], sl))  # skip self-loop

            en = m.new_bool_var(f"enter_{o}")
            ex = m.new_bool_var(f"exit_{o}")
            self.enter[o] = en
            self.exit[o] = ex
            arcs.append((DEPOT, self.node[o], en))
            arcs.append((self.node[o], DEPOT, ex))

        for i in ops:
            for j in ops:
                if i == j:
                    continue
                a = m.new_bool_var(f"arc_{i}_{j}")
                self.arc[(i, j)] = a
                arcs.append((self.node[i], self.node[j], a))
                gap = setup_minutes(i, j)
                # (c) sequencing + sequence-dependent setup gap
                m.add(self.start[j] >= self.end[i] + gap).only_enforce_if(a)

        m.add_circuit(arcs)

        # --- machine no-overlap over op intervals (+ optional cleanout) ---
        no_overlap_intervals = list(self.interval.values())

        self.cleanout_start: cp_model.IntVar | None = None
        self.cleanout_interval: cp_model.IntervalVar | None = None
        if with_cleanout_pair is not None:
            i, j = with_cleanout_pair
            cs = m.new_int_var(0, HORIZON, "cleanout_start")
            self.cleanout_start = cs
            ci = m.new_interval_var(cs, CLEANOUT_MIN, cs + CLEANOUT_MIN, "cleanout_iv")
            self.cleanout_interval = ci
            no_overlap_intervals.append(ci)
            # (d) materialized cleanout sits strictly between the two ops
            m.add(cs >= self.end[i])
            m.add(cs + CLEANOUT_MIN <= self.start[j])
            if cleanout_start is not None:
                m.add(cs == cleanout_start)
            if night_ban:
                # (f) cleanout must be fully inside a single day window [0, 960)
                m.add(cs >= DAY_START)
                m.add(cs + CLEANOUT_MIN <= DAY_END)

        m.add_no_overlap(no_overlap_intervals)

    def solve(self) -> tuple[cp_model.CpSolver, int]:
        solver = cp_model.CpSolver()
        solver.parameters.max_time_in_seconds = 10.0
        status = solver.solve(self.model)
        return solver, status


def canonical_sequence(starts: dict[str, int], present: dict[str, bool]) -> list[str]:
    """The pinned canonical machine sequence: sort present ops by (start, op_id)."""
    return sorted([o for o in starts if present[o]], key=lambda o: (starts[o], o))


# ---------------------------------------------------------------------------
# (a) optional ops get sequenced
# ---------------------------------------------------------------------------
def test_a_optional_ops_sequenced() -> None:
    b = SpikeBuild(OPS, force_present={o: True for o in OPS})
    solver, status = b.solve()
    assert status in (cp_model.OPTIMAL, cp_model.FEASIBLE)
    for o in OPS:
        assert solver.value(b.present[o]) == 1
        assert solver.value(b.self_loop[o]) == 0
    starts = {o: solver.value(b.start[o]) for o in OPS}
    assert len(set(starts.values())) == len(OPS)  # truly sequenced, distinct starts


# ---------------------------------------------------------------------------
# (b) biconditional + vacuous permissiveness
# ---------------------------------------------------------------------------
def test_b_biconditional_absent_takes_self_loop() -> None:
    b = SpikeBuild(OPS, force_present={"o0": True, "o1": False, "o2": True})
    solver, status = b.solve()
    assert status in (cp_model.OPTIMAL, cp_model.FEASIBLE)
    assert solver.value(b.present["o1"]) == 0 and solver.value(b.self_loop["o1"]) == 1
    assert solver.value(b.present["o0"]) == 1 and solver.value(b.self_loop["o0"]) == 0


def test_b_vacuous_permissiveness_is_infeasible() -> None:
    # Drop o1 from the circuit (self-loop forced true) while present forced True.
    b = SpikeBuild(
        OPS,
        force_present={"o1": True},
        force_self_loop={"o1": True},
    )
    _, status = b.solve()
    assert status == cp_model.INFEASIBLE


# ---------------------------------------------------------------------------
# (c) arc implies setup gap
# ---------------------------------------------------------------------------
def test_c_arc_setup_gap() -> None:
    # Force the Allergen(o0) -> Standard(o1) adjacency; expect a 90-min gap.
    b = SpikeBuild(OPS, force_present={"o0": True, "o1": True, "o2": False})
    b.model.add(b.arc[("o0", "o1")] == 1)
    solver, status = b.solve()
    assert status in (cp_model.OPTIMAL, cp_model.FEASIBLE)
    assert solver.value(b.start["o1"]) >= solver.value(b.end["o0"]) + CLEANOUT_MIN


# ---------------------------------------------------------------------------
# (d) materialized cleanout interval, no overlap
# ---------------------------------------------------------------------------
def test_d_cleanout_materialized_no_overlap() -> None:
    b = SpikeBuild(
        OPS,
        force_present={"o0": True, "o1": True, "o2": False},
        with_cleanout_pair=("o0", "o1"),
        cleanout_start=LEGAL_CLEANOUT_START,
        night_ban=True,
    )
    b.model.add(b.arc[("o0", "o1")] == 1)
    solver, status = b.solve()
    assert status in (cp_model.OPTIMAL, cp_model.FEASIBLE)
    cs = solver.value(b.cleanout_start)
    assert cs == LEGAL_CLEANOUT_START
    # no op overlaps the cleanout window [cs, cs+90)
    for o in ("o0", "o1"):
        s, e = solver.value(b.start[o]), solver.value(b.end[o])
        assert e <= cs or s >= cs + CLEANOUT_MIN


# ---------------------------------------------------------------------------
# (e) canonical (start, op_id) sequence == arc-chain order
# ---------------------------------------------------------------------------
def test_e_canonical_sequence_matches_arcs() -> None:
    b = SpikeBuild(OPS, force_present={o: True for o in OPS})
    solver, status = b.solve()
    assert status in (cp_model.OPTIMAL, cp_model.FEASIBLE)
    starts = {o: solver.value(b.start[o]) for o in OPS}
    present = {o: bool(solver.value(b.present[o])) for o in OPS}
    by_start = canonical_sequence(starts, present)
    # rebuild the arc chain: start at the op entered from depot, follow true arcs
    first = next(o for o in OPS if solver.value(b.enter[o]) == 1)
    chain = [first]
    while True:
        cur = chain[-1]
        nxt = [j for j in OPS if j != cur and solver.value(b.arc[(cur, j)]) == 1]
        if not nxt:
            break
        chain.append(nxt[0])
    assert by_start == chain


# ---------------------------------------------------------------------------
# (f) night ban rejects the illegal 23:30 cleanout
# ---------------------------------------------------------------------------
def test_f_night_cleanout_rejected() -> None:
    b = SpikeBuild(
        OPS,
        force_present={"o0": True, "o1": True, "o2": False},
        with_cleanout_pair=("o0", "o1"),
        cleanout_start=ILLEGAL_CLEANOUT_START,  # 23:30 -> night
        night_ban=True,
    )
    b.model.add(b.arc[("o0", "o1")] == 1)
    _, status = b.solve()
    assert status == cp_model.INFEASIBLE


def test_f_day_cleanout_allowed() -> None:
    b = SpikeBuild(
        OPS,
        force_present={"o0": True, "o1": True, "o2": False},
        with_cleanout_pair=("o0", "o1"),
        cleanout_start=LEGAL_CLEANOUT_START,  # 16:00 -> day
        night_ban=True,
    )
    b.model.add(b.arc[("o0", "o1")] == 1)
    _, status = b.solve()
    assert status in (cp_model.OPTIMAL, cp_model.FEASIBLE)
