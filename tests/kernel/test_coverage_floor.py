from __future__ import annotations
from feasible.checker.coverage_floor import coverage_floor_violations

def _avail(seq):  # available count per timestep 0..len-1
    return {t: n for t, n in enumerate(seq)}

def test_floor_held_every_timestep_no_violation():
    assert coverage_floor_violations(_avail([2, 2, 2]), floor=2, group_id="feeds", horizon=3) == []

def test_below_floor_at_one_timestep_flagged_with_witness():
    vs = coverage_floor_violations(_avail([2, 1, 2]), floor=2, group_id="feeds", horizon=3)
    assert len(vs) == 1
    assert vs[0].witness_kind == "coverage_floor"
    assert vs[0].counter_witness == {"group_id": "feeds", "timestep": 1, "available": 1, "floor": 2}

def test_average_ok_but_one_timestep_below_is_caught():
    # avg = 2.0 but t=1 dips to 1 -> must be caught (floor is per-timestep, not average)
    assert len(coverage_floor_violations(_avail([3, 1, 2]), floor=2, group_id="f", horizon=3)) == 1

def test_missing_timestep_treated_as_zero_available_failclosed():
    # off-by-one / omitted timestep must not pass silently: horizon=3 but only t=0,1 supplied
    vs = coverage_floor_violations(_avail([2, 2]), floor=2, group_id="f", horizon=3)
    assert any(v.counter_witness["timestep"] == 2 for v in vs)  # t=2 missing -> available 0 -> violation

def test_z3_mirror_unsat_when_below_floor():
    import z3
    from feasible.checker.coverage_floor import coverage_floor_z3
    s = z3.Solver()
    avail = {t: z3.Int(f"a{t}") for t in range(3)}
    s.add(avail[0] == 2, avail[1] == 1, avail[2] == 2)
    s.add(z3.And(coverage_floor_z3(avail, floor=2, horizon=3)))
    assert s.check() == z3.unsat
