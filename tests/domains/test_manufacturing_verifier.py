from feasible.checker.checker import check
from feasible.scenario import build_scenario_ir
from feasible.solve.orchestrate import solve

def test_manufacturing_check_unchanged_after_seam():
    ir = build_scenario_ir()
    plan = solve(ir, workers=1, seed=1).plan
    res = check(plan, ir)
    assert res.passed is True   # the optimal plan still passes via the domain-dispatched checker
