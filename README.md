# Feasible — Constraint Intelligence Engine (demo loop v1)

Feasible turns messy operational rules into **formal, provenance-linked
constraints**, solves them with a real optimizer, and returns a plan that is
**testable, explainable, and auditable**. Its thesis vs LLM-only tools is
**generate + verify + certify**: the answer ships with a signed certificate a
skeptic can independently re-check offline.

This repo is the **v1 demo loop** on an industrial-scheduling wedge (a flexible
job shop at a synthetic sauce co-packer):

```
messy inputs ─▶ formalized rules ─▶ governance ─▶ candidate plan ─▶ verified ─▶ signed certificate
 (SOP + orders)   (FC-IR)         (coverage,        (CP-SAT)      (checker+Z3)   (rule-pack + plan)
                                   conflict policy)
```

## What it does (the live demo)

```
$ feasible certify feasible/scenario/data
extraction: 8 candidate rules -> 8 approved universe -> 7 active after policy
coverage ledger: complete=True denominator=8 red=0
§5.2 back-translation correction [R-5.2]: 'whole-line lock' -> 'fill operation only'
§4.4 conflict [R-SETUP vs R-4.4]: AUTO_BY_POLICY -> SAFETY_SANITATION(100) > CUSTOMER_PRIORITY(50)
plan: status=OPTIMAL objective(wt,co)=(0, 90) checker=PASS
KPI vs incumbent B:
  weighted_tardiness : 0  vs  1698
  late_priority_ords : 0  vs  2
  total_changeover   : 90  vs  90
GOTCHA — incumbent A violates R-6.1-NIGHT-CLEANOUT: "Cleanouts may only be performed during the day shift..."
Rule-Pack Cert verify: OK
Plan Cert verify     : OK
two-cert digest binding: OK
```

The optimizer ships every order on time (weighted tardiness **0** vs the naive
baseline's **1698**, with **0 vs 2** late priority orders), catches the
incumbent's **illegal 23:30 sanitation cleanout** with the exact cited SOP
clause, and emits two signed certificates that re-verify offline.

## Architecture (the moat is the middle layer)

- **FC-IR** (`feasible/ir`) — a typed, provenance-carrying constraint IR: a
  wedge-agnostic temporal/resource **kernel** + a thin **FJSP domain layer**.
  Every rule carries a deontic facet (`clause_kind`/`compile_mode`), an opaque
  conflict class, severity, trust tier, and source spans.
- **Polynomial checker** (`feasible/checker`) — the *authoritative* verifier: a
  total, code-disjoint, closed-predicate evaluator (in P). It is the engine that
  catches the gotcha. A **fail-closed rule registry** guarantees every active hard
  rule is *evaluated-or-structurally-guaranteed* (nothing is silently inert;
  structural rules like `non_preemption` are reported separately from
  predicate-checked ones), and a **plan-shape** layer rejects malformed plans.
  **Z3** (`feasible/smt`) independently corroborates and emits UNSAT cores; a
  **same-engine CP-SAT tripwire** corroborates optimality.
- **CP-SAT compiler** (`feasible/compile`) — optional intervals + per-machine
  `AddCircuit` with the full self-loop biconditional, sequence-dependent setups,
  materialized day-shift cleanouts, maintenance blocks, staged lexicographic
  objective (priority-weighted tardiness, then changeover).
- **Governance** (`feasible/govern`) — the extraction-independence layer:
  coverage/omission ledger, back-translation + deontic-polarity check, the
  signed **ConflictPolicy** (Z3 rule-vs-rule detection → policy resolution), and
  a hash-chained trust ledger.
- **Two-certificate split** (`feasible/cert`) — a **Rule-Pack Certificate**
  (certifies the constraints) + a **Plan Certificate** (certifies a plan,
  bound to the rule pack only by an immutable digest). DSSE/Ed25519 signed,
  JCS-canonical, no floats. `feasible verify` is solver-free and self-contained.

Determinism is sacred: JCS canonicalization, NFC, no floats in any hashed
payload, hash-chained Merkle ledger.

## Install & run

```bash
py -3.11 -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"

python -m feasible.cli certify feasible/scenario/data   # the full loop
python -m feasible.cli run     feasible/scenario/data   # Build-A spine only
python -m feasible.cli verify  plan_cert.json --rulepack rule_pack_cert.json  # offline re-check + binding

python -m pytest -q     # 168 tests
python -m mypy feasible # clean
```

## Honest ceilings (stated in every certificate's `trust_boundary`)

- Verification is **IR-relative** (the plan satisfies the *approved* IR);
  the source→IR edge is closed by the governance layer + human gate.
- Optimality is CP-SAT-self-reported + a **same-engine** tripwire — not
  independently proven (a different solver is the v1.1 upgrade).
- Coverage completeness is **relative** to the deterministic span enumeration +
  classifier, not absolute.
- The LLM never touches a plan certificate's truth claims; extraction is
  non-gating (the recorded §5.2 transcript is honest about being recorded). Every
  rule is **source-grounded** — §4.4 and §5.2 are real clauses in the SOP, anchored
  to char spans a skeptic can find.

The Rule-Pack Cert certifies the full approved **universe** (incl. the policy-dropped
permission); the Plan Cert records what was **dropped by policy** and binds to the
universe digest. `verify --rulepack` re-checks both and the binding offline; the
Rule-Pack Cert's conflict resolution is **deterministically replayed** (no solver).

## Provenance

Design + research are under `docs/superpowers/` (the spec and the multi-agent
foundation exploration / adversarial reviews that shaped it).
