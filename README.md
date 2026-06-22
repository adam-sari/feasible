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
  (certifies the constraints + the instance) + a **Plan Certificate** (certifies a
  plan). The Plan Cert embeds the instance, the active rules, the plan **and both
  incumbents**, so a solver-free `verify` re-derives every headline claim — the
  objective, the KPI-vs-baseline table, and the cited-clause gotcha — rather than
  trusting the signed numbers. `verify --rulepack` then binds the two certs across
  the rule-pack digest, the instance digest, the dropped set, and the active rule
  set (so a plan can't silently disable, weaken, or re-instance a hard rule).
  DSSE/Ed25519 signed, JCS-canonical, no floats.

Determinism is sacred: JCS canonicalization, NFC, no floats in any hashed
payload, hash-chained Merkle ledger.

## Install & run

```bash
py -3.11 -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"

python -m feasible.cli certify feasible/scenario/data   # the full loop (also writes signer_pub.hex)
python -m feasible.cli run     feasible/scenario/data   # Build-A spine only
# offline re-check + cross-cert binding, AUTHENTICATED against the published signer key:
python -m feasible.cli verify  plan_cert.json --rulepack rule_pack_cert.json --signer-key signer_pub.hex

python -m pytest -q     # 194 tests (incl. a 16-attack cert-forgery suite)
python -m mypy feasible # clean
```

## Trust model

The verifier authenticates the **signer**, exactly like code-signing: `verify
--signer-key` pins a published Ed25519 key and rejects any cert re-signed under a
different key, and the conflict **policy** is pinned to a published trust store (a
re-signed cert can't invert the safety>customer priority lattice). Everything a demo
leans on is then **re-derived**, not trusted: the plan is re-checked, the objective,
KPI table, and cited-clause gotcha are recomputed from embedded data, rule quotes are
re-anchored to the SOP, and auto-resolution may only ever drop a soft permission —
disabling a hard rule escalates to a human. The repo ships a **16-attack
cert-forgery suite** (`tests/test_cert_forgery.py`) that re-signs tampered certs and
asserts rejection (plus coverage / replay regressions for the omission moat). The residual, stated honestly: a rule's **formalization metadata**
(is this clause a hard plan constraint?) is the signer's human-gated *attestation* —
it isn't in the SOP, so it rests on the pinned key, not on re-derivation. (Without
`--signer-key`, `verify` still re-checks but reports the signer as **self-described /
unverified** — it never claims authentication it didn't perform.)

## Honest ceilings (stated in every certificate's `trust_boundary`)

- Verification is **IR-relative** (the plan satisfies the *approved* IR);
  the source→IR edge is closed by the governance layer + human gate.
- Optimality is CP-SAT-self-reported + a **same-engine** tripwire — not
  independently proven (a different solver is a post-v1.1 roadmap item).
- Coverage completeness is **relative** to the deterministic span enumeration +
  classifier, not absolute.
- The LLM never touches a plan certificate's truth claims; extraction is
  non-gating (the recorded §5.2 transcript is honest about being recorded). Every
  rule is **source-grounded** — §4.4 and §5.2 are real clauses in the SOP, anchored
  to char spans a skeptic can find.

The Rule-Pack Cert certifies the full approved **universe** (incl. the policy-dropped
permission) over a committed instance; the Plan Cert records what was **dropped by
policy** and binds to the universe digest + instance digest. `verify --rulepack`
re-checks both offline and binds them: the plan's active set must equal
*universe − auto-drops*, every shared rule body must be byte-identical, and the two
certs must commit to the same instance. The Rule-Pack Cert's conflict resolution is
**deterministically replayed** (no solver) — and each resolution is re-established to
be over a real `CONFLICT_ONLY`-permission→target pair, so a re-signed cert cannot
forge a conflict to silently drop a hard rule. (What replay does *not* re-run is the
instance-grounded Z3 detection itself — that stays a documented trust boundary; a
drop must still trace to a visible permission in the pack.)

## Provenance

Design + research are under `docs/superpowers/` (the spec and the multi-agent
foundation exploration / adversarial reviews that shaped it).
