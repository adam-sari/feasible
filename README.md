# Feasible — Constraint Intelligence Engine (multi-domain demo, v0.2)

Feasible turns messy operational rules into **formal, provenance-linked
constraints**, solves them with a real optimizer, and returns a plan that is
**testable, explainable, and auditable**. Its thesis vs LLM-only tools is
**generate + verify + certify**: the answer ships with a signed certificate a
skeptic can independently re-check offline.

```
messy inputs ─▶ formalized rules ─▶ governance ─▶ candidate plan ─▶ verified ─▶ signed certificate
 (SOP/policy +    (FC-IR)          (coverage,       (CP-SAT)      (checker+Z3)   (rule-pack + plan)
  orders/facility)                  conflict policy)
```

## One engine, two domains, one console

v0.2 generalizes the trust core into a **domain-pluggable** engine. The *trust
substrate* (canonicalization, DSSE/Ed25519 signing, two-cert binding, key + policy
pinning, the coverage/conflict ledger) is shared; the *verifier* (checker
predicates, Z3 encodings, CP-SAT compilation, objective/KPIs, coverage classifier,
conflict realizability) is supplied **per-domain** through a `DomainVerifier` seam,
resolved from a **signed `domain_id`**. Two domains ship behind one console:

| Domain | Data | Verification | The gotcha it catches |
|---|---|---|---|
| **manufacturing** | real SOP + orders (synthetic sauce co-packer, FJSP) | real | an illegal 23:30 sanitation cleanout, with the cited SOP clause |
| **datacenter** | **synthetic** facility (colo/neocloud capacity & maintenance planning) | **real** | maintenance that **spends the N+1 redundancy buffer** at a timestep |

> **Synthetic data, real verification.** The datacenter scenario's numbers are
> illustrative; the checker, Z3 mirror, CP-SAT solve, and certificate machinery are
> the *same real engine* as manufacturing. Every certificate carries a per-claim
> **trust vector** that says so honestly (the datacenter cert reports
> `data=synthetic`, `coverage=preview`).

## The live demos

**Manufacturing** (real data) — `python -m feasible.cli certify feasible/scenario/data`:

```
plan: status=OPTIMAL objective(weighted_tardiness, total_changeover)=(0, 90) checker=PASS
KPI vs incumbent B:  weighted_tardiness 0 vs 1698  ·  late_priority_orders 0 vs 2
GOTCHA — incumbent A violates R-6.1-NIGHT-CLEANOUT: "Cleanouts may only be performed during the day shift…"
Rule-Pack Cert verify: OK · Plan Cert verify: OK · two-cert digest binding: OK
```

**Datacenter** (synthetic facility, real verification) — `api.certify("datacenter")`:

```
plan: objective(stranded_power_kw, makespan)=(0, 4) checker=PASS
checked rules        : dc:maintenance_window, dc:redundancy_floor   (predicate + Z3)
structurally enforced: dc:anti_affinity, dc:power_cap               (instance-invariant guards)
GOTCHA — incumbent A violates dc:redundancy_floor: a planned maintenance outage drops fault-group G1
        to 1 available redundant path at timestep 6 (contracted N+1 floor = 2)
trust vector: signature=authenticated · checker=pass · coverage=preview · conflict=verified · data=synthetic
```

The datacenter hero rule is a **min-cardinality coverage floor** (`CoverageFloor`):
*at every timestep, available redundant paths ≥ N+1*. The gotcha is **emergent** — it
is the output of a documented degenerate-objective solve (defer maintenance), not a
hand-planted violation — and `verify` re-derives that the cited `violated_rule_ref`
is the domain's declared gotcha rule, never an arbitrary failure dressed up as the
headline.

## Architecture (the moat is the middle layer)

- **FC-IR** (`feasible/ir`) — a typed, provenance-carrying constraint IR: a
  domain-agnostic temporal/resource **kernel** (now including a min-cardinality
  `CoverageFloor` lower-bound primitive alongside the `Cumulative` upper bound) + thin
  per-domain layers. Every rule carries a deontic facet (`clause_kind`/`compile_mode`),
  an opaque conflict class, severity, trust tier, source spans, and a signed `domain_id`.
- **Domain-pluggable trust core** (`feasible/domains`) — a `DomainVerifier` protocol
  (checker predicates, Z3 encodings, CP-SAT compile, objective + objective-labels,
  KPIs, coverage classifier, conflict realizability, the gotcha id) resolved by signed
  `domain_id`. Per-domain `known_rule_ids` are asserted **disjoint** (manufacturing
  `R-*`, datacenter `dc:*`) for cross-domain isolation. `manufacturing/` and
  `datacenter/` each plug in a verifier + a data half.
- **Polynomial checker** (`feasible/checker`) — the *authoritative* verifier: a total,
  code-disjoint, closed-predicate evaluator (in P), now domain-dispatched. A
  **fail-closed rule registry** guarantees every active hard rule is
  *evaluated-or-structurally-guaranteed* (nothing silently inert); predicate-checked
  rules are reported separately from structural ones. **Z3** (`feasible/smt`)
  independently corroborates and emits UNSAT cores; a **same-engine CP-SAT tripwire**
  corroborates optimality for domains that opt in (manufacturing), and a non-FJSP
  domain opts out honestly rather than over-claiming.
- **CP-SAT compiler** (`feasible/compile` + per-domain `solve`) — manufacturing:
  optional intervals, per-machine `AddCircuit`, sequence-dependent setups, day-shift
  cleanouts, lexicographic (tardiness, changeover). Datacenter: a capacity &
  maintenance schedule minimizing (stranded power, makespan) subject to the redundancy
  floor / maintenance windows.
- **Governance** (`feasible/govern`) — the extraction-independence layer:
  coverage/omission ledger, back-translation + deontic-polarity check, the signed
  **ConflictPolicy** (Z3 rule-vs-rule detection → policy resolution), a hash-chained
  trust ledger — all threading the signed `domain_id`.
- **Two-certificate split** (`feasible/cert`) — a **Rule-Pack Certificate** (the
  constraints + the instance) + a **Plan Certificate** (a plan). The Plan Cert embeds
  the instance, the active rules, the plan **and both incumbents**, so a solver-free
  `verify` re-derives every headline claim — the objective (via the per-domain
  `verifier.objective` seam, labelled by the signed `objective_labels`), the formalization
  leaves (`checked` / `structurally_enforced` rule ids, sourced per-domain), the
  KPI-vs-baseline table, and the cited-clause gotcha — rather than trusting the signed
  numbers. `verify --rulepack` then binds the two certs across the rule-pack digest, the
  instance digest, the dropped set, and the active rule set.

Determinism is sacred: JCS canonicalization, NFC, **no floats** in any hashed
payload, hash-chained Merkle ledger.

## Web console (`web/`)

A demo console — FastAPI backend + a Vite/React/TS SPA — over the **frozen
`feasible.api` facade**. The backend is a pure transport: every route calls exactly
one facade function and serializes its frozen view-model verbatim; it never
constructs, mutates, or re-signs a certificate. Five tabs (Overview · Inputs ·
Constraint Studio · Planner · Verifier/Certificates) with a scenario selector. A
structural **console-honesty invariant** is asserted in the test suite: no checker
"pass" is ever rendered as a standalone "verified" claim without the five trust-vector
fields beside it, and the auth line is the engine's own `signer_note` rendered
**verbatim** (no hand-written trust prose). TypeScript view-model types are pinned to
the Python dataclasses by a real drift tripwire.

## Gemini extraction (`feasible/extract/`) — strictly non-gating

An LLM (`gemini-2.5-flash`) **drafts** candidate FC-IR rules from *pre-enumerated*
SOP spans — it never selects which spans exist and **never reaches a certificate
truth claim**. Drafts are echoed as verbatim quotes anchored to their originating
segment; a deterministic, LLM-free coverage ledger flags omissions; only a
human-approved golden IR is ever certified. The package imports nothing from
`feasible.cert` (enforced by an AST + call-graph guard), and runs **offline from
recorded fixtures by default** (live Gemini only with `GEMINI_API_KEY` + `--record`).

```
python -m feasible.cli extract feasible/scenario/data/shop_rules.md --out draft.json --report report.md
# → drafts gate nothing — only a human-approved golden_ir is certified.
```

## Install & run

```bash
py -3.11 -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev,web,extract]"

# the full two-cert loop (writes signer_pub.hex); manufacturing scenario
python -m feasible.cli certify feasible/scenario/data
# offline re-check + cross-cert binding, AUTHENTICATED against the published signer key:
python -m feasible.cli verify  plan_cert.json --rulepack rule_pack_cert.json --signer-key signer_pub.hex
# LLM rule-drafting (offline fixtures by default; non-gating)
python -m feasible.cli extract feasible/scenario/data/shop_rules.md

# the web console (two processes): API on :8000, SPA on :5173 (proxies /api)
python -m uvicorn web.server:app --port 8000
npm --prefix web/app install && npm --prefix web/app run dev

python -m pytest -q     # 467 tests (incl. a 17-attack cert-forgery suite over BOTH domains)
python -m mypy feasible # clean (58 source files)
```

The datacenter domain is exercised through the facade / console (`api.certify("datacenter")`)
and the web console's scenario selector.

## Trust model

The verifier authenticates the **signer**, exactly like code-signing: `verify
--signer-key` pins a published Ed25519 key and rejects any cert re-signed under a
different key, and the conflict **policy** is pinned to a published trust store (now
resolved *live*, so each domain's policy — e.g. the datacenter's N+1 safety lattice —
is admitted and a re-signed cert can't invert it). Everything a demo leans on is then
**re-derived**, not trusted: the plan is re-checked, the objective (and its
`objective_labels`), the formalization leaves, the KPI table, and the cited-clause
gotcha are recomputed from embedded data; rule quotes are re-anchored to the source;
and auto-resolution may only ever drop a soft permission — disabling a hard rule
escalates to a human. The repo ships a **17-attack cert-forgery suite**
(`tests/test_cert_forgery.py`), **parametrized over both domains**, that re-signs
tampered certs and asserts rejection (plus coverage / replay regressions for the
omission moat). Offline `verify` resolves *every* registered domain regardless of
import order (a domain-registry bootstrap), and is solver-free + LLM-free.

Each certificate exposes a per-claim **trust vector** —
`signature · checker · coverage · conflict_replay · data` — so the console can render
*exactly* what is authenticated vs self-described, real vs synthetic, complete vs
preview. The residual, stated honestly: a rule's **formalization metadata** (is this
clause a hard plan constraint?) is the signer's human-gated *attestation* — it rests
on the pinned key, not on re-derivation. (Without `--signer-key`, `verify` still
re-checks but reports the signer as **self-described / unverified**.)

## Honest ceilings (stated in every certificate's `trust_boundary`)

- Verification is **IR-relative** (the plan satisfies the *approved* IR); the
  source→IR edge is closed by the governance layer + the human gate.
- Optimality is CP-SAT-self-reported + a **same-engine** tripwire (manufacturing) —
  not independently proven by a second solver (a roadmap item).
- Coverage completeness is **relative** to the deterministic span enumeration +
  classifier, not absolute (the datacenter cert reports `coverage=preview`).
- The LLM never touches a certificate's truth claims; extraction is non-gating.
- **Datacenter scenario data is synthetic; the verification is real.** Feasible is
  complementary to (not a replacement for) Uptime commissioning / a PE seal, and does
  not model airflow/CFD or electrical-study depth — it proves the *discrete logical &
  resource* plan never drops below contracted redundancy at any step.

## Provenance

Design, plans, market validation, and the multi-agent adversarial reviews that shaped
v0.2 are under `docs/superpowers/`; the frozen facade contract is in
`docs/superpowers/specs/feasible-api-schema.md`.
