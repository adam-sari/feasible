"""The signed ConflictPolicy: the SOLE authority for legal conflict-class ids.

Integer priorities live ONLY here (never on FC-IR nodes, never in checker code),
so an organisation's risk posture is swappable and auditable. A rule's opaque
``resolution_class`` id is valid iff it is declared in ``class_priorities``;
``human_label`` is signed render-only text so the "why safety wins" explanation
stays digest-bound.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from feasible.canon.canonical import digest_of


class ClassPriority(BaseModel):
    class_id: str
    human_label: str
    priority: int


class ConflictPolicy(BaseModel):
    policy_id: str
    version: int
    class_priorities: list[ClassPriority] = Field(default_factory=list)
    tie_behavior: str = "ESCALATE_TO_HUMAN"

    def class_ids(self) -> set[str]:
        return {c.class_id for c in self.class_priorities}

    def priority(self, class_id: str) -> int | None:
        return next((c.priority for c in self.class_priorities if c.class_id == class_id), None)

    def label(self, class_id: str) -> str | None:
        return next((c.human_label for c in self.class_priorities if c.class_id == class_id), None)

    def digest(self) -> str:
        return digest_of(self.model_dump(mode="json"))


# The manufacturing-wedge fixture policy (shipped as data, not a kernel enum).
MANUFACTURING_POLICY = ConflictPolicy(
    policy_id="manufacturing_v1",
    version=1,
    class_priorities=[
        ClassPriority(class_id="SAFETY_SANITATION", human_label="Safety / sanitation / allergen control", priority=100),
        ClassPriority(class_id="HARD_AVAILABILITY_MAINTENANCE", human_label="Machine maintenance / hard availability", priority=90),
        ClassPriority(class_id="LEGAL_LABOR", human_label="Legal / labor constraint", priority=90),
        ClassPriority(class_id="CUSTOMER_PRIORITY", human_label="Customer priority acceleration", priority=50),
        ClassPriority(class_id="DUE_DATE_PREFERENCE", human_label="Due-date preference", priority=30),
        ClassPriority(class_id="EFFICIENCY", human_label="Efficiency objective", priority=10),
    ],
)

# The datacenter capacity & maintenance-planning policy (Track B, Task 8).
#
# CRITICAL (B-3): the N+1/2N redundancy floor's ``resolution_class`` is LITERALLY
# ``SAFETY_SANITATION`` — NOT a bespoke ``REDUNDANCY`` class. The frozen
# ``no_permission_outranks_safety`` guard keys ONLY on ``SAFETY_CLASS_ID ==
# "SAFETY_SANITATION"`` (it checks ``all(c.priority <= policy.priority(
# "SAFETY_SANITATION"))``). A bespoke ``REDUNDANCY`` class would satisfy that guard
# VACUOUSLY (the guard never inspects it), so a policy demoting redundancy below an
# acceleration class would be SILENTLY ADMITTED into ``trusted_policy_set()``. By
# making the N+1/2N floor THE ``SAFETY_SANITATION`` class (its ``human_label`` names
# it "Redundancy / N+1 / 2N safety floor"), the guard's ``<=`` actually protects
# redundancy. No acceleration/efficiency class outranks it (50, 10 < 100), so
# ``no_permission_outranks_safety(DATACENTER_POLICY) is True``.
DATACENTER_POLICY = ConflictPolicy(
    policy_id="datacenter_v1",
    version=1,
    class_priorities=[
        ClassPriority(class_id="SAFETY_SANITATION", human_label="Redundancy / N+1 / 2N safety floor", priority=100),
        ClassPriority(class_id="HARD_AVAILABILITY_MAINTENANCE", human_label="Hard maintenance availability", priority=90),
        ClassPriority(class_id="ACCELERATION", human_label="Commissioning acceleration", priority=50),
        ClassPriority(class_id="EFFICIENCY", human_label="Stranded-power efficiency", priority=10),
    ],
)

# The class id whose priority every other class must NOT strictly exceed: the safety /
# sanitation obligation that the "safety wins / permission dropped" invariant protects.
SAFETY_CLASS_ID = "SAFETY_SANITATION"


def no_permission_outranks_safety(policy: ConflictPolicy) -> bool:
    """The per-domain conflict-policy guard (design §1.6): under ``policy`` NO class
    may strictly outrank the safety class, so a safety obligation can never be the
    AUTO-dropped side of a conflict — a clash a permission would win must ESCALATE.

    Returns ``True`` iff the policy is safe to trust. A policy missing the safety
    class entirely fails the guard (fail-closed: a domain whose policy cannot even
    name its safety obligation must not be auto-trusted)."""
    safety = policy.priority(SAFETY_CLASS_ID)
    if safety is None:
        return False
    return all(c.priority <= safety for c in policy.class_priorities)


def trusted_policy_set() -> frozenset[tuple[str, str]]:
    """The published trust store, assembled from the policies of the REGISTERED
    domains (design §1.6) — not a hand-written global frozenset. A re-signed cert
    that embeds an INVERTED policy (e.g. customer > safety) is rejected at the root:
    the priority lattice that decides which rule may be dropped is pinned to a
    published, registered-domain policy, never re-derivable from cert bytes.

    Adding a domain policy is therefore a reviewed, tested act — the
    ``no_permission_outranks_safety`` guard (asserted in the domain-registry tests)
    keeps every entry safety-preserving. Only policies that pass the guard are
    admitted, so a domain cannot widen the trust store with an inverted policy."""
    from feasible.domains import _DOMAINS, bootstrap_domains

    # Bootstrap the explicit registered-domain package import-list so the trust
    # store resolves EVERY domain's policy in a fresh process regardless of import
    # order (manufacturing now; the datacenter track appends its package). Idempotent.
    bootstrap_domains()

    pairs: set[tuple[str, str]] = set()
    for _domain_id, (domain, _verifier) in _DOMAINS.items():
        policy = domain.policy()
        if policy is None:
            continue
        if not no_permission_outranks_safety(policy):
            continue  # fail-closed: never admit a safety-inverting policy
        pairs.add((policy.policy_id, policy.digest()))
    return frozenset(pairs)


# Backwards-compatible alias: the published trust store as a value (computed from the
# registered domains at import time). Callers may pass it as ``trusted_policies=`` or
# omit the argument to let ``verify_rulepack_cert`` resolve ``trusted_policy_set()``.
DEFAULT_TRUSTED_POLICIES: frozenset[tuple[str, str]] = trusted_policy_set()
