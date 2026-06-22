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

# The published trust store: the (policy_id, digest) pairs a verifier will accept as an
# authority for conflict resolution. A re-signed cert that embeds an INVERTED policy (e.g.
# customer > safety) is rejected here at the root — the priority lattice that decides which
# rule may be dropped is pinned to a published policy, never re-derivable from cert bytes.
DEFAULT_TRUSTED_POLICIES: frozenset[tuple[str, str]] = frozenset(
    {(MANUFACTURING_POLICY.policy_id, MANUFACTURING_POLICY.digest())}
)
