"""CI tripwire for the KPI input-schema digest pin.

``INPUT_SCHEMA_DIGEST`` is computed at import from ``Instance.model_json_schema()``
+ ``Plan.model_json_schema()`` and is echoed into every plan cert's KPI version
triple. ``verify`` asserts the cert triple byte-equals the registered one — so a
Pydantic upgrade (or a schema/field change) that silently rotates the emitted JSON
schema would rotate this digest and break cert<->registry equality for ALL existing
certs. Pinning the expected value here turns that into a LOUD CI failure that a
human must consciously re-pin, rather than a silent longevity break.
"""
from __future__ import annotations

from feasible.domains.manufacturing.kpi import INPUT_SCHEMA_DIGEST, KPI_FUNCTION_VERSION

# Hardcoded expected values. If a Pydantic upgrade / Instance|Plan schema change
# trips this, that is the point: re-derive the new digest deliberately, bump
# KPI_FUNCTION_VERSION, and regenerate the affected golden — do NOT just paste the
# new digest in (existing certs would no longer verify against the new registry).
EXPECTED_INPUT_SCHEMA_DIGEST = "69ecc397abfb9379cd423155ffa0db6cafd195953f03a4a4f33bb5ac0e834f88"
EXPECTED_KPI_FUNCTION_VERSION = "v1"


def test_kpi_input_schema_digest_is_pinned():
    assert INPUT_SCHEMA_DIGEST == EXPECTED_INPUT_SCHEMA_DIGEST, (
        "KPI INPUT_SCHEMA_DIGEST changed — a Pydantic schema-emission change would "
        "break cert<->registry KPI-triple equality for existing certs. Re-pin only "
        "deliberately (bump KPI_FUNCTION_VERSION + regenerate goldens)."
    )


def test_kpi_function_version_is_pinned():
    assert KPI_FUNCTION_VERSION == EXPECTED_KPI_FUNCTION_VERSION
