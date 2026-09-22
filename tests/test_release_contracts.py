"""Release-critical public and persistence version pins."""

from bfrs.recovery.unified_scan_checkpoint import (
    UNIFIED_CHECKPOINT_FORMAT_VERSION,
    UNIFIED_SCANNER_SEMANTICS_VERSION,
)
from bfrs.reporting.json_report import REPORT_SCHEMA_VERSION


def test_p1_release_contract_versions_are_pinned() -> None:
    assert UNIFIED_SCANNER_SEMANTICS_VERSION == 2
    assert UNIFIED_CHECKPOINT_FORMAT_VERSION == 3
    assert REPORT_SCHEMA_VERSION == 5
