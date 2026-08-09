from bfrs.core.models import (
    Hotspot,
    RawHit,
    ScanRange,
    ValidationResult,
    ValidationStatus,
)


def test_create_scan_range() -> None:
    scan_range = ScanRange(start_offset=0, end_offset=4096, source="disk.img")

    assert scan_range.start_offset == 0
    assert scan_range.end_offset == 4096
    assert scan_range.source == "disk.img"


def test_create_raw_hit() -> None:
    hit = RawHit(
        start_offset=128,
        end_offset=160,
        hit_type="candidate",
        confidence=0.75,
        source="disk.img",
        evidence={"signature": "example"},
    )

    assert hit.hit_type == "candidate"
    assert hit.confidence == 0.75
    assert hit.evidence == {"signature": "example"}


def test_create_hotspot() -> None:
    hotspot = Hotspot(
        start_offset=1024,
        end_offset=2048,
        score=0.9,
        source="disk.img",
        evidence={"raw_hit_count": 3},
    )

    assert hotspot.start_offset == 1024
    assert hotspot.end_offset == 2048
    assert hotspot.score == 0.9


def test_create_validation_result() -> None:
    result = ValidationResult(
        start_offset=128,
        end_offset=160,
        validator="test_validator",
        status=ValidationStatus.STRUCTURAL,
        source="disk.img",
        evidence={"check": "passed"},
    )

    assert result.validator == "test_validator"
    assert result.status is ValidationStatus.STRUCTURAL
    assert result.source == "disk.img"
