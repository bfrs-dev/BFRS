from copy import deepcopy
from io import BytesIO
from pathlib import Path

import pytest

from bfrs.core.hotspot_reader import HotspotReader
from bfrs.core.models import Hotspot, ValidationResult, ValidationStatus
from bfrs.validators.base import ValidationContext, Validator


def write_source(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "source.bin"
    path.write_bytes(data)
    return path


def make_hotspot(path: Path, start: int, end: int) -> Hotspot:
    return Hotspot(
        start_offset=start,
        end_offset=end,
        score=0.0,
        source=str(path.resolve()),
        evidence={"hit_count": 1},
    )


def test_reads_complete_small_hotspot(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"0123456789")

    context = HotspotReader(path).read(make_hotspot(path, 2, 6))

    assert context.data == b"2345"


def test_context_preserves_start_offset(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"0123456789")

    context = HotspotReader(path).read(make_hotspot(path, 3, 7))

    assert context.start_offset == 3


def test_context_has_correct_end_offset(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"0123456789")

    context = HotspotReader(path).read(make_hotspot(path, 3, 7))

    assert context.end_offset == 7


def test_reads_hotspot_starting_at_zero(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdefgh")

    assert HotspotReader(path).read(make_hotspot(path, 0, 3)).data == b"abc"


def test_reads_hotspot_ending_at_file_end(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdefgh")

    context = HotspotReader(path).read(make_hotspot(path, 5, 8))

    assert context.data == b"fgh"
    assert context.end_offset == 8


def test_reads_hotspot_from_middle(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"AAAAMIDDLEBBBB")

    assert HotspotReader(path).read(make_hotspot(path, 4, 10)).data == b"MIDDLE"


def test_reads_exact_half_open_range(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"AAAA11112222BBBB")

    data = HotspotReader(path).read(make_hotspot(path, 4, 12)).data

    assert data == b"11112222"
    assert not data.startswith(b"AAAA")
    assert not data.endswith(b"BBBB")


def test_empty_hotspot_returns_empty_context(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdefgh")

    context = HotspotReader(path).read(make_hotspot(path, 4, 4))

    assert context.data == b""
    assert context.start_offset == context.end_offset == 4


def test_negative_start_offset_is_rejected(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdefgh")

    with pytest.raises(ValueError, match="start_offset"):
        HotspotReader(path).read(make_hotspot(path, -1, 2))


def test_end_before_start_is_rejected(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdefgh")

    with pytest.raises(ValueError, match="end_offset"):
        HotspotReader(path).read(make_hotspot(path, 5, 4))


def test_end_beyond_file_size_is_rejected(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdefgh")

    with pytest.raises(ValueError, match="file size"):
        HotspotReader(path).read(make_hotspot(path, 5, 9))


def test_missing_source_raises_file_not_found(tmp_path: Path) -> None:
    path = tmp_path / "missing.bin"

    with pytest.raises(FileNotFoundError):
        HotspotReader(path).read(make_hotspot(path, 0, 0))


def test_source_mismatch_is_rejected(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdefgh")
    other = tmp_path / "other.bin"

    with pytest.raises(ValueError, match="source"):
        HotspotReader(path).read(make_hotspot(other, 0, 3))


def test_short_read_raises_os_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write_source(tmp_path, b"abcdefgh")
    monkeypatch.setattr(Path, "open", lambda self, mode: BytesIO(b"abc"))

    with pytest.raises(OSError, match="short read"):
        HotspotReader(path).read(make_hotspot(path, 0, 8))


def test_result_uses_existing_validation_context(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdefgh")

    context = HotspotReader(path).read(make_hotspot(path, 1, 3))

    assert isinstance(context, ValidationContext)
    assert context.source == str(path.resolve())


def test_reader_does_not_modify_hotspot(tmp_path: Path) -> None:
    path = write_source(tmp_path, b"abcdefgh")
    hotspot = make_hotspot(path, 1, 3)
    original_evidence = deepcopy(hotspot.evidence)

    HotspotReader(path).read(hotspot)

    assert hotspot == make_hotspot(path, 1, 3)
    assert hotspot.evidence == original_evidence


def test_context_can_be_passed_to_validator(tmp_path: Path) -> None:
    class FakeValidator:
        name = "fake"

        def validate(self, context: ValidationContext) -> ValidationResult:
            return ValidationResult(
                start_offset=context.start_offset,
                end_offset=context.end_offset,
                validator=self.name,
                status=ValidationStatus.STRUCTURAL,
                source=context.source,
                evidence={"data_matches": context.data == b"DATA"},
            )

    def validate(validator: Validator, context: ValidationContext) -> ValidationResult:
        return validator.validate(context)

    path = write_source(tmp_path, b"xxDATAyy")
    context = HotspotReader(path).read(make_hotspot(path, 2, 6))

    result = validate(FakeValidator(), context)

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence == {"data_matches": True}
