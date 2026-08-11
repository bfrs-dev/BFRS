"""Diagnose historical Bitcoin record-key framing at exact scanner hits."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from bfrs.core.models import RawHit
from bfrs.recovery.logical_berkeley_reader import PhysicalRangeReader
from bfrs.recovery.metadata_less_fragments import FRAMED_BITCOIN_RECORD_PATTERNS
from bfrs.validators.bitcoin_record_key import BitcoinRecordKeyValidator
from bfrs.validators.bitcoin_record_type import BitcoinRecordTypeDecoder


MAX_KEY_DIAGNOSTIC_BYTES = 256
_EXPECTED_NAME_BY_HIT_TYPE = {
    hit_type: hit_type.removeprefix("bitcoin_")
    for hit_type, _ in FRAMED_BITCOIN_RECORD_PATTERNS
}


@dataclass(frozen=True, slots=True)
class OrphanBitcoinRecordKeyLocation:
    record_type: str
    absolute_offset: int
    canonical_framing: bool
    master_key_id: int | None = None


@dataclass(frozen=True, slots=True)
class OrphanBitcoinRecordKeyDiagnostic:
    source: str
    raw_strong_hit_count: int
    valid_record_key_count: int
    valid_key_count: int
    valid_wkey_count: int
    valid_ckey_keyside_count: int
    valid_mkey_keyside_count: int
    valid_defaultkey_count: int
    valid_keymeta_count: int
    canonical_framing_count: int
    noncanonical_framing_count: int
    locations: tuple[OrphanBitcoinRecordKeyLocation, ...]
    evidence: dict[str, Any]


class OrphanBitcoinRecordKeyDiagnosticPipeline:
    """Validate only self-delimiting key-side framing; never wallet evidence."""

    def __init__(
        self,
        hits: Iterable[RawHit],
        *,
        source: str,
        range_start: int,
        range_end: int,
        range_reader: PhysicalRangeReader,
        maximum_read_size: int = MAX_KEY_DIAGNOSTIC_BYTES,
    ) -> None:
        collected = tuple(hits)
        if not source:
            raise ValueError("source must not be empty")
        if range_start < 0 or range_end < range_start:
            raise ValueError("invalid diagnostic range")
        if maximum_read_size <= 0 or maximum_read_size > MAX_KEY_DIAGNOSTIC_BYTES:
            raise ValueError("maximum_read_size must be from 1 through 256")
        if not hasattr(range_reader, "read_at"):
            raise ValueError("range_reader must provide read_at")
        if any(not isinstance(hit, RawHit) for hit in collected):
            raise ValueError("hits must contain RawHit values")
        if any(
            hit.source != source
            or not range_start <= hit.start_offset <= hit.end_offset <= range_end
            for hit in collected
        ):
            raise ValueError("hit source/range does not match diagnostic input")
        self.hits = tuple(
            sorted(
                (
                    hit
                    for hit in collected
                    if hit.hit_type in _EXPECTED_NAME_BY_HIT_TYPE
                ),
                key=lambda hit: (hit.start_offset, hit.end_offset, hit.hit_type),
            )
        )
        self.source = source
        self.range_start = range_start
        self.range_end = range_end
        self.range_reader = range_reader
        self.maximum_read_size = maximum_read_size
        self._decoder = BitcoinRecordTypeDecoder()
        self._validator = BitcoinRecordKeyValidator()

    def run(self) -> OrphanBitcoinRecordKeyDiagnostic:
        locations: dict[
            tuple[str, str, int], OrphanBitcoinRecordKeyLocation
        ] = {}
        read_failure_count = 0
        short_read_count = 0
        type_mismatch_count = 0
        for hit in self.hits:
            requested = min(
                self.maximum_read_size,
                self.range_end - hit.start_offset,
            )
            if requested <= 0:
                short_read_count += 1
                continue
            try:
                data = self.range_reader.read_at(hit.start_offset, requested)
            except OSError:
                read_failure_count += 1
                continue
            if not isinstance(data, bytes) or len(data) > requested:
                read_failure_count += 1
                continue
            if requested < self.maximum_read_size or len(data) < requested:
                short_read_count += 1
            expected_name = _EXPECTED_NAME_BY_HIT_TYPE[hit.hit_type]
            location, mismatch = self._validate_prefix(
                data, expected_name, hit.start_offset
            )
            type_mismatch_count += mismatch
            if location is not None:
                locations.setdefault(
                    (self.source, location.record_type, location.absolute_offset),
                    location,
                )

        ordered = tuple(
            sorted(
                locations.values(),
                key=lambda item: (item.absolute_offset, item.record_type),
            )
        )
        return OrphanBitcoinRecordKeyDiagnostic(
            source=self.source,
            raw_strong_hit_count=len(self.hits),
            valid_record_key_count=len(ordered),
            valid_key_count=sum(item.record_type == "key" for item in ordered),
            valid_wkey_count=sum(item.record_type == "wkey" for item in ordered),
            valid_ckey_keyside_count=sum(
                item.record_type == "ckey" for item in ordered
            ),
            valid_mkey_keyside_count=sum(
                item.record_type == "mkey" for item in ordered
            ),
            valid_defaultkey_count=sum(
                item.record_type == "defaultkey" for item in ordered
            ),
            valid_keymeta_count=sum(
                item.record_type == "keymeta" for item in ordered
            ),
            canonical_framing_count=sum(
                item.canonical_framing for item in ordered
            ),
            noncanonical_framing_count=sum(
                not item.canonical_framing for item in ordered
            ),
            locations=ordered,
            evidence={
                "maximum_read_size": self.maximum_read_size,
                "read_failure_count": read_failure_count,
                "short_read_count": short_read_count,
                "record_type_mismatch_count": type_mismatch_count,
            },
        )

    def diagnose(self) -> OrphanBitcoinRecordKeyDiagnostic:
        return self.run()

    def _validate_prefix(
        self,
        data: bytes,
        expected_name: str,
        absolute_offset: int,
    ) -> tuple[OrphanBitcoinRecordKeyLocation | None, int]:
        mismatch = 0
        for end in range(1, len(data) + 1):
            decoded = self._decoder.decode(data[:end])
            if decoded is None:
                continue
            if decoded.name != expected_name:
                mismatch = 1
                continue
            validation = self._validator.validate(decoded)
            if not validation.valid:
                continue
            master_key_id = validation.evidence.get("mkey_id")
            return (
                OrphanBitcoinRecordKeyLocation(
                    record_type=decoded.name,
                    absolute_offset=absolute_offset,
                    canonical_framing=validation.canonical_framing,
                    master_key_id=(
                        master_key_id if isinstance(master_key_id, int) else None
                    ),
                ),
                mismatch,
            )
        return None, mismatch
