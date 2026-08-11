"""Recover validated Bitcoin record fragments without Berkeley metadata."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from bfrs.core.models import RawHit, ValidationStatus
from bfrs.recovery.berkeley_records import (
    BerkeleyLeafPair,
    BerkeleyLeafRecordExtractor,
    BerkeleyRecordExtraction,
)
from bfrs.recovery.logical_berkeley_reader import PhysicalRangeReader
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_metadata import MAX_PAGE_SIZE, MIN_PAGE_SIZE
from bfrs.validators.berkeley_page import BTREE_LEAF, BerkeleyPageValidator
from bfrs.validators.bitcoin_crypted_key import HistoricalCryptedKeyValidator
from bfrs.validators.bitcoin_master_key import HistoricalMasterKeyValidator
from bfrs.validators.bitcoin_plain_key import HistoricalPlainKeyValidator
from bfrs.validators.bitcoin_record_type import BitcoinRecordTypeDecoder


FRAMED_BITCOIN_RECORD_PATTERNS: tuple[tuple[str, bytes], ...] = (
    ("bitcoin_key", b"\x03key"),
    ("bitcoin_wkey", b"\x04wkey"),
    ("bitcoin_defaultkey", b"\x0adefaultkey"),
    ("bitcoin_ckey", b"\x04ckey"),
    ("bitcoin_mkey", b"\x04mkey"),
    ("bitcoin_keymeta", b"\x07keymeta"),
)
_PATTERN_BY_HIT_TYPE = dict(FRAMED_BITCOIN_RECORD_PATTERNS)
_RECORD_NAME_BY_HIT_TYPE = {
    hit_type: hit_type.removeprefix("bitcoin_")
    for hit_type in _PATTERN_BY_HIT_TYPE
}
_PAGE_SIZES = tuple(
    1 << exponent
    for exponent in range(MIN_PAGE_SIZE.bit_length() - 1, MAX_PAGE_SIZE.bit_length())
)
_LEAF_HEADER_MARKER = bytes((1, BTREE_LEAF))


@dataclass(frozen=True, slots=True)
class MetadataLessPageLocation:
    physical_offset: int
    page_number: int
    page_size: int
    byte_order: str
    validation_status: ValidationStatus


@dataclass(frozen=True, slots=True)
class MetadataLessRecordLocation:
    record_type: str
    physical_page_offset: int
    page_number: int
    page_size: int
    byte_order: str
    page_status: ValidationStatus
    key_offset: int
    value_offset: int
    discovery_hit_offset: int


@dataclass(frozen=True, slots=True)
class MetadataLessBerkeleyFragmentRecovery:
    status: ValidationStatus
    source: str
    candidate_page_count: int
    structural_leaf_count: int
    fragment_leaf_count: int
    record_pair_count: int
    valid_plaintext_key_count: int
    valid_ckey_count: int
    valid_mkey_count: int
    recognized_wkey_count: int
    recognized_defaultkey_count: int
    recognized_keymeta_count: int
    page_locations: tuple[MetadataLessPageLocation, ...]
    record_locations: tuple[MetadataLessRecordLocation, ...]
    reasons: tuple[str, ...]
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _RecoveredPage:
    location: MetadataLessPageLocation
    extraction: BerkeleyRecordExtraction


class MetadataLessBerkeleyFragmentRecoveryPipeline:
    """Use strong scanner hits as bounded seeds for strict leaf validation."""

    def __init__(
        self,
        hits: Iterable[RawHit],
        *,
        source: str,
        range_start: int,
        range_end: int,
        range_reader: PhysicalRangeReader,
    ) -> None:
        collected = tuple(hits)
        if not source:
            raise ValueError("source must not be empty")
        if range_start < 0 or range_end < range_start:
            raise ValueError("invalid recovery range")
        if not hasattr(range_reader, "read_at"):
            raise ValueError("range_reader must provide read_at")
        if any(not isinstance(hit, RawHit) for hit in collected):
            raise ValueError("hits must contain RawHit values")
        if any(
            hit.source != source
            or not range_start <= hit.start_offset <= hit.end_offset <= range_end
            for hit in collected
        ):
            raise ValueError("hit source/range does not match recovery input")
        self.hits = tuple(
            sorted(
                (hit for hit in collected if hit.hit_type in _PATTERN_BY_HIT_TYPE),
                key=lambda hit: (hit.start_offset, hit.end_offset, hit.hit_type),
            )
        )
        self.source = source
        self.range_start = range_start
        self.range_end = range_end
        self.range_reader = range_reader
        self._plain = HistoricalPlainKeyValidator()
        self._ckey = HistoricalCryptedKeyValidator()
        self._mkey = HistoricalMasterKeyValidator()
        self._decoder = BitcoinRecordTypeDecoder()

    def run(self) -> MetadataLessBerkeleyFragmentRecovery:
        tested_starts: set[int] = set()
        attempts: dict[tuple[int, int, str], _RecoveredPage | None] = {}
        pages: dict[tuple[int, int, str, int], _RecoveredPage] = {}
        pair_identities: set[tuple[int, int, int]] = set()
        validated_records: dict[
            tuple[str, int, int, int], MetadataLessRecordLocation
        ] = {}
        recognized_records: dict[
            tuple[str, int, int, int], MetadataLessRecordLocation
        ] = {}

        for hit in self.hits:
            for page_start in self._candidate_starts(hit):
                tested_starts.add(page_start)
                for page_size in _PAGE_SIZES:
                    if hit.end_offset > page_start + page_size:
                        continue
                    for byte_order in ("little", "big"):
                        attempt_key = (page_start, page_size, byte_order)
                        if attempt_key not in attempts:
                            attempts[attempt_key] = self._recover_page(
                                page_start, page_size, byte_order
                            )
                        recovered = attempts[attempt_key]
                        if recovered is None:
                            continue
                        location = recovered.location
                        page_identity = (
                            location.physical_offset,
                            location.page_size,
                            location.byte_order,
                            location.page_number,
                        )
                        pages.setdefault(page_identity, recovered)
                        for pair in recovered.extraction.pairs:
                            if not self._hit_belongs_to_pair(hit, pair):
                                continue
                            decoded = self._decoder.decode_pair(pair)
                            expected_name = _RECORD_NAME_BY_HIT_TYPE[hit.hit_type]
                            if decoded is None or decoded.name != expected_name:
                                continue
                            pair_identities.add(
                                (
                                    location.physical_offset,
                                    pair.key.absolute_offset,
                                    pair.value.absolute_offset,
                                )
                            )
                            record_location = MetadataLessRecordLocation(
                                record_type=decoded.name,
                                physical_page_offset=location.physical_offset,
                                page_number=location.page_number,
                                page_size=location.page_size,
                                byte_order=location.byte_order,
                                page_status=location.validation_status,
                                key_offset=pair.key.absolute_offset,
                                value_offset=pair.value.absolute_offset,
                                discovery_hit_offset=hit.start_offset,
                            )
                            record_identity = (
                                decoded.name,
                                location.physical_offset,
                                pair.key.absolute_offset,
                                pair.value.absolute_offset,
                            )
                            if decoded.name in ("wkey", "defaultkey", "keymeta"):
                                recognized_records.setdefault(
                                    record_identity, record_location
                                )
                            elif self._historically_valid(decoded.name, pair):
                                validated_records.setdefault(
                                    record_identity, record_location
                                )

        page_locations = tuple(
            sorted(
                (page.location for page in pages.values()),
                key=lambda item: (
                    item.physical_offset,
                    item.page_size,
                    item.byte_order,
                    item.page_number,
                ),
            )
        )
        record_locations = tuple(
            sorted(
                (*validated_records.values(), *recognized_records.values()),
                key=lambda item: (
                    item.key_offset,
                    item.value_offset,
                    item.record_type,
                    item.physical_page_offset,
                ),
            )
        )
        valid_plain = sum(item.record_type == "key" for item in validated_records.values())
        valid_ckey = sum(item.record_type == "ckey" for item in validated_records.values())
        valid_mkey = sum(item.record_type == "mkey" for item in validated_records.values())
        valid_count = valid_plain + valid_ckey + valid_mkey
        physical_page_offsets = {
            item.physical_offset for item in page_locations
        }
        structural_offsets = {
            item.physical_offset
            for item in page_locations
            if item.validation_status is ValidationStatus.STRUCTURAL
        }
        fragment_only_offsets = {
            item.physical_offset
            for item in page_locations
            if item.validation_status is ValidationStatus.FRAGMENT
        } - structural_offsets
        status = ValidationStatus.FRAGMENT if valid_count else ValidationStatus.REJECTED
        reasons = (
            ("metadata_less_bitcoin_evidence",)
            if valid_count
            else ("no_valid_metadata_less_bitcoin_evidence",)
        )
        return MetadataLessBerkeleyFragmentRecovery(
            status=status,
            source=self.source,
            candidate_page_count=len(physical_page_offsets),
            structural_leaf_count=len(structural_offsets),
            fragment_leaf_count=len(fragment_only_offsets),
            record_pair_count=len(pair_identities),
            valid_plaintext_key_count=valid_plain,
            valid_ckey_count=valid_ckey,
            valid_mkey_count=valid_mkey,
            recognized_wkey_count=sum(
                item.record_type == "wkey" for item in recognized_records.values()
            ),
            recognized_defaultkey_count=sum(
                item.record_type == "defaultkey"
                for item in recognized_records.values()
            ),
            recognized_keymeta_count=sum(
                item.record_type == "keymeta"
                for item in recognized_records.values()
            ),
            page_locations=page_locations,
            record_locations=record_locations,
            reasons=reasons,
            evidence={
                "candidate_page_starts_tested": len(tested_starts),
                "candidate_geometry_count": len(page_locations),
                "page_validation_attempt_count": len(attempts),
                "page_validator_structural_count": sum(
                    page is not None
                    and page.location.validation_status
                    is ValidationStatus.STRUCTURAL
                    for page in attempts.values()
                ),
                "page_validator_fragment_count": sum(
                    page is not None
                    and page.location.validation_status is ValidationStatus.FRAGMENT
                    for page in attempts.values()
                ),
                "strong_hit_count": len(self.hits),
            },
        )

    def recover(self) -> MetadataLessBerkeleyFragmentRecovery:
        return self.run()

    def _candidate_starts(self, hit: RawHit) -> tuple[int, ...]:
        window_start = max(self.range_start, hit.start_offset - MAX_PAGE_SIZE + 1)
        window_end = min(self.range_end, hit.end_offset)
        if window_end <= window_start:
            return ()
        try:
            read_before = getattr(self.range_reader, "read_before", None)
            if callable(read_before):
                window_start, data = read_before(
                    window_end,
                    window_end - window_start,
                    self.range_start,
                )
            else:
                data = self.range_reader.read_at(
                    window_start, window_end - window_start
                )
        except OSError:
            return ()
        if not isinstance(data, bytes) or len(data) > window_end - window_start:
            return ()
        starts: set[int] = set()
        position = data.find(_LEAF_HEADER_MARKER)
        while position != -1:
            candidate = window_start + position - 24
            if self.range_start <= candidate <= hit.start_offset:
                starts.add(candidate)
            position = data.find(_LEAF_HEADER_MARKER, position + 1)
        return tuple(sorted(starts))

    def _recover_page(
        self, page_start: int, page_size: int, byte_order: str
    ) -> _RecoveredPage | None:
        if not self.range_start <= page_start < self.range_end:
            return None
        requested = min(page_size, self.range_end - page_start)
        try:
            data = self.range_reader.read_at(page_start, requested)
        except OSError:
            return None
        if not isinstance(data, bytes) or len(data) > requested:
            return None
        context = ValidationContext(self.source, page_start, data)
        validation = BerkeleyPageValidator(
            page_size=page_size,
            byte_order=byte_order,
            expected_page_number=None,
        ).validate(context)
        if (
            validation.status is ValidationStatus.REJECTED
            or validation.evidence.get("page_type") != BTREE_LEAF
        ):
            return None
        try:
            extraction = BerkeleyLeafRecordExtractor(
                page_size=page_size,
                byte_order=byte_order,
                expected_page_number=None,
            ).extract(context)
        except RuntimeError as error:
            if str(error) != "BerkeleyPageValidator and record extractor disagree":
                raise
            return None
        if extraction.page_status is ValidationStatus.REJECTED:
            return None
        return _RecoveredPage(
            MetadataLessPageLocation(
                physical_offset=page_start,
                page_number=extraction.page_number,
                page_size=page_size,
                byte_order=byte_order,
                validation_status=extraction.page_status,
            ),
            extraction,
        )

    @staticmethod
    def _hit_belongs_to_pair(hit: RawHit, pair: BerkeleyLeafPair) -> bool:
        payload_start = pair.key.absolute_offset + 3
        payload_end = payload_start + len(pair.key.payload)
        pattern = _PATTERN_BY_HIT_TYPE[hit.hit_type]
        if not payload_start <= hit.start_offset <= hit.end_offset <= payload_end:
            return False
        local = hit.start_offset - payload_start
        return pair.key.payload[local : local + len(pattern)] == pattern

    def _historically_valid(self, name: str, pair: BerkeleyLeafPair) -> bool:
        if name == "key":
            return self._plain.validate(pair).valid
        if name == "ckey":
            return self._ckey.validate(pair).valid
        if name == "mkey":
            return self._mkey.validate(pair).valid
        return False
