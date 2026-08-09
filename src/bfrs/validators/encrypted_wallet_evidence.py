"""Correlate independently validated encrypted-wallet Berkeley records."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_records import (
    BerkeleyLeafPair,
    BerkeleyRecord,
    BerkeleyRecordExtraction,
)
from bfrs.validators.berkeley_page_locator import BerkeleyAnchor
from bfrs.validators.bitcoin_crypted_key import HistoricalCryptedKeyValidator
from bfrs.validators.bitcoin_master_key import HistoricalMasterKeyValidator


@dataclass(frozen=True, slots=True)
class BerkeleyRecordPageContext:
    source: str
    anchor: BerkeleyAnchor
    extraction: BerkeleyRecordExtraction

    def __post_init__(self) -> None:
        if not self.source:
            raise ValueError("source must not be empty")
        if self.extraction.page_number < 0:
            raise ValueError("extraction page_number must not be negative")


@dataclass(frozen=True, slots=True)
class EncryptedWalletEvidence:
    status: ValidationStatus
    source: str
    database_base_offset: int
    valid_ckey_count: int
    valid_mkey_count: int
    structural_ckey_count: int
    structural_mkey_count: int
    fragment_ckey_count: int
    fragment_mkey_count: int
    page_numbers: tuple[int, ...]
    canonical_record_count: int
    noncanonical_record_count: int
    reasons: tuple[str, ...]
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _PairCandidate:
    page_number: int
    page_status: ValidationStatus
    pair: BerkeleyLeafPair


@dataclass(frozen=True, slots=True)
class _ValidatedRecord:
    record_type: str
    page_number: int
    page_status: ValidationStatus
    pair: BerkeleyLeafPair
    canonical_framing: bool
    master_key_id: int | None = None
    derivation_method: int | None = None
    derivation_iterations: int | None = None


class EncryptedWalletEvidenceCorrelator:
    """Join structural ``ckey`` and ``mkey`` evidence from one database."""

    def __init__(self) -> None:
        self._ckey_validator = HistoricalCryptedKeyValidator()
        self._mkey_validator = HistoricalMasterKeyValidator()

    def correlate(
        self,
        contexts: Iterable[BerkeleyRecordPageContext],
    ) -> EncryptedWalletEvidence:
        context_tuple = tuple(contexts)
        if not context_tuple:
            return self._build_result(
                status=ValidationStatus.REJECTED,
                source="",
                database_base_offset=0,
                records=(),
                reasons=("no_encrypted_wallet_records",),
                duplicate_pair_count=0,
                rejected_page_numbers=(),
            )

        source = context_tuple[0].source
        selected_anchor = context_tuple[0].anchor
        database_base_offset = selected_anchor.database_base_offset
        expected_identity = self._database_identity(context_tuple[0])
        for context in context_tuple[1:]:
            if self._database_identity(context) != expected_identity:
                raise ValueError("contexts refer to different Berkeley databases")

        geometry_violations = self._geometry_violations(context_tuple)
        if geometry_violations:
            return self._build_result(
                status=ValidationStatus.REJECTED,
                source=source,
                database_base_offset=database_base_offset,
                records=(),
                reasons=("record_geometry_invalid",),
                duplicate_pair_count=0,
                rejected_page_numbers=self._rejected_pages(context_tuple),
                extra_evidence={"geometry_violations": geometry_violations},
            )

        candidates = self._active_candidates(context_tuple)
        unique_candidates, duplicate_count, duplicate_conflict = (
            self._deduplicate(candidates)
        )
        if duplicate_conflict:
            return self._build_result(
                status=ValidationStatus.REJECTED,
                source=source,
                database_base_offset=database_base_offset,
                records=(),
                reasons=("duplicate_input",),
                duplicate_pair_count=duplicate_count,
                rejected_page_numbers=self._rejected_pages(context_tuple),
            )

        records: list[_ValidatedRecord] = []
        for candidate in unique_candidates:
            ckey = self._ckey_validator.validate(candidate.pair)
            if ckey.valid:
                records.append(
                    _ValidatedRecord(
                        record_type="ckey",
                        page_number=candidate.page_number,
                        page_status=candidate.page_status,
                        pair=candidate.pair,
                        canonical_framing=ckey.canonical_framing,
                    )
                )

            mkey = self._mkey_validator.validate(candidate.pair)
            if mkey.valid:
                records.append(
                    _ValidatedRecord(
                        record_type="mkey",
                        page_number=candidate.page_number,
                        page_status=candidate.page_status,
                        pair=candidate.pair,
                        canonical_framing=mkey.canonical_framing,
                        master_key_id=mkey.master_key_id,
                        derivation_method=mkey.derivation_method,
                        derivation_iterations=mkey.derivation_iterations,
                    )
                )

        ordered_records = tuple(sorted(records, key=self._record_sort_key))
        ckey_count = sum(record.record_type == "ckey" for record in ordered_records)
        mkey_count = sum(record.record_type == "mkey" for record in ordered_records)
        structural_ckey_count = sum(
            record.record_type == "ckey"
            and record.page_status is ValidationStatus.STRUCTURAL
            for record in ordered_records
        )
        structural_mkey_count = sum(
            record.record_type == "mkey"
            and record.page_status is ValidationStatus.STRUCTURAL
            for record in ordered_records
        )

        if not ckey_count and not mkey_count:
            status = ValidationStatus.REJECTED
            reasons = ["no_encrypted_wallet_records"]
        elif structural_ckey_count and structural_mkey_count:
            status = ValidationStatus.STRUCTURAL
            reasons = []
        elif ckey_count and not mkey_count:
            status = ValidationStatus.FRAGMENT
            reasons = ["only_crypted_keys"]
        elif mkey_count and not ckey_count:
            status = ValidationStatus.FRAGMENT
            reasons = ["only_master_keys"]
        else:
            status = ValidationStatus.FRAGMENT
            reasons = ["fragment_page_evidence"]

        if duplicate_count:
            reasons.append("duplicate_input")

        return self._build_result(
            status=status,
            source=source,
            database_base_offset=database_base_offset,
            records=ordered_records,
            reasons=tuple(reasons),
            duplicate_pair_count=duplicate_count,
            rejected_page_numbers=self._rejected_pages(context_tuple),
        )

    @staticmethod
    def _database_identity(
        context: BerkeleyRecordPageContext,
    ) -> tuple[str, BerkeleyAnchor]:
        return (context.source, context.anchor)

    @staticmethod
    def _geometry_violations(
        contexts: tuple[BerkeleyRecordPageContext, ...],
    ) -> tuple[tuple[int, int], ...]:
        violations: set[tuple[int, int]] = set()
        for context in contexts:
            page_number = context.extraction.page_number
            page_start = (
                context.anchor.database_base_offset
                + page_number * context.anchor.page_size
            )
            page_end = page_start + context.anchor.page_size
            for record in _context_records(context.extraction):
                if not page_start <= record.absolute_offset < page_end:
                    violations.add((page_number, record.absolute_offset))
        return tuple(sorted(violations))

    @staticmethod
    def _active_candidates(
        contexts: tuple[BerkeleyRecordPageContext, ...],
    ) -> tuple[_PairCandidate, ...]:
        candidates = [
            _PairCandidate(
                page_number=context.extraction.page_number,
                page_status=context.extraction.page_status,
                pair=pair,
            )
            for context in contexts
            if context.extraction.page_status
            in (ValidationStatus.STRUCTURAL, ValidationStatus.FRAGMENT)
            for pair in context.extraction.pairs
        ]
        return tuple(sorted(candidates, key=_candidate_sort_key))

    @staticmethod
    def _deduplicate(
        candidates: tuple[_PairCandidate, ...],
    ) -> tuple[tuple[_PairCandidate, ...], int, bool]:
        unique: dict[tuple[int, int], _PairCandidate] = {}
        duplicate_count = 0
        duplicate_conflict = False
        for candidate in candidates:
            identity = (
                candidate.pair.key.absolute_offset,
                candidate.pair.value.absolute_offset,
            )
            existing = unique.get(identity)
            if existing is None:
                unique[identity] = candidate
                continue

            duplicate_count += 1
            if (
                existing.pair.key != candidate.pair.key
                or existing.pair.value != candidate.pair.value
            ):
                duplicate_conflict = True
                continue
            if candidate.page_status is ValidationStatus.FRAGMENT:
                unique[identity] = candidate

        return (
            tuple(sorted(unique.values(), key=_candidate_sort_key)),
            duplicate_count,
            duplicate_conflict,
        )

    @staticmethod
    def _record_sort_key(record: _ValidatedRecord) -> tuple[int, int, str]:
        return (
            record.pair.key.absolute_offset,
            record.pair.value.absolute_offset,
            record.record_type,
        )

    @staticmethod
    def _rejected_pages(
        contexts: tuple[BerkeleyRecordPageContext, ...],
    ) -> tuple[int, ...]:
        return tuple(
            sorted(
                {
                    context.extraction.page_number
                    for context in contexts
                    if context.extraction.page_status is ValidationStatus.REJECTED
                }
            )
        )

    @staticmethod
    def _build_result(
        *,
        status: ValidationStatus,
        source: str,
        database_base_offset: int,
        records: tuple[_ValidatedRecord, ...],
        reasons: tuple[str, ...],
        duplicate_pair_count: int,
        rejected_page_numbers: tuple[int, ...],
        extra_evidence: dict[str, Any] | None = None,
    ) -> EncryptedWalletEvidence:
        ckeys = tuple(record for record in records if record.record_type == "ckey")
        mkeys = tuple(record for record in records if record.record_type == "mkey")
        structural_ckeys = sum(
            record.page_status is ValidationStatus.STRUCTURAL for record in ckeys
        )
        structural_mkeys = sum(
            record.page_status is ValidationStatus.STRUCTURAL for record in mkeys
        )
        fragment_ckeys = len(ckeys) - structural_ckeys
        fragment_mkeys = len(mkeys) - structural_mkeys
        canonical_count = sum(record.canonical_framing for record in records)
        deleted_count = sum(
            record.pair.key.deleted or record.pair.value.deleted
            for record in records
        )

        ckey_locations = tuple(
            (
                record.page_number,
                record.pair.key.absolute_offset,
                record.pair.value.absolute_offset,
            )
            for record in ckeys
        )
        mkey_locations = tuple(
            (
                record.page_number,
                record.pair.key.absolute_offset,
                record.pair.value.absolute_offset,
                record.master_key_id,
            )
            for record in mkeys
        )
        evidence: dict[str, Any] = {
            "ckey_locations": ckey_locations,
            "mkey_locations": mkey_locations,
            "ckey_details": tuple(
                (
                    *location,
                    record.canonical_framing,
                    record.page_status.value,
                )
                for location, record in zip(ckey_locations, ckeys)
            ),
            "mkey_details": tuple(
                (
                    *location,
                    record.canonical_framing,
                    record.page_status.value,
                    record.derivation_method,
                    record.derivation_iterations,
                )
                for location, record in zip(mkey_locations, mkeys)
            ),
            "deleted_valid_record_count": deleted_count,
            "duplicate_pair_count": duplicate_pair_count,
            "rejected_page_numbers": rejected_page_numbers,
        }
        if extra_evidence:
            evidence.update(extra_evidence)

        return EncryptedWalletEvidence(
            status=status,
            source=source,
            database_base_offset=database_base_offset,
            valid_ckey_count=len(ckeys),
            valid_mkey_count=len(mkeys),
            structural_ckey_count=structural_ckeys,
            structural_mkey_count=structural_mkeys,
            fragment_ckey_count=fragment_ckeys,
            fragment_mkey_count=fragment_mkeys,
            page_numbers=tuple(
                sorted({record.page_number for record in records})
            ),
            canonical_record_count=canonical_count,
            noncanonical_record_count=len(records) - canonical_count,
            reasons=reasons,
            evidence=evidence,
        )


def _context_records(
    extraction: BerkeleyRecordExtraction,
) -> tuple[BerkeleyRecord, ...]:
    records: dict[int, BerkeleyRecord] = {
        record.absolute_offset: record for record in extraction.records
    }
    for pair in extraction.pairs:
        records.setdefault(pair.key.absolute_offset, pair.key)
        records.setdefault(pair.value.absolute_offset, pair.value)
    return tuple(records.values())


def _candidate_sort_key(candidate: _PairCandidate) -> tuple[int, int, int, int]:
    page_rank = (
        0 if candidate.page_status is ValidationStatus.FRAGMENT else 1
    )
    return (
        candidate.pair.key.absolute_offset,
        candidate.pair.value.absolute_offset,
        page_rank,
        candidate.page_number,
    )
