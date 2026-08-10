"""Correlate encrypted-wallet records through logical Berkeley membership."""

from collections.abc import Iterable
from dataclasses import dataclass
import ntpath
from typing import Any

from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_records import (
    BerkeleyLeafPair,
    BerkeleyRecord,
    BerkeleyRecordExtraction,
)
from bfrs.recovery.logical_btree_membership import (
    LogicalBerkeleySubdatabaseIdentity,
    LogicalBtreeMembership,
)
from bfrs.validators.berkeley_page import (
    KEYDATA,
    OVERFLOW_RECORD,
    OVERFLOW_REFERENCE_SIZE,
    RECORD_HEADER_SIZE,
)
from bfrs.validators.bitcoin_crypted_key import HistoricalCryptedKeyValidator
from bfrs.validators.bitcoin_master_key import HistoricalMasterKeyValidator


@dataclass(frozen=True, slots=True)
class LogicalBerkeleyRecordPageContext:
    """One extracted leaf page at its independently mapped physical location."""

    identity: LogicalBerkeleySubdatabaseIdentity
    source: str
    page_number: int
    physical_offset: int
    page_size: int
    page_status: ValidationStatus
    extraction: BerkeleyRecordExtraction

    def __post_init__(self) -> None:
        if not self.source:
            raise ValueError("source must not be empty")
        normalized_source = ntpath.normcase(ntpath.normpath(self.source))
        object.__setattr__(self, "source", normalized_source)
        if normalized_source != self.identity.database.source:
            raise ValueError("source must match logical database identity")
        if self.page_number < 0:
            raise ValueError("page_number must not be negative")
        if self.physical_offset < 0:
            raise ValueError("physical_offset must not be negative")
        if self.page_size != self.identity.page_size:
            raise ValueError("page_size must match subdatabase identity")
        if self.extraction.page_number != self.page_number:
            raise ValueError("extraction page_number must match context")
        if self.extraction.page_status is not self.page_status:
            raise ValueError("extraction page_status must match context")
        records = set(self.extraction.records)
        for record in self.extraction.records:
            self._validate_record_geometry(record)
        for pair in self.extraction.pairs:
            if pair.key not in records or pair.value not in records:
                raise ValueError(
                    "pair records must belong to extraction.records"
                )

    def _validate_record_geometry(self, record: BerkeleyRecord) -> None:
        if not 0 <= record.local_offset < self.page_size:
            raise ValueError("record local_offset is outside page bounds")
        expected_absolute = self.physical_offset + record.local_offset
        if record.absolute_offset != expected_absolute:
            raise ValueError(
                "record absolute_offset does not match physical and local offsets"
            )
        page_end = self.physical_offset + self.page_size
        if not self.physical_offset <= record.absolute_offset < page_end:
            raise ValueError("record absolute_offset is outside page bounds")
        if record.length < 0:
            raise ValueError("record length must not be negative")
        if record.record_type == KEYDATA:
            body_size = record.length
            if len(record.payload) != body_size:
                raise ValueError("key/data record payload length is inconsistent")
        elif record.record_type == OVERFLOW_RECORD:
            body_size = OVERFLOW_REFERENCE_SIZE
            if len(record.payload) != body_size:
                raise ValueError("overflow record payload length is inconsistent")
        else:
            raise ValueError("record type is not supported by leaf extraction")
        if record.local_offset + RECORD_HEADER_SIZE + body_size > self.page_size:
            raise ValueError("complete record extends beyond page bounds")


@dataclass(frozen=True, slots=True)
class LogicalEncryptedWalletEvidence:
    """Safe, immutable summary of logical encrypted-wallet evidence."""

    status: ValidationStatus
    identity: LogicalBerkeleySubdatabaseIdentity
    membership_status: ValidationStatus
    valid_ckey_count: int
    valid_mkey_count: int
    structural_ckey_count: int
    structural_mkey_count: int
    fragment_ckey_count: int
    fragment_mkey_count: int
    canonical_record_count: int
    noncanonical_record_count: int
    page_numbers: tuple[int, ...]
    deleted_valid_record_count: int
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


class LogicalEncryptedWalletEvidenceCorrelator:
    """Join ``ckey`` and ``mkey`` evidence from one logical B-tree."""

    def __init__(self) -> None:
        self._ckey_validator = HistoricalCryptedKeyValidator()
        self._mkey_validator = HistoricalMasterKeyValidator()

    def correlate(
        self,
        contexts: Iterable[LogicalBerkeleyRecordPageContext],
        *,
        membership: LogicalBtreeMembership,
    ) -> LogicalEncryptedWalletEvidence:
        context_tuple = tuple(contexts)
        self._validate_context_identities(context_tuple, membership)
        self._validate_leaf_membership(context_tuple, membership)
        self._validate_duplicate_page_contexts(context_tuple)

        input_contradictions = self._input_contradictions(
            context_tuple, membership
        )
        if input_contradictions:
            return self._build_result(
                membership=membership,
                status=ValidationStatus.REJECTED,
                records=(),
                reasons=("input_contradiction",),
                duplicate_pair_count=0,
                extra_evidence={
                    "input_contradictions": input_contradictions,
                },
            )

        geometry_violations = self._geometry_violations(context_tuple)
        if geometry_violations:
            return self._build_result(
                membership=membership,
                status=ValidationStatus.REJECTED,
                records=(),
                reasons=("record_geometry_invalid",),
                duplicate_pair_count=0,
                extra_evidence={"geometry_violations": geometry_violations},
            )

        candidates = self._active_candidates(context_tuple)
        unique_candidates, duplicate_count = self._deduplicate(candidates)
        records = self._validate_candidates(unique_candidates)

        ckeys = tuple(record for record in records if record.record_type == "ckey")
        mkeys = tuple(record for record in records if record.record_type == "mkey")
        structural_ckeys = tuple(
            record
            for record in ckeys
            if record.page_status is ValidationStatus.STRUCTURAL
        )
        structural_mkeys = tuple(
            record
            for record in mkeys
            if record.page_status is ValidationStatus.STRUCTURAL
        )

        reasons: list[str] = []
        if membership.status is ValidationStatus.REJECTED:
            status = ValidationStatus.REJECTED
            reasons.append("membership_rejected")
        elif not ckeys and not mkeys:
            status = ValidationStatus.REJECTED
            reasons.append("no_encrypted_wallet_records")
        elif (
            membership.status is ValidationStatus.STRUCTURAL
            and structural_ckeys
            and structural_mkeys
        ):
            status = ValidationStatus.STRUCTURAL
        else:
            status = ValidationStatus.FRAGMENT
            if membership.status is ValidationStatus.FRAGMENT:
                reasons.append("membership_fragment")
            if ckeys and not mkeys:
                reasons.append("only_crypted_keys")
            elif mkeys and not ckeys:
                reasons.append("only_master_keys")
            elif ckeys and mkeys:
                reasons.append("fragment_page_evidence")
        if duplicate_count:
            reasons.append("duplicate_input")

        return self._build_result(
            membership=membership,
            status=status,
            records=records,
            reasons=tuple(reasons),
            duplicate_pair_count=duplicate_count,
        )

    @staticmethod
    def _validate_context_identities(
        contexts: tuple[LogicalBerkeleyRecordPageContext, ...],
        membership: LogicalBtreeMembership,
    ) -> None:
        for context in contexts:
            if context.identity != membership.identity:
                raise ValueError(
                    "contexts and membership refer to different logical "
                    "Berkeley subdatabases"
                )

    @staticmethod
    def _validate_leaf_membership(
        contexts: tuple[LogicalBerkeleyRecordPageContext, ...],
        membership: LogicalBtreeMembership,
    ) -> None:
        leaves = set(membership.leaf_page_numbers)
        orphan_pages = sorted(
            {context.page_number for context in contexts if context.page_number not in leaves}
        )
        if orphan_pages:
            raise ValueError(
                "record context page is not a reachable membership leaf: "
                + ", ".join(str(page) for page in orphan_pages)
            )

    @staticmethod
    def _validate_duplicate_page_contexts(
        contexts: tuple[LogicalBerkeleyRecordPageContext, ...],
    ) -> None:
        pages: dict[int, LogicalBerkeleyRecordPageContext] = {}
        for context in contexts:
            existing = pages.setdefault(context.page_number, context)
            if existing != context:
                raise ValueError("conflicting duplicate logical page context")

    @staticmethod
    def _input_contradictions(
        contexts: tuple[LogicalBerkeleyRecordPageContext, ...],
        membership: LogicalBtreeMembership,
    ) -> tuple[str, ...]:
        contradictions: set[str] = set()
        if membership.root_page_number != membership.identity.root_page_number:
            contradictions.add("membership_root_mismatch")
        if not set(membership.leaf_page_numbers).issubset(
            membership.reachable_page_numbers
        ):
            contradictions.add("membership_leaf_not_reachable")
        if set(membership.leaf_page_numbers).intersection(
            membership.rejected_page_numbers
        ):
            contradictions.add("membership_leaf_rejected")
        if membership.status is ValidationStatus.STRUCTURAL and (
            membership.missing_page_numbers or membership.rejected_page_numbers
        ):
            contradictions.add("structural_membership_has_gaps")
        if any(
            context.page_status is ValidationStatus.REJECTED
            for context in contexts
        ):
            contradictions.add("reachable_leaf_extraction_rejected")
        for context in contexts:
            extraction_records: dict[tuple[int, int], BerkeleyRecord] = {}
            for record in context.extraction.records:
                record_identity = (record.absolute_offset, record.slot_index)
                existing = extraction_records.setdefault(record_identity, record)
                if existing != record:
                    contradictions.add("conflicting_extraction_record")
            for pair in context.extraction.pairs:
                for record in (pair.key, pair.value):
                    extraction_record = extraction_records.get(
                        (record.absolute_offset, record.slot_index)
                    )
                    if extraction_record is not None and extraction_record != record:
                        contradictions.add("pair_extraction_record_mismatch")
        return tuple(sorted(contradictions))

    @staticmethod
    def _geometry_violations(
        contexts: tuple[LogicalBerkeleyRecordPageContext, ...],
    ) -> tuple[tuple[int, int], ...]:
        violations: set[tuple[int, int]] = set()
        for context in contexts:
            page_end = context.physical_offset + context.page_size
            for record in _context_records(context.extraction):
                if not context.physical_offset <= record.absolute_offset < page_end:
                    violations.add((context.page_number, record.absolute_offset))
        return tuple(sorted(violations))

    @staticmethod
    def _active_candidates(
        contexts: tuple[LogicalBerkeleyRecordPageContext, ...],
    ) -> tuple[_PairCandidate, ...]:
        return tuple(
            _PairCandidate(context.page_number, context.page_status, pair)
            for context in contexts
            if context.page_status
            in (ValidationStatus.STRUCTURAL, ValidationStatus.FRAGMENT)
            for pair in context.extraction.pairs
        )

    @staticmethod
    def _deduplicate(
        candidates: tuple[_PairCandidate, ...],
    ) -> tuple[tuple[_PairCandidate, ...], int]:
        unique: dict[tuple[int, int, int], _PairCandidate] = {}
        duplicate_count = 0
        for candidate in candidates:
            identity = (
                candidate.page_number,
                candidate.pair.key.absolute_offset,
                candidate.pair.value.absolute_offset,
            )
            existing = unique.get(identity)
            if existing is None:
                unique[identity] = candidate
            elif existing == candidate:
                duplicate_count += 1
            else:
                raise ValueError("conflicting payload or extraction for pair identity")
        return (
            tuple(sorted(unique.values(), key=_candidate_sort_key)),
            duplicate_count,
        )

    def _validate_candidates(
        self,
        candidates: tuple[_PairCandidate, ...],
    ) -> tuple[_ValidatedRecord, ...]:
        records: list[_ValidatedRecord] = []
        for candidate in candidates:
            ckey = self._ckey_validator.validate(candidate.pair)
            if ckey.valid:
                records.append(
                    _ValidatedRecord(
                        "ckey",
                        candidate.page_number,
                        candidate.page_status,
                        candidate.pair,
                        ckey.canonical_framing,
                    )
                )
            mkey = self._mkey_validator.validate(candidate.pair)
            if mkey.valid:
                records.append(
                    _ValidatedRecord(
                        "mkey",
                        candidate.page_number,
                        candidate.page_status,
                        candidate.pair,
                        mkey.canonical_framing,
                        mkey.master_key_id,
                    )
                )
        return tuple(sorted(records, key=_record_sort_key))

    @staticmethod
    def _build_result(
        *,
        membership: LogicalBtreeMembership,
        status: ValidationStatus,
        records: tuple[_ValidatedRecord, ...],
        reasons: tuple[str, ...],
        duplicate_pair_count: int,
        extra_evidence: dict[str, Any] | None = None,
    ) -> LogicalEncryptedWalletEvidence:
        ckeys = tuple(record for record in records if record.record_type == "ckey")
        mkeys = tuple(record for record in records if record.record_type == "mkey")
        structural_ckeys = sum(
            record.page_status is ValidationStatus.STRUCTURAL for record in ckeys
        )
        structural_mkeys = sum(
            record.page_status is ValidationStatus.STRUCTURAL for record in mkeys
        )
        canonical_count = sum(record.canonical_framing for record in records)
        deleted_count = sum(
            record.pair.key.deleted or record.pair.value.deleted for record in records
        )
        evidence: dict[str, Any] = {
            "ckey_locations": tuple(
                (
                    record.page_number,
                    record.pair.key.absolute_offset,
                    record.pair.value.absolute_offset,
                )
                for record in ckeys
            ),
            "mkey_locations": tuple(
                (
                    record.page_number,
                    record.pair.key.absolute_offset,
                    record.pair.value.absolute_offset,
                    record.master_key_id,
                )
                for record in mkeys
            ),
            "duplicate_pair_count": duplicate_pair_count,
        }
        if extra_evidence:
            evidence.update(extra_evidence)
        return LogicalEncryptedWalletEvidence(
            status=status,
            identity=membership.identity,
            membership_status=membership.status,
            valid_ckey_count=len(ckeys),
            valid_mkey_count=len(mkeys),
            structural_ckey_count=structural_ckeys,
            structural_mkey_count=structural_mkeys,
            fragment_ckey_count=len(ckeys) - structural_ckeys,
            fragment_mkey_count=len(mkeys) - structural_mkeys,
            canonical_record_count=canonical_count,
            noncanonical_record_count=len(records) - canonical_count,
            page_numbers=tuple(sorted({record.page_number for record in records})),
            deleted_valid_record_count=deleted_count,
            reasons=reasons,
            evidence=evidence,
        )


def _context_records(
    extraction: BerkeleyRecordExtraction,
) -> tuple[BerkeleyRecord, ...]:
    records: dict[tuple[int, int], BerkeleyRecord] = {
        (record.absolute_offset, record.slot_index): record
        for record in extraction.records
    }
    for pair in extraction.pairs:
        records.setdefault((pair.key.absolute_offset, pair.key.slot_index), pair.key)
        records.setdefault(
            (pair.value.absolute_offset, pair.value.slot_index), pair.value
        )
    return tuple(records.values())


def _candidate_sort_key(candidate: _PairCandidate) -> tuple[int, int, int]:
    return (
        candidate.page_number,
        candidate.pair.key.absolute_offset,
        candidate.pair.value.absolute_offset,
    )


def _record_sort_key(record: _ValidatedRecord) -> tuple[int, int, int, str]:
    return (
        record.page_number,
        record.pair.key.absolute_offset,
        record.pair.value.absolute_offset,
        record.record_type,
    )
