"""Orchestrate recovery of Bitcoin evidence from one Berkeley DB byte context."""

from dataclasses import dataclass, replace
from typing import Any

from bfrs.core.models import ValidationResult, ValidationStatus
from bfrs.recovery.berkeley_records import BerkeleyLeafRecordExtractor
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_metadata import (
    BTREE_MAGIC,
    MAGIC_OFFSET,
    MAX_PAGE_SIZE,
    MIN_METADATA_SIZE,
    BerkeleyMetadataValidator,
    is_valid_page_size,
)
from bfrs.validators.berkeley_page import BTREE_LEAF
from bfrs.validators.berkeley_page_locator import BerkeleyAnchor, BerkeleyPageLocator
from bfrs.validators.bitcoin_plain_key import HistoricalPlainKeyValidator
from bfrs.validators.encrypted_wallet_aggregator import (
    EncryptedWalletAggregation,
    EncryptedWalletEvidenceAggregator,
)
from bfrs.validators.encrypted_wallet_evidence import BerkeleyRecordPageContext


@dataclass(frozen=True, slots=True)
class BerkeleyDatabaseRecoverySummary:
    metadata_structural_count: int
    metadata_fragment_count: int
    anchor_count: int
    page_structural_count: int
    page_fragment_count: int
    page_rejected_count: int
    leaf_page_count: int
    record_pair_count: int
    valid_plaintext_key_count: int
    structural_plaintext_key_count: int
    fragment_plaintext_key_count: int
    canonical_plaintext_key_count: int
    noncanonical_plaintext_key_count: int
    encrypted_database_count: int
    encrypted_structural_database_count: int
    encrypted_fragment_database_count: int


@dataclass(frozen=True, slots=True)
class BerkeleyRecoveredRecordPage:
    source: str
    anchor: BerkeleyAnchor
    page_number: int
    page_status: ValidationStatus
    page_start_offset: int
    complete_record_count: int
    record_pair_count: int
    deleted_record_count: int
    incomplete_slot_count: int
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BerkeleyDatabaseRecoveryResult:
    source: str
    status: ValidationStatus
    anchors: tuple[BerkeleyAnchor, ...]
    page_results: tuple[ValidationResult, ...]
    record_pages: tuple[BerkeleyRecoveredRecordPage, ...]
    plaintext_key_count: int
    encrypted_wallet_evidence: EncryptedWalletAggregation
    summary: BerkeleyDatabaseRecoverySummary
    reasons: tuple[str, ...]
    evidence: dict[str, Any]


class BerkeleyDatabaseRecoveryPipeline:
    """Recover already-buffered Berkeley DB and Bitcoin wallet evidence."""

    def run(self, context: ValidationContext) -> BerkeleyDatabaseRecoveryResult:
        metadata_results = self._metadata_results(context)
        anchors = tuple(
            sorted(
                {
                    self._anchor(result)
                    for result in metadata_results
                    if result.status is ValidationStatus.STRUCTURAL
                },
                key=self._anchor_sort_key,
            )
        )

        located: list[tuple[BerkeleyAnchor, ValidationResult]] = []
        for anchor in anchors:
            located.extend(
                (anchor, result)
                for result in BerkeleyPageLocator(anchor).locate(context)
            )
        located.sort(
            key=lambda item: (
                item[1].start_offset,
                *self._anchor_sort_key(item[0]),
            )
        )
        page_results = tuple(result for _, result in located)

        record_contexts: list[BerkeleyRecordPageContext] = []
        record_pages: list[BerkeleyRecoveredRecordPage] = []
        plain_locations: list[tuple[int, int, str, bool]] = []
        leaf_page_count = 0
        record_pair_count = 0
        plain_validator = HistoricalPlainKeyValidator()
        for anchor, page_result in located:
            if page_result.evidence.get("page_type") != BTREE_LEAF:
                continue
            leaf_page_count += 1
            page_context = self._page_context(context, page_result, anchor.page_size)
            page_number = (
                page_result.start_offset - anchor.database_base_offset
            ) // anchor.page_size
            extraction = BerkeleyLeafRecordExtractor(
                anchor.page_size,
                anchor.byte_order,
                expected_page_number=page_number,
            ).extract(page_context)
            if extraction.page_number != page_number:
                extraction = replace(extraction, page_number=page_number)
            record_page = BerkeleyRecordPageContext(context.source, anchor, extraction)
            record_contexts.append(record_page)
            record_pages.append(
                BerkeleyRecoveredRecordPage(
                    source=context.source,
                    anchor=anchor,
                    page_number=page_number,
                    page_status=extraction.page_status,
                    page_start_offset=page_result.start_offset,
                    complete_record_count=extraction.complete_record_count,
                    record_pair_count=len(extraction.pairs),
                    deleted_record_count=extraction.deleted_record_count,
                    incomplete_slot_count=extraction.incomplete_slot_count,
                    reasons=extraction.reasons,
                )
            )
            record_pair_count += len(extraction.pairs)
            if extraction.page_status is ValidationStatus.REJECTED:
                continue
            for pair in extraction.pairs:
                validation = plain_validator.validate(pair)
                if validation.valid:
                    plain_locations.append(
                        (
                            pair.key.absolute_offset,
                            pair.value.absolute_offset,
                            extraction.page_status.value,
                            validation.canonical_framing,
                        )
                    )

        encrypted = EncryptedWalletEvidenceAggregator().aggregate(record_contexts)
        structural_plain = sum(
            status == ValidationStatus.STRUCTURAL.value
            for _, _, status, _ in plain_locations
        )
        fragment_plain = sum(
            status == ValidationStatus.FRAGMENT.value
            for _, _, status, _ in plain_locations
        )
        canonical_plain = sum(item[3] for item in plain_locations)
        summary = BerkeleyDatabaseRecoverySummary(
            metadata_structural_count=sum(r.status is ValidationStatus.STRUCTURAL for r in metadata_results),
            metadata_fragment_count=sum(r.status is ValidationStatus.FRAGMENT for r in metadata_results),
            anchor_count=len(anchors),
            page_structural_count=sum(r.status is ValidationStatus.STRUCTURAL for r in page_results),
            page_fragment_count=sum(r.status is ValidationStatus.FRAGMENT for r in page_results),
            page_rejected_count=sum(r.status is ValidationStatus.REJECTED for r in page_results),
            leaf_page_count=leaf_page_count,
            record_pair_count=record_pair_count,
            valid_plaintext_key_count=len(plain_locations),
            structural_plaintext_key_count=structural_plain,
            fragment_plaintext_key_count=fragment_plain,
            canonical_plaintext_key_count=canonical_plain,
            noncanonical_plaintext_key_count=len(plain_locations) - canonical_plain,
            encrypted_database_count=encrypted.database_count,
            encrypted_structural_database_count=encrypted.structural_database_count,
            encrypted_fragment_database_count=encrypted.fragment_database_count,
        )
        if structural_plain or encrypted.structural_database_count:
            status = ValidationStatus.STRUCTURAL
            reasons: tuple[str, ...] = ()
        elif fragment_plain or encrypted.fragment_database_count:
            status = ValidationStatus.FRAGMENT
            reasons = ("partial_bitcoin_wallet_evidence",)
        else:
            status = ValidationStatus.REJECTED
            reasons = (
                ("berkeley_only_evidence",)
                if record_pair_count
                else ("no_confirmed_bitcoin_wallet_evidence",)
            )

        evidence: dict[str, Any] = {
            "mathematically_valid_plaintext_key_count": len(plain_locations),
            "structural_plaintext_key_count": structural_plain,
            "fragment_plaintext_key_count": fragment_plain,
            "berkeley_only_evidence": (
                bool(record_pair_count)
                and not plain_locations
                and not encrypted.fragment_database_count
                and not encrypted.structural_database_count
            ),
            "plaintext_key_locations": tuple(sorted(plain_locations)),
            "metadata_results": tuple(
                (r.start_offset, r.status.value, tuple(r.evidence.get("reasons", ())))
                for r in metadata_results
            ),
        }
        return BerkeleyDatabaseRecoveryResult(
            source=context.source,
            status=status,
            anchors=anchors,
            page_results=page_results,
            record_pages=tuple(record_pages),
            plaintext_key_count=len(plain_locations),
            encrypted_wallet_evidence=encrypted,
            summary=summary,
            reasons=reasons,
            evidence=evidence,
        )

    def recover(self, context: ValidationContext) -> BerkeleyDatabaseRecoveryResult:
        return self.run(context)

    @staticmethod
    def _metadata_results(context: ValidationContext) -> tuple[ValidationResult, ...]:
        candidates: set[tuple[int, str]] = set()
        for byte_order in ("little", "big"):
            pattern = BTREE_MAGIC.to_bytes(4, byte_order)
            position = context.data.find(pattern)
            while position != -1:
                start = position - MAGIC_OFFSET
                if start >= 0:
                    candidates.add((start, byte_order))
                position = context.data.find(pattern, position + 1)

        results: list[ValidationResult] = []
        for local_start, byte_order in sorted(candidates):
            prefix = context.data[local_start:]
            page_size = int.from_bytes(prefix[20:24], byte_order) if len(prefix) >= 24 else 0
            length = page_size if is_valid_page_size(page_size) else MIN_METADATA_SIZE
            length = min(length, MAX_PAGE_SIZE, len(prefix))
            candidate_context = ValidationContext(
                context.source,
                context.start_offset + local_start,
                bytes(prefix[:length]),
            )
            result = BerkeleyMetadataValidator().validate(candidate_context)
            if result.start_offset == candidate_context.start_offset:
                results.append(result)
        return tuple(sorted(results, key=lambda r: (r.start_offset, r.status.value)))

    @staticmethod
    def _anchor(result: ValidationResult) -> BerkeleyAnchor:
        evidence = result.evidence
        return BerkeleyAnchor(
            metadata_absolute_offset=result.start_offset,
            metadata_page_number=int(evidence["page_number"]),
            page_size=int(evidence["page_size"]),
            byte_order=str(evidence["byte_order"]),
        )

    @staticmethod
    def _page_context(
        context: ValidationContext,
        result: ValidationResult,
        page_size: int,
    ) -> ValidationContext:
        local_start = result.start_offset - context.start_offset
        if local_start < 0 or local_start >= len(context.data):
            raise RuntimeError("located page lies outside validation context")
        expected_length = min(page_size, context.end_offset - result.start_offset)
        page = context.data[local_start : local_start + expected_length]
        if len(page) != expected_length:
            raise RuntimeError("located page slice is incomplete")
        return ValidationContext(context.source, result.start_offset, bytes(page))

    @staticmethod
    def _anchor_sort_key(anchor: BerkeleyAnchor) -> tuple[int, int, int, str]:
        return (
            anchor.metadata_absolute_offset,
            anchor.metadata_page_number,
            anchor.page_size,
            anchor.byte_order,
        )
