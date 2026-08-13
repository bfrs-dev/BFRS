"""Recover Bitcoin evidence from one mapped logical Berkeley database."""

from dataclasses import dataclass
from typing import Any

from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_records import BerkeleyLeafRecordExtractor
from bfrs.recovery.logical_berkeley_reader import (
    LogicalBerkeleyMetadataAnchor,
    LogicalBerkeleyPageReader,
    PhysicalRangeReader,
)
from bfrs.recovery.logical_btree_membership import (
    LogicalBerkeleySubdatabaseIdentity,
    LogicalBtreeMembership,
    LogicalBtreeMembershipResolver,
)
from bfrs.recovery.logical_page_map import LogicalBerkeleyPageMap
from bfrs.recovery.legacy_wallet_candidate_assembler import (
    LegacyBitcoinWalletCandidateAssemblerV1,
)
from bfrs.recovery.logical_wallet_record_decoder import (
    LogicalBitcoinWalletRecordDecoderV1,
    LogicalWalletRecordState,
)
from bfrs.validators.bitcoin_plain_key import HistoricalPlainKeyValidator
from bfrs.validators.logical_encrypted_wallet_evidence import (
    LogicalBerkeleyRecordPageContext,
    LogicalEncryptedWalletEvidence,
    LogicalEncryptedWalletEvidenceCorrelator,
)


@dataclass(frozen=True, slots=True)
class LogicalBerkeleySubdatabaseRecovery:
    identity: LogicalBerkeleySubdatabaseIdentity
    status: ValidationStatus
    membership_status: ValidationStatus
    reachable_page_count: int
    leaf_page_count: int
    record_pair_count: int
    valid_plaintext_key_count: int
    structural_plaintext_key_count: int
    fragment_plaintext_key_count: int
    canonical_plaintext_key_count: int
    noncanonical_plaintext_key_count: int
    deleted_plaintext_key_count: int
    encrypted_wallet_evidence: LogicalEncryptedWalletEvidence
    logical_records_examined: int
    wallet_records_valid: int
    wallet_records_partial: int
    wallet_records_rejected: int
    wallet_candidate_reports: tuple[dict[str, Any], ...]
    reasons: tuple[str, ...]
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class LogicalBerkeleyDatabaseRecoveryResult:
    source: str
    logical_file_id: str
    status: ValidationStatus
    metadata_structural_count: int
    metadata_fragment_count: int
    subdatabases: tuple[LogicalBerkeleySubdatabaseRecovery, ...]
    structural_subdatabase_count: int
    fragment_subdatabase_count: int
    rejected_subdatabase_count: int
    valid_plaintext_key_count: int
    logical_records_examined: int
    wallet_records_valid: int
    wallet_records_partial: int
    wallet_records_rejected: int
    wallet_candidate_reports: tuple[dict[str, Any], ...]
    reasons: tuple[str, ...]
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _PlaintextKeyEvidence:
    page_number: int
    key_absolute_offset: int
    value_absolute_offset: int
    page_status: ValidationStatus
    canonical_framing: bool
    deleted: bool


class LogicalBerkeleyDatabaseRecoveryPipeline:
    """Orchestrate recovery through logical page and B-tree membership."""

    def __init__(
        self,
        page_map: LogicalBerkeleyPageMap,
        *,
        logical_file_id: str,
        range_reader: PhysicalRangeReader,
    ) -> None:
        self.page_reader = LogicalBerkeleyPageReader(
            page_map,
            logical_file_id=logical_file_id,
            range_reader=range_reader,
        )
        self.page_map = page_map
        self.logical_file_id = self.page_reader.identity.logical_file_id
        self._plain_validator = HistoricalPlainKeyValidator()
        self._encrypted_correlator = (
            LogicalEncryptedWalletEvidenceCorrelator()
        )
        self._wallet_decoder = LogicalBitcoinWalletRecordDecoderV1()
        self._candidate_assembler = LegacyBitcoinWalletCandidateAssemblerV1()

    def run(self) -> LogicalBerkeleyDatabaseRecoveryResult:
        metadata_pages = self.page_reader.validate_metadata_pages()
        anchors = tuple(
            sorted(
                (
                    LogicalBerkeleyMetadataAnchor(
                        identity=self.page_reader.identity,
                        metadata_page_number=page.page_number,
                        page_size=page.page_size,
                        byte_order=self.page_map.byte_order,
                        root_page=int(page.validation.evidence["root_page"]),
                        metadata_physical_offset=page.physical_offset,
                    )
                    for page in metadata_pages
                    if page.validation.status is ValidationStatus.STRUCTURAL
                ),
                key=lambda anchor: (
                    anchor.metadata_page_number,
                    anchor.root_page,
                ),
            )
        )
        subdatabases = tuple(
            self._recover_subdatabase(anchor) for anchor in anchors
        )

        structural_count = sum(
            item.status is ValidationStatus.STRUCTURAL
            for item in subdatabases
        )
        fragment_count = sum(
            item.status is ValidationStatus.FRAGMENT for item in subdatabases
        )
        rejected_count = sum(
            item.status is ValidationStatus.REJECTED for item in subdatabases
        )
        if structural_count:
            status = ValidationStatus.STRUCTURAL
            reasons: tuple[str, ...] = ()
        elif fragment_count:
            status = ValidationStatus.FRAGMENT
            reasons = ("partial_bitcoin_wallet_evidence",)
        else:
            status = ValidationStatus.REJECTED
            reasons = ("no_confirmed_bitcoin_wallet_evidence",)

        structural_metadata_pages = tuple(
            page.page_number
            for page in metadata_pages
            if page.validation.status is ValidationStatus.STRUCTURAL
        )
        fragment_metadata_pages = tuple(
            page.page_number
            for page in metadata_pages
            if page.validation.status is ValidationStatus.FRAGMENT
        )
        return LogicalBerkeleyDatabaseRecoveryResult(
            source=self.page_reader.identity.source,
            logical_file_id=self.logical_file_id,
            status=status,
            metadata_structural_count=len(structural_metadata_pages),
            metadata_fragment_count=len(fragment_metadata_pages),
            subdatabases=subdatabases,
            structural_subdatabase_count=structural_count,
            fragment_subdatabase_count=fragment_count,
            rejected_subdatabase_count=rejected_count,
            valid_plaintext_key_count=sum(
                item.valid_plaintext_key_count for item in subdatabases
            ),
            logical_records_examined=sum(
                item.logical_records_examined for item in subdatabases
            ),
            wallet_records_valid=sum(item.wallet_records_valid for item in subdatabases),
            wallet_records_partial=sum(item.wallet_records_partial for item in subdatabases),
            wallet_records_rejected=sum(item.wallet_records_rejected for item in subdatabases),
            wallet_candidate_reports=tuple(
                report
                for item in subdatabases
                for report in item.wallet_candidate_reports
            ),
            reasons=reasons,
            evidence={
                "structural_metadata_page_numbers": structural_metadata_pages,
                "fragment_metadata_page_numbers": fragment_metadata_pages,
                "subdatabase_statuses": tuple(
                    (
                        item.identity.metadata_page_number,
                        item.identity.root_page_number,
                        item.status.value,
                    )
                    for item in subdatabases
                ),
            },
        )

    def recover(self) -> LogicalBerkeleyDatabaseRecoveryResult:
        return self.run()

    def _recover_subdatabase(
        self,
        anchor: LogicalBerkeleyMetadataAnchor,
    ) -> LogicalBerkeleySubdatabaseRecovery:
        membership = LogicalBtreeMembershipResolver(
            anchor, self.page_reader
        ).resolve()
        record_contexts: list[LogicalBerkeleyRecordPageContext] = []
        plaintext: list[_PlaintextKeyEvidence] = []
        record_pair_count = 0
        leaf_read_failures: list[int] = []
        rejected_leaf_extractions: list[int] = []

        if membership.status is not ValidationStatus.REJECTED:
            for page_number in membership.leaf_page_numbers:
                location = self.page_map.locate(page_number)
                page_context = self.page_reader.read_page_context(page_number)
                if location is None or page_context is None:
                    leaf_read_failures.append(page_number)
                    continue
                extraction = BerkeleyLeafRecordExtractor(
                    page_size=membership.identity.page_size,
                    byte_order=membership.identity.byte_order,
                    expected_page_number=page_number,
                ).extract(page_context)
                if extraction.page_status is ValidationStatus.REJECTED:
                    rejected_leaf_extractions.append(page_number)
                    continue
                logical_context = LogicalBerkeleyRecordPageContext(
                    identity=membership.identity,
                    source=self.page_reader.identity.source,
                    page_number=page_number,
                    physical_offset=location.physical_offset,
                    page_size=location.page_size,
                    page_status=extraction.page_status,
                    extraction=extraction,
                )
                record_contexts.append(logical_context)
                record_pair_count += len(extraction.pairs)
                for pair in extraction.pairs:
                    validation = self._plain_validator.validate(pair)
                    if validation.valid:
                        plaintext.append(
                            _PlaintextKeyEvidence(
                                page_number=page_number,
                                key_absolute_offset=pair.key.absolute_offset,
                                value_absolute_offset=pair.value.absolute_offset,
                                page_status=extraction.page_status,
                                canonical_framing=(
                                    validation.canonical_framing
                                ),
                                deleted=pair.key.deleted or pair.value.deleted,
                            )
                        )

        ordered_plaintext = tuple(
            sorted(
                plaintext,
                key=lambda item: (
                    item.page_number,
                    item.key_absolute_offset,
                    item.value_absolute_offset,
                ),
            )
        )
        structural_plaintext_count = sum(
            membership.status is ValidationStatus.STRUCTURAL
            and item.page_status is ValidationStatus.STRUCTURAL
            for item in ordered_plaintext
        )
        fragment_plaintext_count = (
            len(ordered_plaintext) - structural_plaintext_count
        )
        encrypted = self._encrypted_correlator.correlate(
            record_contexts,
            membership=membership,
        )
        decoded_records = tuple(
            record
            for context in sorted(record_contexts, key=lambda item: item.page_number)
            for record in self._wallet_decoder.decode_context(context)
        )
        candidates = self._candidate_assembler.assemble(decoded_records)
        status, reasons = self._subdatabase_status(
            membership,
            structural_plaintext_count=structural_plaintext_count,
            fragment_plaintext_count=fragment_plaintext_count,
            encrypted=encrypted,
            record_pair_count=record_pair_count,
        )
        canonical_count = sum(
            item.canonical_framing for item in ordered_plaintext
        )
        return LogicalBerkeleySubdatabaseRecovery(
            identity=membership.identity,
            status=status,
            membership_status=membership.status,
            reachable_page_count=len(membership.reachable_page_numbers),
            leaf_page_count=len(membership.leaf_page_numbers),
            record_pair_count=record_pair_count,
            valid_plaintext_key_count=len(ordered_plaintext),
            structural_plaintext_key_count=structural_plaintext_count,
            fragment_plaintext_key_count=fragment_plaintext_count,
            canonical_plaintext_key_count=canonical_count,
            noncanonical_plaintext_key_count=(
                len(ordered_plaintext) - canonical_count
            ),
            deleted_plaintext_key_count=sum(
                item.deleted for item in ordered_plaintext
            ),
            encrypted_wallet_evidence=encrypted,
            logical_records_examined=len(decoded_records),
            wallet_records_valid=sum(
                record.state is LogicalWalletRecordState.VALID
                for record in decoded_records
            ),
            wallet_records_partial=sum(
                record.state is LogicalWalletRecordState.PARTIAL
                for record in decoded_records
            ),
            wallet_records_rejected=sum(
                record.state is LogicalWalletRecordState.REJECTED
                for record in decoded_records
            ),
            wallet_candidate_reports=tuple(
                candidate.to_report_dict() for candidate in candidates
            ),
            reasons=reasons,
            evidence={
                "plaintext_key_locations": tuple(
                    (
                        item.page_number,
                        item.key_absolute_offset,
                        item.value_absolute_offset,
                        item.page_status.value,
                        item.canonical_framing,
                        item.deleted,
                    )
                    for item in ordered_plaintext
                ),
                "membership_missing_page_numbers": (
                    membership.missing_page_numbers
                ),
                "membership_rejected_page_numbers": (
                    membership.rejected_page_numbers
                ),
                "leaf_read_failure_page_numbers": tuple(
                    sorted(leaf_read_failures)
                ),
                "rejected_leaf_extraction_page_numbers": tuple(
                    sorted(rejected_leaf_extractions)
                ),
                "berkeley_only_evidence": (
                    bool(record_pair_count)
                    and not ordered_plaintext
                    and encrypted.status is ValidationStatus.REJECTED
                ),
            },
        )

    @staticmethod
    def _subdatabase_status(
        membership: LogicalBtreeMembership,
        *,
        structural_plaintext_count: int,
        fragment_plaintext_count: int,
        encrypted: LogicalEncryptedWalletEvidence,
        record_pair_count: int,
    ) -> tuple[ValidationStatus, tuple[str, ...]]:
        if membership.status is ValidationStatus.REJECTED:
            return ValidationStatus.REJECTED, ("membership_rejected",)
        if membership.status is ValidationStatus.STRUCTURAL and (
            structural_plaintext_count
            or encrypted.status is ValidationStatus.STRUCTURAL
        ):
            return ValidationStatus.STRUCTURAL, ()
        if (
            fragment_plaintext_count
            or encrypted.status is ValidationStatus.FRAGMENT
        ):
            return ValidationStatus.FRAGMENT, (
                "partial_bitcoin_wallet_evidence",
            )
        if record_pair_count:
            return ValidationStatus.REJECTED, ("berkeley_only_evidence",)
        return ValidationStatus.REJECTED, (
            "no_confirmed_bitcoin_wallet_evidence",
        )
