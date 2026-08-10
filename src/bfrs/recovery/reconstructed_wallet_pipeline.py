"""Recover Bitcoin evidence from one reconstructed Berkeley B-tree."""

from dataclasses import dataclass
import ntpath
from typing import Any

from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_records import (
    BerkeleyLeafPair,
    BerkeleyLeafRecordExtractor,
    BerkeleyRecord,
    BerkeleyRecordExtraction,
)
from bfrs.recovery.fragmented_berkeley_reassembler import (
    ReconstructedBerkeleyDatabase,
    ReconstructedBerkeleyDatabaseIdentity,
    ReconstructedBerkeleyPage,
)
from bfrs.recovery.logical_berkeley_reader import PhysicalRangeReader
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_page import (
    BTREE_LEAF,
    KEYDATA,
    OVERFLOW_RECORD,
    OVERFLOW_REFERENCE_SIZE,
    RECORD_HEADER_SIZE,
)
from bfrs.validators.bitcoin_crypted_key import HistoricalCryptedKeyValidator
from bfrs.validators.bitcoin_master_key import HistoricalMasterKeyValidator
from bfrs.validators.bitcoin_plain_key import HistoricalPlainKeyValidator


@dataclass(frozen=True, slots=True)
class ReconstructedBerkeleyRecordPageContext:
    identity: ReconstructedBerkeleyDatabaseIdentity
    source: str
    page_number: int
    physical_offset: int
    page_size: int
    page_status: ValidationStatus
    extraction: BerkeleyRecordExtraction

    def __post_init__(self) -> None:
        normalized_source = ntpath.normcase(ntpath.normpath(self.source))
        object.__setattr__(self, "source", normalized_source)
        if not self.source or normalized_source != self.identity.source:
            raise ValueError("source must match reconstructed database identity")
        if self.page_number < 0:
            raise ValueError("page_number must not be negative")
        if self.physical_offset < 0:
            raise ValueError("physical_offset must not be negative")
        if self.page_size != self.identity.page_size:
            raise ValueError("page_size must match reconstructed database identity")
        if self.extraction.page_number != self.page_number:
            raise ValueError("extraction page_number must match context")
        if self.extraction.page_status is not self.page_status:
            raise ValueError("extraction page_status must match context")
        records = set(self.extraction.records)
        for record in self.extraction.records:
            self._validate_record(record)
        for pair in self.extraction.pairs:
            if pair.key not in records or pair.value not in records:
                raise ValueError(
                    "pair records must belong to extraction.records"
                )

    def _validate_record(self, record: BerkeleyRecord) -> None:
        if not 0 <= record.local_offset < self.page_size:
            raise ValueError("record local_offset is outside page bounds")
        if record.absolute_offset != self.physical_offset + record.local_offset:
            raise ValueError(
                "record absolute_offset does not match physical and local offsets"
            )
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
class ReconstructedBerkeleyWalletRecovery:
    identity: ReconstructedBerkeleyDatabaseIdentity
    database_status: ValidationStatus
    status: ValidationStatus
    selected_leaf_count: int
    record_pair_count: int
    valid_plaintext_key_count: int
    structural_plaintext_key_count: int
    fragment_plaintext_key_count: int
    valid_ckey_count: int
    valid_mkey_count: int
    structural_ckey_count: int
    structural_mkey_count: int
    fragment_ckey_count: int
    fragment_mkey_count: int
    page_numbers: tuple[int, ...]
    deleted_valid_record_count: int
    reasons: tuple[str, ...]
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _ValidatedWalletRecord:
    record_type: str
    page_number: int
    page_status: ValidationStatus
    pair: BerkeleyLeafPair
    canonical_framing: bool
    master_key_id: int | None = None


class ReconstructedBerkeleyWalletPipeline:
    """Analyze only selected reachable leaves from one reconstructed tree."""

    def __init__(
        self,
        database: ReconstructedBerkeleyDatabase,
        *,
        range_reader: PhysicalRangeReader,
    ) -> None:
        if not isinstance(database, ReconstructedBerkeleyDatabase):
            raise ValueError("database must be ReconstructedBerkeleyDatabase")
        if not hasattr(range_reader, "read_at"):
            raise ValueError("range_reader must provide read_at")
        self.database = database
        self.range_reader = range_reader
        self._plain_validator = HistoricalPlainKeyValidator()
        self._ckey_validator = HistoricalCryptedKeyValidator()
        self._mkey_validator = HistoricalMasterKeyValidator()

    def run(self) -> ReconstructedBerkeleyWalletRecovery:
        if self.database.status is ValidationStatus.REJECTED:
            return self._build_result(
                status=ValidationStatus.REJECTED,
                selected_leaf_count=len(self.database.leaf_page_numbers),
                record_pair_count=0,
                records=(),
                reasons=("reconstructed_database_rejected",),
                read_failures=(),
                rejected_extractions=(),
            )

        selected_leaves = self._selected_leaf_pages()
        records: list[_ValidatedWalletRecord] = []
        record_pair_count = 0
        read_failures: list[int] = []
        rejected_extractions: list[int] = []
        for page in selected_leaves:
            data = self._read_page(page)
            if data is None:
                read_failures.append(page.page_number)
                continue
            extraction = BerkeleyLeafRecordExtractor(
                page_size=self.database.identity.page_size,
                byte_order=self.database.identity.byte_order,
                expected_page_number=page.page_number,
            ).extract(
                ValidationContext(
                    source=self.database.identity.source,
                    start_offset=page.physical_offset,
                    data=data,
                )
            )
            if extraction.page_status is ValidationStatus.REJECTED:
                rejected_extractions.append(page.page_number)
                continue
            context = ReconstructedBerkeleyRecordPageContext(
                identity=self.database.identity,
                source=self.database.identity.source,
                page_number=page.page_number,
                physical_offset=page.physical_offset,
                page_size=page.page_size,
                page_status=extraction.page_status,
                extraction=extraction,
            )
            effective_status = (
                ValidationStatus.STRUCTURAL
                if page.validation_status is ValidationStatus.STRUCTURAL
                and context.page_status is ValidationStatus.STRUCTURAL
                else ValidationStatus.FRAGMENT
            )
            record_pair_count += len(context.extraction.pairs)
            records.extend(
                self._validate_pairs(
                    page.page_number,
                    effective_status,
                    context.extraction.pairs,
                )
            )

        ordered_records = tuple(sorted(records, key=self._record_sort_key))
        structural_plaintext = self._structural_count(
            ordered_records, "plaintext"
        )
        structural_ckeys = self._structural_count(ordered_records, "ckey")
        structural_mkeys = self._structural_count(ordered_records, "mkey")
        if self.database.status is ValidationStatus.STRUCTURAL and (
            structural_plaintext or (structural_ckeys and structural_mkeys)
        ):
            status = ValidationStatus.STRUCTURAL
            reasons: tuple[str, ...] = ()
        elif ordered_records:
            status = ValidationStatus.FRAGMENT
            reasons = ("partial_bitcoin_wallet_evidence",)
        elif record_pair_count:
            status = ValidationStatus.REJECTED
            reasons = ("berkeley_only_evidence",)
        else:
            status = ValidationStatus.REJECTED
            reasons = ("no_confirmed_bitcoin_wallet_evidence",)

        return self._build_result(
            status=status,
            selected_leaf_count=len(selected_leaves),
            record_pair_count=record_pair_count,
            records=ordered_records,
            reasons=reasons,
            read_failures=tuple(sorted(read_failures)),
            rejected_extractions=tuple(sorted(rejected_extractions)),
        )

    def recover(self) -> ReconstructedBerkeleyWalletRecovery:
        return self.run()

    def _selected_leaf_pages(self) -> tuple[ReconstructedBerkeleyPage, ...]:
        selected: dict[int, ReconstructedBerkeleyPage] = {}
        for page in self.database.selected_pages:
            existing = selected.setdefault(page.page_number, page)
            if existing != page:
                raise ValueError("conflicting selected page number")
        forbidden = (
            set(self.database.missing_page_numbers)
            | set(self.database.ambiguous_page_numbers)
            | set(self.database.rejected_page_numbers)
        )
        if set(self.database.leaf_page_numbers).intersection(forbidden):
            raise ValueError("selected leaf conflicts with reconstruction status")

        leaves: list[ReconstructedBerkeleyPage] = []
        for page_number in self.database.leaf_page_numbers:
            page = selected.get(page_number)
            if page is None:
                raise ValueError("leaf_page_numbers must refer to selected pages")
            if page.page_number != page_number:
                raise ValueError("selected leaf page number mismatch")
            if page.page_type != BTREE_LEAF or page.level != 1:
                raise ValueError("selected leaf has incompatible type or level")
            if page.page_size != self.database.identity.page_size:
                raise ValueError("selected leaf page_size differs from identity")
            if page.physical_offset < 0:
                raise ValueError("selected leaf physical_offset must not be negative")
            if page.validation_status is ValidationStatus.REJECTED:
                raise ValueError("rejected selected leaf is an input contradiction")
            leaves.append(page)
        return tuple(sorted(leaves, key=lambda page: page.page_number))

    def _read_page(self, page: ReconstructedBerkeleyPage) -> bytes | None:
        try:
            data = self.range_reader.read_at(
                page.physical_offset,
                self.database.identity.page_size,
            )
        except OSError:
            return None
        if not isinstance(data, bytes) or len(data) > self.database.identity.page_size:
            return None
        return data

    def _validate_pairs(
        self,
        page_number: int,
        page_status: ValidationStatus,
        pairs: tuple[BerkeleyLeafPair, ...],
    ) -> tuple[_ValidatedWalletRecord, ...]:
        records: list[_ValidatedWalletRecord] = []
        for pair in pairs:
            plain = self._plain_validator.validate(pair)
            if plain.valid:
                records.append(
                    _ValidatedWalletRecord(
                        "plaintext",
                        page_number,
                        page_status,
                        pair,
                        plain.canonical_framing,
                    )
                )
            ckey = self._ckey_validator.validate(pair)
            if ckey.valid:
                records.append(
                    _ValidatedWalletRecord(
                        "ckey",
                        page_number,
                        page_status,
                        pair,
                        ckey.canonical_framing,
                    )
                )
            mkey = self._mkey_validator.validate(pair)
            if mkey.valid:
                records.append(
                    _ValidatedWalletRecord(
                        "mkey",
                        page_number,
                        page_status,
                        pair,
                        mkey.canonical_framing,
                        mkey.master_key_id,
                    )
                )
        return tuple(records)

    def _structural_count(
        self,
        records: tuple[_ValidatedWalletRecord, ...],
        record_type: str,
    ) -> int:
        if self.database.status is not ValidationStatus.STRUCTURAL:
            return 0
        return sum(
            record.record_type == record_type
            and record.page_status is ValidationStatus.STRUCTURAL
            for record in records
        )

    def _build_result(
        self,
        *,
        status: ValidationStatus,
        selected_leaf_count: int,
        record_pair_count: int,
        records: tuple[_ValidatedWalletRecord, ...],
        reasons: tuple[str, ...],
        read_failures: tuple[int, ...],
        rejected_extractions: tuple[int, ...],
    ) -> ReconstructedBerkeleyWalletRecovery:
        plaintext = tuple(r for r in records if r.record_type == "plaintext")
        ckeys = tuple(r for r in records if r.record_type == "ckey")
        mkeys = tuple(r for r in records if r.record_type == "mkey")
        structural_plaintext = self._structural_count(records, "plaintext")
        structural_ckeys = self._structural_count(records, "ckey")
        structural_mkeys = self._structural_count(records, "mkey")
        canonical_count = sum(record.canonical_framing for record in records)
        deleted_count = sum(
            record.pair.key.deleted or record.pair.value.deleted
            for record in records
        )
        return ReconstructedBerkeleyWalletRecovery(
            identity=self.database.identity,
            database_status=self.database.status,
            status=status,
            selected_leaf_count=selected_leaf_count,
            record_pair_count=record_pair_count,
            valid_plaintext_key_count=len(plaintext),
            structural_plaintext_key_count=structural_plaintext,
            fragment_plaintext_key_count=len(plaintext) - structural_plaintext,
            valid_ckey_count=len(ckeys),
            valid_mkey_count=len(mkeys),
            structural_ckey_count=structural_ckeys,
            structural_mkey_count=structural_mkeys,
            fragment_ckey_count=len(ckeys) - structural_ckeys,
            fragment_mkey_count=len(mkeys) - structural_mkeys,
            page_numbers=tuple(sorted({record.page_number for record in records})),
            deleted_valid_record_count=deleted_count,
            reasons=reasons,
            evidence={
                "plaintext_key_locations": tuple(
                    (
                        record.page_number,
                        record.pair.key.absolute_offset,
                        record.pair.value.absolute_offset,
                    )
                    for record in plaintext
                ),
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
                "canonical_valid_record_count": canonical_count,
                "noncanonical_valid_record_count": len(records) - canonical_count,
                "read_failure_page_numbers": read_failures,
                "rejected_extraction_page_numbers": rejected_extractions,
            },
        )

    @staticmethod
    def _record_sort_key(
        record: _ValidatedWalletRecord,
    ) -> tuple[int, int, int, str]:
        return (
            record.page_number,
            record.pair.key.absolute_offset,
            record.pair.value.absolute_offset,
            record.record_type,
        )
