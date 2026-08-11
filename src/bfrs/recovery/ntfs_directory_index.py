"""Strict targeted recovery of filename evidence from current NTFS $I30 indexes."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import ntpath

from bfrs.recovery.logical_page_map import LogicalFileExtent
from bfrs.recovery.ntfs_bitcoin_artifacts import (
    ATTRIBUTE_END,
    ATTRIBUTE_FILE_NAME,
    FILE_DIRECTORY,
    NTFSBitcoinArtifactLocator,
    NTFSFileNameAlias,
    NTFSStaleRecoveryContext,
    _Data,
    _Image,
    _LogicalStream,
    _Record,
)
from bfrs.recovery.ntfs_mft_data import NtfsMftDataExtractor, NtfsMftRecordError


ATTRIBUTE_INDEX_ROOT = 0x90
ATTRIBUTE_INDEX_ALLOCATION = 0xA0
INDEX_ENTRY_NODE = 0x0001
INDEX_ENTRY_END = 0x0002
INDEX_NAME = "$I30"
FILE_NAME_COLLATION_RULE = 1
MIN_INDEX_ENTRY_SIZE = 16


@dataclass(frozen=True, slots=True)
class NTFSDirectoryIndexArtifactCandidate:
    source_directory_mft_record: int
    source_directory_sequence: int
    source_directory_path: str | None
    recovered_path: str | None
    partial_path: bool
    index_source: str
    index_vcn: int | None
    entry_offset: int
    file_reference_record: int
    file_reference_sequence: int
    filename: str
    namespace: str
    entry_state: str
    reference_state: str
    parent_reference_state: str
    artifact_class: str
    validation_strength: str


@dataclass(frozen=True, slots=True)
class NTFSDirectoryIndexArtifactRecovery:
    source: str
    directory_record_count: int
    index_root_count: int
    index_allocation_stream_count: int
    indx_block_count: int
    indx_block_valid_count: int
    indx_block_invalid_count: int
    active_entry_count: int
    slack_candidate_count: int
    structural_slack_entry_count: int
    wallet_candidate_count: int
    active_wallet_candidate_count: int
    slack_wallet_candidate_count: int
    bitcoin_context_candidate_count: int
    rejection_counts: tuple[tuple[str, int], ...]
    candidates: tuple[NTFSDirectoryIndexArtifactCandidate, ...]
    diagnostics: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _RootGeometry:
    block_size: int


@dataclass(frozen=True, slots=True)
class _IndexEntry:
    offset: int
    file_reference: int
    alias: NTFSFileNameAlias
    state: str


class NTFSDirectoryIndexArtifactRecoveryPipeline:
    """Read only current MFT directory records and their mapped $I30 streams."""

    def __init__(
        self,
        *,
        context: NTFSStaleRecoveryContext | None,
        locator: NTFSBitcoinArtifactLocator,
    ) -> None:
        self._context = context
        self._locator = locator

    def run(self) -> NTFSDirectoryIndexArtifactRecovery:
        context = self._context
        if context is None:
            return self._empty("", "ntfs_stale_recovery_context_unavailable")

        counters: Counter[str] = Counter()
        rejections: Counter[str] = Counter()
        diagnostics: list[str] = []
        candidates: list[NTFSDirectoryIndexArtifactCandidate] = []
        identities: set[tuple[object, ...]] = set()
        image = _Image(Path(context.source))
        mft_stream = _LogicalStream(
            image, context.mft_extents, context.mft_logical_size
        )

        directories = tuple(
            sorted(
                (
                    record
                    for record in context.current_records_by_number.values()
                    if record.directory
                ),
                key=lambda record: record.number,
            )
        )
        counters["directory_record_count"] = len(directories)
        for directory in directories:
            logical_offset = directory.number * context.boot.record_size
            try:
                raw = mft_stream.read_at(
                    logical_offset, context.boot.record_size
                )
                fixed, first, used, sequence, flags = (
                    self._locator._validated_record_header(raw, context.boot)
                )
            except (OSError, ValueError, NtfsMftRecordError) as error:
                rejections["directory_record_read_or_validation_failed"] += 1
                self._diagnostic(
                    diagnostics,
                    f"directory_record_invalid:{directory.number}:{error}",
                )
                continue
            if sequence != directory.sequence or not flags & FILE_DIRECTORY:
                rejections["directory_record_identity_or_flags_changed"] += 1
                continue

            source_path, source_partial = self._locator._path(
                directory, context.current_records
            )
            roots: list[tuple[int, int, bytes, _RootGeometry]] = []
            allocations: list[tuple[int, _Data]] = []
            try:
                attributes = tuple(self._attributes(fixed, first, used))
            except NtfsMftRecordError as error:
                rejections["directory_attribute_walk_invalid"] += 1
                self._diagnostic(
                    diagnostics,
                    f"directory_attribute_walk_invalid:{directory.number}:{error}",
                )
                continue

            for offset, length, type_code, nonresident, name in attributes:
                if name != INDEX_NAME:
                    continue
                if type_code == ATTRIBUTE_INDEX_ROOT:
                    if nonresident:
                        rejections["index_root_nonresident"] += 1
                        continue
                    try:
                        value_offset, value = self._resident_value(
                            fixed, offset, length
                        )
                        geometry = self._root_geometry(value, context)
                    except NtfsMftRecordError as error:
                        rejections[str(error)] += 1
                        continue
                    roots.append((offset, value_offset, value, geometry))
                elif type_code == ATTRIBUTE_INDEX_ALLOCATION:
                    if not nonresident:
                        rejections["index_allocation_resident"] += 1
                        continue
                    try:
                        data = self._locator._data(
                            fixed,
                            offset,
                            length,
                            nonresident,
                            context.boot,
                            min(image.size, context.boot.volume_end),
                        )
                        self._validate_allocation_data(data, context, image)
                    except NtfsMftRecordError as error:
                        rejections[str(error)] += 1
                        continue
                    allocations.append((offset, data))

            for attribute_offset, value_offset, value, geometry in roots:
                counters["index_root_count"] += 1
                try:
                    active, slack, slack_attempts = self._parse_node(
                        value,
                        header_offset=16,
                        entry_offset_base=attribute_offset + value_offset,
                        source_kind="index_root",
                    )
                except NtfsMftRecordError as error:
                    rejections[str(error)] += 1
                    continue
                counters["active_entry_count"] += len(active)
                counters["slack_candidate_count"] += slack_attempts
                counters["structural_slack_entry_count"] += len(slack)
                self._collect(
                    directory,
                    source_path,
                    source_partial,
                    "index_root",
                    None,
                    active + slack,
                    context,
                    candidates,
                    identities,
                    counters,
                    diagnostics,
                )

            if allocations and len(roots) != 1:
                rejections["index_allocation_without_unique_valid_root"] += len(
                    allocations
                )
                continue
            if not allocations:
                continue
            geometry = roots[0][3]
            for _, data in allocations:
                counters["index_allocation_stream_count"] += 1
                extents = tuple(
                    LogicalFileExtent(
                        extent.vcn_start * context.boot.cluster_size,
                        extent.physical_byte_start,
                        (extent.vcn_end - extent.vcn_start)
                        * context.boot.cluster_size,
                    )
                    for extent in data.extents
                    if not extent.sparse
                    and extent.physical_byte_start is not None
                )
                allocation_stream = _LogicalStream(image, extents, data.logical_size)
                full_block_count = data.logical_size // geometry.block_size
                if data.logical_size % geometry.block_size:
                    rejections["index_allocation_trailing_partial_block"] += 1
                for block_number in range(full_block_count):
                    counters["indx_block_count"] += 1
                    block_offset = block_number * geometry.block_size
                    try:
                        block = allocation_stream.read_at(
                            block_offset, geometry.block_size
                        )
                        fixed_block, vcn = self._validated_indx(
                            block, block_offset, context
                        )
                        active, slack, slack_attempts = self._parse_node(
                            fixed_block,
                            header_offset=24,
                            entry_offset_base=block_offset,
                            source_kind="index_allocation",
                        )
                    except (OSError, ValueError, NtfsMftRecordError) as error:
                        counters["indx_block_invalid_count"] += 1
                        rejections[str(error)] += 1
                        continue
                    counters["indx_block_valid_count"] += 1
                    counters["active_entry_count"] += len(active)
                    counters["slack_candidate_count"] += slack_attempts
                    counters["structural_slack_entry_count"] += len(slack)
                    self._collect(
                        directory,
                        source_path,
                        source_partial,
                        "index_allocation",
                        vcn,
                        active + slack,
                        context,
                        candidates,
                        identities,
                        counters,
                        diagnostics,
                    )

        ordered = tuple(
            sorted(
                candidates,
                key=lambda item: (
                    item.source_directory_mft_record,
                    item.index_source,
                    -1 if item.index_vcn is None else item.index_vcn,
                    item.entry_offset,
                    item.filename.casefold(),
                ),
            )
        )
        return NTFSDirectoryIndexArtifactRecovery(
            source=context.source,
            directory_record_count=counters["directory_record_count"],
            index_root_count=counters["index_root_count"],
            index_allocation_stream_count=counters[
                "index_allocation_stream_count"
            ],
            indx_block_count=counters["indx_block_count"],
            indx_block_valid_count=counters["indx_block_valid_count"],
            indx_block_invalid_count=counters["indx_block_invalid_count"],
            active_entry_count=counters["active_entry_count"],
            slack_candidate_count=counters["slack_candidate_count"],
            structural_slack_entry_count=counters[
                "structural_slack_entry_count"
            ],
            wallet_candidate_count=counters["wallet_candidate_count"],
            active_wallet_candidate_count=counters[
                "active_wallet_candidate_count"
            ],
            slack_wallet_candidate_count=counters[
                "slack_wallet_candidate_count"
            ],
            bitcoin_context_candidate_count=counters[
                "bitcoin_context_candidate_count"
            ],
            rejection_counts=tuple(sorted(rejections.items())),
            candidates=ordered,
            diagnostics=tuple(diagnostics),
        )

    @staticmethod
    def _attributes(fixed: bytes, first: int, used: int):
        offset = first
        ended = False
        while offset + 4 <= used:
            type_code = int.from_bytes(fixed[offset:offset + 4], "little")
            if type_code == ATTRIBUTE_END:
                ended = True
                break
            if offset % 8 or offset + 16 > used:
                raise NtfsMftRecordError("attribute_header_truncated")
            length = int.from_bytes(fixed[offset + 4:offset + 8], "little")
            nonresident = fixed[offset + 8]
            name_length = fixed[offset + 9]
            name_offset = int.from_bytes(
                fixed[offset + 10:offset + 12], "little"
            )
            minimum = 64 if nonresident else 24
            name_end = name_offset + name_length * 2
            if (
                nonresident not in (0, 1)
                or length < minimum
                or length % 8
                or offset + length > used
                or (name_length and (name_offset < 16 or name_end > length))
            ):
                raise NtfsMftRecordError("attribute_record_invalid")
            try:
                name = fixed[
                    offset + name_offset:offset + name_end
                ].decode("utf-16-le", errors="strict") if name_length else ""
            except UnicodeDecodeError as error:
                raise NtfsMftRecordError("attribute_name_utf16_invalid") from error
            yield offset, length, type_code, nonresident, name
            offset += length
        if not ended:
            raise NtfsMftRecordError("attribute_end_marker_missing")

    @staticmethod
    def _resident_value(
        fixed: bytes, offset: int, length: int
    ) -> tuple[int, bytes]:
        value_length = int.from_bytes(fixed[offset + 16:offset + 20], "little")
        value_offset = int.from_bytes(fixed[offset + 20:offset + 22], "little")
        if value_offset < 24 or value_offset + value_length > length:
            raise NtfsMftRecordError("index_root_value_bounds_invalid")
        return value_offset, bytes(
            fixed[offset + value_offset:offset + value_offset + value_length]
        )

    @staticmethod
    def _root_geometry(
        value: bytes, context: NTFSStaleRecoveryContext
    ) -> _RootGeometry:
        if len(value) < 32:
            raise NtfsMftRecordError("index_root_header_truncated")
        indexed_type = int.from_bytes(value[0:4], "little")
        collation = int.from_bytes(value[4:8], "little")
        block_size = int.from_bytes(value[8:12], "little")
        clusters = int.from_bytes(value[12:13], "little", signed=True)
        if indexed_type != ATTRIBUTE_FILE_NAME:
            raise NtfsMftRecordError("index_root_indexed_type_invalid")
        if collation != FILE_NAME_COLLATION_RULE:
            raise NtfsMftRecordError("index_root_collation_rule_invalid")
        if (
            block_size < context.boot.bytes_per_sector
            or block_size > 16 * 1024 * 1024
            or block_size % context.boot.bytes_per_sector
            or block_size & (block_size - 1)
            or clusters == 0
        ):
            raise NtfsMftRecordError("index_root_block_size_invalid")
        derived = (
            clusters * context.boot.cluster_size
            if clusters > 0
            else 1 << -clusters
        )
        if derived != block_size:
            raise NtfsMftRecordError("index_root_block_geometry_mismatch")
        return _RootGeometry(block_size)

    @staticmethod
    def _validate_allocation_data(
        data: _Data,
        context: NTFSStaleRecoveryContext,
        image: _Image,
    ) -> None:
        if data.resident or data.logical_size <= 0 or not data.extents:
            raise NtfsMftRecordError("index_allocation_mapping_invalid")
        if data.state != "nonresident_extent_map_only":
            raise NtfsMftRecordError(
                f"index_allocation_mapping_invalid:{data.state}"
            )
        for extent in data.extents:
            if (
                extent.sparse
                or extent.physical_byte_start is None
                or extent.physical_byte_end is None
                or extent.physical_byte_start < context.boot.volume_offset
                or extent.physical_byte_end > context.boot.volume_end
                or extent.physical_byte_end > image.size
            ):
                raise NtfsMftRecordError("index_allocation_extent_outside_range")

    @staticmethod
    def _validated_indx(
        block: bytes,
        logical_offset: int,
        context: NTFSStaleRecoveryContext,
    ) -> tuple[bytes, int]:
        if block[:4] != b"INDX":
            raise NtfsMftRecordError("indx_signature_invalid")
        if len(block) % context.boot.bytes_per_sector:
            raise NtfsMftRecordError("indx_sector_geometry_invalid")
        fixed, _, _ = NtfsMftDataExtractor()._apply_fixup(
            block, context.boot.bytes_per_sector
        )
        vcn = int.from_bytes(fixed[16:24], "little")
        expected_vcn = logical_offset // context.boot.cluster_size
        if logical_offset % context.boot.cluster_size or vcn != expected_vcn:
            raise NtfsMftRecordError("indx_vcn_invalid")
        return fixed, vcn

    def _parse_node(
        self,
        data: bytes,
        *,
        header_offset: int,
        entry_offset_base: int,
        source_kind: str,
    ) -> tuple[list[_IndexEntry], list[_IndexEntry], int]:
        if header_offset + 16 > len(data):
            raise NtfsMftRecordError("index_header_truncated")
        entries_offset = int.from_bytes(
            data[header_offset:header_offset + 4], "little"
        )
        total_size = int.from_bytes(
            data[header_offset + 4:header_offset + 8], "little"
        )
        allocated_size = int.from_bytes(
            data[header_offset + 8:header_offset + 12], "little"
        )
        node_flags = data[header_offset + 12]
        entries_start = header_offset + entries_offset
        active_end = header_offset + total_size
        allocated_end = header_offset + allocated_size
        if (
            entries_offset < 16
            or entries_offset % 8
            or total_size < entries_offset + MIN_INDEX_ENTRY_SIZE
            or total_size > allocated_size
            or allocated_end > len(data)
            or node_flags not in (0, 1)
        ):
            raise NtfsMftRecordError("index_header_bounds_invalid")

        active: list[_IndexEntry] = []
        cursor = entries_start
        end_found = False
        while cursor < active_end:
            entry, length, flags = self._one_entry(
                data, cursor, active_end, "active"
            )
            if flags & INDEX_ENTRY_END:
                if entry is not None or flags & ~(
                    INDEX_ENTRY_NODE | INDEX_ENTRY_END
                ):
                    raise NtfsMftRecordError("index_end_entry_invalid")
                end_found = True
                cursor += length
                break
            if entry is None:
                raise NtfsMftRecordError("index_active_entry_invalid")
            active.append(
                _IndexEntry(
                    entry.offset + entry_offset_base,
                    entry.file_reference,
                    entry.alias,
                    entry.state,
                )
            )
            cursor += length
        if not end_found:
            raise NtfsMftRecordError("index_end_marker_missing")

        slack: list[_IndexEntry] = []
        attempts = 0
        slack_cursor = (active_end + 7) & ~7
        while slack_cursor + MIN_INDEX_ENTRY_SIZE <= allocated_end:
            if not self._plausible_slack_header(
                data, slack_cursor, allocated_end
            ):
                slack_cursor += 8
                continue
            attempts += 1
            try:
                entry, _, flags = self._one_entry(
                    data, slack_cursor, allocated_end, "slack"
                )
            except NtfsMftRecordError:
                slack_cursor += 8
                continue
            if entry is not None and not flags & INDEX_ENTRY_END:
                slack.append(
                    _IndexEntry(
                        entry.offset + entry_offset_base,
                        entry.file_reference,
                        entry.alias,
                        entry.state,
                    )
                )
            slack_cursor += 8
        return active, slack, attempts

    @staticmethod
    def _plausible_slack_header(
        data: bytes, offset: int, limit: int
    ) -> bool:
        file_reference = int.from_bytes(data[offset:offset + 8], "little")
        length = int.from_bytes(data[offset + 8:offset + 10], "little")
        key_length = int.from_bytes(data[offset + 10:offset + 12], "little")
        flags = int.from_bytes(data[offset + 12:offset + 14], "little")
        child_size = 8 if flags & INDEX_ENTRY_NODE else 0
        return (
            file_reference != 0
            and length >= MIN_INDEX_ENTRY_SIZE
            and length % 8 == 0
            and offset + length <= limit
            and key_length > 0
            and MIN_INDEX_ENTRY_SIZE + key_length + child_size <= length
            and flags & ~(INDEX_ENTRY_NODE | INDEX_ENTRY_END) == 0
            and not flags & INDEX_ENTRY_END
        )

    def _one_entry(
        self, data: bytes, offset: int, limit: int, state: str
    ) -> tuple[_IndexEntry | None, int, int]:
        if offset + MIN_INDEX_ENTRY_SIZE > limit:
            raise NtfsMftRecordError("index_entry_header_outside_node")
        file_reference = int.from_bytes(data[offset:offset + 8], "little")
        length = int.from_bytes(data[offset + 8:offset + 10], "little")
        key_length = int.from_bytes(data[offset + 10:offset + 12], "little")
        flags = int.from_bytes(data[offset + 12:offset + 14], "little")
        if (
            length < MIN_INDEX_ENTRY_SIZE
            or length % 8
            or offset + length > limit
            or flags & ~(INDEX_ENTRY_NODE | INDEX_ENTRY_END)
        ):
            raise NtfsMftRecordError("index_entry_bounds_invalid")
        child_size = 8 if flags & INDEX_ENTRY_NODE else 0
        if flags & INDEX_ENTRY_END:
            if key_length != 0 or length < MIN_INDEX_ENTRY_SIZE + child_size:
                raise NtfsMftRecordError("index_end_entry_invalid")
            return None, length, flags
        if (
            file_reference == 0
            or file_reference >> 48 == 0
            or key_length == 0
            or MIN_INDEX_ENTRY_SIZE + key_length + child_size > length
        ):
            raise NtfsMftRecordError("index_entry_key_bounds_invalid")
        key = bytes(data[offset + 16:offset + 16 + key_length])
        if len(key) < 66 or key_length != 66 + key[64] * 2:
            raise NtfsMftRecordError("index_entry_filename_key_length_invalid")
        alias = self._locator._filename_value(key)
        return _IndexEntry(offset, file_reference, alias, state), length, flags

    def _collect(
        self,
        directory: _Record,
        source_path: str | None,
        source_partial: bool,
        source_kind: str,
        vcn: int | None,
        entries: list[_IndexEntry],
        context: NTFSStaleRecoveryContext,
        candidates: list[NTFSDirectoryIndexArtifactCandidate],
        identities: set[tuple[object, ...]],
        counters: Counter[str],
        diagnostics: list[str],
    ) -> None:
        for entry in entries:
            record_number = entry.file_reference & ((1 << 48) - 1)
            sequence = entry.file_reference >> 48
            artifact_class = self._artifact_class(
                entry.alias, directory, source_path, context
            )
            if artifact_class is None:
                continue
            identity = (
                directory.number,
                source_kind,
                vcn,
                entry.offset,
                record_number,
                entry.alias.filename.casefold(),
            )
            if identity in identities:
                continue
            identities.add(identity)
            reference_state = self._reference_state(
                record_number, sequence, context
            )
            parent_matches = (
                entry.alias.parent_mft_record_number == directory.number
                and entry.alias.parent_sequence_number == directory.sequence
            )
            parent_state = (
                "source_directory_matches"
                if parent_matches
                else "embedded_parent_reference_mismatch"
            )
            if not parent_matches:
                self._diagnostic(
                    diagnostics,
                    "embedded_parent_reference_mismatch:"
                    f"{directory.number}:{source_kind}:{entry.offset}",
                )
            recovered_path = (
                ntpath.join(source_path, entry.alias.filename)
                if source_path
                else entry.alias.filename
            )
            validation = (
                "active_ntfs_directory_index_entry"
                if entry.state == "active"
                else "structural_index_slack_entry"
            )
            candidates.append(
                NTFSDirectoryIndexArtifactCandidate(
                    directory.number,
                    directory.sequence,
                    source_path,
                    recovered_path,
                    source_partial,
                    source_kind,
                    vcn,
                    entry.offset,
                    record_number,
                    sequence,
                    entry.alias.filename,
                    entry.alias.namespace,
                    entry.state,
                    reference_state,
                    parent_state,
                    artifact_class,
                    validation,
                )
            )
            if artifact_class in {"wallet_dat", "wallet_backup_like"}:
                counters["wallet_candidate_count"] += 1
                counters[
                    "active_wallet_candidate_count"
                    if entry.state == "active"
                    else "slack_wallet_candidate_count"
                ] += 1
            elif artifact_class == "bitcoin_context_artifact":
                counters["bitcoin_context_candidate_count"] += 1

    def _artifact_class(
        self,
        alias: NTFSFileNameAlias,
        directory: _Record,
        source_path: str | None,
        context: NTFSStaleRecoveryContext,
    ) -> str | None:
        synthetic = _Record(
            alias.parent_mft_record_number,
            alias.parent_sequence_number,
            False,
            False,
            (alias,),
            None,
        )
        classified = self._locator._classify(
            synthetic, context.current_records
        )
        if classified is not None:
            return classified
        if source_path and any(
            component.casefold() == "bitcoin"
            for component in source_path.replace("/", "\\").split("\\")
        ):
            return "bitcoin_context_artifact"
        if any(
            item.filename.casefold() == "bitcoin" for item in directory.aliases
        ):
            return "bitcoin_context_artifact"
        return None

    @staticmethod
    def _reference_state(
        number: int,
        sequence: int,
        context: NTFSStaleRecoveryContext,
    ) -> str:
        record_count = context.mft_logical_size // context.boot.record_size
        if number >= record_count:
            return "record_number_out_of_range"
        current = context.current_records_by_number.get(number)
        if current is None:
            return "current_record_missing"
        if current.sequence == sequence:
            return "current_reference_matches"
        return "current_record_reused_sequence_differs"

    @staticmethod
    def _diagnostic(diagnostics: list[str], message: str) -> None:
        if len(diagnostics) < 200:
            diagnostics.append(message)

    @staticmethod
    def _empty(
        source: str, diagnostic: str
    ) -> NTFSDirectoryIndexArtifactRecovery:
        return NTFSDirectoryIndexArtifactRecovery(
            source, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (), (),
            (diagnostic,),
        )
