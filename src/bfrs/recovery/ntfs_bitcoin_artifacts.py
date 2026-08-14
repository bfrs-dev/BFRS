"""Conservative NTFS MFT index of historical Bitcoin filename artifacts."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re

from bfrs.recovery.ntfs_extents import (
    NtfsMappingPairsDecoder,
    NtfsMappingPairsError,
)
from bfrs.recovery.ntfs_mft_data import (
    NtfsMftDataExtractor,
    NtfsMftRecordError,
)
from bfrs.recovery.ntfs_mft_recovery import (
    NTFSMFTRecoveryDiagnostic,
    NTFSMirrorArtifactCandidate,
    NTFSMirrorRecordComparison,
    NTFSInvalidMainRecordDiagnostic,
    NTFSPartialFileRecordSalvage,
    empty_ntfs_mft_recovery_diagnostic,
)


ATTRIBUTE_END = 0xFFFFFFFF
ATTRIBUTE_LIST = 0x20
ATTRIBUTE_FILE_NAME = 0x30
ATTRIBUTE_DATA = 0x80
ATTRIBUTE_COMPRESSED = 0x0001
ATTRIBUTE_ENCRYPTED = 0x4000
ATTRIBUTE_SPARSE = 0x8000
FILE_IN_USE = 0x0001
FILE_DIRECTORY = 0x0002
NAMESPACE_NAMES = {0: "posix", 1: "win32", 2: "dos", 3: "win32_dos"}
MAX_MFT_RECORDS = 50_000_000
MFT_MIRROR_RECORD_COUNT = 4


@dataclass(frozen=True, slots=True)
class NTFSFileNameAlias:
    filename: str
    namespace: str
    parent_mft_record_number: int
    parent_sequence_number: int


@dataclass(frozen=True, slots=True)
class NTFSDataExtent:
    vcn_start: int
    vcn_end: int
    physical_lcn_start: int | None
    physical_byte_start: int | None
    physical_byte_end: int | None
    sparse: bool


@dataclass(frozen=True, slots=True)
class NTFSBitcoinArtifactCandidate:
    mft_record_number: int
    sequence_number: int
    allocation_state: str
    filename: str
    namespace: str
    aliases: tuple[NTFSFileNameAlias, ...]
    path: str | None
    partial_path: bool
    artifact_class: str
    resident: bool | None
    nonresident: bool | None
    logical_size: int | None
    allocated_size: int | None
    extent_count: int
    extents: tuple[NTFSDataExtent, ...]
    extent_trust: str
    data_recovery_state: str


@dataclass(frozen=True, slots=True)
class NTFSBitcoinArtifactIndex:
    source: str
    volume_offset: int | None
    cluster_size: int | None
    mft_record_size: int | None
    mft_records_scanned: int
    mft_records_valid: int
    mft_records_invalid: int
    allocated_record_count: int
    deleted_record_count: int
    wallet_dat_candidate_count: int
    bitcoin_context_artifact_count: int
    candidates: tuple[NTFSBitcoinArtifactCandidate, ...]
    diagnostics: tuple[str, ...]
    mft_attribute_list_present: bool = False
    mft_stream_may_be_incomplete: bool = False
    mft_recovery_diagnostic: NTFSMFTRecoveryDiagnostic | None = None


@dataclass(frozen=True, slots=True)
class _Boot:
    volume_offset: int
    bytes_per_sector: int
    cluster_size: int
    mft_lcn: int
    mft_mirror_lcn: int
    record_size: int
    volume_end: int
    sectors_per_cluster: int = 0
    total_sectors: int = 0
    index_block_size: int = 0
    volume_serial: int | None = None


@dataclass(frozen=True, slots=True)
class _Data:
    resident: bool
    logical_size: int
    allocated_size: int
    initialized_size: int
    extents: tuple[NTFSDataExtent, ...]
    state: str


@dataclass(frozen=True, slots=True)
class _Record:
    number: int
    sequence: int
    allocated: bool
    directory: bool
    aliases: tuple[NTFSFileNameAlias, ...]
    data: _Data | None
    base_record_number: int = 0
    base_record_sequence: int = 0


@dataclass(frozen=True, slots=True)
class NTFSStaleRecoveryContext:
    source: str
    boot: _Boot
    mft_extents: tuple
    mft_logical_size: int
    current_records: dict[tuple[int, int], _Record]
    current_records_by_number: dict[int, _Record]
    provenance: str = "main"
    initialization_failures: tuple[str, ...] = ()

    def current_mft_record_at(self, physical_offset: int) -> int | None:
        for extent in self.mft_extents:
            physical_end = extent.physical_start + extent.length
            if (
                extent.physical_start <= physical_offset
                and physical_offset + self.boot.record_size <= physical_end
            ):
                logical_offset = (
                    extent.logical_start
                    + physical_offset
                    - extent.physical_start
                )
                if (
                    logical_offset % self.boot.record_size == 0
                    and logical_offset + self.boot.record_size
                    <= self.mft_logical_size
                ):
                    return logical_offset // self.boot.record_size
        return None

    def is_mft_mirror_record(self, physical_offset: int) -> bool:
        mirror_start = (
            self.boot.volume_offset
            + self.boot.mft_mirror_lcn * self.boot.cluster_size
        )
        return any(
            physical_offset == mirror_start + number * self.boot.record_size
            for number in range(MFT_MIRROR_RECORD_COUNT)
        )

    def read_current_record(self, number: int) -> bytes | None:
        logical_offset = number * self.boot.record_size
        if (
            number < 0
            or logical_offset + self.boot.record_size > self.mft_logical_size
        ):
            return None
        image = _Image(Path(self.source))
        stream = _LogicalStream(image, self.mft_extents, self.mft_logical_size)
        try:
            return stream.read_at(logical_offset, self.boot.record_size)
        except (OSError, ValueError):
            return None

    def physical_offset_for_mft_record(self, number: int) -> int | None:
        if number < 0:
            return None
        logical = number * self.boot.record_size
        for extent in self.mft_extents:
            if (extent.logical_start <= logical and
                    logical + self.boot.record_size <= extent.logical_end):
                return extent.physical_start + logical - extent.logical_start
        return None


class _Image:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.size = path.stat().st_size

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset > self.size or length > self.size - offset:
            raise ValueError("read_outside_image")
        with self.path.open("rb") as source:
            source.seek(offset)
            data = source.read(length)
        if len(data) != length:
            raise OSError("short_image_read")
        return data


class _LogicalStream:
    def __init__(self, image: _Image, extents, logical_size: int) -> None:
        self._image = image
        self._extents = tuple(sorted(extents, key=lambda item: item.logical_start))
        self.size = logical_size

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset > self.size or length > self.size - offset:
            raise ValueError("logical_read_outside_stream")
        cursor = offset
        remaining = length
        output = bytearray()
        while remaining:
            extent = next(
                (item for item in self._extents if item.logical_start <= cursor < item.logical_end),
                None,
            )
            if extent is None:
                raise ValueError("logical_stream_gap_or_sparse")
            take = min(remaining, extent.logical_end - cursor)
            physical = extent.physical_start + cursor - extent.logical_start
            output.extend(self._image.read_at(physical, take))
            cursor += take
            remaining -= take
        return bytes(output)

    def physical_offset_for(self, offset: int, length: int) -> int | None:
        if offset < 0 or length <= 0 or offset + length > self.size:
            return None
        extent = next(
            (
                item
                for item in self._extents
                if item.logical_start <= offset
                and offset + length <= item.logical_end
            ),
            None,
        )
        if extent is None:
            return None
        return extent.physical_start + offset - extent.logical_start


class NTFSBitcoinArtifactLocator:
    """Discover one supported NTFS volume and index MFT filename artifacts."""

    def __init__(self) -> None:
        self._stale_context: NTFSStaleRecoveryContext | None = None

    @property
    def stale_recovery_context(self) -> NTFSStaleRecoveryContext | None:
        return self._stale_context

    def validate_ntfs_boot_sector_at(
        self,
        source: str | Path,
        offset: int,
        *,
        allow_truncated_volume: bool = False,
    ) -> _Boot:
        """Apply the shared strict NTFS boot parser at an exact image offset."""
        image = _Image(Path(source).resolve())
        return self._parse_boot(
            image,
            offset,
            image.size,
            allow_truncated_volume=allow_truncated_volume,
            require_index_geometry=True,
        )

    def index(self, source: str | Path) -> NTFSBitcoinArtifactIndex:
        self._stale_context = None
        path = Path(source).resolve()
        image = _Image(path)
        diagnostics: list[str] = []
        boot = self._discover(image, diagnostics)
        if boot is None:
            return self._empty(path, diagnostics or ["supported_ntfs_volume_not_found"])

        record_zero_offset = boot.volume_offset + boot.mft_lcn * boot.cluster_size
        try:
            record_zero = image.read_at(record_zero_offset, boot.record_size)
            mft = NtfsMftDataExtractor().extract(
                record_zero,
                bytes_per_sector=boot.bytes_per_sector,
                cluster_size=boot.cluster_size,
                partition_offset=boot.volume_offset,
            )
        except (OSError, ValueError, NtfsMftRecordError) as error:
            diagnostics.append(f"mft_record_zero_invalid:{error}")
            return self._empty(path, diagnostics, boot)
        if mft is None:
            diagnostics.append("mft_unnamed_nonresident_data_missing")
            return self._empty(path, diagnostics, boot)

        attribute_list = bool(mft.evidence.get("attribute_list_present", False))
        incomplete = attribute_list or mft.partial_extent_mapping
        if attribute_list:
            diagnostics.append("mft_attribute_list_present")
            diagnostics.append("mft_stream_may_be_incomplete")
        if mft.file_size <= 0 or mft.file_size // boot.record_size > MAX_MFT_RECORDS:
            diagnostics.append("mft_stream_size_invalid")
            return self._empty(path, diagnostics, boot, attribute_list, True)
        for extent in mft.extent_mapping.extents:
            if (
                extent.physical_start + extent.length > image.size
                or extent.physical_start < boot.volume_offset
            ):
                diagnostics.append("mft_extent_outside_image")
                return self._empty(path, diagnostics, boot, attribute_list, True)

        contiguous_end = 0
        for extent in sorted(
            mft.extent_mapping.extents, key=lambda item: item.logical_start
        ):
            if extent.logical_start > contiguous_end:
                break
            contiguous_end = max(contiguous_end, extent.logical_end)
        safe_stream_size = min(mft.file_size, contiguous_end)
        if safe_stream_size < mft.file_size:
            incomplete = True
            diagnostics.append("mft_stream_may_be_incomplete")
        if safe_stream_size < boot.record_size:
            diagnostics.append("mft_contiguous_stream_prefix_missing")
            return self._empty(path, diagnostics, boot, attribute_list, True)
        if safe_stream_size % boot.record_size:
            diagnostics.append("mft_trailing_partial_record_ignored")
        stream = _LogicalStream(
            image, mft.extent_mapping.extents, safe_stream_size
        )
        record_count = safe_stream_size // boot.record_size
        records: dict[tuple[int, int], _Record] = {}
        main_by_number: dict[int, _Record] = {}
        mirror_expected = MFT_MIRROR_RECORD_COUNT
        main_mirror_raw: dict[int, bytes] = {}
        invalid_entries: list[
            tuple[int, bytes | None, int, int | None, str]
        ] = []
        scanned = valid = invalid = allocated = deleted = 0
        for number in range(record_count):
            scanned += 1
            raw: bytes | None = None
            logical_offset = number * boot.record_size
            physical_offset = stream.physical_offset_for(
                logical_offset, boot.record_size
            )
            try:
                raw = stream.read_at(logical_offset, boot.record_size)
                if number < mirror_expected:
                    main_mirror_raw[number] = raw
                record = self._parse_record(raw, number, boot, boot.volume_end)
            except (OSError, ValueError, NtfsMftRecordError) as error:
                invalid += 1
                invalid_entries.append(
                    (
                        number,
                        raw,
                        logical_offset,
                        physical_offset,
                        str(error),
                    )
                )
                if len(diagnostics) < 200:
                    diagnostics.append(f"mft_record_invalid:{number}:{error}")
                continue
            valid += 1
            allocated += int(record.allocated)
            deleted += int(not record.allocated)
            records[(number, record.sequence)] = record
            main_by_number[number] = record

        recovery_diagnostic = self._build_mft_recovery_diagnostic(
            path=path,
            image=image,
            boot=boot,
            records=records,
            main_by_number=main_by_number,
            main_mirror_raw=main_mirror_raw,
            invalid_entries=invalid_entries,
            mirror_expected=mirror_expected,
        )
        self._stale_context = NTFSStaleRecoveryContext(
            source=str(path),
            boot=boot,
            mft_extents=tuple(mft.extent_mapping.extents),
            mft_logical_size=safe_stream_size,
            current_records=records,
            current_records_by_number=main_by_number,
        )

        candidates: list[NTFSBitcoinArtifactCandidate] = []
        for record in records.values():
            artifact_class = self._classify(record, records)
            if artifact_class is None:
                continue
            path_value, partial = self._path(record, records)
            primary = self._primary_alias(record.aliases)
            data = record.data
            state = "data_attribute_missing" if data is None else data.state
            candidates.append(
                NTFSBitcoinArtifactCandidate(
                    mft_record_number=record.number,
                    sequence_number=record.sequence,
                    allocation_state="allocated" if record.allocated else "deleted",
                    filename=primary.filename,
                    namespace=primary.namespace,
                    aliases=record.aliases,
                    path=path_value,
                    partial_path=partial,
                    artifact_class=artifact_class,
                    resident=None if data is None else data.resident,
                    nonresident=None if data is None else not data.resident,
                    logical_size=None if data is None else data.logical_size,
                    allocated_size=None if data is None else data.allocated_size,
                    extent_count=0 if data is None else len(data.extents),
                    extents=() if data is None else data.extents,
                    extent_trust="current" if record.allocated else "stale_possible",
                    data_recovery_state=state,
                )
            )
        ordered = tuple(sorted(candidates, key=lambda item: (item.mft_record_number, item.sequence_number)))
        return NTFSBitcoinArtifactIndex(
            source=str(path), volume_offset=boot.volume_offset,
            cluster_size=boot.cluster_size, mft_record_size=boot.record_size,
            mft_records_scanned=scanned, mft_records_valid=valid,
            mft_records_invalid=invalid, allocated_record_count=allocated,
            deleted_record_count=deleted,
            wallet_dat_candidate_count=sum(item.artifact_class in {"wallet_dat", "wallet_backup_like"} for item in ordered),
            bitcoin_context_artifact_count=sum(item.artifact_class == "bitcoin_context_artifact" for item in ordered),
            candidates=ordered, diagnostics=tuple(diagnostics),
            mft_attribute_list_present=attribute_list,
            mft_stream_may_be_incomplete=incomplete,
            mft_recovery_diagnostic=recovery_diagnostic,
        )

    def _build_mft_recovery_diagnostic(
        self,
        *,
        path: Path,
        image: _Image,
        boot: _Boot,
        records: dict[tuple[int, int], _Record],
        main_by_number: dict[int, _Record],
        main_mirror_raw: dict[int, bytes],
        invalid_entries: list[
            tuple[int, bytes | None, int, int | None, str]
        ],
        mirror_expected: int,
    ) -> NTFSMFTRecoveryDiagnostic:
        diagnostic_messages: list[str] = []
        mirror_offset = (
            boot.volume_offset + boot.mft_mirror_lcn * boot.cluster_size
        )
        mirror_raw: dict[int, bytes] = {}
        mirror_records: dict[int, _Record] = {}
        mirror_invalid_reasons: dict[int, str] = {}
        mirror_read = 0
        for number in range(mirror_expected):
            offset = mirror_offset + number * boot.record_size
            if (
                offset < boot.volume_offset
                or offset + boot.record_size > boot.volume_end
                or offset + boot.record_size > image.size
            ):
                diagnostic_messages.append(
                    f"mirror_record_outside_volume:{number}"
                )
                break
            try:
                raw = image.read_at(offset, boot.record_size)
            except (OSError, ValueError) as error:
                diagnostic_messages.append(
                    f"mirror_record_read_error:{number}:{error}"
                )
                break
            mirror_read += 1
            mirror_raw[number] = raw
            try:
                mirror_records[number] = self._parse_record(
                    raw, number, boot, boot.volume_end
                )
            except (ValueError, NtfsMftRecordError) as error:
                mirror_invalid_reasons[number] = str(error)

        comparisons: list[NTFSMirrorRecordComparison] = []
        difference_counts: Counter[str] = Counter()
        mirror_artifacts: list[NTFSMirrorArtifactCandidate] = []
        for number in range(mirror_read):
            main = main_by_number.get(number)
            mirror = mirror_records.get(number)
            main_valid = main is not None
            mirror_valid = mirror is not None
            main_hash = self._fixed_record_hash(
                main_mirror_raw.get(number), boot
            ) if main_valid else None
            mirror_hash = self._fixed_record_hash(
                mirror_raw.get(number), boot
            ) if mirror_valid else None
            if main_valid and mirror_valid:
                classification = (
                    "identical"
                    if main_hash == mirror_hash
                    else "mirror_valid_main_valid_different"
                )
            elif mirror_valid:
                classification = "mirror_valid_main_invalid"
            elif main_valid:
                classification = "mirror_invalid_main_valid"
            else:
                classification = "both_invalid"
            difference_counts[classification] += 1
            comparisons.append(
                self._mirror_comparison(
                    number,
                    classification,
                    main,
                    mirror,
                    main_mirror_raw.get(number),
                    mirror_raw.get(number),
                    main_hash,
                    mirror_hash,
                    boot,
                )
            )
            if mirror is not None:
                artifact_class = self._classify(mirror, records)
                if artifact_class is not None and mirror.aliases:
                    alias = self._primary_alias(mirror.aliases)
                    data = mirror.data
                    mirror_artifacts.append(
                        NTFSMirrorArtifactCandidate(
                            mft_record_number=number,
                            sequence_number=mirror.sequence,
                            allocation_state=(
                                "allocated" if mirror.allocated else "deleted"
                            ),
                            filename=alias.filename,
                            aliases=mirror.aliases,
                            artifact_class=artifact_class,
                            resident=None if data is None else data.resident,
                            nonresident=None if data is None else not data.resident,
                            logical_size=(
                                None if data is None else data.logical_size
                            ),
                            allocated_size=(
                                None if data is None else data.allocated_size
                            ),
                            extents=() if data is None else data.extents,
                        )
                    )

        invalid_diagnostics: list[NTFSInvalidMainRecordDiagnostic] = []
        partial_salvage: list[NTFSPartialFileRecordSalvage] = []
        reason_counts: Counter[str] = Counter()
        for number, raw, logical, physical, reason in invalid_entries:
            stage = self._failure_stage(reason)
            reason_counts[reason] += 1
            invalid_diagnostics.append(
                NTFSInvalidMainRecordDiagnostic(
                    mft_record_number=number,
                    logical_mft_offset=logical,
                    physical_offset=physical,
                    failure_stage=stage,
                    failure_reason=reason,
                )
            )
            salvage = self._partial_salvage(
                raw=raw,
                number=number,
                logical_offset=logical,
                physical_offset=physical,
                failure_stage=stage,
                failure_reason=reason,
                boot=boot,
                records=records,
            )
            if salvage is not None:
                partial_salvage.append(salvage)

        return NTFSMFTRecoveryDiagnostic(
            source=str(path),
            mirror_physical_offset=mirror_offset,
            mirror_record_count_expected=mirror_expected,
            mirror_record_count_read=mirror_read,
            mirror_record_count_valid=len(mirror_records),
            mirror_record_count_invalid=(
                mirror_read - len(mirror_records)
            ),
            mirror_difference_counts=tuple(sorted(difference_counts.items())),
            mirror_comparisons=tuple(comparisons),
            invalid_main_record_count=len(invalid_entries),
            invalid_reason_counts=tuple(sorted(reason_counts.items())),
            invalid_main_records=tuple(invalid_diagnostics),
            partial_salvage_count=len(partial_salvage),
            salvaged_wallet_candidate_count=sum(
                item.artifact_class in {"wallet_dat", "wallet_backup_like"}
                for item in partial_salvage
            ),
            salvaged_bitcoin_context_count=sum(
                item.artifact_class == "bitcoin_context_artifact"
                for item in partial_salvage
            ),
            mirror_artifact_candidates=tuple(mirror_artifacts),
            partial_salvage_candidates=tuple(partial_salvage),
            diagnostics=tuple(
                diagnostic_messages
                + [
                    f"mirror_record_invalid:{number}:{reason}"
                    for number, reason in sorted(mirror_invalid_reasons.items())
                ]
            ),
        )

    def _partial_salvage(
        self,
        *,
        raw: bytes | None,
        number: int,
        logical_offset: int,
        physical_offset: int | None,
        failure_stage: str,
        failure_reason: str,
        boot: _Boot,
        records: dict[tuple[int, int], _Record],
    ) -> NTFSPartialFileRecordSalvage | None:
        if raw is None:
            return None
        try:
            fixed, first, used, sequence, flags = (
                self._validated_record_header(raw, boot)
            )
        except (ValueError, NtfsMftRecordError):
            return None

        aliases: list[NTFSFileNameAlias] = []
        data_attributes: list[_Data] = []
        valid_prefix_count = 0
        offset = first
        while offset <= used:
            try:
                next_offset, alias, data, _, ended = (
                    self._parse_one_attribute(
                        fixed, offset, used, boot, boot.volume_end
                    )
                )
            except (ValueError, NtfsMftRecordError):
                break
            if ended:
                break
            valid_prefix_count += 1
            if alias is not None:
                aliases.append(alias)
            if data is not None:
                data_attributes.append(data)
            offset = next_offset
        if valid_prefix_count == 0:
            return None
        unique_aliases = tuple(
            {
                (
                    item.filename.casefold(),
                    item.namespace,
                    item.parent_mft_record_number,
                    item.parent_sequence_number,
                ): item
                for item in aliases
            }.values()
        )
        data = data_attributes[0] if len(data_attributes) == 1 else None
        partial_record = _Record(
            number=number,
            sequence=sequence,
            allocated=bool(flags & FILE_IN_USE),
            directory=bool(flags & FILE_DIRECTORY),
            aliases=unique_aliases,
            data=data,
        )
        artifact_class = self._classify(partial_record, records)
        return NTFSPartialFileRecordSalvage(
            mft_record_number=number,
            logical_mft_offset=logical_offset,
            physical_offset=physical_offset,
            failure_stage=failure_stage,
            failure_reason=failure_reason,
            valid_prefix_attribute_count=valid_prefix_count,
            aliases=unique_aliases,
            artifact_class=artifact_class,
            resident=None if data is None else data.resident,
            nonresident=None if data is None else not data.resident,
            logical_size=None if data is None else data.logical_size,
            allocated_size=None if data is None else data.allocated_size,
            extents=() if data is None else data.extents,
            extent_trust="partial_invalid_record",
            confidence="structural_partial",
        )

    def _mirror_comparison(
        self,
        number: int,
        classification: str,
        main: _Record | None,
        mirror: _Record | None,
        main_raw: bytes | None,
        mirror_raw: bytes | None,
        main_hash: str | None,
        mirror_hash: str | None,
        boot: _Boot,
    ) -> NTFSMirrorRecordComparison:
        both = main is not None and mirror is not None
        main_header = self._safe_fixed_header(main_raw, boot) if both else None
        mirror_header = self._safe_fixed_header(mirror_raw, boot) if both else None
        main_data = self._data_identity(main.data) if main is not None else None
        mirror_data = (
            self._data_identity(mirror.data) if mirror is not None else None
        )
        return NTFSMirrorRecordComparison(
            mft_record_number=number,
            classification=classification,
            main_valid=main is not None,
            mirror_valid=mirror is not None,
            main_sequence_number=None if main is None else main.sequence,
            mirror_sequence_number=None if mirror is None else mirror.sequence,
            sequence_equal=None if not both else main.sequence == mirror.sequence,
            flags_equal=(
                None
                if main_header is None or mirror_header is None
                else main_header[2] == mirror_header[2]
            ),
            bytes_in_use_equal=(
                None
                if main_header is None or mirror_header is None
                else main_header[1] == mirror_header[1]
            ),
            first_attribute_offset_equal=(
                None
                if main_header is None or mirror_header is None
                else main_header[0] == mirror_header[0]
            ),
            filename_metadata_equal=(
                None if not both else main.aliases == mirror.aliases
            ),
            data_metadata_equal=(
                None if not both else main_data == mirror_data
            ),
            fixed_record_sha256_equal=(
                None if not both else main_hash == mirror_hash
            ),
            main_fixed_sha256=main_hash,
            mirror_fixed_sha256=mirror_hash,
        )

    def _safe_fixed_header(
        self, raw: bytes | None, boot: _Boot
    ) -> tuple[int, int, int] | None:
        if raw is None:
            return None
        try:
            fixed, first, used, _, flags = self._validated_record_header(
                raw, boot
            )
        except (ValueError, NtfsMftRecordError):
            return None
        return first, used, flags

    def _fixed_record_hash(self, raw: bytes | None, boot: _Boot) -> str | None:
        if raw is None:
            return None
        try:
            fixed, _, _, _, _ = self._validated_record_header(raw, boot)
        except (ValueError, NtfsMftRecordError):
            return None
        return hashlib.sha256(fixed).hexdigest()

    @staticmethod
    def _data_identity(data: _Data | None) -> tuple | None:
        if data is None:
            return None
        return (
            data.resident,
            data.logical_size,
            data.allocated_size,
            data.extents,
            data.state,
        )

    @staticmethod
    def _failure_stage(reason: str) -> str:
        if reason == "file_signature_invalid":
            return "signature_invalid"
        if reason.startswith("update_sequence"):
            return "usa_invalid"
        if reason in {
            "file_record_size_invalid",
            "logical_read_outside_stream",
            "logical_stream_gap_or_sparse",
            "short_image_read",
        }:
            return "truncated_record"
        if reason == "sequence_number_invalid" or "file_header" in reason:
            return "header_invalid"
        if "first_attribute" in reason:
            return "first_attribute_invalid"
        if reason.startswith("mapping_pairs_invalid"):
            return "mapping_pairs_invalid"
        if "attribute_list" in reason:
            return "unsupported_attribute_list"
        if "attribute" in reason and (
            "bounds" in reason
            or "record_invalid" in reason
            or "header_truncated" in reason
        ):
            return "attribute_bounds_invalid"
        if any(
            token in reason
            for token in ("filename", "resident_data", "nonresident_header")
        ):
            return "attribute_parse_invalid"
        return "other_invalid"

    def _discover(self, image: _Image, diagnostics: list[str]) -> _Boot | None:
        offsets = [(0, image.size)]
        try:
            sector = image.read_at(0, 512)
        except (OSError, ValueError):
            diagnostics.append("image_boot_sector_unreadable")
            return None
        if sector[510:512] == b"\x55\xaa":
            for index in range(4):
                entry = sector[446 + index * 16 : 462 + index * 16]
                lba = int.from_bytes(entry[8:12], "little")
                sectors = int.from_bytes(entry[12:16], "little")
                if lba and sectors:
                    partition_offset = lba * 512
                    offsets.append(
                        (partition_offset, partition_offset + sectors * 512)
                    )
        for offset, declared_end in dict.fromkeys(offsets):
            try:
                boot = self._parse_boot(image, offset, declared_end)
            except (OSError, ValueError) as error:
                diagnostics.append(f"ntfs_boot_rejected:{offset}:{error}")
                continue
            return boot
        diagnostics.append("supported_ntfs_volume_not_found")
        return None

    @staticmethod
    def _parse_boot(
        image: _Image,
        offset: int,
        declared_end: int,
        *,
        allow_truncated_volume: bool = False,
        require_index_geometry: bool = False,
    ) -> _Boot:
        sector = image.read_at(offset, 512)
        if sector[3:11] != b"NTFS    ":
            raise ValueError("oem_id_invalid")
        if sector[510:512] != b"\x55\xaa":
            raise ValueError("boot_signature_invalid")
        bps = int.from_bytes(sector[11:13], "little")
        spc = sector[13]
        if bps not in (512, 1024, 2048, 4096) or spc == 0 or spc > 128 or spc & (spc - 1):
            raise ValueError("cluster_geometry_invalid")
        cluster = bps * spc
        total_sectors = int.from_bytes(sector[40:48], "little")
        mft_lcn = int.from_bytes(sector[48:56], "little")
        mirror_lcn = int.from_bytes(sector[56:64], "little")
        total_clusters = total_sectors // spc
        if not total_sectors or mft_lcn >= total_clusters or mirror_lcn >= total_clusters:
            raise ValueError("mft_location_invalid")
        encoded = int.from_bytes(sector[64:65], "little", signed=True)
        record_size = encoded * cluster if encoded > 0 else 1 << -encoded if encoded < 0 else 0
        if record_size < 512 or record_size > 65536 or record_size % bps:
            raise ValueError("file_record_size_invalid")
        encoded_index = int.from_bytes(sector[68:69], "little", signed=True)
        index_size = (
            encoded_index * cluster
            if encoded_index > 0
            else 1 << -encoded_index
            if encoded_index < 0
            else 0
        )
        if require_index_geometry and (
            index_size < bps or index_size > 16 * 1024 * 1024 or index_size % bps
        ):
            raise ValueError("index_block_size_invalid")
        volume_end = offset + total_sectors * bps
        if (
            (not allow_truncated_volume and volume_end > image.size)
            or (not allow_truncated_volume and volume_end > declared_end)
            or volume_end <= offset
        ):
            raise ValueError("volume_outside_image")
        return _Boot(
            volume_offset=offset,
            bytes_per_sector=bps,
            cluster_size=cluster,
            mft_lcn=mft_lcn,
            mft_mirror_lcn=mirror_lcn,
            record_size=record_size,
            volume_end=volume_end,
            sectors_per_cluster=spc,
            total_sectors=total_sectors,
            index_block_size=index_size,
            volume_serial=int.from_bytes(sector[72:80], "little"),
        )

    def _validated_record_header(
        self,
        raw: bytes,
        boot: _Boot,
    ) -> tuple[bytes, int, int, int, int]:
        extractor = NtfsMftDataExtractor()
        if len(raw) != boot.record_size or len(raw) % boot.bytes_per_sector:
            raise NtfsMftRecordError("file_record_size_invalid")
        if raw[:4] != b"FILE":
            raise NtfsMftRecordError("file_signature_invalid")
        fixed, usa_offset, usa_count = extractor._apply_fixup(
            raw, boot.bytes_per_sector
        )
        first = self._u16(fixed, 20)
        used = self._u32(fixed, 24)
        allocated = self._u32(fixed, 28)
        if (
            first < 48
            or first < usa_offset + usa_count * 2
            or first % 8
            or used < first + 4
            or used > allocated
            or allocated > len(fixed)
        ):
            raise NtfsMftRecordError("file_header_bounds_invalid")
        sequence = self._u16(fixed, 16)
        if sequence == 0:
            raise NtfsMftRecordError("sequence_number_invalid")
        flags = self._u16(fixed, 22)
        return fixed, first, used, sequence, flags

    def _parse_one_attribute(
        self,
        fixed: bytes,
        offset: int,
        used: int,
        boot: _Boot,
        image_size: int,
        allow_invalid_data: bool = False,
    ) -> tuple[int, NTFSFileNameAlias | None, _Data | None, bool, bool]:
        if offset + 4 > used:
            raise NtfsMftRecordError("attribute_end_marker_missing")
        type_code = self._u32(fixed, offset)
        if type_code == ATTRIBUTE_END:
            return offset, None, None, False, True
        if offset + 16 > used:
            raise NtfsMftRecordError("attribute_header_truncated")
        length = self._u32(fixed, offset + 4)
        nonresident = fixed[offset + 8]
        name_length = fixed[offset + 9]
        if (
            length < 16
            or length % 8
            or offset + length > used
            or nonresident not in (0, 1)
        ):
            raise NtfsMftRecordError("attribute_record_invalid")
        alias = None
        data = None
        attribute_list = type_code == ATTRIBUTE_LIST
        if type_code == ATTRIBUTE_FILE_NAME:
            if nonresident:
                raise NtfsMftRecordError("filename_nonresident")
            alias = self._filename(fixed, offset, length)
        elif type_code == ATTRIBUTE_DATA and name_length == 0:
            try:
                data = self._data(
                    fixed,
                    offset,
                    length,
                    nonresident,
                    boot,
                    image_size,
                )
            except NtfsMftRecordError as error:
                if (
                    not allow_invalid_data
                    or not str(error).startswith("mapping_pairs")
                    or not nonresident
                    or length < 64
                ):
                    raise
                data = _Data(
                    resident=False,
                    logical_size=self._u64(fixed, offset + 48),
                    allocated_size=self._u64(fixed, offset + 40),
                    initialized_size=self._u64(fixed, offset + 56),
                    extents=(),
                    state=f"invalid:{error}",
                )
        return offset + length, alias, data, attribute_list, False

    def _parse_record(
        self,
        raw: bytes,
        number: int,
        boot: _Boot,
        image_size: int,
        allow_invalid_data: bool = False,
    ) -> _Record:
        fixed, first, used, sequence, flags = self._validated_record_header(
            raw, boot
        )
        aliases: list[NTFSFileNameAlias] = []
        data_attributes: list[_Data] = []
        attribute_list = False
        offset = first
        ended = False
        while offset <= used:
            next_offset, alias, data, found_list, ended = (
                self._parse_one_attribute(
                    fixed,
                    offset,
                    used,
                    boot,
                    image_size,
                    allow_invalid_data=allow_invalid_data,
                )
            )
            if ended:
                ended = True
                break
            attribute_list |= found_list
            if alias is not None:
                aliases.append(alias)
            if data is not None:
                data_attributes.append(data)
            offset = next_offset
        if not ended:
            raise NtfsMftRecordError("attribute_end_marker_missing")
        unique = {
            (
                item.filename.casefold(),
                item.namespace,
                item.parent_mft_record_number,
                item.parent_sequence_number,
            ): item
            for item in aliases
        }
        data: _Data | None
        if attribute_list:
            data = self._unsupported_data(data_attributes, "unsupported_attribute_list")
        elif len(data_attributes) > 1:
            data = self._unsupported_data(data_attributes, "unsupported_multiple_data_extents")
        else:
            data = data_attributes[0] if data_attributes else None
        return _Record(
            number,
            sequence,
            bool(flags & FILE_IN_USE),
            bool(flags & FILE_DIRECTORY),
            tuple(unique.values()),
            data,
            self._u64(fixed, 32) & ((1 << 48) - 1),
            self._u64(fixed, 32) >> 48,
        )

    def _filename(self, fixed: bytes, offset: int, length: int) -> NTFSFileNameAlias:
        value_length = self._u32(fixed, offset + 16)
        value_offset = self._u16(fixed, offset + 20)
        if value_offset < 24 or value_length < 66 or value_offset + value_length > length:
            raise NtfsMftRecordError("filename_value_bounds_invalid")
        start = offset + value_offset
        return self._filename_value(fixed[start:start + value_length])

    @staticmethod
    def _filename_value(value: bytes) -> NTFSFileNameAlias:
        """Parse one complete NTFS FILE_NAME value or $I30 key."""
        if len(value) < 66:
            raise NtfsMftRecordError("filename_value_bounds_invalid")
        parent_ref = int.from_bytes(value[0:8], "little")
        name_length = value[64]
        namespace = value[65]
        name_end = 66 + name_length * 2
        if namespace not in NAMESPACE_NAMES or name_end > len(value):
            raise NtfsMftRecordError("filename_name_bounds_invalid")
        try:
            filename = value[66:name_end].decode("utf-16-le", errors="strict")
        except UnicodeDecodeError as error:
            raise NtfsMftRecordError("filename_utf16_invalid") from error
        if not filename or "\x00" in filename or "/" in filename or "\\" in filename:
            raise NtfsMftRecordError("filename_invalid")
        return NTFSFileNameAlias(filename, NAMESPACE_NAMES[namespace], parent_ref & ((1 << 48) - 1), parent_ref >> 48)

    def _data(self, fixed: bytes, offset: int, length: int, nonresident: int, boot: _Boot, image_size: int) -> _Data:
        flags = self._u16(fixed, offset + 12)
        unsupported = "unsupported_compressed_data" if flags & ATTRIBUTE_COMPRESSED else "unsupported_encrypted_data" if flags & ATTRIBUTE_ENCRYPTED else None
        if not nonresident:
            value_length = self._u32(fixed, offset + 16)
            value_offset = self._u16(fixed, offset + 20)
            if value_offset < 24 or value_offset + value_length > length:
                raise NtfsMftRecordError("resident_data_bounds_invalid")
            return _Data(True, value_length, value_length, value_length, (), unsupported or "resident_metadata_only")
        if length < 64:
            raise NtfsMftRecordError("nonresident_header_truncated")
        lowest = self._u64(fixed, offset + 16)
        highest = self._u64(fixed, offset + 24)
        pairs_offset = self._u16(fixed, offset + 32)
        allocated_size = self._u64(fixed, offset + 40)
        logical_size = self._u64(fixed, offset + 48)
        initialized_size = self._u64(fixed, offset + 56)
        if pairs_offset < 64 or pairs_offset >= length:
            raise NtfsMftRecordError("mapping_pairs_offset_invalid")
        mapping_region = bytes(
            fixed[offset + pairs_offset:offset + length]
        )
        mapping_diagnostic = (
            NtfsMftDataExtractor.diagnose_mapping_pairs_input(
                mapping_region,
                mapping_pairs_offset=pairs_offset,
                attribute_boundary_ok=True,
            )
        )
        if (
            mapping_diagnostic.terminator_offset is not None
            and mapping_diagnostic.trailing_byte_count
            != mapping_diagnostic.required_alignment_padding
        ):
            raise NtfsMftRecordError(
                "mapping_pairs_invalid:mapping_pairs_trailing_data"
            )
        mapping_bytes = mapping_region[
            : mapping_diagnostic.mapping_pairs_input_length
        ]
        try:
            mapping = NtfsMappingPairsDecoder().decode(
                mapping_bytes, lowest_vcn=lowest,
                highest_vcn=highest, cluster_size=boot.cluster_size,
                partition_offset=boot.volume_offset,
            )
        except NtfsMappingPairsError as error:
            raise NtfsMftRecordError(f"mapping_pairs_invalid:{error}") from error
        extents = tuple(
            NTFSDataExtent(
                run.vcn_start, run.vcn_end, run.lcn_start,
                None if run.sparse else boot.volume_offset + run.lcn_start * boot.cluster_size,
                None if run.sparse else boot.volume_offset + (run.lcn_start + run.cluster_count) * boot.cluster_size,
                run.sparse,
            ) for run in mapping.runs
        )
        outside = any(item.physical_byte_end is not None and item.physical_byte_end > image_size for item in extents)
        state = unsupported or ("extent_outside_image" if outside else "nonresident_extent_map_only")
        if flags & ATTRIBUTE_SPARSE and not any(item.sparse for item in extents):
            state = "sparse_flag_without_sparse_run"
        return _Data(False, logical_size, allocated_size, initialized_size, extents, state)

    @staticmethod
    def _unsupported_data(items: list[_Data], state: str) -> _Data | None:
        if not items:
            return None
        item = items[0]
        return _Data(
            item.resident, item.logical_size, item.allocated_size,
            item.initialized_size, item.extents, state
        )

    def _classify(
        self,
        record: _Record,
        records: dict[tuple[int, int], _Record],
    ) -> str | None:
        names = {item.filename.casefold() for item in record.aliases}
        if "wallet.dat" in names or any(re.fullmatch(r"wallet~\d+\.dat", name) for name in names):
            return "wallet_dat"
        if any(re.fullmatch(r"wallet[^\\/]*\.(?:dat|bak|backup|old)", name) for name in names):
            return "wallet_backup_like"
        context = self._has_bitcoin_path_component(record, records) or any(
            name in {"bitcoin", "bitcoin.conf", "debug.log", "db.log", "peers.dat"}
            or re.fullmatch(r"blk\d+\.dat", name)
            for name in names
        )
        if context:
            return "bitcoin_context_artifact"
        return None

    def _has_bitcoin_path_component(
        self,
        record: _Record,
        records: dict[tuple[int, int], _Record],
    ) -> bool:
        current = record
        seen: set[tuple[int, int]] = set()
        while current.aliases:
            identity = (current.number, current.sequence)
            if identity in seen:
                return False
            seen.add(identity)
            if any(alias.filename.casefold() == "bitcoin" for alias in current.aliases):
                return True
            alias = self._primary_alias(current.aliases)
            parent_identity = (
                alias.parent_mft_record_number,
                alias.parent_sequence_number,
            )
            if parent_identity == identity:
                return False
            parent = records.get(parent_identity)
            if parent is None:
                return False
            current = parent
        return False

    def _path(self, record: _Record, records: dict[tuple[int, int], _Record]) -> tuple[str | None, bool]:
        parts: list[str] = []
        current = record
        seen: set[tuple[int, int]] = set()
        partial = False
        while current.aliases:
            identity = (current.number, current.sequence)
            if identity in seen:
                partial = True
                break
            seen.add(identity)
            alias = self._primary_alias(current.aliases)
            parts.append(alias.filename)
            parent_identity = (alias.parent_mft_record_number, alias.parent_sequence_number)
            if parent_identity == identity:
                break
            parent = records.get(parent_identity)
            if parent is None:
                partial = True
                break
            current = parent
        if not parts:
            return None, True
        return "\\".join(reversed(parts)), partial

    @staticmethod
    def _primary_alias(aliases: tuple[NTFSFileNameAlias, ...]) -> NTFSFileNameAlias:
        priority = {"win32": 0, "win32_dos": 1, "posix": 2, "dos": 3}
        return min(aliases, key=lambda item: (priority[item.namespace], item.filename.casefold()))

    @staticmethod
    def _empty(path: Path, diagnostics: list[str], boot: _Boot | None = None, attribute_list: bool = False, incomplete: bool = False) -> NTFSBitcoinArtifactIndex:
        return NTFSBitcoinArtifactIndex(
            str(path), None if boot is None else boot.volume_offset,
            None if boot is None else boot.cluster_size,
            None if boot is None else boot.record_size,
            0, 0, 0, 0, 0, 0, 0, (), tuple(diagnostics), attribute_list, incomplete,
            mft_recovery_diagnostic=empty_ntfs_mft_recovery_diagnostic(
                str(path), "mft_stream_not_available"
            ),
        )

    @staticmethod
    def _u16(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset:offset + 2], "little")

    @staticmethod
    def _u32(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset:offset + 4], "little")

    @staticmethod
    def _u64(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset:offset + 8], "little")
