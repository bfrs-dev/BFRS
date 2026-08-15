"""Targeted, content-free NTFS file identity analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from bfrs.recovery.ntfs_bitcoin_artifacts import (
    ATTRIBUTE_DATA,
    ATTRIBUTE_END,
    ATTRIBUTE_FILE_NAME,
    NTFSBitcoinArtifactLocator,
    NTFSStaleRecoveryContext,
    _Image,
    _LogicalStream,
)
from bfrs.recovery.logical_page_map import LogicalFileExtent
from bfrs.recovery.ntfs_directory_index import (
    ATTRIBUTE_INDEX_ALLOCATION,
    ATTRIBUTE_INDEX_ROOT,
    INDEX_NAME,
    NTFSDirectoryIndexArtifactRecoveryPipeline,
)
from bfrs.recovery.ntfs_mft_data import NtfsMftRecordError


ATTRIBUTE_STANDARD_INFORMATION = 0x10
NAMESPACE_LABELS = {0: "POSIX", 1: "WIN32", 2: "DOS", 3: "WIN32_AND_DOS"}
WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class NTFSTimestamps:
    created: str | None
    modified: str | None
    mft_changed: str | None
    accessed: str | None


@dataclass(frozen=True, slots=True)
class NTFSFileNameIdentity:
    namespace: str
    filename: str
    parent_mft_record: int
    parent_sequence: int
    timestamps: NTFSTimestamps
    allocated_size: int
    logical_size: int
    attribute_flags: int


@dataclass(frozen=True, slots=True)
class NTFSDataIdentity:
    stream_name: str
    resident: bool
    logical_size: int
    initialized_size: int
    allocated_size: int
    compressed: bool
    sparse: bool
    encrypted_ntfs: bool
    extents: tuple[dict, ...]


@dataclass(frozen=True, slots=True)
class NTFSPathIdentity:
    path: str | None
    complete: bool
    parent_chain_mft: tuple[int, ...]
    confidence: str
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NTFSSiblingIdentity:
    filename: str
    namespace: str
    mft_record: int
    sequence: int
    logical_size: int | None
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class NTFSDirectoryContext:
    parent_mft_record: int
    parent_sequence: int
    directory_name: str | None
    directory_path: str | None
    active: bool | None
    index_state: str
    historical_names: tuple[str, ...]
    ele_siblings: tuple[NTFSSiblingIdentity, ...]
    generated_name_series: bool
    category: str
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NTFSFileIdentity:
    mft_record: int
    sequence: int
    allocated: bool
    file_names: tuple[NTFSFileNameIdentity, ...]
    short_filename: str | None
    long_filename: str | None
    standard_information_timestamps: NTFSTimestamps | None
    paths: tuple[NTFSPathIdentity, ...]
    data_attributes: tuple[NTFSDataIdentity, ...]
    directory_contexts: tuple[NTFSDirectoryContext, ...]
    timestamp_inferences: tuple[str, ...]
    confidence: str
    reason_codes: tuple[str, ...]

    def safe_dict(self) -> dict:
        return asdict(self)


def _filetime(raw: bytes) -> str | None:
    ticks = int.from_bytes(raw, "little")
    if ticks == 0:
        return None
    try:
        return (WINDOWS_EPOCH + timedelta(microseconds=ticks // 10)).isoformat()
    except OverflowError:
        return None


def _timestamps(value: bytes, offset: int = 0) -> NTFSTimestamps:
    if len(value) < offset + 32:
        raise NtfsMftRecordError("timestamp_value_truncated")
    return NTFSTimestamps(*(
        _filetime(value[offset + index:offset + index + 8])
        for index in range(0, 32, 8)
    ))


class NTFSFileIdentityResolver:
    """Resolve exact MFT records without reading their DATA payloads."""

    def __init__(self, context: NTFSStaleRecoveryContext) -> None:
        self.context = context
        self.locator = NTFSBitcoinArtifactLocator()

    def resolve_many(self, records: Iterable[int]) -> tuple[NTFSFileIdentity, ...]:
        return tuple(self.resolve(number) for number in records)

    def resolve(self, number: int) -> NTFSFileIdentity:
        record = self.context.current_records_by_number.get(number)
        if record is None:
            return NTFSFileIdentity(
                number, 0, False, (), None, None, None, (), (), (), (), "LOW",
                ("MFT_RECORD_NOT_AVAILABLE",),
            )
        raw = self.context.read_current_record(number)
        if raw is None:
            return NTFSFileIdentity(
                number, record.sequence, record.allocated, (), None, None, None,
                (), (), (), (), "LOW", ("MFT_RECORD_READ_FAILED",),
            )
        try:
            fixed, first, used, sequence, _ = self.locator._validated_record_header(
                raw, self.context.boot
            )
            attributes = tuple(self._attributes(fixed, first, used))
        except NtfsMftRecordError as error:
            return NTFSFileIdentity(
                number, record.sequence, record.allocated, (), None, None, None,
                (), (), (), (), "LOW", (f"MFT_RECORD_INVALID:{error}",),
            )
        reasons = []
        if sequence != record.sequence:
            reasons.append("MFT_SEQUENCE_CHANGED_DURING_ANALYSIS")
        names = []
        si = None
        data = []
        for offset, length, type_code, nonresident, name in attributes:
            if type_code == ATTRIBUTE_STANDARD_INFORMATION and not nonresident:
                value = self._resident_value(fixed, offset, length)
                if len(value) >= 32:
                    si = _timestamps(value)
            elif type_code == ATTRIBUTE_FILE_NAME and not nonresident:
                value = self._resident_value(fixed, offset, length)
                names.append(self._filename(value))
            elif type_code == ATTRIBUTE_DATA:
                data.append(self._data(fixed, offset, length, nonresident, name))
        names = tuple(names)
        paths = tuple(self._path(name) for name in names)
        directories = tuple(self._directory(name) for name in names)
        short = next((item.filename for item in names if item.namespace == "DOS"), None)
        long = next((item.filename for item in names
                     if item.namespace in {"WIN32", "WIN32_AND_DOS"}), None)
        if short and long:
            reasons.append("DOS_AND_WIN32_FILE_NAME_PAIR")
        elif short:
            reasons.append("DOS_FILE_NAME_WITHOUT_WIN32_PAIR")
        if len(names) > 1:
            reasons.append("MULTIPLE_FILE_NAME_ATTRIBUTES")
        inferences = self._timestamp_inferences(si, names)
        if all(item.complete for item in paths) and paths:
            confidence = "HIGH"
        elif paths:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        return NTFSFileIdentity(
            number, sequence, record.allocated, names, short, long, si, paths,
            tuple(data), directories, inferences, confidence,
            tuple(dict.fromkeys(reasons)),
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
            if offset + 16 > used:
                raise NtfsMftRecordError("attribute_header_truncated")
            length = int.from_bytes(fixed[offset + 4:offset + 8], "little")
            nonresident = fixed[offset + 8]
            name_length = fixed[offset + 9]
            name_offset = int.from_bytes(fixed[offset + 10:offset + 12], "little")
            minimum = 64 if nonresident else 24
            if (length < minimum or length % 8 or offset + length > used
                    or nonresident not in (0, 1)):
                raise NtfsMftRecordError("attribute_record_invalid")
            name_end = name_offset + name_length * 2
            if name_length and (name_offset < 16 or name_end > length):
                raise NtfsMftRecordError("attribute_name_bounds_invalid")
            try:
                name = (fixed[offset + name_offset:offset + name_end]
                        .decode("utf-16-le") if name_length else "")
            except UnicodeDecodeError as error:
                raise NtfsMftRecordError("attribute_name_utf16_invalid") from error
            yield offset, length, type_code, nonresident, name
            offset += length
        if not ended:
            raise NtfsMftRecordError("attribute_end_marker_missing")

    @staticmethod
    def _resident_value(fixed: bytes, offset: int, length: int) -> bytes:
        size = int.from_bytes(fixed[offset + 16:offset + 20], "little")
        start = int.from_bytes(fixed[offset + 20:offset + 22], "little")
        if start < 24 or start + size > length:
            raise NtfsMftRecordError("resident_value_bounds_invalid")
        return bytes(fixed[offset + start:offset + start + size])

    @staticmethod
    def _filename(value: bytes) -> NTFSFileNameIdentity:
        if len(value) < 66:
            raise NtfsMftRecordError("filename_value_bounds_invalid")
        reference = int.from_bytes(value[:8], "little")
        length, namespace = value[64], value[65]
        end = 66 + length * 2
        if namespace not in NAMESPACE_LABELS or end > len(value):
            raise NtfsMftRecordError("filename_value_invalid")
        try:
            filename = value[66:end].decode("utf-16-le")
        except UnicodeDecodeError as error:
            raise NtfsMftRecordError("filename_utf16_invalid") from error
        return NTFSFileNameIdentity(
            NAMESPACE_LABELS[namespace], filename,
            reference & ((1 << 48) - 1), reference >> 48,
            _timestamps(value, 8), int.from_bytes(value[40:48], "little"),
            int.from_bytes(value[48:56], "little"),
            int.from_bytes(value[56:60], "little"),
        )

    def _data(self, fixed, offset, length, nonresident, name):
        flags = int.from_bytes(fixed[offset + 12:offset + 14], "little")
        if not nonresident:
            value_size = int.from_bytes(fixed[offset + 16:offset + 20], "little")
            return NTFSDataIdentity(
                name, True, value_size, value_size, value_size,
                bool(flags & 1), bool(flags & 0x8000), bool(flags & 0x4000), (),
            )
        parsed = self.locator._data(
            fixed, offset, length, nonresident, self.context.boot,
            min(Path(self.context.source).stat().st_size, self.context.boot.volume_end),
        )
        extents = tuple({
            "vcn_start": item.vcn_start,
            "vcn_end": item.vcn_end,
            "lcn_start": item.physical_lcn_start,
            "lcn_end": (None if item.physical_lcn_start is None else
                        item.physical_lcn_start + item.vcn_end - item.vcn_start - 1),
            "physical_start": item.physical_byte_start,
            "physical_end": item.physical_byte_end,
            "sparse": item.sparse,
        } for item in parsed.extents)
        return NTFSDataIdentity(
            name, False, parsed.logical_size, parsed.initialized_size,
            parsed.allocated_size, bool(flags & 1), bool(flags & 0x8000),
            bool(flags & 0x4000), extents,
        )

    def _path(self, name: NTFSFileNameIdentity) -> NTFSPathIdentity:
        parts = [name.filename]
        chain = []
        reasons = []
        number, expected = name.parent_mft_record, name.parent_sequence
        seen = set()
        complete = True
        while number not in seen and len(chain) < 128:
            seen.add(number)
            chain.append(number)
            parent = self.context.current_records_by_number.get(number)
            if parent is None:
                complete = False
                reasons.append(f"PARENT_RECORD_MISSING:{number}")
                break
            if parent.sequence != expected:
                complete = False
                reasons.append(f"PARENT_SEQUENCE_MISMATCH:{number}:{expected}:{parent.sequence}")
                break
            if not parent.aliases:
                if number != 5:
                    complete = False
                    reasons.append(f"PARENT_NAME_MISSING:{number}")
                break
            alias = self.locator._primary_alias(parent.aliases)
            if alias.filename != ".":
                parts.append(alias.filename)
            if alias.parent_mft_record_number == number:
                break
            number, expected = alias.parent_mft_record_number, alias.parent_sequence_number
        else:
            complete = False
            reasons.append("PARENT_CHAIN_LOOP_OR_LIMIT")
        return NTFSPathIdentity(
            "\\" + "\\".join(reversed(parts)), complete, tuple(chain),
            "HIGH" if complete else "MEDIUM", tuple(reasons or ("PARENT_CHAIN_VALID",)),
        )

    def _directory(self, name: NTFSFileNameIdentity) -> NTFSDirectoryContext:
        parent = self.context.current_records_by_number.get(name.parent_mft_record)
        path = self._path(NTFSFileNameIdentity(
            name.namespace, "", name.parent_mft_record, name.parent_sequence,
            name.timestamps, 0, 0, 0,
        ))
        directory_path = path.path[:-1] if path.path and path.path.endswith("\\") else path.path
        directory_name = None
        if parent and parent.aliases:
            directory_name = self.locator._primary_alias(parent.aliases).filename
        siblings = []
        seen_records = set()
        for record in self.context.current_records_by_number.values():
            if not record.allocated or record.data is None:
                continue
            matching = tuple(alias for alias in record.aliases
                if alias.parent_mft_record_number == name.parent_mft_record
                and alias.parent_sequence_number == name.parent_sequence)
            ele = next((alias for alias in matching
                        if alias.filename.casefold().endswith(".ele")), None)
            if ele is not None and record.number not in seen_records:
                seen_records.add(record.number)
                siblings.append(NTFSSiblingIdentity(
                    ele.filename, ele.namespace.upper(), record.number,
                    record.sequence, record.data.logical_size,
                    tuple(alias.filename for alias in matching),
                ))
        unique = tuple({(item.mft_record, item.filename.casefold()): item
                        for item in siblings}.values())
        names = [item.filename.casefold() for item in unique]
        generated = len(unique) > 1 and any("~" in item for item in names)
        low = (directory_path or "").casefold()
        category = ("ELECTRUM_DIRECTORY" if "\\electrum\\" in low else
                    "BACKUP_DIRECTORY" if "backup" in low else
                    "RECOVERY_DIRECTORY" if any(token in low for token in
                        ("recover", "odzysk", "sprawd", "szukan")) else
                    "TEMP_OR_CACHE" if any(token in low for token in
                        ("\\temp\\", "\\cache\\")) else "OTHER_USER_DIRECTORY")
        index_state, historical = self._directory_index_state(
            name.parent_mft_record, name.parent_sequence, name.filename
        )
        return NTFSDirectoryContext(
            name.parent_mft_record, name.parent_sequence, directory_name,
            directory_path, None if parent is None else parent.allocated,
            index_state, historical,
            tuple(sorted(unique, key=lambda item: (item.mft_record, item.filename))),
            generated, category,
            tuple(path.reason_codes),
        )

    def _directory_index_state(self, number, sequence, filename):
        """Inspect only one parent directory's validated current $I30."""
        record = self.context.current_records_by_number.get(number)
        raw = None if record is None else self.context.read_current_record(number)
        if record is None or raw is None or not record.directory:
            return "PARENT_INDEX_UNAVAILABLE", ()
        parser = NTFSDirectoryIndexArtifactRecoveryPipeline(
            context=self.context, locator=self.locator
        )
        active = []
        slack = []
        try:
            fixed, first, used, actual_sequence, _ = self.locator._validated_record_header(
                raw, self.context.boot
            )
            if actual_sequence != sequence:
                return "PARENT_SEQUENCE_MISMATCH", ()
            attributes = tuple(parser._attributes(fixed, first, used))
            roots = []
            allocations = []
            for offset, length, type_code, nonresident, name in attributes:
                if name != INDEX_NAME:
                    continue
                if type_code == ATTRIBUTE_INDEX_ROOT and not nonresident:
                    value_offset, value = parser._resident_value(fixed, offset, length)
                    roots.append((value, parser._root_geometry(value, self.context)))
                elif type_code == ATTRIBUTE_INDEX_ALLOCATION and nonresident:
                    data = self.locator._data(
                        fixed, offset, length, nonresident, self.context.boot,
                        min(Path(self.context.source).stat().st_size,
                            self.context.boot.volume_end),
                    )
                    parser._validate_allocation_data(
                        data, self.context, _Image(Path(self.context.source))
                    )
                    allocations.append(data)
            for value, _ in roots:
                found, old, _ = parser._parse_node(
                    value, header_offset=16, entry_offset_base=0,
                    source_kind="index_root",
                )
                active.extend(found)
                slack.extend(old)
            if allocations and len(roots) == 1:
                block_size = roots[0][1].block_size
                image = _Image(Path(self.context.source))
                for data in allocations:
                    extents = tuple(LogicalFileExtent(
                        item.vcn_start * self.context.boot.cluster_size,
                        item.physical_byte_start,
                        (item.vcn_end - item.vcn_start) * self.context.boot.cluster_size,
                    ) for item in data.extents if not item.sparse)
                    stream = _LogicalStream(image, extents, data.logical_size)
                    for block_number in range(data.logical_size // block_size):
                        block = stream.read_at(block_number * block_size, block_size)
                        fixed_block, _ = parser._validated_indx(
                            block, block_number * block_size, self.context
                        )
                        found, old, _ = parser._parse_node(
                            fixed_block, header_offset=24,
                            entry_offset_base=block_number * block_size,
                            source_kind="index_allocation",
                        )
                        active.extend(found)
                        slack.extend(old)
        except (OSError, ValueError, NtfsMftRecordError):
            return "PARENT_INDEX_INVALID_OR_INCOMPLETE", ()
        target = self.context.current_records_by_number
        confirmed = any(
            (item.file_reference & ((1 << 48) - 1)) in target
            and (item.file_reference & ((1 << 48) - 1)) == next(
                (candidate.number for candidate in target.values()
                 if candidate.sequence == item.file_reference >> 48
                 and any(alias.filename == filename for alias in candidate.aliases)), -1)
            for item in active
        )
        history = tuple(sorted({item.alias.filename for item in slack
                                if item.alias.filename.casefold().endswith(".ele")}))
        return ("ACTIVE_INDX_ENTRY_CONFIRMED" if confirmed else
                "ACTIVE_INDX_ENTRY_NOT_FOUND"), history

    @staticmethod
    def _timestamp_inferences(si, names):
        if si is None or not names:
            return ("TIMESTAMP_INFERENCE_UNAVAILABLE",)
        if any(item.timestamps != si for item in names):
            return ("SI_FILE_NAME_TIMESTAMPS_DIFFER", "COPY_RENAME_OR_MOVE_POSSIBLE")
        return ("SI_FILE_NAME_TIMESTAMPS_EQUAL", "ORDINARY_ACTIVE_FILE_POSSIBLE")
