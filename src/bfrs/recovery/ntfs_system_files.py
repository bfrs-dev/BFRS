"""Resolve NTFS system files and named streams from the current MFT."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from bfrs.recovery.ntfs_bitcoin_artifacts import NTFSStaleRecoveryContext
from bfrs.recovery.ntfs_extents import NtfsDataRun, NtfsMappingPairsDecoder
from bfrs.recovery.ntfs_mft_data import NtfsMftDataExtractor, NtfsMftRecordError

ATTR_LIST, ATTR_NAME, ATTR_DATA, ATTR_END = 0x20, 0x30, 0x80, 0xFFFFFFFF


class NtfsSystemFileError(ValueError):
    """A controlled, non-fatal NTFS metadata failure."""


@dataclass(frozen=True, slots=True)
class NtfsStreamRun:
    logical_start: int
    length: int
    physical_start: int | None
    sparse: bool


@dataclass(frozen=True, slots=True)
class NtfsResolvedStream:
    record_number: int
    name: str
    logical_size: int
    initialized_size: int
    runs: tuple[NtfsStreamRun, ...]
    extension_records: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class NtfsStreamChunk:
    logical_start: int
    data: bytes
    physical_start: int | None
    gap_before: bool


@dataclass(frozen=True, slots=True)
class NtfsSystemFiles:
    mft_record_number: int
    logfile_record_number: int | None
    usn_jrnl_record_number: int | None
    usn_j: NtfsResolvedStream | None
    usn_max: NtfsResolvedStream | None
    failures: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Attr:
    type_code: int
    name: str
    instance: int
    nonresident: bool
    value: bytes
    lowest_vcn: int = 0
    highest_vcn: int = 0
    logical_size: int = 0
    initialized_size: int = 0
    runs: tuple[NtfsDataRun, ...] = ()


@dataclass(frozen=True, slots=True)
class _AttrListEntry:
    type_code: int
    name: str
    lowest_vcn: int
    record_number: int
    instance: int


class NtfsSystemFileResolver:
    """Resolve `$LogFile` and `$UsnJrnl` without fixed geometry assumptions."""

    def __init__(self, context: NTFSStaleRecoveryContext) -> None:
        if context is None:
            raise ValueError("context is required")
        self.context = context
        self.source = Path(context.source)
        self.failures: list[str] = []

    def read_mft_record(self, number: int) -> bytes:
        raw = self.context.read_current_record(number)
        if raw is None:
            raise NtfsSystemFileError("mft_record_unreadable")
        return raw

    def resolve(self) -> NtfsSystemFiles:
        root = self._resolve_root()
        extend = self._resolve_child("$Extend", root, directory=True)
        logfile = self._resolve_child("$LogFile", root, directory=False)
        usn, resolved_attrs, resolved_extensions = self._resolve_usn(extend)
        j = maximum = None
        if usn is not None:
            try:
                attrs = resolved_attrs or []
                extensions = resolved_extensions or set()
                j = self._stream(usn, "$J", attrs, extensions)
                maximum = self._stream(usn, "$Max", attrs, extensions)
                if j is None:
                    self.failures.append("usn_j_stream_missing")
            except (OSError, ValueError, NtfsMftRecordError) as exc:
                self.failures.append(f"usn_resolve_failure:{exc}")
        else:
            self.failures.append("usn_journal_not_found")
        return NtfsSystemFiles(0, logfile, usn, j, maximum, tuple(self.failures))

    def iter_physical(self, stream: NtfsResolvedStream):
        """Yield (logical offset, physical offset, bytes) for allocated runs only."""
        limit = min(stream.logical_size, stream.initialized_size or stream.logical_size)
        with self.source.open("rb") as image:
            for run in stream.runs:
                if run.sparse or run.physical_start is None or run.logical_start >= limit:
                    continue
                length = min(run.length, limit - run.logical_start)
                try:
                    image.seek(run.physical_start)
                    data = image.read(length)
                except OSError as exc:
                    self.failures.append(f"usn_run_read_failure:{type(exc).__name__}")
                    continue
                if len(data) != length:
                    self.failures.append("usn_run_short_read")
                    continue
                yield run.logical_start, run.physical_start, data

    def iter_stream_chunks(self, stream: NtfsResolvedStream, *,
                           chunk_size: int = 8 * 1024 * 1024):
        """Stream allocated bytes in VCN order and explicitly mark logical gaps."""
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        limit = min(stream.logical_size, stream.initialized_size or stream.logical_size)
        expected = 0
        with self.source.open("rb") as image:
            for run in sorted(stream.runs, key=lambda item: item.logical_start):
                if run.logical_start >= limit:
                    break
                length = min(run.length, limit - run.logical_start)
                gap = run.logical_start != expected or run.sparse or run.physical_start is None
                if run.sparse or run.physical_start is None:
                    yield NtfsStreamChunk(run.logical_start, b"", None, True)
                    expected = run.logical_start + length
                    continue
                consumed = 0
                while consumed < length:
                    take = min(chunk_size, length - consumed)
                    physical = run.physical_start + consumed
                    try:
                        image.seek(physical)
                        data = image.read(take)
                    except OSError as exc:
                        self.failures.append(f"usn_run_read_failure:{type(exc).__name__}")
                        yield NtfsStreamChunk(run.logical_start + consumed, b"", None, True)
                        expected = run.logical_start + length
                        break
                    if len(data) != take:
                        self.failures.append("usn_run_short_read")
                        yield NtfsStreamChunk(run.logical_start + consumed, b"", None, True)
                        expected = run.logical_start + length
                        break
                    yield NtfsStreamChunk(run.logical_start + consumed, data, physical,
                                          gap and consumed == 0)
                    consumed += take
                    expected = run.logical_start + consumed

    def _resolve_root(self) -> int | None:
        candidates = []
        for number, record in self.context.current_records_by_number.items():
            if (record.allocated and record.directory and
                    getattr(record, "base_record_number", 0) == 0 and
                    any(alias.filename == "." and
                        alias.parent_mft_record_number == number and
                        alias.parent_sequence_number == record.sequence
                        for alias in record.aliases)):
                candidates.append(number)
        if len(candidates) != 1:
            self.failures.append("ntfs_root_missing" if not candidates
                                 else "ntfs_root_ambiguous")
            return None
        return candidates[0]

    def _resolve_child(self, wanted: str, parent: int | None, *,
                       directory: bool) -> int | None:
        if parent is None:
            return None
        parent_record = self.context.current_records_by_number[parent]
        candidates = []
        for number, record in self.context.current_records_by_number.items():
            aliases = [alias for alias in record.aliases
                       if alias.filename.casefold() == wanted.casefold()]
            if not aliases:
                continue
            if not record.allocated:
                self.failures.append(f"{wanted}_candidate_rejected:not_allocated:{number}")
                continue
            if record.directory != directory:
                self.failures.append(f"{wanted}_candidate_rejected:record_type:{number}")
                continue
            if getattr(record, "base_record_number", 0) != 0:
                self.failures.append(f"{wanted}_candidate_rejected:not_base_record:{number}")
                continue
            if not any(alias.parent_mft_record_number == parent and
                       alias.parent_sequence_number == parent_record.sequence
                       for alias in aliases):
                self.failures.append(f"{wanted}_candidate_rejected:wrong_parent:{number}")
                continue
            candidates.append(number)
        if len(candidates) > 1:
            self.failures.append(f"{wanted}_candidate_ambiguous")
            return None
        return candidates[0] if candidates else None

    def _resolve_usn(self, extend: int | None):
        if extend is None:
            self.failures.append("usn_extend_directory_unresolved")
            return None, None, None
        parent = self.context.current_records_by_number[extend]
        valid = []
        for number, record in self.context.current_records_by_number.items():
            aliases = [alias for alias in record.aliases
                       if alias.filename.casefold() == "$usnjrnl"]
            if not aliases:
                continue
            reason = None
            if not record.allocated:
                reason = "not_allocated"
            elif record.directory:
                reason = "record_is_directory"
            elif getattr(record, "base_record_number", 0) != 0:
                reason = "not_base_record"
            elif not any(alias.parent_mft_record_number == extend and
                         alias.parent_sequence_number == parent.sequence
                         for alias in aliases):
                reason = "wrong_extend_parent"
            if reason:
                self.failures.append(f"usn_candidate_rejected:{reason}:{number}")
                continue
            before = len(self.failures)
            try:
                attrs, extensions = self._attributes_with_extensions(number)
                stream = self._stream(number, "$J", attrs, extensions)
            except (OSError, ValueError, NtfsMftRecordError) as exc:
                self.failures.append(f"usn_candidate_rejected:attributes:{number}:{exc}")
                continue
            if stream is None:
                self.failures.append(f"usn_candidate_rejected:j_stream_missing:{number}")
                continue
            valid.append((number, attrs, extensions))
        if not valid:
            return None, None, None
        if len(valid) > 1:
            self.failures.append("usn_candidate_ambiguous")
            return None, None, None
        return valid[0]

    def _attributes_with_extensions(self, base: int) -> tuple[list[_Attr], set[int]]:
        attrs = self._parse_attrs(self.read_mft_record(base))
        extension_numbers: set[int] = set()
        list_entries: list[_AttrListEntry] = []
        for attr in tuple(attrs):
            if attr.type_code != ATTR_LIST:
                continue
            try:
                value = self._read_nonresident_value(attr) if attr.nonresident else attr.value
                entries = self._attribute_list_entries(value)
                for entry in entries:
                    if entry in list_entries:
                        self.failures.append("attribute_list_duplicate_entry")
                    else:
                        list_entries.append(entry)
                    if entry.record_number != base:
                        extension_numbers.add(entry.record_number)
            except (OSError, ValueError) as exc:
                self.failures.append(f"attribute_list_malformed:{exc}")
        for number in sorted(extension_numbers):
            try:
                raw = self.read_mft_record(number)
                fixed, _, _ = NtfsMftDataExtractor()._apply_fixup(
                    raw, self.context.boot.bytes_per_sector
                )
                base_reference = int.from_bytes(fixed[32:40], "little")
                base_number = base_reference & ((1 << 48) - 1)
                base_sequence = base_reference >> 48
                expected_sequence = self.context.current_records_by_number[base].sequence
                if base_number != base or base_sequence != expected_sequence:
                    raise NtfsSystemFileError("extension_base_record_mismatch")
                attrs.extend(self._parse_attrs(raw))
            except (ValueError, OSError) as exc:
                self.failures.append(f"extension_record_failure:{number}:{exc}")
        for entry in list_entries:
            if not any(attr.type_code == entry.type_code and
                       attr.name == entry.name and
                       attr.lowest_vcn == entry.lowest_vcn and
                       attr.instance == entry.instance
                       for attr in attrs):
                raise NtfsSystemFileError(
                    f"attribute_list_extent_missing:{entry.record_number}:"
                    f"{entry.type_code:x}:{entry.name}:{entry.lowest_vcn}"
                )
        return attrs, extension_numbers

    def _read_nonresident_value(self, attr: _Attr) -> bytes:
        """Read metadata value only where every logical byte is allocated."""
        size = min(attr.logical_size, attr.initialized_size or attr.logical_size)
        cursor, output = 0, bytearray()
        with self.source.open("rb") as image:
            for run in sorted(attr.runs, key=lambda item: item.vcn_start):
                logical = run.vcn_start * self.context.boot.cluster_size
                length = min(run.cluster_count * self.context.boot.cluster_size,
                             max(0, size - logical))
                if not length:
                    continue
                if logical != cursor or run.sparse or run.lcn_start is None:
                    raise NtfsSystemFileError("attribute_list_sparse_or_discontinuous")
                physical = (self.context.boot.volume_offset
                            + run.lcn_start * self.context.boot.cluster_size)
                image.seek(physical)
                chunk = image.read(length)
                if len(chunk) != length:
                    raise NtfsSystemFileError("attribute_list_short_read")
                output.extend(chunk)
                cursor += length
        if cursor != size:
            raise NtfsSystemFileError("attribute_list_incomplete")
        return bytes(output)

    def _stream(self, base: int, name: str, attrs: Iterable[_Attr], extensions: set[int]):
        selected = sorted(
            (a for a in attrs if a.type_code == ATTR_DATA and a.name == name),
            key=lambda a: a.lowest_vcn,
        )
        if not selected:
            return None
        if not all(a.nonresident for a in selected):
            value = next(a.value for a in selected if not a.nonresident)
            return NtfsResolvedStream(base, name, len(value), len(value), (), tuple(sorted(extensions)))
        expected = selected[0].lowest_vcn
        runs: list[NtfsStreamRun] = []
        for attr in selected:
            if attr.lowest_vcn != expected:
                raise NtfsSystemFileError("stream_vcn_gap")
            for run in attr.runs:
                runs.append(NtfsStreamRun(
                    run.vcn_start * self.context.boot.cluster_size,
                    run.cluster_count * self.context.boot.cluster_size,
                    None if run.sparse else self.context.boot.volume_offset + run.lcn_start * self.context.boot.cluster_size,
                    run.sparse,
                ))
            expected = attr.highest_vcn + 1
        first = selected[0]
        return NtfsResolvedStream(base, name, first.logical_size, first.initialized_size, tuple(runs), tuple(sorted(extensions)))

    def _parse_attrs(self, raw: bytes) -> list[_Attr]:
        fixed, _, _ = NtfsMftDataExtractor()._apply_fixup(raw, self.context.boot.bytes_per_sector)
        used = int.from_bytes(fixed[24:28], "little")
        pos = int.from_bytes(fixed[20:22], "little")
        output: list[_Attr] = []
        while pos + 4 <= used:
            kind = int.from_bytes(fixed[pos:pos + 4], "little")
            if kind == ATTR_END:
                return output
            length = int.from_bytes(fixed[pos + 4:pos + 8], "little")
            if length < 24 or pos + length > used or length % 8:
                raise NtfsSystemFileError("attribute_length_invalid")
            nonresident = fixed[pos + 8] == 1
            nlen, noff = fixed[pos + 9], int.from_bytes(fixed[pos + 10:pos + 12], "little")
            if noff + nlen * 2 > length:
                raise NtfsSystemFileError("attribute_name_invalid")
            name = fixed[pos + noff:pos + noff + nlen * 2].decode("utf-16le") if nlen else ""
            instance = int.from_bytes(fixed[pos + 14:pos + 16], "little")
            if nonresident:
                if length < 64:
                    raise NtfsSystemFileError("nonresident_attribute_truncated")
                low = int.from_bytes(fixed[pos + 16:pos + 24], "little")
                high = int.from_bytes(fixed[pos + 24:pos + 32], "little")
                roff = int.from_bytes(fixed[pos + 32:pos + 34], "little")
                if roff < 64 or roff >= length:
                    raise NtfsSystemFileError("runlist_offset_invalid")
                region = bytes(fixed[pos + roff:pos + length])
                diagnostic = NtfsMftDataExtractor.diagnose_mapping_pairs_input(
                    region, mapping_pairs_offset=roff,
                    attribute_boundary_ok=True,
                )
                if diagnostic.terminator_offset is None:
                    raise NtfsSystemFileError("runlist_terminator_missing")
                mapping = NtfsMappingPairsDecoder().decode(
                    region[:diagnostic.mapping_pairs_input_length],
                    lowest_vcn=low, highest_vcn=high,
                    cluster_size=self.context.boot.cluster_size,
                )
                output.append(_Attr(kind, name, instance, True, b"", low, high,
                    int.from_bytes(fixed[pos + 48:pos + 56], "little"),
                    int.from_bytes(fixed[pos + 56:pos + 64], "little"), mapping.runs))
            else:
                vlen = int.from_bytes(fixed[pos + 16:pos + 20], "little")
                voff = int.from_bytes(fixed[pos + 20:pos + 22], "little")
                if voff < 24 or voff + vlen > length:
                    raise NtfsSystemFileError("resident_value_invalid")
                output.append(_Attr(kind, name, instance, False, bytes(fixed[pos + voff:pos + voff + vlen])))
            pos += length
        raise NtfsSystemFileError("attribute_end_missing")

    @staticmethod
    def _attribute_list_entries(value: bytes) -> list[_AttrListEntry]:
        pos, entries = 0, []
        while pos < len(value):
            if len(value) - pos < 26:
                raise NtfsSystemFileError("entry_truncated")
            length = int.from_bytes(value[pos + 4:pos + 6], "little")
            if length < 26 or pos + length > len(value):
                raise NtfsSystemFileError("entry_length_invalid")
            name_length = value[pos + 6]
            name_offset = value[pos + 7]
            if name_length:
                name_end = name_offset + name_length * 2
                if name_offset < 26 or name_end > length:
                    raise NtfsSystemFileError("entry_name_invalid")
                name = value[pos + name_offset:pos + name_end].decode("utf-16le")
            else:
                name = ""
            reference = int.from_bytes(value[pos + 16:pos + 24], "little")
            entries.append(_AttrListEntry(
                int.from_bytes(value[pos:pos + 4], "little"), name,
                int.from_bytes(value[pos + 8:pos + 16], "little"),
                reference & ((1 << 48) - 1),
                int.from_bytes(value[pos + 24:pos + 26], "little"),
            ))
            pos += length
        return entries

    @staticmethod
    def _attribute_list_refs(value: bytes, base: int) -> set[int]:
        """Backward-compatible helper retained for focused callers."""
        return {entry.record_number for entry in
                NtfsSystemFileResolver._attribute_list_entries(value)
                if entry.record_number != base}
