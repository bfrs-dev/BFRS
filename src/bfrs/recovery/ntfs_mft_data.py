"""Extract one unnamed nonresident NTFS $DATA mapping from an MFT record."""

from dataclasses import dataclass
from typing import Any

from bfrs.recovery.ntfs_extents import (
    NtfsExtentMapping,
    NtfsMappingPairsDecoder,
    NtfsMappingPairsError,
)


FILE_SIGNATURE = b"FILE"
FILE_HEADER_SIZE = 48
ATTRIBUTE_HEADER_SIZE = 16
NONRESIDENT_HEADER_SIZE = 64
ATTRIBUTE_END = 0xFFFFFFFF
ATTRIBUTE_DATA = 0x80
ATTRIBUTE_LIST = 0x20
FILE_IN_USE = 0x0001
FILE_DIRECTORY = 0x0002


class NtfsMftRecordError(ValueError):
    """Controlled failure raised for a malformed NTFS FILE record."""


@dataclass(frozen=True, slots=True)
class NtfsMappingPairsInputDiagnostic:
    mapping_pairs_region_length: int
    mapping_pairs_input_length: int
    terminator_offset: int | None
    trailing_byte_count: int
    trailing_nonzero_count: int
    required_alignment_padding: int | None
    trailing_classification: str
    attribute_boundary_ok: bool


@dataclass(frozen=True, slots=True)
class NtfsMftDataMapping:
    record_number: int | None
    in_use: bool
    directory: bool
    lowest_vcn: int
    highest_vcn: int
    allocated_size: int
    file_size: int
    valid_data_length: int
    partial_extent_mapping: bool
    extent_mapping: NtfsExtentMapping
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _DataAttribute:
    start: int
    record_length: int
    flags: int
    lowest_vcn: int
    highest_vcn: int
    mapping_pairs_offset: int
    allocated_size: int
    file_size: int
    valid_data_length: int


class NtfsMftDataExtractor:
    """Validate one FILE record and decode its primary nonresident $DATA."""

    def extract(
        self,
        record: bytes,
        *,
        bytes_per_sector: int,
        cluster_size: int,
        partition_offset: int = 0,
    ) -> NtfsMftDataMapping | None:
        self._validate_configuration(
            record,
            bytes_per_sector,
            cluster_size,
            partition_offset,
        )
        fixed, usa_offset, usa_count = self._apply_fixup(
            record,
            bytes_per_sector,
        )
        first_attribute_offset = self._u16(fixed, 20)
        bytes_in_use = self._u32(fixed, 24)
        bytes_allocated = self._u32(fixed, 28)
        usa_end = usa_offset + usa_count * 2
        if (
            first_attribute_offset < FILE_HEADER_SIZE
            or first_attribute_offset < usa_end
            or first_attribute_offset % 8
            or first_attribute_offset + 4 > bytes_in_use
        ):
            raise NtfsMftRecordError("first_attribute_offset_invalid")
        if (
            bytes_in_use < first_attribute_offset + 4
            or bytes_in_use > bytes_allocated
            or bytes_allocated > len(fixed)
        ):
            raise NtfsMftRecordError("file_record_size_fields_invalid")

        selected, evidence = self._walk_attributes(
            fixed,
            first_attribute_offset,
            bytes_in_use,
        )
        if selected is None:
            return None

        attribute_end = selected.start + selected.record_length
        mapping_start = selected.start + selected.mapping_pairs_offset
        mapping_region = bytes(fixed[mapping_start:attribute_end])
        mapping_diagnostic = self.diagnose_mapping_pairs_input(
            mapping_region,
            mapping_pairs_offset=selected.mapping_pairs_offset,
            attribute_boundary_ok=attribute_end <= bytes_in_use,
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
            extent_mapping = NtfsMappingPairsDecoder().decode(
                mapping_bytes,
                lowest_vcn=selected.lowest_vcn,
                highest_vcn=selected.highest_vcn,
                cluster_size=cluster_size,
                partition_offset=partition_offset,
            )
        except NtfsMappingPairsError as exc:
            raise NtfsMftRecordError(f"mapping_pairs_invalid:{exc}") from exc

        flags = self._u16(fixed, 22)
        record_number = self._u32(fixed, 44) if len(fixed) >= 48 else None
        result_evidence: dict[str, Any] = {
            **evidence,
            "usa_offset": usa_offset,
            "usa_count": usa_count,
            "sector_count": len(record) // bytes_per_sector,
            "first_attribute_offset": first_attribute_offset,
            "bytes_in_use": bytes_in_use,
            "bytes_allocated": bytes_allocated,
            "selected_attribute_offset": selected.start,
            "selected_attribute_length": selected.record_length,
            "selected_attribute_flags": selected.flags,
            "selected_attribute_nonresident": True,
            "mapping_pairs_offset": selected.mapping_pairs_offset,
            "mapping_pairs_absolute_record_offset": mapping_start,
            "mapping_pairs_region_length": (
                mapping_diagnostic.mapping_pairs_region_length
            ),
            "mapping_pairs_input_length": (
                mapping_diagnostic.mapping_pairs_input_length
            ),
            "mapping_pairs_terminator_offset": (
                mapping_diagnostic.terminator_offset
            ),
            "mapping_pairs_trailing_byte_count": (
                mapping_diagnostic.trailing_byte_count
            ),
            "mapping_pairs_trailing_nonzero_count": (
                mapping_diagnostic.trailing_nonzero_count
            ),
            "mapping_pairs_required_alignment_padding": (
                mapping_diagnostic.required_alignment_padding
            ),
            "mapping_pairs_trailing_classification": (
                mapping_diagnostic.trailing_classification
            ),
            "attribute_boundary_ok": (
                mapping_diagnostic.attribute_boundary_ok
            ),
        }
        return NtfsMftDataMapping(
            record_number=record_number,
            in_use=bool(flags & FILE_IN_USE),
            directory=bool(flags & FILE_DIRECTORY),
            lowest_vcn=selected.lowest_vcn,
            highest_vcn=selected.highest_vcn,
            allocated_size=selected.allocated_size,
            file_size=selected.file_size,
            valid_data_length=selected.valid_data_length,
            partial_extent_mapping=(
                selected.lowest_vcn != 0
                or bool(evidence["attribute_list_present"])
            ),
            extent_mapping=extent_mapping,
            evidence=result_evidence,
        )

    @staticmethod
    def _validate_configuration(
        record: bytes,
        bytes_per_sector: int,
        cluster_size: int,
        partition_offset: int,
    ) -> None:
        if not isinstance(record, bytes):
            raise ValueError("record must be bytes")
        if bytes_per_sector < 2:
            raise ValueError("bytes_per_sector must be at least two")
        if cluster_size <= 0:
            raise ValueError("cluster_size must be positive")
        if partition_offset < 0:
            raise ValueError("partition_offset must not be negative")
        if len(record) < FILE_HEADER_SIZE:
            raise NtfsMftRecordError("file_record_too_short")
        if len(record) % bytes_per_sector:
            raise NtfsMftRecordError("file_record_sector_geometry_invalid")
        if record[:4] != FILE_SIGNATURE:
            raise NtfsMftRecordError("file_signature_invalid")

    def _apply_fixup(
        self,
        record: bytes,
        bytes_per_sector: int,
    ) -> tuple[bytes, int, int]:
        usa_offset = self._u16(record, 4)
        usa_count = self._u16(record, 6)
        sector_count = len(record) // bytes_per_sector
        usa_end = usa_offset + usa_count * 2
        if (
            usa_count < 1
            or usa_count != sector_count + 1
            or usa_offset < 8
            or usa_end > len(record)
        ):
            raise NtfsMftRecordError("update_sequence_array_invalid")

        update_sequence_number = record[usa_offset : usa_offset + 2]
        if len(update_sequence_number) != 2:
            raise NtfsMftRecordError("update_sequence_array_invalid")
        trailer_offsets = tuple(
            sector_number * bytes_per_sector - 2
            for sector_number in range(1, sector_count + 1)
        )
        if any(
            record[trailer : trailer + 2] != update_sequence_number
            for trailer in trailer_offsets
        ):
            raise NtfsMftRecordError("update_sequence_mismatch")

        fixed = bytearray(record)
        for index, trailer in enumerate(trailer_offsets, start=1):
            replacement_start = usa_offset + index * 2
            fixed[trailer : trailer + 2] = record[
                replacement_start : replacement_start + 2
            ]
        return bytes(fixed), usa_offset, usa_count

    def _walk_attributes(
        self,
        fixed: bytes,
        first_attribute_offset: int,
        bytes_in_use: int,
    ) -> tuple[_DataAttribute | None, dict[str, Any]]:
        offset = first_attribute_offset
        attribute_count = 0
        named_data_count = 0
        resident_unnamed_count = 0
        attribute_list_present = False
        unnamed_data_count = 0
        selected: _DataAttribute | None = None
        end_marker_found = False

        while offset + 4 <= bytes_in_use:
            type_code = self._u32(fixed, offset)
            if type_code == ATTRIBUTE_END:
                end_marker_found = True
                break
            if offset % 8 or offset + ATTRIBUTE_HEADER_SIZE > bytes_in_use:
                raise NtfsMftRecordError("attribute_header_truncated")
            record_length = self._u32(fixed, offset + 4)
            if (
                record_length < ATTRIBUTE_HEADER_SIZE
                or record_length % 8
                or offset + record_length > bytes_in_use
            ):
                raise NtfsMftRecordError("attribute_record_length_invalid")
            nonresident = fixed[offset + 8]
            name_length = fixed[offset + 9]
            name_offset = self._u16(fixed, offset + 10)
            if nonresident not in (0, 1):
                raise NtfsMftRecordError("attribute_form_invalid")
            if name_length:
                name_end = name_offset + name_length * 2
                if name_offset < ATTRIBUTE_HEADER_SIZE or name_end > record_length:
                    raise NtfsMftRecordError("attribute_name_bounds_invalid")

            attribute_count += 1
            if type_code == ATTRIBUTE_LIST:
                attribute_list_present = True
            if type_code == ATTRIBUTE_DATA:
                if name_length:
                    named_data_count += 1
                else:
                    unnamed_data_count += 1
                    if unnamed_data_count > 1:
                        raise NtfsMftRecordError("unnamed_data_attribute_ambiguous")
                    if nonresident == 0:
                        resident_unnamed_count += 1
                    else:
                        selected = self._parse_nonresident_data(
                            fixed,
                            offset,
                            record_length,
                        )
            offset += record_length

        if not end_marker_found:
            raise NtfsMftRecordError("attribute_end_marker_missing")
        return selected, {
            "attribute_count": attribute_count,
            "named_data_attribute_count": named_data_count,
            "resident_unnamed_data_count": resident_unnamed_count,
            "attribute_list_present": attribute_list_present,
        }

    @staticmethod
    def diagnose_mapping_pairs_input(
        data: bytes,
        *,
        mapping_pairs_offset: int,
        attribute_boundary_ok: bool,
    ) -> NtfsMappingPairsInputDiagnostic:
        """Locate a semantic runlist terminator without exposing raw bytes."""
        if not isinstance(data, bytes):
            raise ValueError("data must be bytes")
        if mapping_pairs_offset < NONRESIDENT_HEADER_SIZE:
            raise ValueError("mapping_pairs_offset is invalid")

        offset = 0
        terminator_offset: int | None = None
        while offset < len(data):
            header_offset = offset
            header = data[offset]
            offset += 1
            if header == 0:
                terminator_offset = header_offset
                break
            length_size = header & 0x0F
            delta_size = header >> 4
            if (
                length_size == 0
                or length_size > 8
                or delta_size > 8
                or offset + length_size + delta_size > len(data)
            ):
                offset = len(data)
                break
            offset += length_size + delta_size

        if terminator_offset is None:
            return NtfsMappingPairsInputDiagnostic(
                mapping_pairs_region_length=len(data),
                mapping_pairs_input_length=len(data),
                terminator_offset=None,
                trailing_byte_count=0,
                trailing_nonzero_count=0,
                required_alignment_padding=None,
                trailing_classification="terminator_missing_or_unreachable",
                attribute_boundary_ok=attribute_boundary_ok,
            )

        input_length = terminator_offset + 1
        trailing = data[input_length:]
        required_padding = (-(mapping_pairs_offset + input_length)) % 8
        nonzero_count = sum(byte != 0 for byte in trailing)
        if len(trailing) != required_padding:
            classification = "trailing_data_not_alignment_padding"
        elif not trailing:
            classification = "no_trailing_bytes"
        elif nonzero_count:
            classification = "nonzero_attribute_alignment_slack"
        else:
            classification = "zero_attribute_alignment_padding"
        return NtfsMappingPairsInputDiagnostic(
            mapping_pairs_region_length=len(data),
            mapping_pairs_input_length=input_length,
            terminator_offset=terminator_offset,
            trailing_byte_count=len(trailing),
            trailing_nonzero_count=nonzero_count,
            required_alignment_padding=required_padding,
            trailing_classification=classification,
            attribute_boundary_ok=attribute_boundary_ok,
        )

    def _parse_nonresident_data(
        self,
        fixed: bytes,
        offset: int,
        record_length: int,
    ) -> _DataAttribute:
        if record_length < NONRESIDENT_HEADER_SIZE:
            raise NtfsMftRecordError("nonresident_header_truncated")
        lowest_vcn = self._u64(fixed, offset + 16)
        highest_vcn = self._u64(fixed, offset + 24)
        mapping_pairs_offset = self._u16(fixed, offset + 32)
        if (
            mapping_pairs_offset < NONRESIDENT_HEADER_SIZE
            or mapping_pairs_offset >= record_length
        ):
            raise NtfsMftRecordError("mapping_pairs_offset_invalid")
        return _DataAttribute(
            start=offset,
            record_length=record_length,
            flags=self._u16(fixed, offset + 12),
            lowest_vcn=lowest_vcn,
            highest_vcn=highest_vcn,
            mapping_pairs_offset=mapping_pairs_offset,
            allocated_size=self._u64(fixed, offset + 40),
            file_size=self._u64(fixed, offset + 48),
            valid_data_length=self._u64(fixed, offset + 56),
        )

    @staticmethod
    def _u16(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset : offset + 2], "little")

    @staticmethod
    def _u32(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset : offset + 4], "little")

    @staticmethod
    def _u64(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset : offset + 8], "little")
