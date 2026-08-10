"""Decode NTFS nonresident mapping pairs into logical file extents."""

from dataclasses import dataclass

from bfrs.recovery.logical_page_map import LogicalFileExtent


MAX_FIELD_BYTES = 8


class NtfsMappingPairsError(ValueError):
    """Controlled failure raised for malformed mapping-pairs bytes."""


@dataclass(frozen=True, slots=True)
class NtfsDataRun:
    vcn_start: int
    cluster_count: int
    lcn_start: int | None
    sparse: bool

    def __post_init__(self) -> None:
        if self.vcn_start < 0:
            raise ValueError("vcn_start must not be negative")
        if self.cluster_count <= 0:
            raise ValueError("cluster_count must be positive")
        if self.sparse:
            if self.lcn_start is not None:
                raise ValueError("sparse run must not have lcn_start")
        elif self.lcn_start is None or self.lcn_start < 0:
            raise ValueError("allocated run requires nonnegative lcn_start")

    @property
    def vcn_end(self) -> int:
        return self.vcn_start + self.cluster_count

    @property
    def logical_cluster_end(self) -> int:
        return self.vcn_end


@dataclass(frozen=True, slots=True)
class NtfsSparseRange:
    logical_start: int
    length: int

    def __post_init__(self) -> None:
        if self.logical_start < 0:
            raise ValueError("logical_start must not be negative")
        if self.length <= 0:
            raise ValueError("length must be positive")

    @property
    def logical_end(self) -> int:
        return self.logical_start + self.length


@dataclass(frozen=True, slots=True)
class NtfsExtentMapping:
    runs: tuple[NtfsDataRun, ...]
    extents: tuple[LogicalFileExtent, ...]
    sparse_ranges: tuple[NtfsSparseRange, ...]
    lowest_vcn: int
    highest_vcn: int
    cluster_size: int
    partition_offset: int


class NtfsMappingPairsDecoder:
    """Decode one complete, zero-terminated NTFS mapping-pairs stream."""

    def decode(
        self,
        data: bytes,
        *,
        lowest_vcn: int,
        highest_vcn: int | None,
        cluster_size: int,
        partition_offset: int = 0,
    ) -> NtfsExtentMapping:
        self._validate_configuration(
            data,
            lowest_vcn,
            highest_vcn,
            cluster_size,
            partition_offset,
        )

        offset = 0
        current_vcn = lowest_vcn
        current_lcn = 0
        runs: list[NtfsDataRun] = []
        extents: list[LogicalFileExtent] = []
        sparse_ranges: list[NtfsSparseRange] = []
        terminated = False

        while offset < len(data):
            header = data[offset]
            offset += 1
            if header == 0:
                terminated = True
                break

            length_size = header & 0x0F
            delta_size = header >> 4
            if length_size == 0:
                raise NtfsMappingPairsError("run_length_field_missing")
            if length_size > MAX_FIELD_BYTES or delta_size > MAX_FIELD_BYTES:
                raise NtfsMappingPairsError("mapping_pair_field_too_large")
            field_end = offset + length_size + delta_size
            if field_end > len(data):
                raise NtfsMappingPairsError("mapping_pair_truncated")

            cluster_count = int.from_bytes(
                data[offset : offset + length_size],
                "little",
                signed=False,
            )
            offset += length_size
            if cluster_count == 0:
                raise NtfsMappingPairsError("run_length_zero")

            vcn_start = current_vcn
            current_vcn += cluster_count
            if current_vcn < 0:
                raise NtfsMappingPairsError("vcn_negative")

            if delta_size == 0:
                run = NtfsDataRun(vcn_start, cluster_count, None, True)
                sparse_ranges.append(
                    NtfsSparseRange(
                        logical_start=vcn_start * cluster_size,
                        length=cluster_count * cluster_size,
                    )
                )
            else:
                lcn_delta = int.from_bytes(
                    data[offset : offset + delta_size],
                    "little",
                    signed=True,
                )
                current_lcn += lcn_delta
                if current_lcn < 0:
                    raise NtfsMappingPairsError("lcn_negative")
                run = NtfsDataRun(
                    vcn_start,
                    cluster_count,
                    current_lcn,
                    False,
                )
                physical_start = partition_offset + current_lcn * cluster_size
                if physical_start < 0:
                    raise NtfsMappingPairsError("physical_offset_negative")
                extents.append(
                    LogicalFileExtent(
                        logical_start=vcn_start * cluster_size,
                        physical_start=physical_start,
                        length=cluster_count * cluster_size,
                    )
                )
            offset += delta_size
            runs.append(run)

        if not terminated:
            raise NtfsMappingPairsError("mapping_pairs_terminator_missing")
        if any(data[offset:]):
            raise NtfsMappingPairsError("mapping_pairs_trailing_data")

        decoded_highest_vcn = current_vcn - 1
        if highest_vcn is not None and decoded_highest_vcn != highest_vcn:
            raise NtfsMappingPairsError("highest_vcn_mismatch")

        return NtfsExtentMapping(
            runs=tuple(runs),
            extents=tuple(extents),
            sparse_ranges=tuple(sparse_ranges),
            lowest_vcn=lowest_vcn,
            highest_vcn=decoded_highest_vcn,
            cluster_size=cluster_size,
            partition_offset=partition_offset,
        )

    @staticmethod
    def _validate_configuration(
        data: bytes,
        lowest_vcn: int,
        highest_vcn: int | None,
        cluster_size: int,
        partition_offset: int,
    ) -> None:
        if not isinstance(data, bytes):
            raise ValueError("data must be bytes")
        if lowest_vcn < 0:
            raise ValueError("lowest_vcn must not be negative")
        if highest_vcn is not None and highest_vcn < lowest_vcn:
            raise ValueError("highest_vcn must not precede lowest_vcn")
        if cluster_size <= 0:
            raise ValueError("cluster_size must be positive")
        if partition_offset < 0:
            raise ValueError("partition_offset must not be negative")
