"""Recover strict historical ECPrivateKey inner fragments after outer loss."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from bfrs.core.models import RawHit
from bfrs.core.secp256k1 import GROUP_ORDER, decode_sec_public_key, scalar_multiply
from bfrs.recovery.logical_berkeley_reader import PhysicalRangeReader
from bfrs.recovery.orphan_private_key_der import (
    HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR,
    HISTORICAL_EC_PRIVATE_KEY_DER_SIGNATURE,
    MAX_ORPHAN_DER_READ_SIZE,
)
from bfrs.validators.bitcoin_plain_key import (
    _DerError,
    _DerReader,
    _parse_ec_private_key,
)


INNER_FRAGMENT_VALIDATION_STRENGTH = "cryptographic_inner_fragment"


@dataclass(frozen=True, slots=True)
class OrphanHistoricalECPrivateKeyFragmentLocation:
    absolute_anchor_offset: int
    recovered_fragment_length: int
    public_key_encoding: str
    validation_strength: str


@dataclass(frozen=True, slots=True)
class OrphanHistoricalECPrivateKeyFragmentRecovery:
    source: str
    raw_inner_anchor_count: int
    candidate_inner_fragment_count: int
    valid_inner_fragment_count: int
    locations: tuple[OrphanHistoricalECPrivateKeyFragmentLocation, ...]
    reasons: tuple[str, ...]
    evidence: dict[str, Any]


class OrphanHistoricalECPrivateKeyFragmentRecoveryPipeline:
    """Validate exact inner SEC1 fields without claiming complete DER."""

    def __init__(
        self,
        hits: Iterable[RawHit],
        *,
        source: str,
        range_start: int,
        range_end: int,
        range_reader: PhysicalRangeReader,
        maximum_read_size: int = MAX_ORPHAN_DER_READ_SIZE,
    ) -> None:
        collected = tuple(hits)
        if not source:
            raise ValueError("source must not be empty")
        if range_start < 0 or range_end < range_start:
            raise ValueError("invalid inner-fragment range")
        if maximum_read_size <= 0 or maximum_read_size > MAX_ORPHAN_DER_READ_SIZE:
            raise ValueError("maximum_read_size must be from 1 through 1024")
        if not hasattr(range_reader, "read_at"):
            raise ValueError("range_reader must provide read_at")
        if any(not isinstance(hit, RawHit) for hit in collected):
            raise ValueError("hits must contain RawHit values")
        if any(
            hit.source != source
            or not range_start <= hit.start_offset <= hit.end_offset <= range_end
            for hit in collected
        ):
            raise ValueError("hit source/range does not match fragment input")
        self.hits = tuple(
            sorted(
                (
                    hit
                    for hit in collected
                    if hit.hit_type == HISTORICAL_EC_PRIVATE_KEY_DER_SIGNATURE
                ),
                key=lambda hit: (hit.start_offset, hit.end_offset),
            )
        )
        self.source = source
        self.range_start = range_start
        self.range_end = range_end
        self.range_reader = range_reader
        self.maximum_read_size = maximum_read_size

    def run(self) -> OrphanHistoricalECPrivateKeyFragmentRecovery:
        candidate_offsets: set[int] = set()
        locations: dict[
            int, OrphanHistoricalECPrivateKeyFragmentLocation
        ] = {}
        rejection_counts: dict[str, int] = {}
        read_failure_count = 0
        truncated_read_count = 0

        for hit in self.hits:
            offset = hit.start_offset
            if offset in candidate_offsets:
                continue
            requested = min(self.maximum_read_size, self.range_end - offset)
            if requested <= 0:
                continue
            try:
                data = self.range_reader.read_at(offset, requested)
            except OSError:
                read_failure_count += 1
                continue
            if not isinstance(data, bytes) or len(data) > requested:
                read_failure_count += 1
                continue
            if requested < self.maximum_read_size or len(data) < requested:
                truncated_read_count += 1
            if not data.startswith(HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR):
                self._reject(rejection_counts, "inner_anchor_mismatch")
                continue
            candidate_offsets.add(offset)
            try:
                inner_length = self._inner_fragment_length(data)
                inner = data[:inner_length]
                parsed = _parse_ec_private_key(
                    b"\x30" + self._der_length(inner_length) + inner
                )
            except _DerError as error:
                self._reject(rejection_counts, error.reason)
                continue
            if len(parsed.private_bytes) != 32:
                self._reject(rejection_counts, "private_scalar_invalid")
                continue
            scalar = int.from_bytes(parsed.private_bytes, "big")
            if not 1 <= scalar < GROUP_ORDER:
                self._reject(rejection_counts, "private_scalar_invalid")
                continue
            embedded_point = decode_sec_public_key(parsed.embedded_public_key)
            if embedded_point is None:
                self._reject(rejection_counts, "embedded_public_key_invalid")
                continue
            if embedded_point != scalar_multiply(scalar):
                self._reject(rejection_counts, "embedded_public_key_mismatch")
                continue
            locations[offset] = OrphanHistoricalECPrivateKeyFragmentLocation(
                absolute_anchor_offset=offset,
                recovered_fragment_length=inner_length,
                public_key_encoding=(
                    "compressed"
                    if len(parsed.embedded_public_key) == 33
                    else "uncompressed"
                ),
                validation_strength=INNER_FRAGMENT_VALIDATION_STRENGTH,
            )

        ordered = tuple(locations[offset] for offset in sorted(locations))
        return OrphanHistoricalECPrivateKeyFragmentRecovery(
            source=self.source,
            raw_inner_anchor_count=len(self.hits),
            candidate_inner_fragment_count=len(candidate_offsets),
            valid_inner_fragment_count=len(ordered),
            locations=ordered,
            reasons=(
                ()
                if ordered
                else ("no_valid_historical_private_key_inner_fragment",)
            ),
            evidence={
                "maximum_read_size": self.maximum_read_size,
                "read_failure_count": read_failure_count,
                "truncated_read_count": truncated_read_count,
                "rejection_counts": tuple(sorted(rejection_counts.items())),
            },
        )

    def recover(self) -> OrphanHistoricalECPrivateKeyFragmentRecovery:
        return self.run()

    @staticmethod
    def _inner_fragment_length(data: bytes) -> int:
        reader = _DerReader(data)
        version = reader.read(0x02)
        if version != b"\x01":
            raise _DerError("der_version_invalid")
        private_bytes = reader.read(0x04)
        if len(private_bytes) != 32:
            raise _DerError("private_scalar_invalid")
        reader.read(0xA0)
        reader.read(0xA1)
        return reader.offset

    @staticmethod
    def _der_length(value: int) -> bytes:
        if value < 0x80:
            return bytes((value,))
        encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return bytes((0x80 | len(encoded),)) + encoded

    @staticmethod
    def _reject(counts: dict[str, int], reason: str) -> None:
        counts[reason] = counts.get(reason, 0) + 1
