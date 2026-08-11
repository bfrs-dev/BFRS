"""Recover internally consistent historical secp256k1 ECPrivateKey DER."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from bfrs.core.models import RawHit
from bfrs.core.secp256k1 import (
    GROUP_ORDER,
    decode_sec_public_key,
    scalar_multiply,
)
from bfrs.recovery.logical_berkeley_reader import PhysicalRangeReader
from bfrs.validators.bitcoin_plain_key import (
    _DerError,
    _DerReader,
    _parse_ec_private_key,
)


HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR = bytes.fromhex("0201010420")
HISTORICAL_EC_PRIVATE_KEY_DER_SIGNATURE = (
    "historical_ec_private_key_der_anchor"
)
MAX_ORPHAN_DER_READ_SIZE = 1024


@dataclass(frozen=True, slots=True)
class OrphanHistoricalECPrivateKeyLocation:
    absolute_der_offset: int
    der_length: int
    public_key_encoding: str
    validation_strength: str


@dataclass(frozen=True, slots=True)
class OrphanHistoricalECPrivateKeyRecovery:
    source: str
    raw_der_anchor_count: int
    candidate_der_count: int
    valid_secp256k1_der_count: int
    canonical_der_count: int
    valid_with_embedded_pubkey_count: int
    valid_without_embedded_pubkey_count: int
    locations: tuple[OrphanHistoricalECPrivateKeyLocation, ...]
    reasons: tuple[str, ...]
    evidence: dict[str, Any]


class OrphanHistoricalECPrivateKeyRecoveryPipeline:
    """Validate only DER sequences directly implied by strong anchor hits."""

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
            raise ValueError("invalid DER recovery range")
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
            raise ValueError("hit source/range does not match DER recovery input")
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

    def run(self) -> OrphanHistoricalECPrivateKeyRecovery:
        candidate_starts: set[int] = set()
        locations: dict[int, OrphanHistoricalECPrivateKeyLocation] = {}
        rejection_counts: dict[str, int] = {}
        read_failure_count = 0
        truncated_read_count = 0

        for hit in self.hits:
            for start, header_length in self._candidate_starts(hit):
                if start in candidate_starts:
                    continue
                candidate_starts.add(start)
                requested = min(
                    self.maximum_read_size,
                    self.range_end - start,
                )
                if requested <= 0:
                    continue
                try:
                    data = self.range_reader.read_at(start, requested)
                except OSError:
                    read_failure_count += 1
                    continue
                if not isinstance(data, bytes) or len(data) > requested:
                    read_failure_count += 1
                    continue
                if requested < self.maximum_read_size or len(data) < requested:
                    truncated_read_count += 1
                if (
                    len(data) < header_length + len(HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR)
                    or data[header_length : header_length + 5]
                    != HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR
                ):
                    self._reject(rejection_counts, "anchor_position_mismatch")
                    continue
                try:
                    reader = _DerReader(data)
                    reader.read(0x30)
                    der_length = reader.offset
                    der = data[:der_length]
                    parsed = _parse_ec_private_key(der)
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
                encoding = (
                    "compressed"
                    if len(parsed.embedded_public_key) == 33
                    else "uncompressed"
                )
                locations[start] = OrphanHistoricalECPrivateKeyLocation(
                    absolute_der_offset=start,
                    der_length=der_length,
                    public_key_encoding=encoding,
                    validation_strength="embedded_pubkey_match",
                )

        ordered = tuple(locations[offset] for offset in sorted(locations))
        return OrphanHistoricalECPrivateKeyRecovery(
            source=self.source,
            raw_der_anchor_count=len(self.hits),
            candidate_der_count=len(candidate_starts),
            valid_secp256k1_der_count=len(ordered),
            canonical_der_count=len(ordered),
            valid_with_embedded_pubkey_count=len(ordered),
            valid_without_embedded_pubkey_count=0,
            locations=ordered,
            reasons=(
                ()
                if ordered
                else ("no_valid_historical_secp256k1_der",)
            ),
            evidence={
                "maximum_read_size": self.maximum_read_size,
                "read_failure_count": read_failure_count,
                "truncated_read_count": truncated_read_count,
                "rejection_counts": tuple(sorted(rejection_counts.items())),
            },
        )

    def recover(self) -> OrphanHistoricalECPrivateKeyRecovery:
        return self.run()

    def _candidate_starts(self, hit: RawHit) -> tuple[tuple[int, int], ...]:
        candidates: list[tuple[int, int]] = []
        for header_length, length_marker in ((2, "short"), (3, 0x81), (4, 0x82)):
            start = hit.start_offset - header_length
            if start < self.range_start:
                continue
            try:
                header = self.range_reader.read_at(start, header_length)
            except OSError:
                continue
            if not isinstance(header, bytes) or len(header) != header_length:
                continue
            if not header or header[0] != 0x30:
                continue
            if length_marker == "short":
                if header[1] >= 0x80:
                    continue
            elif header[1] != length_marker:
                continue
            candidates.append((start, header_length))
        return tuple(candidates)

    @staticmethod
    def _reject(counts: dict[str, int], reason: str) -> None:
        counts[reason] = counts.get(reason, 0) + 1
