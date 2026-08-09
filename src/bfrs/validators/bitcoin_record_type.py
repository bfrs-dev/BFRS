"""Decode historical Bitcoin wallet record type framing from Berkeley keys."""

from collections.abc import Iterable
from dataclasses import dataclass

from bfrs.recovery.berkeley_records import BerkeleyLeafPair


MAX_RECORD_TYPE_LENGTH = 64
DEFAULT_RECORD_TYPES = frozenset(
    {
        "key",
        "wkey",
        "defaultkey",
        "ckey",
        "mkey",
        "keymeta",
    }
)


@dataclass(frozen=True, slots=True)
class CompactSizeResult:
    value: int
    encoded_length: int
    canonical: bool


@dataclass(frozen=True, slots=True)
class BitcoinRecordType:
    name: str
    name_length: int
    prefix_length: int
    remaining_key: bytes
    canonical_framing: bool


def decode_compact_size(
    data: bytes,
    offset: int = 0,
) -> CompactSizeResult | None:
    """Decode CompactSize without rejecting forms tolerated by old readers."""
    if offset < 0 or offset >= len(data):
        return None

    marker = data[offset]
    if marker < 253:
        return CompactSizeResult(marker, 1, True)

    if marker == 253:
        payload_length = 2
        canonical_minimum = 253
    elif marker == 254:
        payload_length = 4
        canonical_minimum = 1 << 16
    else:
        payload_length = 8
        canonical_minimum = 1 << 32

    end = offset + 1 + payload_length
    if end > len(data):
        return None

    value = int.from_bytes(data[offset + 1 : end], "little")
    return CompactSizeResult(
        value=value,
        encoded_length=1 + payload_length,
        canonical=value >= canonical_minimum,
    )


class BitcoinRecordTypeDecoder:
    """Recognize an allowlisted record name at the start of a Berkeley key."""

    def __init__(self, allowed_types: Iterable[str] | None = None) -> None:
        candidates: Iterable[str]
        if allowed_types is None:
            candidates = DEFAULT_RECORD_TYPES
        else:
            if isinstance(allowed_types, (str, bytes)):
                raise TypeError("allowed_types must contain names, not be a name")
            candidates = allowed_types

        validated: set[str] = set()
        for name in candidates:
            if not isinstance(name, str):
                raise TypeError("record type names must be strings")
            if not name:
                raise ValueError("record type names must not be empty")
            try:
                encoded = name.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ValueError("record type names must be ASCII") from exc
            if len(encoded) > MAX_RECORD_TYPE_LENGTH:
                raise ValueError("record type name exceeds safe length limit")
            if name in validated:
                raise ValueError(f"duplicate record type name: {name}")
            validated.add(name)

        self.allowed_types = frozenset(validated)

    def decode(self, key_payload: bytes) -> BitcoinRecordType | None:
        length = decode_compact_size(key_payload)
        if length is None or not 0 < length.value <= MAX_RECORD_TYPE_LENGTH:
            return None

        name_start = length.encoded_length
        name_end = name_start + length.value
        if name_end > len(key_payload):
            return None

        try:
            name = key_payload[name_start:name_end].decode("ascii")
        except UnicodeDecodeError:
            return None
        if name not in self.allowed_types:
            return None

        # Canonical framing is normal historical writer output. A noncanonical
        # length could be accepted by old readers, but needs stronger later
        # structural confirmation and is not promoted here.
        return BitcoinRecordType(
            name=name,
            name_length=length.value,
            prefix_length=name_end,
            remaining_key=bytes(key_payload[name_end:]),
            canonical_framing=length.canonical,
        )

    def decode_pair(self, pair: BerkeleyLeafPair) -> BitcoinRecordType | None:
        """Decode only the key payload; the value payload is never inspected."""
        return self.decode(pair.key.payload)
