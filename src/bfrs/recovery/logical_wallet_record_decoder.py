"""Decode legacy Bitcoin wallet records from validated logical Berkeley pairs."""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from bfrs.core.models import ValidationStatus
from bfrs.core.secp256k1 import decode_sec_public_key
from bfrs.recovery.berkeley_records import BerkeleyLeafPair, BerkeleyRecord
from bfrs.validators.bitcoin_record_type import decode_compact_size
from bfrs.validators.logical_encrypted_wallet_evidence import (
    LogicalBerkeleyRecordPageContext,
)


SUPPORTED_RECORD_TYPES = frozenset(
    {"version", "minversion", "key", "ckey", "mkey", "keymeta", "defaultkey"}
)
_MAX_VECTOR_LENGTH = 1 << 24


class LogicalWalletRecordState(Enum):
    VALID = "VALID"
    PARTIAL = "PARTIAL"
    REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True)
class LogicalWalletRecordProvenance:
    source: str
    physical_key_range: tuple[int, int]
    physical_value_range: tuple[int, int]
    logical_page_identity: tuple[Any, int]
    logical_key_range: tuple[int, int]
    logical_value_range: tuple[int, int]
    key_length: int
    value_length: int
    page_validation_status: ValidationStatus


@dataclass(frozen=True, slots=True)
class DecodedLogicalWalletRecord:
    state: LogicalWalletRecordState
    record_type: str | None
    provenance: LogicalWalletRecordProvenance
    canonical_framing: bool
    findings: tuple[str, ...]
    public_key: bytes | None = None
    private_key_payload: bytes | None = None
    encrypted_secret: bytes | None = None
    master_key_id: int | None = None
    encrypted_master_key: bytes | None = None
    salt: bytes | None = None
    derivation_method: int | None = None
    derivation_iterations: int | None = None
    other_derivation_parameters: bytes | None = None
    keymeta_version: int | None = None
    keymeta_creation_time: int | None = None
    keymeta_hd_path: str | None = None
    keymeta_hd_seed_id: bytes | None = None
    keymeta_key_origin_fingerprint: bytes | None = None
    keymeta_key_origin_path: tuple[int, ...] | None = None
    keymeta_has_key_origin: bool | None = None
    wallet_version: int | None = None


class _DecodeFailure(Exception):
    def __init__(self, reason: str, *, partial: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.partial = partial


class _Reader:
    def __init__(self, data: bytes, label: str) -> None:
        self.data = data
        self.label = label
        self.offset = 0
        self.canonical = True

    def compact(self) -> int:
        decoded = decode_compact_size(self.data, self.offset)
        if decoded is None:
            raise _DecodeFailure(f"{self.label}_compactsize_malformed")
        self.offset += decoded.encoded_length
        self.canonical = self.canonical and decoded.canonical
        if not decoded.canonical:
            raise _DecodeFailure(f"{self.label}_compactsize_noncanonical")
        if decoded.value > _MAX_VECTOR_LENGTH:
            raise _DecodeFailure(f"{self.label}_length_impossible")
        return decoded.value

    def vector(self) -> bytes:
        length = self.compact()
        end = self.offset + length
        if end > len(self.data):
            raise _DecodeFailure(f"{self.label}_truncated", partial=True)
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def fixed(self, length: int) -> bytes:
        end = self.offset + length
        if end > len(self.data):
            raise _DecodeFailure(f"{self.label}_truncated", partial=True)
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def require_end(self) -> None:
        if self.offset != len(self.data):
            raise _DecodeFailure(f"{self.label}_trailing_data")


class LogicalBitcoinWalletRecordDecoderV1:
    """Decode only supplied pairs from an accepted mapped logical page."""

    def decode_context(
        self, context: LogicalBerkeleyRecordPageContext
    ) -> tuple[DecodedLogicalWalletRecord, ...]:
        if not isinstance(context, LogicalBerkeleyRecordPageContext):
            raise TypeError("context must be LogicalBerkeleyRecordPageContext")
        self._require_accepted_context(context)
        return tuple(self.decode_pair(context, pair) for pair in context.extraction.pairs)

    def decode_pair(
        self,
        context: LogicalBerkeleyRecordPageContext,
        pair: BerkeleyLeafPair,
    ) -> DecodedLogicalWalletRecord:
        self._require_accepted_context(context)
        if pair not in context.extraction.pairs:
            raise ValueError("pair does not belong to the logical page context")
        provenance = self._provenance(context, pair)
        record_type: str | None = None
        fields: dict[str, Any] = {}
        canonical = True
        try:
            key = _Reader(pair.key.payload, "record_type")
            name_length = key.compact()
            if name_length == 0 or name_length > 64:
                raise _DecodeFailure("record_type_length_invalid")
            name_bytes = key.fixed(name_length)
            try:
                record_type = name_bytes.decode("ascii")
            except UnicodeDecodeError as exc:
                raise _DecodeFailure("record_type_not_ascii") from exc
            if record_type not in SUPPORTED_RECORD_TYPES:
                raise _DecodeFailure("record_type_unsupported")

            if record_type in {"key", "ckey", "keymeta"}:
                public_key = key.vector()
                self._validate_public_key(public_key)
                fields["public_key"] = public_key
            elif record_type == "mkey":
                fields["master_key_id"] = int.from_bytes(key.fixed(4), "little")
            key.require_end()
            canonical = canonical and key.canonical

            if record_type == "key":
                self._decode_key(pair.value.payload, fields)
            elif record_type == "ckey":
                self._decode_ckey(pair.value.payload, fields)
            elif record_type == "mkey":
                self._decode_mkey(pair.value.payload, fields)
            elif record_type == "keymeta":
                self._decode_keymeta(pair.value.payload, fields)
            elif record_type == "defaultkey":
                self._decode_defaultkey(pair.value.payload, fields)
            else:
                self._decode_version(pair.value.payload, fields)
            return DecodedLogicalWalletRecord(
                LogicalWalletRecordState.VALID, record_type, provenance,
                canonical, ("serialization_complete",), **fields
            )
        except _DecodeFailure as exc:
            state = (
                LogicalWalletRecordState.PARTIAL
                if exc.partial else LogicalWalletRecordState.REJECTED
            )
            return DecodedLogicalWalletRecord(
                state, record_type, provenance, False, (exc.reason,), **fields
            )

    @staticmethod
    def _decode_key(value: bytes, fields: dict[str, Any]) -> None:
        reader = _Reader(value, "private_key_value")
        private = reader.vector()
        if not private:
            raise _DecodeFailure("private_key_value_empty")
        remainder = value[reader.offset:]
        if remainder and len(remainder) != 32:
            raise _DecodeFailure("private_key_value_trailing_data")
        fields["private_key_payload"] = bytes(value)

    @staticmethod
    def _decode_ckey(value: bytes, fields: dict[str, Any]) -> None:
        reader = _Reader(value, "encrypted_secret")
        encrypted = reader.vector()
        reader.require_end()
        if len(encrypted) != 48:
            raise _DecodeFailure("encrypted_secret_length_invalid")
        fields["encrypted_secret"] = encrypted

    @staticmethod
    def _decode_mkey(value: bytes, fields: dict[str, Any]) -> None:
        reader = _Reader(value, "master_key_value")
        encrypted = reader.vector()
        salt = reader.vector()
        method = int.from_bytes(reader.fixed(4), "little")
        iterations = int.from_bytes(reader.fixed(4), "little")
        other = reader.vector()
        reader.require_end()
        if not encrypted or len(encrypted) % 16:
            raise _DecodeFailure("encrypted_master_key_length_invalid")
        if not salt:
            raise _DecodeFailure("salt_length_invalid")
        if iterations == 0:
            raise _DecodeFailure("derivation_iterations_invalid")
        fields.update(encrypted_master_key=encrypted, salt=salt,
                      derivation_method=method, derivation_iterations=iterations,
                      other_derivation_parameters=other)

    @staticmethod
    def _decode_keymeta(value: bytes, fields: dict[str, Any]) -> None:
        if len(value) < 12:
            raise _DecodeFailure("keymeta_value_truncated", partial=True)
        version = int.from_bytes(value[:4], "little", signed=True)
        fields["keymeta_version"] = version
        fields["keymeta_creation_time"] = int.from_bytes(value[4:12], "little", signed=True)
        if version < 10:
            if len(value) != 12:
                raise _DecodeFailure("keymeta_layout_unsupported")
            return
        if version > 12:
            raise _DecodeFailure("keymeta_layout_unsupported")

        reader = _Reader(value, "keymeta_value")
        reader.offset = 12
        encoded_path = reader.vector()
        try:
            hd_path = encoded_path.decode("ascii")
        except UnicodeDecodeError as exc:
            raise _DecodeFailure("keymeta_hd_path_invalid") from exc
        seed_id = reader.fixed(20)
        fields["keymeta_hd_path"] = hd_path
        fields["keymeta_hd_seed_id"] = seed_id
        if version in (10, 11):
            reader.require_end()
            return

        fingerprint = reader.fixed(4)
        path_count = reader.compact()
        if path_count > 1024:
            raise _DecodeFailure("keymeta_origin_path_length_impossible")
        path_bytes = reader.fixed(path_count * 4)
        has_origin = reader.fixed(1)[0]
        if has_origin not in (0, 1):
            raise _DecodeFailure("keymeta_has_origin_invalid")
        reader.require_end()
        fields["keymeta_key_origin_fingerprint"] = fingerprint
        fields["keymeta_key_origin_path"] = tuple(
            int.from_bytes(path_bytes[index:index + 4], "little")
            for index in range(0, len(path_bytes), 4)
        )
        fields["keymeta_has_key_origin"] = bool(has_origin)

    @classmethod
    def _decode_defaultkey(cls, value: bytes, fields: dict[str, Any]) -> None:
        reader = _Reader(value, "defaultkey_value")
        public_key = reader.vector()
        reader.require_end()
        cls._validate_public_key(public_key)
        fields["public_key"] = public_key

    @staticmethod
    def _decode_version(value: bytes, fields: dict[str, Any]) -> None:
        if len(value) < 4:
            raise _DecodeFailure("version_value_truncated", partial=True)
        if len(value) > 4:
            raise _DecodeFailure("version_value_trailing_data")
        version = int.from_bytes(value, "little", signed=True)
        if version < 0:
            raise _DecodeFailure("version_value_invalid")
        fields["wallet_version"] = version

    @staticmethod
    def _validate_public_key(public_key: bytes) -> None:
        if len(public_key) not in (33, 65):
            raise _DecodeFailure("pubkey_length_invalid")
        if (len(public_key) == 33 and public_key[0] not in (2, 3)) or (
            len(public_key) == 65 and public_key[0] != 4
        ):
            raise _DecodeFailure("pubkey_prefix_invalid")
        if decode_sec_public_key(public_key) is None:
            raise _DecodeFailure("pubkey_point_invalid")

    @staticmethod
    def _provenance(context: LogicalBerkeleyRecordPageContext,
                    pair: BerkeleyLeafPair) -> LogicalWalletRecordProvenance:
        def physical(record: BerkeleyRecord) -> tuple[int, int]:
            return (record.absolute_offset, record.absolute_offset + 3 + record.length)
        def logical(record: BerkeleyRecord) -> tuple[int, int]:
            start = context.page_number * context.page_size + record.local_offset
            return (start, start + 3 + record.length)
        return LogicalWalletRecordProvenance(
            context.source, physical(pair.key), physical(pair.value),
            (context.identity, context.page_number), logical(pair.key),
            logical(pair.value), len(pair.key.payload), len(pair.value.payload),
            context.page_status,
        )

    @staticmethod
    def _require_accepted_context(context: LogicalBerkeleyRecordPageContext) -> None:
        if context.page_status not in (
            ValidationStatus.STRUCTURAL,
            ValidationStatus.FRAGMENT,
        ):
            raise ValueError("logical page context was not accepted by the validator")
