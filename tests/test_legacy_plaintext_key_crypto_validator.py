from dataclasses import replace
import hashlib

from bfrs.core.models import ValidationStatus
from bfrs.core.secp256k1 import FIELD_PRIME, GENERATOR, GROUP_ORDER, encode_sec_public_key, scalar_multiply
from bfrs.recovery.berkeley_records import BerkeleyLeafPair, BerkeleyRecord, BerkeleyRecordExtraction
from bfrs.recovery.legacy_plaintext_key_crypto_validator import (
    LegacyPlaintextKeyCryptographicValidatorV1, PlaintextKeyCryptoState,
    PrivateKeyRecoveryClassification,
)
from bfrs.recovery.legacy_wallet_candidate_assembler import LegacyBitcoinWalletCandidateAssemblerV1
from bfrs.recovery.logical_berkeley_reader import LogicalBerkeleyDatabaseIdentity
from bfrs.recovery.logical_btree_membership import LogicalBerkeleySubdatabaseIdentity
from bfrs.recovery.logical_wallet_record_decoder import LogicalBitcoinWalletRecordDecoderV1
from bfrs.validators.logical_encrypted_wallet_evidence import LogicalBerkeleyRecordPageContext


SOURCE = r"E:\evidence\wallet.img"
PAGE_SIZE = 1024
OID = bytes.fromhex("2A8648CE3D0101")


def length(value):
    if value < 128: return bytes((value,))
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def tlv(tag, value): return bytes((tag,)) + length(len(value)) + value


def integer(value):
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80: encoded = b"\x00" + encoded
    return tlv(2, encoded)


def vector(value):
    if len(value) < 253: return bytes((len(value),)) + value
    return b"\xfd" + len(value).to_bytes(2, "little") + value


def private_der(scalar, *, compressed, private_bytes=None, embedded_scalar=None):
    private_bytes = scalar.to_bytes(32, "big") if private_bytes is None else private_bytes
    embedded_scalar = scalar if embedded_scalar is None else embedded_scalar
    embedded = encode_sec_public_key(scalar_multiply(embedded_scalar), compressed=compressed)
    field = tlv(0x30, tlv(6, OID) + integer(FIELD_PRIME))
    curve = tlv(0x30, tlv(4, b"\x00") + tlv(4, b"\x07"))
    params = tlv(0x30, integer(1) + field + curve
                 + tlv(4, encode_sec_public_key(GENERATOR, compressed=compressed))
                 + integer(GROUP_ORDER) + integer(1))
    return tlv(0x30, integer(1) + tlv(4, private_bytes) + tlv(0xA0, params)
               + tlv(0xA1, tlv(3, b"\x00" + embedded)))


def decoded_key(scalar=1, *, compressed=False, key_scalar=None, private_bytes=None,
                checksum=False, checksum_valid=True, der=None, page=4, physical=10000):
    key_scalar = scalar if key_scalar is None else key_scalar
    public = encode_sec_public_key(scalar_multiply(key_scalar), compressed=compressed)
    der = private_der(scalar, compressed=compressed, private_bytes=private_bytes) if der is None else der
    value = vector(der)
    if checksum:
        digest = hashlib.sha256(hashlib.sha256(public + der).digest()).digest()
        value += digest if checksum_valid else bytes((digest[0] ^ 1,)) + digest[1:]
    key_payload = b"\x03key" + vector(public)
    def raw(payload, local, slot):
        return BerkeleyRecord(slot, local, physical + local, len(payload), 1, False, payload)
    pair = BerkeleyLeafPair(0, raw(key_payload, 20, 0), raw(value, 500, 1))
    extraction = BerkeleyRecordExtraction(page, ValidationStatus.STRUCTURAL,
        (pair.key, pair.value), (pair,), 2, 0, 0, ())
    database = LogicalBerkeleyDatabaseIdentity(SOURCE, PAGE_SIZE, "little", "file-1")
    identity = LogicalBerkeleySubdatabaseIdentity(database, 0, 1, PAGE_SIZE, "little")
    context = LogicalBerkeleyRecordPageContext(identity, SOURCE, page, physical,
        PAGE_SIZE, ValidationStatus.STRUCTURAL, extraction)
    return LogicalBitcoinWalletRecordDecoderV1().decode_context(context)[0]


def validate(*records):
    candidate = LegacyBitcoinWalletCandidateAssemblerV1().assemble(records)[0]
    return LegacyPlaintextKeyCryptographicValidatorV1().validate_candidate(candidate)


def test_valid_uncompressed_legacy_private_key():
    result = validate(decoded_key(2)).validations[0]
    assert result.state is PlaintextKeyCryptoState.CRYPTO_VALID
    assert result.public_key_compressed is False
    assert result.recovery_classification is PrivateKeyRecoveryClassification.RECOVERED_PRIVATE_KEY


def test_valid_compressed_legacy_private_key():
    result = validate(decoded_key(2, compressed=True)).validations[0]
    assert result.state is PlaintextKeyCryptoState.CRYPTO_VALID
    assert result.public_key_compressed is True


def test_minimum_valid_scalar():
    assert validate(decoded_key(1)).validations[0].state is PlaintextKeyCryptoState.CRYPTO_VALID


def test_maximum_valid_scalar():
    assert validate(decoded_key(GROUP_ORDER - 1)).validations[0].state is PlaintextKeyCryptoState.CRYPTO_VALID


def test_scalar_zero_is_rejected():
    record = decoded_key(1, private_bytes=bytes(32))
    assert validate(record).validations[0].state is PlaintextKeyCryptoState.PRIVATE_SCALAR_INVALID


def test_scalar_at_curve_order_is_rejected():
    record = decoded_key(1, private_bytes=GROUP_ORDER.to_bytes(32, "big"))
    assert validate(record).validations[0].state is PlaintextKeyCryptoState.PRIVATE_SCALAR_INVALID


def test_public_key_mismatch():
    result = validate(decoded_key(1, key_scalar=2)).validations[0]
    assert result.state is PlaintextKeyCryptoState.PUBLIC_KEY_MISMATCH
    assert result.recovery_classification is PrivateKeyRecoveryClassification.DIAGNOSTIC_EVIDENCE


def test_malformed_public_key_is_rejected_defensively():
    record = replace(decoded_key(1), public_key=b"\x02" + bytes(32))
    assert validate(record).validations[0].state is PlaintextKeyCryptoState.REJECTED


def test_valid_historical_checksum():
    result = validate(decoded_key(3, checksum=True)).validations[0]
    assert result.state is PlaintextKeyCryptoState.CRYPTO_VALID
    assert result.serialization_layout == "K2_DER_CHECKSUM"
    assert result.checksum_valid is True


def test_invalid_historical_checksum():
    result = validate(decoded_key(3, checksum=True, checksum_valid=False)).validations[0]
    assert result.state is PlaintextKeyCryptoState.CHECKSUM_INVALID


def test_truncated_serialization():
    record = replace(decoded_key(1), private_key_payload=b"\xfd\x20")
    assert validate(record).validations[0].state is PlaintextKeyCryptoState.TRUNCATED


def test_unsupported_serialization():
    record = decoded_key(1, der=b"\x30\x00")
    assert validate(record).validations[0].state is PlaintextKeyCryptoState.SERIALIZATION_UNSUPPORTED


def test_duplicate_valid_key_records_are_reported_not_discarded():
    summary = validate(decoded_key(5, page=4, physical=10000),
                       decoded_key(5, page=5, physical=20000))
    assert summary.total_crypto_valid_records == 2
    assert summary.unique_crypto_valid_private_keys == 1
    assert summary.duplicate_occurrences == 1
    assert len(summary.duplicate_groups[0].occurrences) == 2


def test_same_private_key_preserves_every_provenance_occurrence():
    first = decoded_key(7, page=4, physical=10000)
    second = decoded_key(7, page=5, physical=20000)
    group = validate(first, second).duplicate_groups[0]
    assert tuple(item.provenance for item in group.occurrences) == (first.provenance, second.provenance)


def test_provenance_and_original_payload_are_preserved():
    record = decoded_key(9)
    candidate = LegacyBitcoinWalletCandidateAssemblerV1().assemble((record,))[0]
    result = LegacyPlaintextKeyCryptographicValidatorV1().validate_candidate(candidate).validations[0]
    assert result.candidate_id == candidate.candidate_id
    assert result.identity == candidate.identity
    assert result.provenance == record.provenance
    assert result.original_public_key == record.public_key
    assert result.original_private_value_payload == record.private_key_payload


def test_output_is_deterministic_for_reversed_occurrences():
    first = decoded_key(11, page=4, physical=10000)
    second = decoded_key(11, page=5, physical=20000)
    assert validate(first, second) == validate(second, first)
