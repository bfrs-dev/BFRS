from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_records import BerkeleyLeafPair, BerkeleyRecord, BerkeleyRecordExtraction
from bfrs.recovery.logical_berkeley_reader import LogicalBerkeleyDatabaseIdentity
from bfrs.recovery.logical_btree_membership import LogicalBerkeleySubdatabaseIdentity
from bfrs.recovery.logical_wallet_record_decoder import (
    LogicalBitcoinWalletRecordDecoderV1, LogicalWalletRecordState,
)
from bfrs.validators.logical_encrypted_wallet_evidence import LogicalBerkeleyRecordPageContext


SOURCE = r"E:\images\wallet.dat"
PAGE_SIZE = 512
PUBLIC_KEY = bytes.fromhex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")


def vector(value: bytes) -> bytes:
    return bytes((len(value),)) + value


def pair(name: str, suffix: bytes, value: bytes, *, key_prefix: bytes | None = None) -> BerkeleyLeafPair:
    key = (bytes((len(name),)) + name.encode() if key_prefix is None else key_prefix) + suffix
    def record(payload: bytes, local: int, slot: int) -> BerkeleyRecord:
        return BerkeleyRecord(slot, local, 10000 + local, len(payload), 1, False, payload)
    return BerkeleyLeafPair(0, record(key, 40, 0), record(value, 240, 1))


def context(item: BerkeleyLeafPair) -> LogicalBerkeleyRecordPageContext:
    database = LogicalBerkeleyDatabaseIdentity(SOURCE, PAGE_SIZE, "little", "file-7")
    identity = LogicalBerkeleySubdatabaseIdentity(database, 0, 1, PAGE_SIZE, "little")
    extraction = BerkeleyRecordExtraction(7, ValidationStatus.STRUCTURAL,
        (item.key, item.value), (item,), 2, 0, 0, ())
    return LogicalBerkeleyRecordPageContext(identity, SOURCE, 7, 10000, PAGE_SIZE,
                                             ValidationStatus.STRUCTURAL, extraction)


def decode(item: BerkeleyLeafPair):
    ctx = context(item)
    return LogicalBitcoinWalletRecordDecoderV1().decode_pair(ctx, item)


def test_valid_key_preserves_complete_private_value_without_recovery_classification():
    private_value = vector(b"opaque-serialized-private-key") + b"x" * 32
    result = decode(pair("key", vector(PUBLIC_KEY), private_value))
    assert result.state is LogicalWalletRecordState.VALID
    assert result.public_key == PUBLIC_KEY
    assert result.private_key_payload == private_value


def test_valid_ckey():
    secret = bytes(range(48))
    result = decode(pair("ckey", vector(PUBLIC_KEY), vector(secret)))
    assert result.state is LogicalWalletRecordState.VALID
    assert result.encrypted_secret == secret


def test_valid_mkey_retains_all_fields():
    encrypted, salt, other = bytes(range(48)), b"12345678", b"params"
    value = vector(encrypted) + vector(salt) + (1).to_bytes(4, "little") + (50000).to_bytes(4, "little") + vector(other)
    result = decode(pair("mkey", (9).to_bytes(4, "little"), value))
    assert result.state is LogicalWalletRecordState.VALID
    assert (result.master_key_id, result.encrypted_master_key, result.salt) == (9, encrypted, salt)
    assert (result.derivation_method, result.derivation_iterations, result.other_derivation_parameters) == (1, 50000, other)


def test_valid_keymeta_decodes_only_fixed_legacy_fields():
    value = (1).to_bytes(4, "little", signed=True) + (123456789).to_bytes(8, "little", signed=True)
    result = decode(pair("keymeta", vector(PUBLIC_KEY), value))
    assert result.state is LogicalWalletRecordState.VALID
    assert (result.keymeta_version, result.keymeta_creation_time) == (1, 123456789)


def test_valid_defaultkey():
    result = decode(pair("defaultkey", b"", vector(PUBLIC_KEY)))
    assert result.state is LogicalWalletRecordState.VALID
    assert result.public_key == PUBLIC_KEY


def test_malformed_compactsize_is_rejected_deterministically():
    item = pair("ignored", b"", b"", key_prefix=b"\xfd\x04")
    first, second = decode(item), decode(item)
    assert first.state is LogicalWalletRecordState.REJECTED
    assert first.findings == second.findings == ("record_type_compactsize_malformed",)


def test_truncated_pubkey_is_partial_only_from_claimed_vector_length():
    result = decode(pair("ckey", b"\x21" + PUBLIC_KEY[:-1], vector(bytes(48))))
    assert result.state is LogicalWalletRecordState.PARTIAL
    assert result.findings == ("record_type_truncated",)


def test_invalid_pubkey_encoding_is_rejected():
    result = decode(pair("ckey", vector(b"\x05" + b"\x01" * 32), vector(bytes(48))))
    assert result.state is LogicalWalletRecordState.REJECTED
    assert result.findings == ("pubkey_prefix_invalid",)


def test_truncated_value_is_partial():
    result = decode(pair("ckey", vector(PUBLIC_KEY), b"\x30" + bytes(47)))
    assert result.state is LogicalWalletRecordState.PARTIAL
    assert result.findings == ("encrypted_secret_truncated",)


def test_unsupported_record_type_is_rejected_without_payload_scanning():
    result = decode(pair("name", b"", b"bait\x04ckey"))
    assert result.state is LogicalWalletRecordState.REJECTED
    assert result.findings == ("record_type_unsupported",)


def test_provenance_is_preserved():
    result = decode(pair("defaultkey", b"", vector(PUBLIC_KEY)))
    assert result.provenance.source == SOURCE.lower()
    assert result.provenance.physical_key_range[0] == 10040
    assert result.provenance.logical_key_range[0] == 7 * PAGE_SIZE + 40
    assert result.provenance.logical_page_identity[1] == 7
    assert result.provenance.key_length == len(result.record_type) + 1


def test_pair_outside_context_is_refused():
    accepted = pair("defaultkey", b"", vector(PUBLIC_KEY))
    foreign = pair("defaultkey", b"", vector(PUBLIC_KEY) + b"x")
    try:
        LogicalBitcoinWalletRecordDecoderV1().decode_pair(context(accepted), foreign)
    except ValueError as exc:
        assert str(exc) == "pair does not belong to the logical page context"
    else:
        raise AssertionError("foreign pair was decoded")
