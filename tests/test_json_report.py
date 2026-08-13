from dataclasses import replace
import json

from bfrs.cli import BITCOIN_CORE_SIGNATURES_V1
from bfrs.core.secp256k1 import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_ORDER,
    encode_sec_public_key,
    scalar_multiply,
)
from bfrs.recovery.full_image_coordinator import FullImageRecoveryResult
from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator
from bfrs.reporting.json_report import (
    serialize_full_image_result,
    write_json_report,
)
from bfrs.validators.berkeley_metadata import BTREE_MAGIC
from bfrs.validators.berkeley_page import KEYDATA, PAGE_HEADER_SIZE
from bfrs.validators.candidate_policy import CandidatePolicy
from bfrs.version import APP_NAME, VERSION


CONFIGURATION = {
    "chunk_mib": 64,
    "overlap_kib": 64,
    "cluster_mib": 2,
    "padding_mib": 1,
    "minimum_hits": 1,
    "minimum_distinct_types": 1,
    "signature_set": ["safe-test"],
}

PAGE_SIZE = 512
PUBLIC_KEY = encode_sec_public_key(GENERATOR, compressed=False)
PRIME_FIELD_OID = bytes.fromhex("2A8648CE3D0101")


def vector(value: bytes) -> bytes:
    length = len(value)
    prefix = bytes((length,)) if length < 253 else b"\xfd" + length.to_bytes(2, "little")
    return prefix + value


def der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes((value,))
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def tlv(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + der_length(len(content)) + content


def integer(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return tlv(2, encoded)


def private_der(scalar: int = 1) -> bytes:
    field = tlv(0x30, tlv(0x06, PRIME_FIELD_OID) + integer(FIELD_PRIME))
    curve = tlv(0x30, tlv(0x04, b"\x00") + tlv(0x04, b"\x07"))
    parameters = tlv(
        0x30,
        integer(1)
        + field
        + curve
        + tlv(0x04, PUBLIC_KEY)
        + integer(GROUP_ORDER)
        + integer(1),
    )
    body = (
        integer(1)
        + tlv(0x04, scalar.to_bytes(32, "big"))
        + tlv(0xA0, parameters)
        + tlv(
            0xA1,
            tlv(
                0x03,
                b"\x00"
                + encode_sec_public_key(scalar_multiply(scalar), compressed=False),
            ),
        )
    )
    return tlv(0x30, body)


def historical_wallet_image() -> bytes:
    metadata = bytearray(PAGE_SIZE)
    put = lambda offset, value: metadata.__setitem__(
        slice(offset, offset + 4), value.to_bytes(4, "little")
    )
    put(12, BTREE_MAGIC)
    put(16, 9)
    put(20, PAGE_SIZE)
    metadata[25] = 9
    put(32, 1000)
    put(48, 0x20)
    put(88, 1)

    key = vector(b"key") + vector(PUBLIC_KEY)
    private_key = vector(private_der())
    records = tuple(
        len(payload).to_bytes(2, "little") + bytes((KEYDATA,)) + payload
        for payload in (key, private_key)
    )
    leaf = bytearray(PAGE_SIZE)
    cursor = PAGE_SIZE
    slots = []
    for record in records:
        cursor -= len(record)
        leaf[cursor : cursor + len(record)] = record
        slots.append(cursor)
    leaf[8:12] = (1).to_bytes(4, "little")
    leaf[20:22] = len(records).to_bytes(2, "little")
    leaf[22:24] = min(slots).to_bytes(2, "little")
    leaf[24] = 1
    leaf[25] = 5
    for index, slot in enumerate(slots):
        start = PAGE_HEADER_SIZE + index * 2
        leaf[start : start + 2] = slot.to_bytes(2, "little")
    return bytes(metadata + leaf)


def contains_bytes(value: object) -> bool:
    if isinstance(value, bytes):
        return True
    if isinstance(value, dict):
        return any(contains_bytes(key) or contains_bytes(item) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(contains_bytes(item) for item in value)
    return False


def historical_wallet_result(tmp_path) -> FullImageRecoveryResult:
    image = tmp_path / "historical-wallet.img"
    image.write_bytes(historical_wallet_image())
    return FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_size=127,
        cluster_gap=2048,
        hotspot_padding=512,
    ).scan(image)


def test_safe_json_schema_is_explicit_and_deterministic(tmp_path):
    result = historical_wallet_result(tmp_path)
    payload = serialize_full_image_result(result, CONFIGURATION)
    assert payload["application"] == {"name": APP_NAME, "version": VERSION}
    assert payload["source"] == str((tmp_path / "historical-wallet.img").resolve())
    assert payload["scan_range"] == {
        "start_offset": 0,
        "end_offset": len(historical_wallet_image()),
    }
    # Direct and globally reconstructed recovery are intentionally counted
    # as separate successful result paths.
    assert payload["structural_result_count"] == 2
    assert payload["fragment_result_count"] == 1
    assert payload["status"] == "structural"
    legacy = payload["legacy_wallet_recovery"]
    assert legacy["source"] == str((tmp_path / "historical-wallet.img").resolve())
    assert legacy["summary"]["wallet_candidates"] == 1
    assert legacy["summary"]["critical_candidates"] == 1
    assert legacy["summary"]["crypto_valid_key_occurrences"] == 1
    candidate = legacy["candidates"][0]
    assert candidate["priority"] == "CRITICAL"
    assert candidate["physical_image_ranges"]
    assert candidate["provenance"][0]["logical_page_number"] == 1
    safe_candidate_json = json.dumps(candidate, sort_keys=True).lower()
    assert private_der().hex() not in safe_candidate_json
    assert "private_key_bytes" not in safe_candidate_json
    assert "original_private_value_payload" not in safe_candidate_json
    metadata_less = payload["metadata_less_fragment_summary"]
    assert metadata_less["status"] == "fragment"
    assert metadata_less["valid_plaintext_key_count"] == 1
    assert metadata_less["record_locations"]
    assert payload["raw_hit_counts_by_signature"] == {
        "berkeley_metadata_little_endian": 1,
        "bitcoin_key": 1,
        "historical_ec_private_key_der_anchor": 1,
    }
    orphan_keys = payload["orphan_record_key_diagnostic"]
    assert orphan_keys["raw_strong_hit_count"] == 1
    assert orphan_keys["valid_record_key_count"] == 1
    assert orphan_keys["valid_key_count"] == 1
    assert orphan_keys["locations"][0]["record_type"] == "key"
    assert "pubkey" not in json.dumps(orphan_keys, sort_keys=True).lower()
    orphan_private = payload["orphan_private_key_recovery"]
    assert orphan_private["raw_der_anchor_count"] == 1
    assert orphan_private["candidate_der_count"] == 1
    assert orphan_private["valid_secp256k1_der_count"] == 1
    assert orphan_private["locations"][0]["der_length"] == len(private_der())
    serialized_private = json.dumps(orphan_private, sort_keys=True).lower()
    assert private_der().hex() not in serialized_private
    assert "scalar" not in serialized_private
    inner_private = payload["orphan_private_key_fragment_recovery"]
    assert inner_private["raw_inner_anchor_count"] == 1
    assert inner_private["candidate_inner_fragment_count"] == 1
    assert inner_private["valid_inner_fragment_count"] == 1
    assert inner_private["locations"][0]["validation_strength"] == (
        "cryptographic_inner_fragment"
    )
    serialized_inner = json.dumps(inner_private, sort_keys=True).lower()
    assert private_der().hex() not in serialized_inner
    assert "scalar" not in serialized_inner
    ntfs_index = payload["ntfs_bitcoin_artifact_index"]
    assert ntfs_index["wallet_dat_candidate_count"] == 0
    assert ntfs_index["candidates"] == []
    mft_diagnostic = payload["ntfs_mft_recovery_diagnostic"]
    assert mft_diagnostic["mirror_record_count_expected"] == 0
    assert mft_diagnostic["partial_salvage_candidates"] == []
    stale_ntfs = payload["ntfs_stale_file_record_recovery"]
    assert stale_ntfs["structural_stale_record_count"] == 0
    assert stale_ntfs["records"] == []
    assert not contains_bytes(payload)

    first = write_json_report(tmp_path / "first.json", result, CONFIGURATION)
    second = write_json_report(tmp_path / "nested" / "second.json", result, CONFIGURATION)
    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")
    assert first.read_text(encoding="utf-8").endswith("\n")


def test_report_omits_nested_plaintext_ciphertext_and_unknown_evidence(tmp_path):
    result = historical_wallet_result(tmp_path)
    private_key_der = private_der()
    ciphertext = bytes(range(48))
    salt = bytes(reversed(range(8)))
    public_key = bytes.fromhex("04") + bytes(range(64))
    contaminated = replace(
        result,
        evidence={
            **result.evidence,
            "private_key": private_key_der,
            "raw_ckey": ciphertext,
            "salt": salt,
            "pubkey": public_key,
            "raw_berkeley_payload": b"\x04ckey" + ciphertext,
        },
    )
    encoded = json.dumps(
        serialize_full_image_result(contaminated, CONFIGURATION),
        sort_keys=True,
    )
    for secret in (private_key_der, ciphertext, salt, public_key):
        assert secret.hex() not in encoded
        assert repr(secret) not in encoded
    for forbidden_field in (
        "private_key",
        "raw_ckey",
        "salt",
        "pubkey",
        "raw_berkeley_payload",
    ):
        assert f'"{forbidden_field}":' not in encoded


def test_serializer_rejects_unrelated_objects():
    try:
        serialize_full_image_result(object(), CONFIGURATION)
    except ValueError as error:
        assert str(error) == "result must be FullImageRecoveryResult"
    else:
        raise AssertionError("unrelated result was accepted")
