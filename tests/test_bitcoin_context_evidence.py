import hashlib

import pytest

from bfrs.core.chunk_reader import Chunk, ChunkReader
from bfrs.core.models import ValidationStatus
from bfrs.core.secp256k1 import GENERATOR, encode_sec_public_key
from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator
from bfrs.reporting.json_report import serialize_full_image_result
from bfrs.scanners.bitcoin_context import (
    BitcoinTextContextChunkDetector,
    scan_bitcoin_context_for_sec_pubkeys,
)
from bfrs.scanners.fast_scanner import FastScanner
from bfrs.scanners.target_registry import (
    TARGET_BITCOIN_CORE,
    build_target_selection,
)
from bfrs.validators.bitcoin_address import validate_bitcoin_mainnet_address
from bfrs.validators.bitcoin_public_key import validate_textual_sec_public_key
from bfrs.validators.bitcoin_record_key import (
    BITCOIN_RECORD_PUBKEY_NOT_ON_CURVE,
    BITCOIN_RECORD_PUBKEY_PREFIX_INVALID,
)
from bfrs.validators.candidate_policy import CandidatePolicy


P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
P2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
COMPRESSED = encode_sec_public_key(GENERATOR, compressed=True)
UNCOMPRESSED = encode_sec_public_key(GENERATOR, compressed=False)
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _convert_bits(values: bytes, from_bits: int, to_bits: int) -> list[int]:
    accumulator = 0
    bit_count = 0
    result: list[int] = []
    maximum = (1 << to_bits) - 1
    for value in values:
        accumulator = (accumulator << from_bits) | value
        bit_count += from_bits
        while bit_count >= to_bits:
            bit_count -= to_bits
            result.append((accumulator >> bit_count) & maximum)
    if bit_count:
        result.append((accumulator << (to_bits - bit_count)) & maximum)
    return result


def witness_address(version: int, program: bytes, *, bech32m: bool) -> str:
    hrp = "bc"
    data = [version, *_convert_bits(program, 8, 5)]
    expanded = [*(ord(char) >> 5 for char in hrp), 0,
                *(ord(char) & 31 for char in hrp)]
    constant = 0x2BC830A3 if bech32m else 1
    value = _polymod([*expanded, *data, 0, 0, 0, 0, 0, 0]) ^ constant
    checksum = [(value >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[item] for item in data + checksum)


def bad_last_character(value: str) -> str:
    replacement = "q" if value[-1] != "q" else "p"
    return value[:-1] + replacement


def detect(data: bytes, *, base_offset: int = 0):
    chunk = Chunk(base_offset, data)
    return tuple(
        BitcoinTextContextChunkDetector().detect_chunk(
            chunk,
            source="context.bin",
            ownership_start=base_offset,
            ownership_end=base_offset + len(data),
        )
    )


def test_valid_mainnet_p2pkh_and_p2sh_pass_base58check() -> None:
    p2pkh = validate_bitcoin_mainnet_address(P2PKH)
    p2sh = validate_bitcoin_mainnet_address(P2SH)

    assert p2pkh.valid and p2pkh.address_type == "P2PKH"
    assert p2sh.valid and p2sh.address_type == "P2SH"
    assert p2pkh.encoding == p2sh.encoding == "BASE58CHECK"
    assert p2pkh.checksum_valid and p2sh.checksum_valid


@pytest.mark.parametrize("address", [P2PKH, P2SH])
def test_base58_address_bad_checksum_is_rejected(address: str) -> None:
    result = validate_bitcoin_mainnet_address(bad_last_character(address))

    assert not result.valid
    assert result.reason_codes == ("BITCOIN_ADDRESS_CHECKSUM_INVALID",)


def test_valid_bech32_witness_v0_passes() -> None:
    result = validate_bitcoin_mainnet_address(
        witness_address(0, bytes(range(20)), bech32m=False)
    )

    assert result.valid and result.address_type == "P2WPKH"
    assert result.encoding == "BECH32" and result.checksum_valid


def test_bech32_bad_checksum_and_mixed_case_are_rejected() -> None:
    address = witness_address(0, bytes(range(20)), bech32m=False)

    bad_checksum = validate_bitcoin_mainnet_address(bad_last_character(address))
    mixed_case = validate_bitcoin_mainnet_address("bC" + address[2:])

    assert bad_checksum.reason_codes == ("BITCOIN_ADDRESS_CHECKSUM_INVALID",)
    assert mixed_case.reason_codes == ("BITCOIN_ADDRESS_MIXED_CASE",)


def test_valid_bech32m_witness_v1_passes_as_p2tr() -> None:
    result = validate_bitcoin_mainnet_address(
        witness_address(1, bytes(range(32)), bech32m=True)
    )

    assert result.valid and result.address_type == "P2TR"
    assert result.encoding == "BECH32M"


@pytest.mark.parametrize(
    "address",
    [
        witness_address(0, bytes(range(20)), bech32m=True),
        witness_address(1, bytes(range(32)), bech32m=False),
    ],
)
def test_witness_version_requires_the_correct_checksum_variant(address: str) -> None:
    result = validate_bitcoin_mainnet_address(address)

    assert not result.valid
    assert result.checksum_valid
    assert result.reason_codes == ("BITCOIN_ADDRESS_WITNESS_ENCODING_INVALID",)


def test_invalid_witness_program_length_is_rejected() -> None:
    result = validate_bitcoin_mainnet_address(
        witness_address(0, bytes(range(21)), bech32m=False)
    )

    assert not result.valid and result.checksum_valid
    assert result.reason_codes == (
        "BITCOIN_ADDRESS_WITNESS_PROGRAM_LENGTH_INVALID",
    )


def test_random_base58_like_string_is_rejected() -> None:
    assert not validate_bitcoin_mainnet_address("1" + "A" * 33).valid


def test_address_embedded_in_ascii_is_found_at_absolute_offset() -> None:
    data = b"invoice: " + P2PKH.encode() + b" paid"
    findings = detect(data, base_offset=10_000)
    address = next(item for item in findings if item.artifact_kind == "bitcoin_address")

    assert address.start_offset == 10_009
    assert address.validation_status == "CHECKSUM_VALID"
    assert address.safe_metadata["address"] == P2PKH


def test_valid_compressed_and_uncompressed_textual_pubkeys() -> None:
    compressed = validate_textual_sec_public_key(COMPRESSED.hex())
    uncompressed = validate_textual_sec_public_key(UNCOMPRESSED.hex().upper())

    assert compressed.valid and compressed.compressed is True
    assert uncompressed.valid and uncompressed.compressed is False
    assert len(compressed.safe_fingerprint or "") == 64


def test_textual_pubkey_invalid_point_prefix_and_hex_are_rejected() -> None:
    invalid_point = validate_textual_sec_public_key(
        (b"\x02" + bytes(32)).hex()
    )
    wrong_prefix = validate_textual_sec_public_key(
        (b"\x04" + COMPRESSED[1:]).hex()
    )
    invalid_hex = validate_textual_sec_public_key("02" + "g" * 64)

    assert invalid_point.reason_codes == (BITCOIN_RECORD_PUBKEY_NOT_ON_CURVE,)
    assert wrong_prefix.reason_codes == (BITCOIN_RECORD_PUBKEY_PREFIX_INVALID,)
    assert invalid_hex.reason_codes == ("BITCOIN_PUBLIC_KEY_HEX_INVALID",)


def test_textual_pubkey_inside_longer_hex_is_not_detected() -> None:
    findings = detect(b"a" + COMPRESSED.hex().encode() + b"f")

    assert not any(item.artifact_kind == "bitcoin_public_key" for item in findings)


def test_bounded_binary_context_finds_valid_sec_keys() -> None:
    data = b"header" + COMPRESSED + b"gap" + UNCOMPRESSED + b"tail"
    findings = scan_bitcoin_context_for_sec_pubkeys(data, 500, source="bounded.bin")

    assert len(findings) == 2
    assert {item.start_offset for item in findings} == {506, 542}
    assert all(item.structural_status == "CONTEXT_ONLY" for item in findings)
    assert all(item.safe_fingerprint for item in findings)


def test_bounded_binary_context_rejects_random_invalid_point() -> None:
    invalid = b"\x02" + bytes(32)

    assert scan_bitcoin_context_for_sec_pubkeys(invalid, 0) == ()


def test_binary_sec_detector_is_not_a_global_signature_or_chunk_detector() -> None:
    selection = build_target_selection(
        frozenset({TARGET_BITCOIN_CORE}), include_mnemonics=False
    )

    assert not any("binary_sec" in signature.name for signature in selection.signatures)
    assert not any(
        detector.__class__.__name__.lower().startswith("binary")
        for detector in selection.chunk_detectors
    )


def test_binary_pubkey_alone_does_not_create_or_accept_hotspot(tmp_path) -> None:
    source = tmp_path / "binary-only.bin"
    source.write_bytes(COMPRESSED)
    selection = build_target_selection(
        frozenset({TARGET_BITCOIN_CORE}), include_mnemonics=False
    )
    result = FullImageRecoveryCoordinator(
        selection.signatures,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_detectors=selection.chunk_detectors,
        chunk_size=256,
        cluster_gap=0,
        hotspot_padding=0,
    ).scan(source)

    assert result.raw_hit_count == 0
    assert result.hotspot_count == result.accepted_hotspot_count == 0
    assert result.status is ValidationStatus.REJECTED


def test_binary_sec_is_derived_only_from_qualified_wallet_record_context(
    tmp_path,
) -> None:
    source = tmp_path / "record-context.bin"
    source.write_bytes(b"\x03key\x21" + COMPRESSED)
    selection = build_target_selection(
        frozenset({TARGET_BITCOIN_CORE}), include_mnemonics=False
    )
    result = FullImageRecoveryCoordinator(
        selection.signatures,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_detectors=selection.chunk_detectors,
        chunk_size=256,
        cluster_gap=0,
        hotspot_padding=0,
    ).scan(source)
    summary = serialize_full_image_result(result, {})[
        "bitcoin_context_evidence"
    ]

    assert result.raw_hit_count == 1
    assert result.accepted_hotspot_count == 1
    assert result.status is ValidationStatus.REJECTED
    assert summary["binary_context_pubkey_count"] == 1


@pytest.mark.parametrize(
    "data",
    [
        bytes(range(256)) * 2,
        b"\x00\x00\x01\xba" + bytes(range(128)) * 2,
        b"\xff\xd8\xff\xe0JFIF\x00" + bytes(reversed(range(256))),
    ],
    ids=("high-entropy", "mpeg-like", "jpeg-like"),
)
def test_binary_noise_does_not_create_valid_address_evidence(data: bytes) -> None:
    findings = detect(data)

    assert not any(
        item.artifact_kind == "bitcoin_address"
        and item.validation_status == "CHECKSUM_VALID"
        for item in findings
    )


def test_address_and_textual_pubkey_cross_chunk_boundaries_once(tmp_path) -> None:
    address_offset = 140
    pubkey_offset = 350
    data = bytearray(b" " * 600)
    data[address_offset : address_offset + len(P2PKH)] = P2PKH.encode()
    textual = COMPRESSED.hex().encode()
    data[pubkey_offset : pubkey_offset + len(textual)] = textual
    source = tmp_path / "boundary.bin"
    source.write_bytes(data)
    reader = ChunkReader(source, chunk_size=160, overlap=130)
    hits = tuple(
        FastScanner((), chunk_detectors=(BitcoinTextContextChunkDetector(),)).scan(
            reader
        )
    )

    assert [item.start_offset for item in hits] == [address_offset, pubkey_offset]


def test_context_evidence_summary_is_deterministic_and_not_structural(tmp_path) -> None:
    textual = COMPRESSED.hex()
    source = tmp_path / "context.txt"
    source.write_text(
        f"pay {P2PKH}\nagain {P2PKH}\npub {textual}\n",
        encoding="ascii",
    )
    selection = build_target_selection(
        frozenset({TARGET_BITCOIN_CORE}), include_mnemonics=False
    )
    result = FullImageRecoveryCoordinator(
        selection.signatures,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_detectors=selection.chunk_detectors,
        chunk_size=256,
        cluster_gap=0,
        hotspot_padding=0,
    ).scan(source)
    payload = serialize_full_image_result(result, {})
    summary = payload["bitcoin_context_evidence"]

    assert result.hotspot_count == result.accepted_hotspot_count == 0
    assert result.status is ValidationStatus.REJECTED
    assert summary["structural_wallet_confirmation"] == "NOT_EVALUATED"
    assert summary["bitcoin_address_candidate_count"] == 2
    assert summary["bitcoin_address_valid_count"] == 2
    assert summary["textual_pubkey_candidate_count"] == 1
    assert summary["textual_pubkey_valid_count"] == 1
    assert summary["unique_address_count"] == 1
    assert summary["address_groups"][0]["occurrence_count"] == 2
    assert summary["unique_pubkey_fingerprint_count"] == 1
    assert hashlib.sha256(COMPRESSED).hexdigest() in {
        item["safe_fingerprint"]
        for item in payload["target_findings"]
        if item["artifact_kind"] == "bitcoin_public_key"
    }
