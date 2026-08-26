import pytest

from bfrs.cli import BITCOIN_CORE_SIGNATURES_V1
from bfrs.core.secp256k1 import GENERATOR, encode_sec_public_key
from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator
from bfrs.validators.bitcoin_record_key import (
    BITCOIN_RECORD_KEY_COMPACTSIZE_INVALID,
    BITCOIN_RECORD_KEY_SIDE_VALID,
    BITCOIN_RECORD_PUBKEY_LENGTH_INVALID,
    BITCOIN_RECORD_PUBKEY_NOT_ON_CURVE,
    BITCOIN_RECORD_PUBKEY_PREFIX_INVALID,
    RawBitcoinRecordKeySideValidator,
)
from bfrs.validators.candidate_policy import CandidatePolicy


COMPRESSED_PUBLIC_KEY = encode_sec_public_key(GENERATOR, compressed=True)
UNCOMPRESSED_PUBLIC_KEY = encode_sec_public_key(GENERATOR, compressed=False)


def framed(record_type: str, suffix: bytes) -> bytes:
    encoded = record_type.encode("ascii")
    return bytes((len(encoded),)) + encoded + suffix


def public_key_vector(public_key: bytes) -> bytes:
    return bytes((len(public_key),)) + public_key


def validate(record_type: str, suffix: bytes):
    return RawBitcoinRecordKeySideValidator().validate(
        framed(record_type, suffix),
        expected_record_type=record_type,
    )


@pytest.mark.parametrize(
    ("record_type", "suffix"),
    [
        ("wkey", b"\x0c" + b"x" * 12),
        ("ckey", b"\xbd" + b"x" * 70),
        ("key", b"\x51" + b"x" * 70),
        ("key", b"\x07" + b"x" * 7),
        ("key", b"\x62bd_event" + b"x" * 70),
    ],
    ids=("adata-wkey-12", "adata-ckey-189", "adata-key-81",
         "adata-key-7", "adata-keybd-event-98"),
)
def test_real_adata_false_positive_prefixes_are_rejected(
    record_type: str,
    suffix: bytes,
) -> None:
    result = validate(record_type, suffix)

    assert result.valid is False
    assert result.reason_codes == (BITCOIN_RECORD_PUBKEY_LENGTH_INVALID,)


@pytest.mark.parametrize(
    ("record_type", "public_key"),
    [
        ("key", COMPRESSED_PUBLIC_KEY),
        ("ckey", COMPRESSED_PUBLIC_KEY),
        ("key", UNCOMPRESSED_PUBLIC_KEY),
    ],
)
def test_valid_key_sides_pass_raw_admission(
    record_type: str,
    public_key: bytes,
) -> None:
    result = validate(record_type, public_key_vector(public_key))

    assert result.valid is True
    assert result.reason_codes == (BITCOIN_RECORD_KEY_SIDE_VALID,)
    assert result.evidence["pubkey_length"] == len(public_key)


def test_compressed_x_without_a_curve_point_is_rejected() -> None:
    # x=0 gives y^2=7, which has no square root in the secp256k1 field.
    result = validate("key", public_key_vector(b"\x02" + bytes(32)))

    assert result.valid is False
    assert result.reason_codes == (BITCOIN_RECORD_PUBKEY_NOT_ON_CURVE,)


def test_noncanonical_pubkey_compact_size_is_rejected_for_raw_admission() -> None:
    suffix = b"\xfd\x21\x00" + COMPRESSED_PUBLIC_KEY

    result = validate("key", suffix)

    assert result.valid is False
    assert result.reason_codes == (BITCOIN_RECORD_KEY_COMPACTSIZE_INVALID,)


def test_truncated_pubkey_is_rejected() -> None:
    result = validate("key", b"\x21" + COMPRESSED_PUBLIC_KEY[:10])

    assert result.valid is False
    assert result.reason_codes == (BITCOIN_RECORD_PUBKEY_LENGTH_INVALID,)


def test_sec_prefix_is_validated_before_curve_membership() -> None:
    result = validate("key", public_key_vector(b"\x05" + bytes(32)))

    assert result.valid is False
    assert result.reason_codes == (BITCOIN_RECORD_PUBKEY_PREFIX_INVALID,)


@pytest.mark.parametrize(
    ("record_type", "suffix", "hit_type"),
    [
        ("wkey", b"\x0c" + b"x" * 12, "bitcoin_wkey"),
        ("ckey", b"\xbd" + b"x" * 70, "bitcoin_ckey"),
        ("key", b"\x51" + b"x" * 70, "bitcoin_key"),
        ("key", b"\x07" + b"x" * 7, "bitcoin_key"),
        ("key", b"\x62bd_event" + b"x" * 70, "bitcoin_key"),
    ],
)
def test_rejected_raw_hit_is_accounted_but_cannot_admit_a_hotspot(
    tmp_path,
    record_type: str,
    suffix: bytes,
    hit_type: str,
) -> None:
    source = tmp_path / f"{record_type}-false-positive.bin"
    source.write_bytes(framed(record_type, suffix))
    result = FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_size=32,
        cluster_gap=0,
        hotspot_padding=0,
    ).scan(source)

    assert result.raw_hit_count == 1
    assert dict(result.evidence["raw_hit_counts_by_signature"]) == {hit_type: 1}
    assert result.hotspot_count == 0
    assert result.accepted_hotspot_count == 0
    finding = next(item for item in result.target_findings if item.hit_type == hit_type)
    assert finding.validation_status == "BITCOIN_RECORD_KEY_SIDE_REJECTED"
    assert finding.reason_codes == (BITCOIN_RECORD_PUBKEY_LENGTH_INVALID,)


def test_valid_raw_hit_keeps_accounting_and_can_admit_context(tmp_path) -> None:
    source = tmp_path / "valid-key.bin"
    source.write_bytes(framed("key", public_key_vector(COMPRESSED_PUBLIC_KEY)))
    result = FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_size=32,
        cluster_gap=0,
        hotspot_padding=0,
    ).scan(source)

    assert result.raw_hit_count == 1
    assert dict(result.evidence["raw_hit_counts_by_signature"]) == {
        "bitcoin_key": 1
    }
    assert result.hotspot_count == 1
    assert result.accepted_hotspot_count == 1
    finding = next(
        item for item in result.target_findings if item.hit_type == "bitcoin_key"
    )
    assert finding.validation_status == BITCOIN_RECORD_KEY_SIDE_VALID
    assert finding.reason_codes == (BITCOIN_RECORD_KEY_SIDE_VALID,)


def test_rejected_key_hit_does_not_reenter_downstream_with_nearby_signal(
    tmp_path,
) -> None:
    invalid_key = framed("key", b"\x07" + b"x" * 7)
    mkey = framed("mkey", (1).to_bytes(4, "little"))
    source = tmp_path / "mixed-admission.bin"
    source.write_bytes(invalid_key + b"x" * 16 + mkey)
    result = FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_size=32,
        cluster_gap=64,
        hotspot_padding=64,
    ).scan(source)

    assert result.raw_hit_count == 2
    assert result.accepted_hotspot_count == 1
    # Only mkey reaches the downstream orphan diagnostic.  The rejected key
    # remains visible solely in raw accounting and target findings.
    assert result.orphan_record_key_diagnostic.raw_strong_hit_count == 1
    assert result.orphan_record_key_diagnostic.valid_key_count == 0
