from dataclasses import FrozenInstanceError

import pytest

from bfrs.cli import (
    BITCOIN_CORE_SIGNATURES_V1,
    DEFAULT_MINIMUM_DISTINCT_TYPES,
    DEFAULT_MINIMUM_HITS,
)
from bfrs.core.hotspot_reader import HotspotReader
from bfrs.core.models import ValidationStatus
from bfrs.core.secp256k1 import GENERATOR, encode_sec_public_key
from bfrs.recovery.berkeley_database_pipeline import BerkeleyDatabaseRecoveryPipeline
from bfrs.recovery.full_image_coordinator import (
    FullImageRecoveryCoordinator,
    FullImageRecoveryResult,
)
from bfrs.scanners.fast_scanner import Signature
from bfrs.validators.berkeley_metadata import BTREE_MAGIC
from bfrs.validators.berkeley_page import BTREE_INTERNAL, BTREE_LEAF, KEYDATA, PAGE_HEADER_SIZE
from bfrs.validators.candidate_policy import CandidatePolicy


PAGE_SIZE = 512
PUBLIC_KEY = encode_sec_public_key(GENERATOR, compressed=False)


def vector(value: bytes) -> bytes:
    return bytes((len(value),)) + value


def string(value: str) -> bytes:
    return vector(value.encode("ascii"))


def ckey_pair() -> tuple[bytes, bytes]:
    return string("ckey") + vector(PUBLIC_KEY), vector(bytes(range(48)))


def mkey_pair() -> tuple[bytes, bytes]:
    value = vector(bytes(reversed(range(48)))) + vector(bytes(8))
    value += (0).to_bytes(4, "little")
    value += (25_000).to_bytes(4, "little") + vector(b"")
    return string("mkey") + (1).to_bytes(4, "little"), value


def raw_record(payload: bytes) -> bytes:
    return len(payload).to_bytes(2, "little") + bytes((KEYDATA,)) + payload


def page(
    page_number: int,
    *,
    level: int,
    page_type: int,
    records: tuple[bytes, ...] = (),
) -> bytes:
    result = bytearray(PAGE_SIZE)
    cursor = PAGE_SIZE
    slots: list[int] = []
    for record in records:
        cursor -= len(record)
        result[cursor : cursor + len(record)] = record
        slots.append(cursor)
    result[8:12] = page_number.to_bytes(4, "little")
    result[20:22] = len(records).to_bytes(2, "little")
    result[22:24] = min(slots, default=PAGE_SIZE).to_bytes(2, "little")
    result[24] = level
    result[25] = page_type
    for index, slot in enumerate(slots):
        result[PAGE_HEADER_SIZE + 2 * index : PAGE_HEADER_SIZE + 2 * index + 2] = slot.to_bytes(2, "little")
    return bytes(result)


def internal(page_number: int, *children: int) -> bytes:
    records = tuple(
        len(b"k").to_bytes(2, "little")
        + bytes((KEYDATA, 0))
        + child.to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + b"k"
        for child in children
    )
    return page(
        page_number,
        level=2,
        page_type=BTREE_INTERNAL,
        records=records,
    )


def leaf(page_number: int, *payloads: bytes) -> bytes:
    return page(
        page_number,
        level=1,
        page_type=BTREE_LEAF,
        records=tuple(raw_record(payload) for payload in payloads),
    )


def metadata(root_page: int = 10) -> bytes:
    result = bytearray(PAGE_SIZE)
    put = lambda offset, value: result.__setitem__(
        slice(offset, offset + 4), value.to_bytes(4, "little")
    )
    put(8, 0)
    put(12, BTREE_MAGIC)
    put(16, 9)
    put(20, PAGE_SIZE)
    result[25] = 9
    put(32, max(root_page, 1000))
    put(48, 0x20)
    put(88, root_page)
    return bytes(result)


def placed(parts: dict[int, bytes], *, size: int | None = None) -> bytes:
    end = max(offset + len(value) for offset, value in parts.items())
    result = bytearray(max(end, size or 0))
    for offset, value in parts.items():
        result[offset : offset + len(value)] = value
    return bytes(result)


def signatures(*, bait: bytes | None = None) -> tuple[Signature, ...]:
    result = [
        Signature("berkeley_meta", BTREE_MAGIC.to_bytes(4, "little"), "berkeley"),
        Signature("crypted_key", b"ckey", "bitcoin"),
        Signature("master_key", b"mkey", "bitcoin"),
    ]
    if bait is not None:
        result.append(Signature("bait", bait, "generic"))
    return tuple(result)


def coordinator(
    *,
    cluster_gap: int = 2048,
    padding: int = PAGE_SIZE,
    chunk_size: int = 256,
    selected_signatures: tuple[Signature, ...] | None = None,
) -> FullImageRecoveryCoordinator:
    return FullImageRecoveryCoordinator(
        selected_signatures or signatures(),
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_size=chunk_size,
        cluster_gap=cluster_gap,
        hotspot_padding=padding,
    )


def fragmented_encrypted_image(*, include_mkey: bool = True) -> bytes:
    ckey = ckey_pair()
    parts = {
        0: metadata(),
        512: internal(10, *(20, 900) if include_mkey else (20,)),
        1024: leaf(20, *ckey),
    }
    if include_mkey:
        parts[8192] = leaf(900, *mkey_pair())
    return placed(parts)


def test_signature_crossing_chunk_boundary_is_reported_once(tmp_path):
    path = tmp_path / "boundary.img"
    path.write_bytes(b"A" * 30 + b"BOUNDARY" + b"Z" * 30)
    result = coordinator(
        chunk_size=32,
        selected_signatures=(Signature("boundary", b"BOUNDARY", "test"),),
        padding=0,
    ).scan(path)
    assert result.raw_hit_count == 1
    assert result.hotspot_count == 1


def test_overlapping_hotspots_deduplicate_exact_physical_candidates(tmp_path):
    path = tmp_path / "overlap.img"
    path.write_bytes(placed({0: metadata(1), 512: leaf(1, *ckey_pair(), *mkey_pair())}))
    result = coordinator(cluster_gap=0, padding=700).scan(path)
    offsets = [item[0] for item in result.evidence["physical_page_candidates"]]
    assert offsets == sorted(set(offsets))
    assert offsets.count(512) == 1


def test_distant_hotspots_are_reassembled_as_one_database(tmp_path):
    path = tmp_path / "distant.img"
    path.write_bytes(fragmented_encrypted_image())
    result = coordinator().scan(path)
    assert result.hotspot_count == 2
    assert len(result.reconstructed_databases) == 1
    database = result.reconstructed_databases[0]
    assert database.status is ValidationStatus.STRUCTURAL
    assert database.leaf_page_numbers == (20, 900)


def test_ckey_and_mkey_across_hotspots_produce_structural_wallet(tmp_path):
    path = tmp_path / "cross-hotspot.img"
    path.write_bytes(fragmented_encrypted_image())
    result = coordinator().scan(path)
    wallet = result.reconstructed_wallet_results[0]
    assert wallet.status is ValidationStatus.STRUCTURAL
    assert wallet.structural_ckey_count == 1
    assert wallet.structural_mkey_count == 1
    assert result.status is ValidationStatus.STRUCTURAL


def test_default_single_signal_hotspots_share_global_metadata_geometry(tmp_path):
    path = tmp_path / "single-signal-hotspots.img"
    path.write_bytes(
        placed(
            {
                0: metadata(),
                512: internal(10, 20, 900),
                4096: leaf(20, *ckey_pair()),
                8192: leaf(900, *mkey_pair()),
            }
        )
    )
    result = FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
        CandidatePolicy(
            min_hits=DEFAULT_MINIMUM_HITS,
            min_distinct_types=DEFAULT_MINIMUM_DISTINCT_TYPES,
        ),
        chunk_size=127,
        cluster_gap=0,
        hotspot_padding=1024,
    ).scan(path)

    # One hit in each of three disjoint hotspots proves that local signal
    # diversity is not required for global structural reconstruction.
    assert result.raw_hit_count == 3
    assert result.hotspot_count == 3
    assert result.accepted_hotspot_count == 3
    assert all(item[2] for item in result.evidence["hotspot_decisions"])
    physical_pages = result.evidence["physical_page_candidates"]
    assert {item[0] for item in physical_pages} == {512, 4096, 8192}
    assert result.reconstructed_databases[0].leaf_page_numbers == (20, 900)
    wallet = result.reconstructed_wallet_results[0]
    assert wallet.structural_ckey_count == 1
    assert wallet.structural_mkey_count == 1
    assert wallet.status is ValidationStatus.STRUCTURAL
    assert result.status is ValidationStatus.STRUCTURAL


def test_ckey_bait_with_ambiguous_page_copy_does_not_elevate(tmp_path):
    image = fragmented_encrypted_image(include_mkey=False)
    duplicate = leaf(20, *ckey_pair())
    path = tmp_path / "ambiguous.img"
    path.write_bytes(placed({0: image, 8192: duplicate}))
    result = FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
        CandidatePolicy(
            min_hits=DEFAULT_MINIMUM_HITS,
            min_distinct_types=DEFAULT_MINIMUM_DISTINCT_TYPES,
        ),
        chunk_size=127,
        cluster_gap=0,
        hotspot_padding=1024,
    ).scan(path)
    assert result.reconstructed_databases[0].ambiguous_page_numbers == (20,)
    orphan = result.metadata_less_fragment_recovery
    assert orphan.status is ValidationStatus.FRAGMENT
    assert orphan.valid_ckey_count == 2
    assert {item.physical_page_offset for item in orphan.record_locations} == {
        1024,
        8192,
    }
    assert result.status is ValidationStatus.FRAGMENT


def test_generic_berkeley_database_is_rejected_as_wallet(tmp_path):
    path = tmp_path / "generic.img"
    path.write_bytes(placed({0: metadata(1), 512: leaf(1)}))
    result = coordinator(
        selected_signatures=(signatures()[0],), cluster_gap=0, padding=1024
    ).scan(path)
    assert result.reconstructed_databases[0].status is ValidationStatus.STRUCTURAL
    assert result.status is ValidationStatus.REJECTED
    assert result.structural_wallet_count == 0


def test_direct_contiguous_database_produces_structural_result(tmp_path):
    path = tmp_path / "direct.img"
    path.write_bytes(placed({0: metadata(1), 512: leaf(1, *ckey_pair(), *mkey_pair())}))
    result = coordinator().scan(path)
    assert any(item.status is ValidationStatus.STRUCTURAL for item in result.direct_results)
    assert result.structural_wallet_count >= 1


def test_direct_rejected_but_reconstructed_structural_is_preserved(tmp_path):
    path = tmp_path / "reconstructed.img"
    path.write_bytes(fragmented_encrypted_image())
    result = coordinator().scan(path)
    assert result.direct_results
    assert all(item.status is ValidationStatus.REJECTED for item in result.direct_results)
    assert result.reconstructed_wallet_results[0].status is ValidationStatus.STRUCTURAL
    assert result.status is ValidationStatus.STRUCTURAL


def test_partial_reconstruction_with_only_ckey_is_fragment(tmp_path):
    path = tmp_path / "partial.img"
    path.write_bytes(fragmented_encrypted_image(include_mkey=False))
    result = coordinator().scan(path)
    assert result.reconstructed_databases[0].status is ValidationStatus.STRUCTURAL
    assert result.reconstructed_wallet_results[0].status is ValidationStatus.FRAGMENT
    assert result.status is ValidationStatus.FRAGMENT


def test_false_raw_hits_do_not_elevate_status(tmp_path):
    path = tmp_path / "false.img"
    path.write_bytes(b"xx ckey yy mkey zz")
    result = coordinator(padding=0).scan(path)
    assert result.raw_hit_count == 2
    assert result.status is ValidationStatus.REJECTED
    assert not result.reconstructed_databases


def test_rejected_metadata_near_independent_valid_leaf_recovers_fragment(tmp_path):
    invalid_metadata = bytearray(PAGE_SIZE)
    invalid_metadata[12:16] = BTREE_MAGIC.to_bytes(4, "little")
    path = tmp_path / "hp-like-metadata-loss.img"
    path.write_bytes(
        placed(
            {
                0: bytes(invalid_metadata),
                4096: leaf(20, *ckey_pair()),
            }
        )
    )
    result = FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_size=127,
        cluster_gap=0,
        hotspot_padding=1024,
    ).scan(path)

    assert result.raw_hit_count == 2
    assert result.evidence["physical_metadata_candidates"] == ()
    assert result.evidence["physical_page_candidates"] == ()
    orphan = result.metadata_less_fragment_recovery
    assert orphan.status is ValidationStatus.FRAGMENT
    assert orphan.valid_ckey_count == 1
    assert result.status is ValidationStatus.FRAGMENT
    assert dict(result.evidence["raw_hit_counts_by_signature"]) == {
        "berkeley_metadata_little_endian": 1,
        "bitcoin_ckey": 1,
    }


def test_range_scan_clamps_hotspots_to_requested_range(tmp_path):
    path = tmp_path / "range.img"
    path.write_bytes(b"HIT" + b"x" * 97 + b"HIT" + b"x" * 100)
    selected = (Signature("hit", b"HIT", "test"),)
    result = coordinator(
        selected_signatures=selected, padding=1000, chunk_size=32
    ).scan(path, start=50, end=150)
    assert result.raw_hit_count == 1
    assert result.start_offset == 50 and result.end_offset == 150
    assert result.evidence["hotspot_ranges"] == ((50, 150),)


def test_range_does_not_import_metadata_or_page_geometry_from_before_start(tmp_path):
    path = tmp_path / "range-geometry.img"
    path.write_bytes(
        placed(
            {
                0: metadata(),
                512: internal(10, 20, 900),
                4096: leaf(20, *ckey_pair()),
                8192: leaf(900, *mkey_pair()),
            }
        )
    )
    result = FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_size=127,
        cluster_gap=0,
        hotspot_padding=2048,
    ).scan(path, start=4000, end=len(path.read_bytes()))

    assert result.raw_hit_count == 2
    assert result.accepted_hotspot_count == 2
    assert all(
        4000 <= start_offset <= end_offset <= len(path.read_bytes())
        for start_offset, end_offset in result.evidence["read_hotspot_ranges"]
    )
    assert result.evidence["physical_metadata_candidates"] == ()
    assert result.evidence["physical_page_candidates"] == ()
    assert result.metadata_less_fragment_recovery.status is ValidationStatus.FRAGMENT
    assert result.status is ValidationStatus.FRAGMENT


def test_hotspot_read_error_is_isolated_and_diagnosed(tmp_path, monkeypatch):
    path = tmp_path / "read-error.img"
    path.write_bytes(b"ONE" + b"x" * 100 + b"TWO")
    selected = (
        Signature("one", b"ONE", "test"),
        Signature("two", b"TWO", "test"),
    )
    original = HotspotReader.read
    calls = 0

    def flaky(self, hotspot):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated short read")
        return original(self, hotspot)

    monkeypatch.setattr(HotspotReader, "read", flaky)
    result = coordinator(
        selected_signatures=selected, cluster_gap=0, padding=0
    ).scan(path)
    assert result.accepted_hotspot_count == 2
    assert len(result.evidence["read_hotspot_ranges"]) == 1
    assert result.evidence["errors"][0][2] == "hotspot_read_error"


def test_programmer_error_from_direct_pipeline_is_not_hidden(tmp_path, monkeypatch):
    path = tmp_path / "programmer-error.img"
    path.write_bytes(b"HIT")
    monkeypatch.setattr(
        BerkeleyDatabaseRecoveryPipeline,
        "run",
        lambda self, context: (_ for _ in ()).throw(ValueError("programmer bug")),
    )
    with pytest.raises(ValueError, match="programmer bug"):
        coordinator(
            selected_signatures=(Signature("hit", b"HIT", "test"),), padding=0
        ).scan(path)


def test_full_integration_reaches_structural_through_every_stage(tmp_path):
    path = tmp_path / "integration.img"
    path.write_bytes(fragmented_encrypted_image())
    result = coordinator(chunk_size=127).scan(path)
    assert isinstance(result, FullImageRecoveryResult)
    assert result.raw_hit_count == 3
    assert result.hotspot_count == 2
    assert result.accepted_hotspot_count == 2
    assert len(result.direct_results) == 2
    assert result.evidence["physical_metadata_candidates"]
    assert len(result.evidence["physical_page_candidates"]) == 3
    assert len(result.reconstructed_databases) == 1
    assert len(result.reconstructed_wallet_results) == 1
    assert result.structural_wallet_count == 1
    assert result.status is ValidationStatus.STRUCTURAL
    with pytest.raises(FrozenInstanceError):
        result.status = ValidationStatus.REJECTED
