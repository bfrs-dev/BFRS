from __future__ import annotations

import base64
import json
from types import SimpleNamespace

from bfrs.recovery.electrum_provenance_triage import (
    NTFSBitmapResolver,
    TargetRange,
    compare_fingerprints,
    extent_matches,
    safe_fingerprint,
)
from bfrs.recovery.ntfs_bitcoin_artifacts import (
    NTFSDataExtent,
    NTFSFileNameAlias,
    _Data,
    _Record,
)


CLUSTER = 4096


def _bitmap(value: bytes):
    return NTFSBitmapResolver(lambda offset, length: value[offset:offset + length], len(value))


def test_bitmap_allocated_cluster():
    result = _bitmap(b"\x04").allocation(2, 2)
    assert (result.state, result.allocated_cluster_count) == ("ALLOCATED", 1)


def test_bitmap_unallocated_cluster():
    result = _bitmap(b"\x00").allocation(2, 2)
    assert (result.state, result.unallocated_cluster_count) == ("UNALLOCATED", 1)


def test_candidate_spanning_multiple_bitmap_bits():
    result = _bitmap(b"\xff\x03").allocation(6, 9)
    assert result.cluster_count == 4
    assert result.state == "ALLOCATED"


def test_bitmap_mixed_allocation():
    result = _bitmap(b"\x05").allocation(0, 2)
    assert (result.state, result.allocated_cluster_count,
            result.unallocated_cluster_count) == ("MIXED", 2, 1)


def _context(*records):
    by_number = {item.number: item for item in records}
    return SimpleNamespace(current_records_by_number=by_number)


def _record(number=42, *, active=True, start=10_000, end=20_000):
    alias = NTFSFileNameAlias("example.bin", "win32", number, 1)
    extent = NTFSDataExtent(0, 1, 2, start, end, False)
    data = _Data(False, end - start, end - start, end - start,
                 (extent,), "nonresident_extent_map_only")
    return _Record(number, 1, active, False, (alias,), data)


def test_active_mft_owner_and_no_active_owner():
    context = _context(_record())
    assert extent_matches(context, TargetRange("U", 12_000, 13_000), active=True)[0].relation == "INSIDE_EXTENT"
    assert extent_matches(context, TargetRange("U", 30_000, 31_000), active=True) == ()


def test_stale_extent_match():
    context = _context(_record(active=False))
    match = extent_matches(context, TargetRange("U", 12_000, 13_000), active=False)[0]
    assert match.active_state == "STALE_OR_DELETED"
    assert match.validation_strength == "STRUCTURAL_STALE_EXTENT"


def _container(cipher_byte=b"A", *, ephemeral_byte=b"B"):
    decoded = b"BIE1" + b"\x02" + ephemeral_byte * 32 + cipher_byte * 16 + b"M" * 32
    return base64.b64encode(decoded)


def test_exact_encrypted_byte_duplicate():
    value = safe_fingerprint(_container())
    assert compare_fingerprints(value, value) == "BYTE_IDENTICAL"


def test_equal_size_different_encrypted_data_is_size_match_only():
    first = safe_fingerprint(_container(b"A", ephemeral_byte=b"B"))
    second = safe_fingerprint(_container(b"C", ephemeral_byte=b"D"))
    assert compare_fingerprints(first, second) == "SIZE_MATCH_ONLY"


def test_safe_fingerprint_report_has_no_secret_values():
    container = _container()
    report = safe_fingerprint(container)
    encoded = json.dumps({slot: getattr(report, slot) for slot in report.__slots__})
    assert report.complete_container_length == len(container)
    assert report.decoded_bie_length == 85
    assert container.decode() not in encoded
    assert (b"A" * 16).decode() not in encoded
    assert (b"M" * 32).decode() not in encoded
    assert "ciphertext" not in encoded.casefold().replace("ciphertext_sha256", "")
