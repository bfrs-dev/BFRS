import base64
import json
from types import SimpleNamespace

import pytest

import bfrs.recovery.electrum_raw_recovery as electrum_raw_module
from bfrs.core.chunk_reader import ChunkReader
from bfrs.core.models import RawHit
from bfrs.recovery.electrum_raw_recovery import (
    ELECTRUM_BIE1_BASE64_SIGNATURE,
    ELECTRUM_SIGNATURE_NAMES,
    ELECTRUM_SIGNATURE_PATTERNS,
    MAX_BACKWARD_CONTEXT,
    MAX_MERGED_ELECTRUM_READ_SIZE,
    MAX_SCANNER_CANDIDATE_WINDOW,
    ElectrumCandidateAssembler,
    ElectrumRawRecoveryPipeline,
    KnownElectrumArtifact,
    known_electrum_artifacts_from_contexts,
)
from bfrs.recovery.ntfs_bitcoin_artifacts import NTFSBitcoinArtifactLocator
from bfrs.recovery.ntfs_mft_data import NtfsMftRecordError
from bfrs.reporting.json_report import _electrum_raw_recovery
from bfrs.scanners.fast_scanner import FastScanner, Signature
from tests.test_ntfs_bitcoin_artifacts import (
    data_resident,
    file_record,
    filename,
    image_with,
)


SYNTHETIC_SEED = "synthetic seed value for redaction test only"
SYNTHETIC_XPRV = "synthetic-xprv-value-for-redaction-test"


def _plaintext(**updates):
    value = {
        "seed_version": 71,
        "wallet_type": "standard",
        "keystore": {
            "type": "bip32",
            "xpub": "synthetic-public-metadata",
            "xprv": SYNTHETIC_XPRV,
            "seed": SYNTHETIC_SEED,
        },
        "addresses": {"receiving": [], "change": []},
    }
    value.update(updates)
    return json.dumps(value, separators=(",", ":")).encode()


def _encrypted(magic=b"BIE1", *, ciphertext_length=32, ephemeral_prefix=2):
    decoded = (magic + bytes((ephemeral_prefix,)) + b"P" * 32
               + b"C" * ciphertext_length + b"M" * 32)
    return base64.b64encode(decoded)


def _analyze(data, start=100):
    return ElectrumCandidateAssembler().analyze_bytes(
        data, source="disk.img", physical_start=start)


def _resident_context(tmp_path, payload, *, allocated=True, attribute_id=7):
    data = bytearray(data_resident(payload))
    data[14:16] = attribute_id.to_bytes(2, "little")
    records = {
        4: file_record(4, (filename("wallet_1", parent=7), bytes(data)),
                       allocated=allocated),
        5: file_record(5, (filename("Root", parent=5),), directory=True),
        6: file_record(6, (filename("Electrum", parent=5),), directory=True),
        7: file_record(7, (filename("wallets", parent=6),), directory=True),
    }
    path = tmp_path / "resident-ntfs.img"
    path.write_bytes(image_with(records))
    locator = NTFSBitcoinArtifactLocator()
    locator.index(path)
    return path, locator.stale_recovery_context


def test_valid_plaintext_electrum_fixture_is_structural_and_safe():
    candidate = _analyze(_plaintext())[0]
    assert candidate.serialization_type == "ELECTRUM_JSON"
    assert candidate.completeness == "COMPLETE"
    assert candidate.encryption_state == "PLAINTEXT_STRUCTURE"
    assert candidate.confidence == "HIGH"
    assert candidate.safe_metadata == {
        "wallet_type": "standard",
        "seed_version": 71,
        "keystore_types": ["bip32"],
        "keystore_count": 1,
        "has_seed_material": True,
        "has_public_master_metadata": True,
    }
    assert SYNTHETIC_SEED not in json.dumps(candidate.safe_metadata)
    assert SYNTHETIC_XPRV not in json.dumps(candidate.safe_metadata)


def test_valid_encrypted_bie1_and_bie2_containers():
    for magic in (b"BIE1", b"BIE2"):
        candidate = _analyze(_encrypted(magic))[0]
        assert candidate.serialization_type == "ELECTRUM_ECIES_BASE64"
        assert candidate.encryption_state == "ENCRYPTED_CONTAINER"
        assert candidate.safe_metadata["container_magic"] == magic.decode()
        assert candidate.safe_metadata["mac_length"] == 32


def test_truncated_encrypted_container_is_fragment_not_complete():
    candidate = _analyze(b"QklFMQ" + b"A" * 37)[0]
    assert candidate.completeness == "TRUNCATED"
    assert candidate.encryption_state == "UNKNOWN"
    assert "ELECTRUM_SERIALIZATION_TRUNCATED" in candidate.reason_codes


def test_malformed_encrypted_framing_is_rejected():
    assert not _analyze(_encrypted(ephemeral_prefix=4))
    assert not _analyze(_encrypted(ciphertext_length=17))


def test_ordinary_json_or_single_words_are_rejected():
    ordinary = json.dumps({"application": "electrum", "theme": "wallet"}).encode()
    seed_only = json.dumps({"seed": "synthetic"}).encode()
    random = b"wallet keystore electrum seed ordinary documentation"
    assert not _analyze(ordinary)
    assert not _analyze(seed_only)
    assert not _analyze(random)


def test_rejected_recovery_has_explicit_reason_code(tmp_path):
    path = tmp_path / "seed-only.img"
    path.write_bytes(json.dumps({"seed": "ordinary phrase"}).encode())
    result = ElectrumRawRecoveryPipeline(source=path).analyze_range(
        start=0, end=path.stat().st_size,
    )
    assert result.structural_status == "REJECTED"
    assert result.reason_codes == ("NO_ELECTRUM_WALLET_STRUCTURE_CONFIRMED",)


def test_complete_and_fragment_candidates_expose_structural_classification():
    complete = _analyze(_plaintext())[0]
    fragment = _analyze(_plaintext()[:-20])[0]
    assert complete.structural_status == "STRONG"
    assert fragment.structural_status == "FRAGMENT"


def test_inconsistent_wallet_structure_is_rejected():
    assert not _analyze(_plaintext(keystore={"type": "unknown"}))
    assert not _analyze(_plaintext(seed_version="71"))
    assert not _analyze(_plaintext(wallet_type={"not": "a string"}))


def test_truncated_plaintext_wallet_at_input_end():
    data = _plaintext()[:-20]
    candidate = _analyze(data)[0]
    assert candidate.completeness == "TRUNCATED"
    assert candidate.serialization_type == "ELECTRUM_JSON_FRAGMENT"


def test_two_independent_nearby_candidates_are_not_merged():
    first, second = _plaintext(), _encrypted()
    candidates = _analyze(first + b"\x00" * 8 + second)
    assert len(candidates) == 2
    assert candidates[0].physical_end < candidates[1].physical_start
    assert {item.serialization_type for item in candidates} == {
        "ELECTRUM_JSON", "ELECTRUM_ECIES_BASE64"}


def test_signature_crossing_scanner_chunk_boundary(tmp_path):
    token = _encrypted()
    path = tmp_path / "crossing.img"
    path.write_bytes(b"X" * 13 + token + b"\x00")
    signature = Signature(ELECTRUM_BIE1_BASE64_SIGNATURE, b"QklFMQ",
                          "electrum_raw_anchor")
    hits = tuple(FastScanner((signature,)).scan(
        ChunkReader(path, chunk_size=16, overlap=5)))
    assert hits[0].start_offset == 13
    result = ElectrumRawRecoveryPipeline(source=path).run_hits(hits)
    assert result.complete_candidates == 1


def test_duplicate_active_wallet_correlation_and_allocation(tmp_path):
    raw = _plaintext()
    path = tmp_path / "active.img"
    path.write_bytes(raw)
    extent = SimpleNamespace(
        vcn_start=0, sparse=False, physical_byte_start=0,
        physical_byte_end=len(raw),
    )
    artifact = KnownElectrumArtifact(
        "default_wallet", str(path), "ALLOCATED_FILE", True,
        len(raw), (extent,), ("MFT",),
    )
    result = ElectrumRawRecoveryPipeline(
        source=path, known_artifacts=(artifact,)
    ).analyze_range(start=0, end=len(raw))
    candidate = result.candidates[0]
    assert candidate.known_active_duplicate
    assert candidate.allocation_state == "ALLOCATED_FILE"
    assert candidate.correlated_sources == ("MFT",)
    assert "KNOWN_ACTIVE_ELECTRUM_DUPLICATE" in candidate.reason_codes


def test_unknown_raw_candidate_has_unknown_allocation(tmp_path):
    raw = _encrypted()
    path = tmp_path / "unknown.img"
    path.write_bytes(raw)
    result = ElectrumRawRecoveryPipeline(source=path).analyze_range(
        start=0, end=len(raw))
    assert result.new_unknown_candidates == 1
    assert result.candidates[0].allocation_state == "UNKNOWN_ALLOCATION"
    assert not result.candidates[0].known_active_duplicate


def test_known_fragmented_extent_is_reassembled_without_proximity_merge(tmp_path):
    raw = _plaintext()
    split = len(raw) // 2
    path = tmp_path / "fragmented.img"
    path.write_bytes(raw[:split] + b"X" * 4096 + raw[split:])
    extents = (
        SimpleNamespace(vcn_start=0, sparse=False, physical_byte_start=0,
                        physical_byte_end=split),
        SimpleNamespace(vcn_start=1, sparse=False,
                        physical_byte_start=split + 4096,
                        physical_byte_end=split + 4096 + len(raw) - split),
    )
    artifact = KnownElectrumArtifact(
        "custom-name", str(path), "ALLOCATED_FILE", True, len(raw), extents)
    result = ElectrumRawRecoveryPipeline(source=path).analyze_known_artifact(artifact)
    candidate = result.candidates[0]
    assert candidate.completeness == "COMPLETE"
    assert candidate.known_active_duplicate
    assert len(candidate.provenance) == 2


def test_valid_resident_unnamed_data_targeted_read_has_bounded_metadata(tmp_path):
    raw = _plaintext()
    _, context = _resident_context(tmp_path, raw, attribute_id=19)
    resident = context.read_resident_unnamed_data(4)
    assert resident.value == raw
    assert resident.logical_size == len(raw)
    assert resident.attribute_id == 19
    assert resident.physical_mft_record_offset == context.physical_offset_for_mft_record(4)
    assert resident.resident_value_offset > 0


def test_resident_electrum_json_is_active_current_duplicate(tmp_path):
    path, context = _resident_context(tmp_path, _plaintext())
    artifacts = known_electrum_artifacts_from_contexts((context,))
    assert len(artifacts) == 1
    assert artifacts[0].resident_data is not None
    result = ElectrumRawRecoveryPipeline(
        source=path, known_artifacts=artifacts,
    ).analyze_known_artifact(artifacts[0])
    candidate = result.candidates[0]
    assert candidate.serialization_type == "ELECTRUM_JSON"
    assert candidate.state == "ACTIVE_CURRENT"
    assert candidate.allocation_state == "ALLOCATED_FILE"
    assert candidate.known_active_duplicate
    assert candidate.correlated_sources == ("MFT",)
    provenance = candidate.provenance[0]
    assert provenance["source_kind"] == "NTFS_RESIDENT_DATA"
    assert provenance["volume_start"] == 0
    assert provenance["mft_record_number"] == 4
    assert provenance["resident_attribute_id"] == 7
    assert provenance["logical_size"] == len(_plaintext())


def _known_artifact_context(*, extent_start, extent_end, record_offset=9000):
    extent = SimpleNamespace(
        vcn_start=0,
        sparse=False,
        physical_byte_start=extent_start,
        physical_byte_end=extent_end,
    )
    data = SimpleNamespace(
        resident=False,
        logical_size=extent_end - extent_start,
        extents=(extent,),
        resident_value_offset=None,
    )
    alias = SimpleNamespace(
        filename="default_wallet",
        parent_mft_record_number=4,
    )
    record = SimpleNamespace(
        number=4,
        allocated=True,
        data=data,
        aliases=(alias,),
    )
    return SimpleNamespace(
        current_records_by_number={4: record},
        source="synthetic.img",
        boot=SimpleNamespace(volume_offset=0),
        physical_offset_for_mft_record=lambda number: record_offset,
    )


@pytest.mark.parametrize(
    "extent_start,extent_end,range_start,range_end,expected",
    (
        (100, 200, 0, 1000, True),
        (100, 200, 120, 180, True),
        (100, 200, 150, 250, True),
        (100, 200, 50, 150, True),
        (100, 200, 200, 300, False),
        (100, 200, 0, 100, False),
        (300, 400, 0, 100, False),
    ),
)
def test_known_ntfs_artifact_admission_uses_half_open_data_extent_range(
        extent_start, extent_end, range_start, range_end, expected):
    context = _known_artifact_context(
        extent_start=extent_start,
        extent_end=extent_end,
        record_offset=9000,
    )

    artifacts = known_electrum_artifacts_from_contexts(
        (context,), range_start=range_start, range_end=range_end)

    assert bool(artifacts) is expected


def test_global_mft_record_outside_range_does_not_hide_extent_inside_range():
    context = _known_artifact_context(
        extent_start=100,
        extent_end=200,
        record_offset=9000,
    )
    artifacts = known_electrum_artifacts_from_contexts(
        (context,), range_start=120, range_end=180)
    assert len(artifacts) == 1
    assert artifacts[0].physical_mft_record_offset == 9000


def test_mft_record_inside_range_does_not_admit_extent_outside_range():
    context = _known_artifact_context(
        extent_start=300,
        extent_end=400,
        record_offset=50,
    )
    assert known_electrum_artifacts_from_contexts(
        (context,), range_start=0, range_end=100) == ()


def test_known_artifact_without_explicit_range_preserves_full_scan_behavior():
    context = _known_artifact_context(extent_start=300, extent_end=400)
    assert len(known_electrum_artifacts_from_contexts((context,))) == 1


def test_resident_artifact_outside_range_avoids_secondary_record_read():
    reads = []
    data = SimpleNamespace(
        resident=True,
        logical_size=32,
        extents=(),
        resident_value_offset=128,
    )
    alias = SimpleNamespace(
        filename="default_wallet",
        parent_mft_record_number=4,
    )
    record = SimpleNamespace(
        number=4, allocated=True, data=data, aliases=(alias,))
    context = SimpleNamespace(
        current_records_by_number={4: record},
        source="synthetic.img",
        boot=SimpleNamespace(volume_offset=0),
        physical_offset_for_mft_record=lambda number: 50,
        read_resident_unnamed_data=lambda number: reads.append(number),
    )

    artifacts = known_electrum_artifacts_from_contexts(
        (context,), range_start=0, range_end=100)

    assert artifacts == ()
    assert reads == []


@pytest.mark.parametrize("magic", (b"BIE1", b"BIE2"))
def test_resident_bie_containers_are_targeted_and_correlated(tmp_path, magic):
    path, context = _resident_context(tmp_path, _encrypted(magic))
    artifact = known_electrum_artifacts_from_contexts((context,))[0]
    result = ElectrumRawRecoveryPipeline(
        source=path, known_artifacts=(artifact,),
    ).analyze_known_artifact(artifact)
    candidate = result.candidates[0]
    assert candidate.safe_metadata["container_magic"] == magic.decode()
    assert candidate.known_active_duplicate
    assert candidate.state == "ACTIVE_CURRENT"


def test_raw_candidate_inside_resident_value_correlates_to_active_mft(tmp_path):
    raw = _encrypted()
    path, context = _resident_context(tmp_path, raw)
    artifact = known_electrum_artifacts_from_contexts((context,))[0]
    start = artifact.physical_mft_record_offset + artifact.resident_value_offset
    result = ElectrumRawRecoveryPipeline(
        source=path, known_artifacts=(artifact,),
    ).analyze_range(start=start, end=start + len(raw))
    candidate = result.candidates[0]
    assert candidate.state == "ACTIVE_CURRENT"
    assert candidate.allocation_state == "ALLOCATED_FILE"
    assert candidate.known_active_duplicate
    assert result.new_unknown_candidates == 0
    assert candidate.provenance[0]["source_kind"] == "NTFS_RESIDENT_DATA"
    assert candidate.provenance[0]["mft_record_number"] == 4


def test_resident_data_bounds_and_malformed_attribute_are_rejected(tmp_path):
    path, context = _resident_context(tmp_path, _encrypted())
    raw = bytearray(context.read_current_record(4))
    data_offset = raw.find((0x80).to_bytes(4, "little"), 56)
    raw[data_offset + 20:data_offset + 22] = (0xFFFF).to_bytes(2, "little")
    with pytest.raises(NtfsMftRecordError, match="resident_data_bounds_invalid"):
        NTFSBitcoinArtifactLocator().resident_unnamed_data(
            bytes(raw), number=4, boot=context.boot,
            image_size=path.stat().st_size,
            physical_mft_record_offset=context.physical_offset_for_mft_record(4),
        )

    malformed = bytearray(context.read_current_record(4))
    malformed[data_offset + 4:data_offset + 8] = (8).to_bytes(4, "little")
    with pytest.raises(NtfsMftRecordError, match="attribute_record_invalid"):
        NTFSBitcoinArtifactLocator().resident_unnamed_data(
            bytes(malformed), number=4, boot=context.boot,
            image_size=path.stat().st_size,
            physical_mft_record_offset=context.physical_offset_for_mft_record(4),
        )


def test_unallocated_flag_is_not_inferred_for_active_resident_candidate(tmp_path):
    path, context = _resident_context(tmp_path, _encrypted(), allocated=True)
    artifact = known_electrum_artifacts_from_contexts((context,))[0]
    candidate = ElectrumRawRecoveryPipeline(
        source=path, known_artifacts=(artifact,),
    ).analyze_known_artifact(artifact).candidates[0]
    assert candidate.allocation_state == "ALLOCATED_FILE"
    assert candidate.state == "ACTIVE_CURRENT"


def test_resident_wallet_secrets_are_not_serialized_to_json(tmp_path):
    path, context = _resident_context(tmp_path, _plaintext())
    artifact = known_electrum_artifacts_from_contexts((context,))[0]
    result = ElectrumRawRecoveryPipeline(
        source=path, known_artifacts=(artifact,),
    ).analyze_known_artifact(artifact)
    encoded = json.dumps(_electrum_raw_recovery(result))
    assert SYNTHETIC_SEED not in encoded
    assert SYNTHETIC_XPRV not in encoded
    assert "resident_data" not in encoded


def test_nonresident_targeted_behavior_remains_unchanged(tmp_path):
    raw = _encrypted()
    path = tmp_path / "nonresident.img"
    path.write_bytes(raw)
    extent = SimpleNamespace(vcn_start=0, sparse=False,
                             physical_byte_start=0,
                             physical_byte_end=len(raw))
    artifact = KnownElectrumArtifact(
        "wallet_2", str(path), "ALLOCATED_FILE", True,
        len(raw), (extent,), ("MFT",),
    )
    candidate = ElectrumRawRecoveryPipeline(
        source=path, known_artifacts=(artifact,),
    ).analyze_known_artifact(artifact).candidates[0]
    assert candidate.serialization_type == "ELECTRUM_ECIES_BASE64"
    assert candidate.known_active_duplicate
    assert candidate.state == "ACTIVE_CURRENT"


def test_failure_isolation_keeps_valid_candidate(tmp_path):
    valid = _encrypted()
    malformed = b"QklFMQ" + b"!" * 20
    path = tmp_path / "isolated.img"
    path.write_bytes(malformed + b"\x00" * 32 + valid)
    hits = (
        RawHit(0, 6, ELECTRUM_BIE1_BASE64_SIGNATURE, 0.0, str(path), {}),
        RawHit(len(malformed) + 32, len(malformed) + 38,
               ELECTRUM_BIE1_BASE64_SIGNATURE, 0.0, str(path), {}),
    )
    result = ElectrumRawRecoveryPipeline(source=path).run_hits(hits)
    assert result.complete_candidates == 1


def test_report_contains_no_secret_values():
    candidate = _analyze(_plaintext())[0]
    result = SimpleNamespace(
        enabled=True, anchors_found=3, candidates_total=1,
        complete_candidates=1, fragment_candidates=0,
        encrypted_candidates=0, plaintext_candidates=1,
        known_active_duplicates=0, new_unknown_candidates=1,
        failures=(), candidates=(candidate,),
    )
    encoded = json.dumps(_electrum_raw_recovery(result))
    assert SYNTHETIC_SEED not in encoded
    assert SYNTHETIC_XPRV not in encoded
    assert "private_key" not in encoded
    assert "WIF" not in encoded


def test_anchor_set_requires_structural_validation():
    names = {name for name, _ in ELECTRUM_SIGNATURE_PATTERNS}
    assert names == ELECTRUM_SIGNATURE_NAMES
    assert all(pattern not in (b"seed", b"wallet", b"electrum", b"keystore")
               for _, pattern in ELECTRUM_SIGNATURE_PATTERNS)


def _anchored_json(data: bytes, anchor: int, *, stats=None):
    return tuple(ElectrumCandidateAssembler._json_objects_containing(
        data, anchor, scan_stats=stats))


def test_anchored_json_finds_wallet_containing_anchor_with_nested_objects():
    wallet = _plaintext(addresses={"receiving": [{"label": "nested"}]})
    data = b'{"unrelated":true}\x00' + wallet + b'\x00{"after":true}'
    anchor = data.index(b'"seed_version"')
    objects = _anchored_json(data, anchor)
    assert [(start, end) for start, end, _ in objects] == [
        (data.index(wallet), data.index(wallet) + len(wallet))]
    candidates = ElectrumCandidateAssembler().analyze_bytes(
        data, source="disk.img", required_anchor_offset=anchor)
    assert len(candidates) == 1
    assert candidates[0].serialization_type == "ELECTRUM_JSON"


def test_anchored_json_handles_braces_quotes_and_backslashes_in_strings():
    wallet = _plaintext(note='literal { and } with quote " and slash \\\\')
    prefix = b'{"noise":"{not an object}"}\x00'
    data = prefix + wallet + b'\x00{"tail":"}"}'
    anchor = data.index(b'"wallet_type"', len(prefix))
    anchored = _anchored_json(data, anchor)
    old_filtered = tuple(
        item for item in ElectrumCandidateAssembler._json_objects(data)
        if item[0] <= anchor < item[1]
    )
    assert tuple((a, b, value) for a, b, value in anchored) == old_filtered


def test_anchored_json_excludes_objects_before_and_after_anchor():
    before = b'{"before":true}'
    after = b'{"after":true}'
    wallet = _plaintext()
    data = before + b"\x00" + wallet + b"\x00" + after
    anchor = data.index(b'"keystore"')
    spans = [(start, end) for start, end, _ in _anchored_json(data, anchor)]
    assert spans == [(len(before) + 1, len(before) + 1 + len(wallet))]


def test_anchored_json_ignores_many_unrelated_objects_on_both_sides():
    wallet = _plaintext()
    noise = b'{"noise":{}}\x00' * 2000
    data = noise + wallet + noise
    anchor = len(noise) + wallet.index(b'"seed_version"')
    objects = _anchored_json(data, anchor)
    assert len(objects) == 1
    assert data[objects[0][0]:objects[0][1]] == wallet


@pytest.mark.parametrize("data", (
    b'{"seed_version":71,"wallet_type":"standard","keystore":{',
    b'\x00\xffrandom{binary\x80data without json',
    b'{"before":true}\x00anchor\x00{"after":true}',
))
def test_anchored_json_rejects_truncated_random_and_non_containing_data(data):
    anchor = data.find(b"anchor")
    if anchor < 0:
        anchor = min(len(data) - 1, max(0, len(data) // 2))
    assert not _anchored_json(data, anchor)


def test_anchored_json_matches_previous_results_for_valid_nested_wallets():
    inner = json.loads(_plaintext())
    outer = json.dumps({"wrapper": inner, "seed_version": 999,
                        "wallet_type": "standard",
                        "keystore": {"type": "bip32", "xpub": "outer"}},
                       separators=(",", ":")).encode()
    anchor = outer.index(b'"wallet_type"')
    old = tuple(
        (start, end, value)
        for start, end, value in ElectrumCandidateAssembler._json_objects(outer)
        if start <= anchor < end
    )
    assert _anchored_json(outer, anchor) == old


def test_anchored_json_matches_previous_spans_at_every_anchor_position():
    wallet = _plaintext(note='BIE1 { quoted } and escaped " \\\\ value')
    data = (b'junk {broken " prefix\x00' + b'{"ordinary":{"nested":1}}\x00'
            + wallet + b'\x00{"after":"{brace}"}')
    old_objects = tuple(ElectrumCandidateAssembler._json_objects(data))
    for anchor in range(len(data)):
        expected = tuple(
            item for item in old_objects if item[0] <= anchor < item[1])
        assert _anchored_json(data, anchor) == expected, anchor


def test_anchored_json_boundary_scan_is_linear_on_maximum_window():
    wallet = _plaintext()
    opening_count = 2048
    anchor_position = MAX_SCANNER_CANDIDATE_WINDOW // 2
    prefix = b"{" * opening_count
    prefix += b"X" * (anchor_position - len(prefix))
    suffix_size = MAX_SCANNER_CANDIDATE_WINDOW - len(prefix) - len(wallet)
    data = prefix + wallet + b"}" * opening_count
    data += b"Z" * (suffix_size - opening_count)
    anchor = data.index(b'"seed_version"')
    stats = {}
    objects = _anchored_json(data, anchor, stats=stats)
    assert any(data[start:end] == wallet for start, end, _ in objects)
    assert stats["boundary_bytes"] <= 5 * len(data)
    legacy_minimum_byte_visits = opening_count * (anchor - opening_count)
    assert legacy_minimum_byte_visits > 100 * stats["boundary_bytes"]


def test_run_hits_reports_throttled_secret_free_progress(tmp_path):
    wallet = _plaintext()
    path = tmp_path / "progress.img"
    path.write_bytes(wallet)
    offset = wallet.index(b'"seed_version"')
    hits = (RawHit(offset, offset + len(b'"seed_version"'),
                   "electrum_seed_version_anchor", 0.0, str(path), {}),)
    updates = []
    result = ElectrumRawRecoveryPipeline(source=path).run_hits(
        hits, progress=lambda completed, total, elapsed:
        updates.append((completed, total, elapsed)),
    )
    assert result.complete_candidates == 1
    assert updates[0] == (0, 1, 0.0)
    assert updates[-1][0:2] == (1, 1)
    assert SYNTHETIC_SEED not in repr(updates)
    assert SYNTHETIC_XPRV not in repr(updates)


class _CountingRangeReader:
    def __init__(self, data: bytes, *, eof: int | None = None) -> None:
        self.data = data
        self.eof = len(data) if eof is None else eof
        self.calls: list[tuple[int, int]] = []

    def read_at(self, offset: int, length: int) -> bytes:
        self.calls.append((offset, length))
        available_end = min(offset + length, self.eof, len(self.data))
        if available_end <= offset:
            return b""
        return self.data[offset:available_end]

    @property
    def requested_bytes(self) -> int:
        return sum(length for _, length in self.calls)


class _RecordingAssembler:
    def __init__(self) -> None:
        self.calls = []

    def analyze_bytes(self, data, **kwargs):
        self.calls.append((
            kwargs["physical_start"],
            kwargs["required_anchor_offset"],
            kwargs["anchor_types"],
            len(data),
        ))
        return ()


def _sized_source(tmp_path, size: int):
    path = tmp_path / "synthetic-secondary-reads.bin"
    with path.open("wb") as stream:
        if size:
            stream.seek(size - 1)
            stream.write(b"\0")
    return path


def _hit(offset: int, hit_type=ELECTRUM_BIE1_BASE64_SIGNATURE):
    return RawHit(offset, offset + 6, hit_type, 0.0, "synthetic", {})


def _pipeline_with_recorder(path, reader):
    pipeline = ElectrumRawRecoveryPipeline(source=path, range_reader=reader)
    recorder = _RecordingAssembler()
    pipeline.assembler = recorder
    return pipeline, recorder


def _run_per_anchor_baseline(pipeline, hits, reader, *, range_start=0,
                             range_end=None):
    """Test-only copy of the pre-merge physical read behavior."""
    end = pipeline.path.stat().st_size if range_end is None else range_end
    found = {}
    for hit in hits:
        window_start = max(range_start, hit.start_offset - MAX_BACKWARD_CONTEXT)
        window_end = min(end, window_start + MAX_SCANNER_CANDIDATE_WINDOW)
        data = reader.read_at(window_start, window_end - window_start)
        assembled = pipeline.assembler.analyze_bytes(
            data,
            source=str(pipeline.path),
            physical_start=window_start,
            required_anchor_offset=hit.start_offset - window_start,
            anchor_types=(hit.hit_type,),
        )
        for candidate in assembled:
            correlated = pipeline._correlate(candidate)
            found[(correlated.physical_start, correlated.physical_end,
                   correlated.serialization_type)] = correlated
    return pipeline._result(len(hits), tuple(found.values()), ())


def test_one_anchor_uses_one_physical_read_and_preserves_result(tmp_path):
    wallet = _plaintext()
    prefix = b"X" * 128
    data = prefix + wallet + b"\0" * 128
    path = tmp_path / "single-anchor.bin"
    path.write_bytes(data)
    anchor = len(prefix) + wallet.index(b'"seed_version"')
    hit = _hit(anchor, "electrum_seed_version_anchor")
    reader = _CountingRangeReader(data)

    merged = ElectrumRawRecoveryPipeline(
        source=path, range_reader=reader).run_hits((hit,))
    original = ElectrumRawRecoveryPipeline(source=path).run_hits((hit,))

    assert len(reader.calls) == 1
    assert merged == original


def test_two_distant_anchor_windows_use_two_reads(tmp_path):
    size = 6 * 1024 * 1024
    path = _sized_source(tmp_path, size)
    reader = _CountingRangeReader(b"\0" * size)
    pipeline, _ = _pipeline_with_recorder(path, reader)

    pipeline.run_hits((_hit(1024 * 1024), _hit(5 * 1024 * 1024)))

    assert len(reader.calls) == 2


def test_two_strongly_overlapping_windows_use_one_read(tmp_path):
    size = 4 * 1024 * 1024
    path = _sized_source(tmp_path, size)
    reader = _CountingRangeReader(b"\0" * size)
    pipeline, _ = _pipeline_with_recorder(path, reader)

    pipeline.run_hits((_hit(1200 * 1024), _hit(1300 * 1024)))

    assert len(reader.calls) == 1


def test_dense_anchors_reduce_physical_calls_and_requested_bytes(tmp_path):
    size = 4 * 1024 * 1024
    path = _sized_source(tmp_path, size)
    reader = _CountingRangeReader(b"\0" * size)
    pipeline, recorder = _pipeline_with_recorder(path, reader)
    hits = tuple(_hit(MAX_BACKWARD_CONTEXT + index * 4096)
                 for index in range(40))
    baseline_reader = _CountingRangeReader(b"\0" * size)
    baseline_pipeline, _ = _pipeline_with_recorder(path, baseline_reader)

    _run_per_anchor_baseline(baseline_pipeline, hits, baseline_reader)
    pipeline.run_hits(hits)

    assert len(baseline_reader.calls) == len(hits)
    assert baseline_reader.requested_bytes == (
        len(hits) * MAX_SCANNER_CANDIDATE_WINDOW)
    assert len(reader.calls) == 1
    assert len(recorder.calls) == len(hits)
    assert reader.requested_bytes == (
        MAX_SCANNER_CANDIDATE_WINDOW + (len(hits) - 1) * 4096)
    assert reader.requested_bytes < baseline_reader.requested_bytes // 20


def test_three_identical_windows_share_one_read_but_keep_anchor_analysis(tmp_path):
    size = 3 * 1024 * 1024
    path = _sized_source(tmp_path, size)
    reader = _CountingRangeReader(b"\0" * size)
    pipeline, recorder = _pipeline_with_recorder(path, reader)
    hits = (_hit(100), _hit(200), _hit(300))

    pipeline.run_hits(hits)

    assert reader.calls == [(0, MAX_SCANNER_CANDIDATE_WINDOW)]
    assert len(recorder.calls) == 3
    assert [item[1] for item in recorder.calls] == [100, 200, 300]


def test_anchor_near_source_start_preserves_clamp_and_offsets(tmp_path):
    size = 3 * 1024 * 1024
    path = _sized_source(tmp_path, size)
    reader = _CountingRangeReader(b"\0" * size)
    pipeline, recorder = _pipeline_with_recorder(path, reader)

    pipeline.run_hits((_hit(7),))

    assert reader.calls == [(0, MAX_SCANNER_CANDIDATE_WINDOW)]
    assert recorder.calls == [(
        0, 7, (ELECTRUM_BIE1_BASE64_SIGNATURE,),
        MAX_SCANNER_CANDIDATE_WINDOW,
    )]


def test_anchor_near_source_end_preserves_clamp_and_offsets(tmp_path):
    size = 3 * 1024 * 1024
    anchor = size - 7
    path = _sized_source(tmp_path, size)
    reader = _CountingRangeReader(b"\0" * size)
    pipeline, recorder = _pipeline_with_recorder(path, reader)

    pipeline.run_hits((_hit(anchor),))

    expected_start = anchor - MAX_BACKWARD_CONTEXT
    assert reader.calls == [(expected_start, size - expected_start)]
    assert recorder.calls == [(
        expected_start, MAX_BACKWARD_CONTEXT,
        (ELECTRUM_BIE1_BASE64_SIGNATURE,), size - expected_start,
    )]


def test_merged_read_limit_safely_splits_overlap_chain(tmp_path, monkeypatch):
    limit = 4 * 1024 * 1024
    monkeypatch.setattr(
        electrum_raw_module, "MAX_MERGED_ELECTRUM_READ_SIZE", limit)
    assert limit >= MAX_SCANNER_CANDIDATE_WINDOW
    size = 10 * 1024 * 1024
    path = _sized_source(tmp_path, size)
    reader = _CountingRangeReader(b"\0" * size)
    pipeline, recorder = _pipeline_with_recorder(path, reader)
    hits = tuple(_hit(MAX_BACKWARD_CONTEXT + index * 1536 * 1024)
                 for index in range(6))

    pipeline.run_hits(hits)

    assert 1 < len(reader.calls) < len(hits)
    assert all(length <= limit for _, length in reader.calls)
    assert len(recorder.calls) == len(hits)


def test_merged_results_provenance_offsets_and_order_match_original(tmp_path):
    wallet = _plaintext()
    prefix = b"P" * (MAX_BACKWARD_CONTEXT + 128)
    data = prefix + wallet + b"\0" * 128
    path = tmp_path / "semantic-equivalence.bin"
    path.write_bytes(data)
    hits = tuple(
        _hit(len(prefix) + wallet.index(pattern), name)
        for name, pattern in (
            ("electrum_seed_version_anchor", b'"seed_version"'),
            ("electrum_wallet_type_anchor", b'"wallet_type"'),
            ("electrum_keystore_anchor", b'"keystore"'),
        )
    )
    baseline_reader = _CountingRangeReader(data)
    baseline_pipeline = ElectrumRawRecoveryPipeline(
        source=path, range_reader=baseline_reader)
    original = _run_per_anchor_baseline(
        baseline_pipeline, hits, baseline_reader)
    reader = _CountingRangeReader(data)
    merged = ElectrumRawRecoveryPipeline(
        source=path, range_reader=reader).run_hits(hits)
    repeated = ElectrumRawRecoveryPipeline(
        source=path, range_reader=_CountingRangeReader(data)).run_hits(
            tuple(reversed(hits)))

    assert merged == original == repeated
    assert len(baseline_reader.calls) == len(hits)
    assert len(reader.calls) == 1
    assert merged.candidates[0].provenance == original.candidates[0].provenance
    assert merged.candidates[0].physical_start == len(prefix)


def test_no_anchors_performs_zero_secondary_reads(tmp_path):
    path = _sized_source(tmp_path, 1024)
    reader = _CountingRangeReader(b"\0" * 1024)

    result = ElectrumRawRecoveryPipeline(
        source=path, range_reader=reader).run_hits(())

    assert reader.calls == []
    assert result.anchors_found == 0


def test_short_merged_read_matches_per_anchor_eof_slices(tmp_path):
    size = 3 * 1024 * 1024
    eof = 1400 * 1024
    data = b"\0" * size
    path = _sized_source(tmp_path, size)
    hits = (_hit(1024 * 1024), _hit(1300 * 1024))
    merged_reader = _CountingRangeReader(data, eof=eof)
    pipeline, merged_recorder = _pipeline_with_recorder(path, merged_reader)

    pipeline.run_hits(hits)

    expected = []
    baseline_reader = _CountingRangeReader(data, eof=eof)
    for window in pipeline._anchor_windows(hits, range_start=0, range_end=size):
        logical = baseline_reader.read_at(window.start, window.end - window.start)
        expected.append((
            window.start,
            window.hit.start_offset - window.start,
            (window.hit.hit_type,),
            len(logical),
        ))
    assert len(merged_reader.calls) == 1
    assert len(baseline_reader.calls) == len(hits)
    assert merged_recorder.calls == expected


def test_default_merged_read_limit_covers_original_candidate_window():
    assert MAX_MERGED_ELECTRUM_READ_SIZE >= MAX_SCANNER_CANDIDATE_WINDOW
