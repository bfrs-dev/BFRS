import base64
import json
from types import SimpleNamespace

import pytest

from bfrs.core.chunk_reader import ChunkReader
from bfrs.core.models import RawHit
from bfrs.recovery.electrum_raw_recovery import (
    ELECTRUM_BIE1_BASE64_SIGNATURE,
    ELECTRUM_SIGNATURE_NAMES,
    ELECTRUM_SIGNATURE_PATTERNS,
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
