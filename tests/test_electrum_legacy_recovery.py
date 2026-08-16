import json
from types import SimpleNamespace

from bfrs.core.chunk_reader import ChunkReader
from bfrs.core.models import RawHit
from bfrs.recovery.electrum_legacy_recovery import (
    ElectrumLegacyCandidateAssembler,
    LEGACY_ELECTRUM_SIGNATURE_NAMES,
    LEGACY_ELECTRUM_SIGNATURE_PATTERNS,
)
from bfrs.recovery.electrum_raw_recovery import (
    ElectrumCandidateAssembler,
    ElectrumRawRecoveryPipeline,
    KnownElectrumArtifact,
)
from bfrs.reporting.json_report import _electrum_raw_recovery
from bfrs.scanners.fast_scanner import FastScanner, Signature


SYNTHETIC_SECRET = "synthetic legacy seed placeholder never use"
SYNTHETIC_PRIVATE = "synthetic-xprv-private-placeholder"
OLD_MPK = "ab" * 64


def _old_literal(**updates):
    value = {
        "seed_version": 4,
        "use_encryption": False,
        "seed": SYNTHETIC_SECRET,
        "master_public_key": OLD_MPK,
        "accounts": {0: {0: [], 1: [], "name": "Main account"}},
        "addr_history": {},
    }
    value.update(updates)
    return repr(value).encode()


def _transitional(**updates):
    value = {
        "seed_version": 11,
        "wallet_type": "standard",
        "use_encryption": True,
        "seed": SYNTHETIC_SECRET,
        "master_public_keys": {"x/": "xpub-synthetic-public-placeholder"},
        "master_private_keys": {"x/": SYNTHETIC_PRIVATE},
        "accounts": {"0": {"xpub": "xpub-synthetic-public-placeholder"}},
    }
    value.update(updates)
    return json.dumps(value, separators=(",", ":")).encode()


def _legacy(data):
    return ElectrumLegacyCandidateAssembler().analyze_bytes(data)


def test_valid_complete_electrum_1x_python_literal_wallet():
    item = _legacy(_old_literal())[0]
    assert item.legacy_format == "ELECTRUM_1X_PYTHON_LITERAL"
    assert item.completeness == "COMPLETE"
    assert item.safe_metadata["keystore_category"] == "OLD_DETERMINISTIC"
    assert item.safe_metadata["seed_version"] == 4


def test_valid_complete_transitional_json_field_encrypted_wallet():
    item = _legacy(_transitional())[0]
    assert item.legacy_format == "ELECTRUM_TRANSITIONAL_JSON"
    assert item.encryption_state == "FIELD_LEVEL_ENCRYPTED"
    assert item.safe_metadata["has_private_material"]


def test_truncated_and_structural_fragment():
    truncated = _old_literal()[:-20]
    item = _legacy(truncated)[0]
    assert item.completeness == "TRUNCATED"
    structural = (_old_literal()[:-1] + b", 'labels': {}")
    item = _legacy(structural)[0]
    assert item.completeness == "STRUCTURAL_FRAGMENT"
    assert item.safe_metadata["preserved_field_count"] >= 3


def test_malformed_serialization_and_bad_types_rejected():
    assert not _legacy(b"{'seed_version': 4, 'accounts': {}, 'master_public_key': !!!}")
    assert not _legacy(_old_literal(seed_version="4"))
    assert not _legacy(_old_literal(accounts=[]))


def test_ordinary_json_source_and_config_text_rejected():
    ordinary = json.dumps({"seed_version": 4, "accounts": {}, "theme": "wallet"}).encode()
    source = b"config = {'seed_version': 4, 'accounts': {}}\ndef wallet(seed): return seed"
    assert not _legacy(ordinary)
    assert not _legacy(source)


def test_imported_and_watch_only_are_structurally_classified():
    imported = _transitional(
        wallet_type="imported", use_encryption=False, seed="",
        master_private_keys={}, accounts={"/x": {"imported": {"address": ["pub", None]}}},
    )
    item = _legacy(imported)[0]
    assert item.safe_metadata["imported"]
    assert item.safe_metadata["watch_only"]


def test_chunk_boundary_anchor_and_pipeline(tmp_path):
    raw = _old_literal()
    path = tmp_path / "legacy-crossing.img"
    path.write_bytes(b"X" * 13 + raw + b"\x00")
    name, pattern = LEGACY_ELECTRUM_SIGNATURE_PATTERNS[0]
    hits = tuple(FastScanner((Signature(name, pattern, "electrum_raw_anchor"),)).scan(
        ChunkReader(path, chunk_size=32, overlap=len(pattern) - 1)))
    assert hits and hits[0].start_offset > 13
    result = ElectrumRawRecoveryPipeline(source=path).run_hits(hits)
    assert result.legacy_complete_candidates == 1
    assert result.legacy_anchors_found == 1


def test_two_nearby_independent_wallets_do_not_merge():
    first, second = _old_literal(), _transitional()
    items = ElectrumCandidateAssembler().analyze_bytes(
        first + b"\x00" * 8 + second, source="disk.img"
    )
    legacy = [item for item in items if item.legacy_format]
    assert len(legacy) == 2
    assert legacy[0].physical_end < legacy[1].physical_start


def test_known_active_correlation_and_unknown_candidate(tmp_path):
    raw = _old_literal()
    path = tmp_path / "legacy.img"
    path.write_bytes(raw)
    extent = SimpleNamespace(vcn_start=0, sparse=False,
                             physical_byte_start=0, physical_byte_end=len(raw))
    artifact = KnownElectrumArtifact(
        "electrum.dat", str(path), "ALLOCATED_FILE", True, len(raw), (extent,),
    )
    known = ElectrumRawRecoveryPipeline(
        source=path, known_artifacts=(artifact,)
    ).analyze_range(start=0, end=len(raw)).candidates[0]
    unknown = ElectrumRawRecoveryPipeline(source=path).analyze_range(
        start=0, end=len(raw)).candidates[0]
    assert known.known_active_duplicate and known.legacy_format
    assert not unknown.known_active_duplicate


def test_safe_json_and_legacy_counters_do_not_expose_secrets(tmp_path):
    raw = _transitional()
    path = tmp_path / "safe.img"
    path.write_bytes(raw)
    result = ElectrumRawRecoveryPipeline(source=path).analyze_range(start=0, end=len(raw))
    encoded = json.dumps(_electrum_raw_recovery(result))
    assert result.legacy_candidates_total == 1
    assert result.legacy_encrypted_candidates == 1
    for secret in (SYNTHETIC_SECRET, SYNTHETIC_PRIVATE, "xprv", "private_key", "WIF"):
        assert secret not in encoded


def test_failure_isolation_and_bie_regression(tmp_path):
    valid = _old_literal()
    path = tmp_path / "failure.img"
    path.write_bytes(b"{'seed_version': !!!}\x00" + b"X" * (2 * 1024 * 1024) + valid)
    name = next(iter(LEGACY_ELECTRUM_SIGNATURE_NAMES))
    malformed = RawHit(0, 14, name, 0.0, str(path), {})
    valid_offset = path.read_bytes().find(valid) + valid.find(b"'seed_version'")
    good = RawHit(valid_offset, valid_offset + 14, name, 0.0, str(path), {})
    result = ElectrumRawRecoveryPipeline(source=path).run_hits((malformed, good))
    assert result.legacy_complete_candidates == 1
    assert result.legacy_failures == ("ELECTRUM_LEGACY_STRUCTURE_INCONSISTENT",)
    bie = b"QklFMQ" + b"A" * 30
    assert ElectrumCandidateAssembler().analyze_bytes(bie, source="disk.img")[0].legacy_format is None
