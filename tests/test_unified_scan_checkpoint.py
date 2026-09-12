import json

import pytest

from bfrs.recovery.unified_scan_checkpoint import (
    LEGACY_UNIFIED_CHECKPOINT_FORMAT,
    UNIFIED_CHECKPOINT_FORMAT_VERSION,
    UNIFIED_SCANNER_SEMANTICS_VERSION,
    UnifiedCheckpointError,
    UnifiedScanCheckpoint,
    build_scanner_identity,
)
from bfrs.scanners.fast_scanner import Signature


START = 0
END = 64
CHUNK_SIZE = 32
OVERLAP = 4


def _signatures(pattern: bytes = b"alpha") -> tuple[Signature, ...]:
    return (
        Signature("alpha", pattern, "test", "bitcoin-core", "test-anchor"),
        Signature("beta", b"beta", "test", "electrum", "test-anchor"),
    )


def _identity(
    *,
    targets=("bitcoin-core", "electrum"),
    pattern: bytes = b"alpha",
    mnemonic_enabled: bool = True,
    bitcoin_context_enabled: bool = False,
    semantics_version: int = UNIFIED_SCANNER_SEMANTICS_VERSION,
    reverse_signatures: bool = False,
):
    signatures = _signatures(pattern)
    if reverse_signatures:
        signatures = tuple(reversed(signatures))
    return build_scanner_identity(
        targets=targets,
        signatures=signatures,
        mnemonic_enabled=mnemonic_enabled,
        bitcoin_context_enabled=bitcoin_context_enabled,
        semantics_version=semantics_version,
    )


def _create(tmp_path, identity=None):
    source = tmp_path / "source.bin"
    source.write_bytes(b"x" * END)
    checkpoint = UnifiedScanCheckpoint.create(
        tmp_path / "scan.checkpoint.json",
        source,
        start=START,
        end=END,
        chunk_size=CHUNK_SIZE,
        overlap=OVERLAP,
        scanner_identity=identity or _identity(),
    )
    return source, checkpoint


def _resume(checkpoint, source, identity=None, **overrides):
    arguments = {
        "start": START,
        "end": END,
        "chunk_size": CHUNK_SIZE,
        "overlap": OVERLAP,
        "scanner_identity": identity or _identity(),
    }
    arguments.update(overrides)
    return UnifiedScanCheckpoint.resume(checkpoint.path, source, **arguments)


def test_identical_configuration_resumes(tmp_path) -> None:
    identity = _identity()
    source, checkpoint = _create(tmp_path, identity)

    resumed = _resume(checkpoint, source, identity)

    assert resumed.path == checkpoint.path


def test_changed_target_is_rejected(tmp_path) -> None:
    source, checkpoint = _create(tmp_path)

    with pytest.raises(
        UnifiedCheckpointError,
        match="scanner semantic mismatch: selected targets differ",
    ):
        _resume(checkpoint, source, _identity(targets=("bitcoin-core",)))


def test_changed_signature_pattern_with_same_name_is_rejected(tmp_path) -> None:
    source, checkpoint = _create(tmp_path)

    with pytest.raises(
        UnifiedCheckpointError,
        match="scanner semantic mismatch: active signature definitions differ",
    ):
        _resume(checkpoint, source, _identity(pattern=b"changed-alpha"))


def test_changed_scanner_semantics_version_is_rejected(tmp_path) -> None:
    source, checkpoint = _create(tmp_path)

    with pytest.raises(
        UnifiedCheckpointError,
        match="scanner semantic mismatch: scanner semantics version differs",
    ):
        _resume(
            checkpoint,
            source,
            _identity(semantics_version=UNIFIED_SCANNER_SEMANTICS_VERSION + 1),
        )


def test_pre_p1_5_scanner_semantics_checkpoint_is_rejected(tmp_path) -> None:
    source, checkpoint = _create(
        tmp_path,
        _identity(semantics_version=UNIFIED_SCANNER_SEMANTICS_VERSION - 1),
    )

    with pytest.raises(
        UnifiedCheckpointError,
        match="scanner semantic mismatch: scanner semantics version differs",
    ):
        _resume(checkpoint, source)


def test_changed_mnemonic_enablement_is_rejected(tmp_path) -> None:
    source, checkpoint = _create(tmp_path)

    with pytest.raises(
        UnifiedCheckpointError,
        match="scanner semantic mismatch: mnemonic enablement differs",
    ):
        _resume(checkpoint, source, _identity(mnemonic_enabled=False))


def test_changed_bitcoin_context_enablement_is_rejected(tmp_path) -> None:
    source, checkpoint = _create(tmp_path)

    with pytest.raises(
        UnifiedCheckpointError,
        match="scanner semantic mismatch: bitcoin context enablement differs",
    ):
        _resume(checkpoint, source, _identity(bitcoin_context_enabled=True))


def test_worker_count_is_not_part_of_checkpoint_compatibility(tmp_path) -> None:
    workers_at_creation = 2
    workers_at_resume = 4
    creation_identity = _identity()
    resume_identity = _identity()

    assert workers_at_creation != workers_at_resume
    assert "workers" not in creation_identity
    assert creation_identity == resume_identity
    source, checkpoint = _create(tmp_path, creation_identity)
    assert _resume(checkpoint, source, resume_identity).path == checkpoint.path


def test_legacy_v1_without_semantics_version_is_rejected_without_modification(
    tmp_path,
) -> None:
    source, checkpoint = _create(tmp_path)
    payload = checkpoint.payload
    payload["format"] = LEGACY_UNIFIED_CHECKPOINT_FORMAT
    payload.pop("format_version")
    payload["scanner_identity"].pop("scanner_semantics_version")
    checkpoint.path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    original = checkpoint.path.read_bytes()

    with pytest.raises(
        UnifiedCheckpointError,
        match="legacy unified checkpoint rejected:.*V1 compatibility contract.*new checkpoint",
    ):
        _resume(checkpoint, source)

    assert checkpoint.path.read_bytes() == original


def test_unsupported_format_version_has_explicit_error(tmp_path) -> None:
    source, checkpoint = _create(tmp_path)
    payload = checkpoint.payload
    payload["format_version"] = UNIFIED_CHECKPOINT_FORMAT_VERSION + 1
    checkpoint.path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(UnifiedCheckpointError, match="checkpoint format mismatch"):
        _resume(checkpoint, source)


def test_corrupted_checkpoint_has_explicit_error(tmp_path) -> None:
    source, checkpoint = _create(tmp_path)
    checkpoint.path.write_text("{", encoding="utf-8")

    with pytest.raises(UnifiedCheckpointError, match="corrupted unified checkpoint"):
        _resume(checkpoint, source)


def test_canonical_identity_is_independent_of_collection_order() -> None:
    forward = _identity(targets=("electrum", "bitcoin-core"))
    reversed_inputs = _identity(
        targets=("bitcoin-core", "electrum"), reverse_signatures=True
    )

    assert forward == reversed_inputs


def test_source_mismatch_has_explicit_error(tmp_path) -> None:
    _source, checkpoint = _create(tmp_path)
    different_source = tmp_path / "different-source.bin"
    different_source.write_bytes(b"y" * END)

    with pytest.raises(UnifiedCheckpointError, match="checkpoint source mismatch"):
        _resume(checkpoint, different_source)


@pytest.mark.parametrize(
    "override",
    [
        {"end": END - 1},
        {"chunk_size": CHUNK_SIZE * 2},
        {"overlap": OVERLAP + 1},
    ],
)
def test_range_and_chunk_mismatch_have_explicit_error(tmp_path, override) -> None:
    source, checkpoint = _create(tmp_path)

    with pytest.raises(
        UnifiedCheckpointError, match="range/chunk configuration mismatch"
    ):
        _resume(checkpoint, source, **override)


def test_application_version_is_diagnostic_only(tmp_path) -> None:
    source, checkpoint = _create(tmp_path)
    payload = checkpoint.payload
    assert payload["application"]["version"]
    payload["application"]["version"] = "future-diagnostic-version"
    checkpoint.path.write_text(json.dumps(payload), encoding="utf-8")

    assert _resume(checkpoint, source).path == checkpoint.path
