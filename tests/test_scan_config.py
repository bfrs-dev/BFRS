from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from bfrs.application.scan_config import (
    DEFAULT_CHUNK_MIB,
    DEFAULT_CLUSTER_MIB,
    DEFAULT_MINIMUM_DISTINCT_TYPES,
    DEFAULT_MINIMUM_HITS,
    DEFAULT_OVERLAP_KIB,
    DEFAULT_PADDING_MIB,
    ScanConfig,
    ScanConfigError,
)
from bfrs.core.source_types import SourceType


def config(tmp_path, **overrides) -> ScanConfig:
    values = {
        "input_path": tmp_path / "source.img",
        "output_path": tmp_path / "report.json",
    }
    values.update(overrides)
    return ScanConfig(**values)


def test_defaults_match_current_cli_contract(tmp_path):
    value = config(tmp_path)

    assert value.start == 0
    assert value.end is None
    assert value.chunk_mib == DEFAULT_CHUNK_MIB == 64
    assert value.overlap_kib == DEFAULT_OVERLAP_KIB == 64
    assert value.cluster_mib == DEFAULT_CLUSTER_MIB == 2
    assert value.padding_mib == DEFAULT_PADDING_MIB == 1
    assert value.minimum_hits == DEFAULT_MINIMUM_HITS == 1
    assert value.minimum_distinct_types == DEFAULT_MINIMUM_DISTINCT_TYPES == 1
    assert value.workers == 1
    assert value.file_workers == 1
    assert value.targets is None
    assert value.source_type is None


def test_config_is_immutable_and_gui_independent(tmp_path):
    value = config(tmp_path, source_type=SourceType.IMAGE)

    assert value.source_type is SourceType.IMAGE
    with pytest.raises(FrozenInstanceError):
        value.workers = 2


def test_byte_size_properties_are_derived_from_cli_units(tmp_path):
    value = config(tmp_path, chunk_mib=8, overlap_kib=32)

    assert value.chunk_bytes == 8 * 1024 * 1024
    assert value.overlap_bytes == 32 * 1024


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"start": -1}, "--start must be nonnegative"),
        ({"start": 10, "end": 10}, "--end must be greater than --start"),
        ({"chunk_mib": 0}, "--chunk-mib must be at least 1"),
        ({"cluster_mib": 0}, "--cluster-mib must be at least 1"),
        ({"padding_mib": -1}, "--padding-mib must be at least 0"),
        ({"overlap_kib": -1}, "--overlap-kib must be nonnegative"),
        ({"minimum_hits": 0}, "--minimum-hits must be at least 1"),
        (
            {"minimum_distinct_types": 0},
            "--minimum-distinct-types must be at least 1",
        ),
        (
            {"chunk_mib": 1, "overlap_kib": 1024},
            "--overlap-kib must be smaller than --chunk-mib",
        ),
    ],
)
def test_range_and_size_validation_matches_cli(tmp_path, overrides, message):
    with pytest.raises(ScanConfigError, match=message):
        config(tmp_path, **overrides)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"checkpoint": Path("a"), "resume_checkpoint": Path("b")},
            "--checkpoint and --resume-checkpoint are mutually exclusive",
        ),
        (
            {"electrum_only": True, "seed_scan_only": True},
            "--electrum-only and --seed-scan-only are mutually exclusive",
        ),
        (
            {"include_mnemonic": True, "skip_mnemonic": True},
            "--include-mnemonic and --skip-mnemonic are mutually exclusive",
        ),
        (
            {"seed_scan_only": True, "skip_mnemonic": True},
            "--skip-mnemonic cannot be combined with --seed-scan-only",
        ),
        (
            {"seed_scan_only": True, "include_mnemonic": True},
            "--include-mnemonic is redundant with --seed-scan-only",
        ),
        (
            {"targets": frozenset({"bitcoin-core"}), "electrum_only": True},
            "--targets cannot be combined with legacy only-mode flags",
        ),
    ],
)
def test_mode_conflicts_match_cli(tmp_path, overrides, message):
    with pytest.raises(ScanConfigError, match=message):
        config(tmp_path, **overrides)


def test_explicit_targets_cannot_be_empty(tmp_path):
    with pytest.raises(ScanConfigError, match="targets must not be empty"):
        config(tmp_path, targets=frozenset())


def test_wallet_recovery_requires_destination_and_opt_in(tmp_path):
    with pytest.raises(ScanConfigError, match="requires --recovery-dir"):
        config(tmp_path, recover_wallets=True)

    with pytest.raises(ScanConfigError, match="requires --recover-wallets"):
        config(tmp_path, recovery_dir=tmp_path / "recovered")


def test_wallet_recovery_is_not_available_in_seed_only_mode(tmp_path):
    with pytest.raises(
        ScanConfigError,
        match="--recover-wallets cannot be combined with --seed-scan-only",
    ):
        config(
            tmp_path,
            recover_wallets=True,
            recovery_dir=tmp_path / "recovered",
            seed_scan_only=True,
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"targets": frozenset({"bitcoin-core"})},
        {"checkpoint": Path("checkpoint.json")},
        {"resume_checkpoint": Path("checkpoint.json")},
        {"start": 1},
        {"end": 10},
        {"recover_wallets": True, "recovery_dir": Path("recovered")},
    ],
)
def test_revalidation_rejects_scan_only_options(tmp_path, overrides):
    with pytest.raises(
        ScanConfigError,
        match="--revalidate-wallet-records cannot be combined",
    ):
        config(
            tmp_path,
            revalidate_wallet_records=tmp_path / "old-report.json",
            **overrides,
        )


def test_worker_counts_preserve_zero_auto_and_reject_negative(tmp_path):
    assert config(tmp_path, workers=0).workers == 0

    with pytest.raises(ScanConfigError, match="workers must be nonnegative"):
        config(tmp_path, workers=-1)

    with pytest.raises(ScanConfigError, match="--file-workers must be at least 1"):
        config(tmp_path, file_workers=0)


def test_checkpoint_path_exposes_create_or_resume_path(tmp_path):
    create_path = tmp_path / "create.checkpoint.json"
    resume_path = tmp_path / "resume.checkpoint.json"

    assert config(tmp_path, checkpoint=create_path).checkpoint_path == create_path
    assert (
        config(tmp_path, resume_checkpoint=resume_path).checkpoint_path
        == resume_path
    )
    assert config(tmp_path).checkpoint_path is None
