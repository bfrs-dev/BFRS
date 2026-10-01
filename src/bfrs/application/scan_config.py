"""GUI-independent scan configuration contract for BFRS front ends."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from bfrs.core.source_types import SourceType
from bfrs.core.worker_control import validate_worker_count


DEFAULT_CHUNK_MIB = 64
DEFAULT_OVERLAP_KIB = 64
DEFAULT_CLUSTER_MIB = 2
DEFAULT_PADDING_MIB = 1
DEFAULT_MINIMUM_HITS = 1
DEFAULT_MINIMUM_DISTINCT_TYPES = 1


class ScanConfigError(ValueError):
    """A configuration cannot be executed safely by the BFRS scan engine."""


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Immutable scan request shared by CLI and future GUI front ends.

    The model deliberately contains no argparse, Qt, progress rendering, or
    scanning code.  It captures the current CLI contract so front ends can
    validate the same basic invariants before handing work to the engine.
    """

    input_path: Path
    output_path: Path
    source_type: SourceType | None = None

    recover_wallets: bool = False
    recovery_dir: Path | None = None
    revalidate_wallet_records: Path | None = None

    start: int = 0
    end: int | None = None
    chunk_mib: int = DEFAULT_CHUNK_MIB
    overlap_kib: int = DEFAULT_OVERLAP_KIB

    targets: frozenset[str] | None = None
    electrum_only: bool = False
    seed_scan_only: bool = False
    include_mnemonic: bool = False
    include_bitcoin_context: bool = False
    skip_mnemonic: bool = False

    workers: int = 1
    file_workers: int = 1

    checkpoint: Path | None = None
    resume_checkpoint: Path | None = None

    cluster_mib: int = DEFAULT_CLUSTER_MIB
    padding_mib: int = DEFAULT_PADDING_MIB
    minimum_hits: int = DEFAULT_MINIMUM_HITS
    minimum_distinct_types: int = DEFAULT_MINIMUM_DISTINCT_TYPES

    def __post_init__(self) -> None:
        self._validate_modes()
        self._validate_range_and_sizes()
        self._validate_workers()

    def _validate_modes(self) -> None:
        if self.revalidate_wallet_records is not None:
            if any((
                self.targets is not None,
                self.electrum_only,
                self.seed_scan_only,
                self.skip_mnemonic,
                self.checkpoint is not None,
                self.resume_checkpoint is not None,
                self.start != 0,
                self.end is not None,
                self.recover_wallets,
                self.recovery_dir is not None,
            )):
                raise ScanConfigError(
                    "--revalidate-wallet-records cannot be combined with scan "
                    "modes, targets, checkpoints, --start, or --end"
                )

        if self.targets is not None and not self.targets:
            raise ScanConfigError("targets must not be empty when explicitly provided")
        if self.targets is not None and (self.electrum_only or self.seed_scan_only):
            raise ScanConfigError(
                "--targets cannot be combined with legacy only-mode flags"
            )
        if self.electrum_only and self.seed_scan_only:
            raise ScanConfigError(
                "--electrum-only and --seed-scan-only are mutually exclusive"
            )
        if self.seed_scan_only and self.skip_mnemonic:
            raise ScanConfigError(
                "--skip-mnemonic cannot be combined with --seed-scan-only"
            )
        if self.include_mnemonic and self.skip_mnemonic:
            raise ScanConfigError(
                "--include-mnemonic and --skip-mnemonic are mutually exclusive"
            )
        if self.include_mnemonic and self.seed_scan_only:
            raise ScanConfigError(
                "--include-mnemonic is redundant with --seed-scan-only"
            )
        if self.recover_wallets and self.recovery_dir is None:
            raise ScanConfigError("--recover-wallets requires --recovery-dir")
        if self.recovery_dir is not None and not self.recover_wallets:
            raise ScanConfigError("--recovery-dir requires --recover-wallets")
        if self.recover_wallets and self.seed_scan_only:
            raise ScanConfigError(
                "--recover-wallets cannot be combined with --seed-scan-only"
            )
        if self.checkpoint is not None and self.resume_checkpoint is not None:
            raise ScanConfigError(
                "--checkpoint and --resume-checkpoint are mutually exclusive"
            )

    def _validate_range_and_sizes(self) -> None:
        if self.start < 0:
            raise ScanConfigError("--start must be nonnegative")
        if self.end is not None and self.end <= self.start:
            raise ScanConfigError("--end must be greater than --start")

        for name in ("chunk_mib", "cluster_mib", "padding_mib"):
            value = getattr(self, name)
            minimum = 0 if name == "padding_mib" else 1
            if value < minimum:
                option = name.replace("_", "-")
                raise ScanConfigError(
                    f"--{option} must be at least {minimum}"
                )

        if self.overlap_kib < 0:
            raise ScanConfigError("--overlap-kib must be nonnegative")
        if self.minimum_hits < 1:
            raise ScanConfigError("--minimum-hits must be at least 1")
        if self.minimum_distinct_types < 1:
            raise ScanConfigError("--minimum-distinct-types must be at least 1")

        chunk_bytes = self.chunk_mib * 1024 * 1024
        if self.overlap_kib * 1024 >= chunk_bytes:
            raise ScanConfigError(
                "--overlap-kib must be smaller than --chunk-mib"
            )

    def _validate_workers(self) -> None:
        try:
            validate_worker_count(self.workers)
        except ValueError as error:
            raise ScanConfigError(str(error)) from error

        if self.file_workers < 1:
            raise ScanConfigError("--file-workers must be at least 1")
        try:
            validate_worker_count(self.file_workers)
        except ValueError as error:
            message = str(error).replace("workers", "file workers", 1)
            raise ScanConfigError(message) from error

    @property
    def chunk_bytes(self) -> int:
        return self.chunk_mib * 1024 * 1024

    @property
    def overlap_bytes(self) -> int:
        return self.overlap_kib * 1024

    @property
    def checkpoint_path(self) -> Path | None:
        return self.checkpoint or self.resume_checkpoint
