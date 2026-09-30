"""Pure configuration adapter used by the Qt front end."""

from __future__ import annotations

from pathlib import Path

from bfrs.application import ScanConfig
from bfrs.core.source_types import SourceType
from bfrs.gui.i18n import translate


def build_gui_scan_config(
    *,
    input_path: str,
    output_path: str,
    source_type: str | None,
    targets: frozenset[str],
    include_mnemonic: bool,
    include_bitcoin_context: bool,
    workers: int,
    file_workers: int,
    start_offset: str = "0",
    end_offset: str = "",
    chunk_mib: int = 64,
    overlap_kib: int = 64,
    cluster_mib: int = 2,
    padding_mib: int = 1,
    minimum_hits: int = 1,
    minimum_distinct_types: int = 1,
    recover_wallets: bool = False,
    recovery_dir: str = "",
    checkpoint_path: str = "",
    resume_checkpoint: bool = False,
    language: str = "pl",
) -> ScanConfig:
    """Build the application contract from presentation-layer values."""

    input_text = input_path.strip()
    output_text = output_path.strip()
    if not input_text:
        raise ValueError(translate(language, "validation_source_required"))
    if not output_text:
        raise ValueError(translate(language, "validation_report_required"))
    source = Path(input_text)
    output = Path(output_text)
    if not targets:
        raise ValueError(translate(language, "validation_target_required"))

    selected_source_type = (
        SourceType(source_type.upper()) if source_type else None
    )

    start_text = start_offset.strip() or "0"
    end_text = end_offset.strip()
    try:
        start = int(start_text, 10)
    except ValueError as error:
        raise ValueError(translate(language, "validation_start_integer")) from error
    if start < 0:
        raise ValueError(translate(language, "validation_start_nonnegative"))

    end = None
    if end_text:
        try:
            end = int(end_text, 10)
        except ValueError as error:
            raise ValueError(translate(language, "validation_end_integer")) from error
        if end <= start:
            raise ValueError(translate(language, "validation_end_greater"))

    recovery_text = recovery_dir.strip()
    if recover_wallets and not recovery_text:
        raise ValueError(translate(language, "validation_recovery_dir_required"))
    recovery = Path(recovery_text) if recover_wallets and recovery_text else None

    checkpoint_text = checkpoint_path.strip()
    if resume_checkpoint and not checkpoint_text:
        raise ValueError(translate(language, "validation_resume_checkpoint_required"))
    checkpoint = Path(checkpoint_text) if checkpoint_text else None
    if checkpoint is not None:
        if resume_checkpoint and not checkpoint.exists():
            raise ValueError(translate(language, "validation_checkpoint_missing"))
        if not resume_checkpoint and checkpoint.exists():
            raise ValueError(translate(language, "validation_checkpoint_exists"))

    return ScanConfig(
        input_path=source,
        output_path=output,
        source_type=selected_source_type,
        targets=targets,
        skip_mnemonic=not include_mnemonic,
        include_bitcoin_context=include_bitcoin_context,
        start=start,
        end=end,
        chunk_mib=chunk_mib,
        overlap_kib=overlap_kib,
        cluster_mib=cluster_mib,
        padding_mib=padding_mib,
        minimum_hits=minimum_hits,
        minimum_distinct_types=minimum_distinct_types,
        recover_wallets=recover_wallets,
        recovery_dir=recovery,
        workers=workers,
        file_workers=file_workers,
        checkpoint=(None if resume_checkpoint else checkpoint),
        resume_checkpoint=(checkpoint if resume_checkpoint else None),
    )
