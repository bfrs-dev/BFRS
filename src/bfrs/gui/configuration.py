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
        workers=workers,
        file_workers=file_workers,
        checkpoint=(None if resume_checkpoint else checkpoint),
        resume_checkpoint=(checkpoint if resume_checkpoint else None),
    )
