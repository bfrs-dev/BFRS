"""Pure configuration adapter used by the Qt front end."""

from __future__ import annotations

from pathlib import Path

from bfrs.application import ScanConfig
from bfrs.core.source_types import SourceType


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
) -> ScanConfig:
    """Build the application contract from presentation-layer values."""

    source = Path(input_path.strip())
    output = Path(output_path.strip())
    if not str(source):
        raise ValueError("Wybierz źródło skanowania.")
    if not str(output):
        raise ValueError("Wybierz plik raportu JSON.")
    if not targets:
        raise ValueError("Wybierz co najmniej jeden typ danych do skanowania.")

    selected_source_type = (
        SourceType(source_type.upper()) if source_type else None
    )

    checkpoint_text = checkpoint_path.strip()
    checkpoint = Path(checkpoint_text) if checkpoint_text else None

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
