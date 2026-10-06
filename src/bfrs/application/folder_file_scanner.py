"""Reusable, thread-local file scans with in-memory reports for folders."""

from __future__ import annotations

from copy import copy
from pathlib import Path
import threading

from bfrs.recovery.mnemonic.mnemonic_recovery_pipeline import MnemonicRecoveryPipeline


class FolderFileScanner:
    """Keep detector indexes isolated per file worker, reuse them across files.

    Small files use local mnemonic decoding: starting a process pool for every
    recovered file costs much more than scanning the data. Large files retain
    the requested worker count. Both paths run the same detection rules.
    """

    def __init__(self, arguments, *, should_stop=None, on_error=None) -> None:
        self._arguments = arguments
        self._should_stop = should_stop
        self._on_error = on_error
        self._local = threading.local()

    def __call__(self, argv):
        from bfrs.cli import _selection, build_parser, main

        source = Path(argv[argv.index("--input") + 1])
        small = source.stat().st_size <= self._arguments.chunk_mib * 1024 * 1024
        selections = getattr(self._local, "selections", None)
        if selections is None:
            selections = self._local.selections = {}
        if small not in selections:
            settings = copy(self._arguments)
            if small:
                settings.workers = 1
            selections[small] = _selection(build_parser(), settings)
        selection = selections[small]
        pipeline = None
        if self._arguments.seed_scan_only:
            pipeline = getattr(self._local, "seed_pipeline", None)
            if pipeline is None:
                pipeline = self._local.seed_pipeline = MnemonicRecoveryPipeline(
                    chunk_size=self._arguments.chunk_mib * 1024 * 1024,
                    overlap=self._arguments.overlap_kib * 1024,
                )
        reports = []
        try:
            code = main(
                argv,
                _folder_child=True,
                _scan_should_stop=self._should_stop,
                _scan_error=self._on_error,
                _selection_override=selection,
                _report_sink=reports.append,
                _seed_pipeline=pipeline,
                _seed_workers=(1 if small else self._arguments.workers),
            )
            return reports[0] if code == 0 else code
        finally:
            # Token caches contain file data; retain only the reusable indexes.
            for detector in selection.chunk_detectors:
                scanner = getattr(detector, "scanner", None)
                if scanner is not None:
                    scanner._normalize_token.cache_clear()
            if pipeline is not None:
                pipeline.scanner._normalize_token.cache_clear()
