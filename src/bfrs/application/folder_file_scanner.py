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
        # Keep each run's configuration separate from the parent namespace.
        self._arguments = copy(arguments)
        self._should_stop = should_stop
        self._on_error = on_error
        self._local = threading.local()

    def __call__(self, argv):
        source = Path(argv[argv.index("--input") + 1])
        return self._scan(source, argv=argv)

    def scan_file(self, source: Path, output: Path):
        """Prepared non-writing child request; configuration is fixed per run."""
        return self._scan(source, output=output)

    def _scan(self, source: Path, *, argv=None, output=None):
        from bfrs.cli import _selection, _run_scan, _validate_arguments, build_parser, main
        from bfrs.scanners.folder_source_scanner import _child_arguments

        small = source.stat().st_size <= self._arguments.chunk_mib * 1024 * 1024
        parser = getattr(self._local, "parser", None)
        if parser is None:
            parser = self._local.parser = build_parser()
        selections = getattr(self._local, "selections", None)
        if selections is None:
            selections = self._local.selections = {}
        selection_workers = 1 if small else self._arguments.workers
        if selection_workers not in selections:
            settings = copy(self._arguments)
            settings.workers = selection_workers
            # Equal effective worker settings have identical detector indexes,
            # even when alternating small and large files. Never share across
            # file-worker threads; per-file token buffers are cleared below.
            selections[selection_workers] = _selection(parser, settings)
        selection = selections[selection_workers]
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
            options = dict(
                _folder_child=True,
                _scan_should_stop=self._should_stop,
                _scan_error=self._on_error,
                _selection_override=selection,
                _report_sink=reports.append,
                _seed_pipeline=pipeline,
                _seed_workers=(1 if small else self._arguments.workers),
            )
            if argv is not None:
                code = main(argv, **options)
            else:
                template = getattr(self._local, "child_template", None)
                if template is None:
                    template = parser.parse_args(_child_arguments(
                        self._arguments, source, output))
                    _validate_arguments(parser, template)
                    # This is the same non-writing child policy used by the
                    # argv adapter, never a copy of parent checkpoint/recovery.
                    if (template.source_type != "file" or template.file_workers != 1
                            or template.start != 0 or template.end is not None
                            or template.checkpoint is not None or template.resume_checkpoint is not None
                            or template.recover_wallets or template.recovery_dir is not None
                            or template.revalidate_wallet_records is not None):
                        raise ValueError("prepared folder child must be a non-writing whole-file scan")
                    self._local.child_template = template
                arguments = copy(template)
                arguments.input, arguments.output = source, output
                code = _run_scan(arguments, parser, **options)
            return reports[0] if code == 0 else code
        finally:
            # Token caches contain file data; retain only the reusable indexes.
            for detector in selection.chunk_detectors:
                scanner = getattr(detector, "scanner", None)
                if scanner is not None:
                    scanner._normalize_token.cache_clear()
            if pipeline is not None:
                pipeline.scanner._normalize_token.cache_clear()
