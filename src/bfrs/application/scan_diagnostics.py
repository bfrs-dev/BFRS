"""Bounded engine diagnostics and GUI-only destination preflight."""
from __future__ import annotations
import errno
from pathlib import Path
import sys
import uuid

from bfrs.core.path_safety import paths_refer_to_same_file


class PreflightError(RuntimeError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def preflight(config) -> None:
    try:
        config.input_path.stat()
    except OSError as error:
        raise PreflightError(3, f"input error: source unavailable: {error}") from error
    source, output = config.input_path, config.output_path
    checkpoint = config.checkpoint_path
    if (paths_refer_to_same_file(source, output) or
            (checkpoint and (paths_refer_to_same_file(checkpoint, source) or
                             paths_refer_to_same_file(checkpoint, output)))):
        raise PreflightError(2, "output/checkpoint path collides with source or report")
    if source.is_dir():
        root = source.resolve()
        if output.resolve(strict=False).is_relative_to(root) or (
                checkpoint and checkpoint.resolve(strict=False).is_relative_to(root)):
            raise PreflightError(2, "folder report/checkpoint must be outside the source root")
    if config.revalidate_wallet_records and paths_refer_to_same_file(output, config.revalidate_wallet_records):
        raise PreflightError(2, "output path collides with source report")
    if config.recovery_dir and paths_refer_to_same_file(config.recovery_dir, output):
        raise PreflightError(2, "output path collides with recovery directory")
    probe = None
    try:
        try:
            output.lstat()
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(errno.EEXIST, "report already exists; choose a new report path", str(output))
        output.parent.mkdir(parents=True, exist_ok=True)
        probe = output.parent / f".bfrs-write-probe-{uuid.uuid4().hex}"
        with probe.open("xb") as stream:
            stream.write(b"BFRS write probe\n")
            stream.flush()
    except OSError as error:
        raise PreflightError(4, f"report error: {error}") from error
    finally:
        if probe is not None:
            try:
                probe.unlink(missing_ok=True)
            except OSError:
                pass


class DiagnosticStderr:
    """Tee stderr; retain only bounded, recognized engine error lines."""
    _prefixes = ("folder checkpoint error:", "folder worker error:", "folder temporary storage error:",
                 "report error:", "checkpoint error:", "input error:", "worker error:")

    def __init__(self, stream, callback):
        self.stream, self.callback = stream, callback
        self.pending = ""
        self.last_error = None

    def _line(self, line):
        line = line.strip()
        if line.startswith(self._prefixes) or ": error:" in line:
            self.last_error = line
            if self.callback:
                self.callback(line)

    def write(self, text):
        # Frozen/windowed Windows applications can have sys.stderr=None.
        # Diagnostics must still reach the event channel without a console.
        result = self.stream.write(text) if self.stream is not None else len(text)
        if text.lstrip().startswith(self._prefixes):
            # Progress uses carriage returns without a terminating newline.
            # Do not glue a real error to an unterminated progress line.
            if not self.pending.lstrip().startswith(self._prefixes):
                self.pending = ""
        for piece in text.replace("\r", "\n").splitlines(keepends=True):
            self.pending = (self.pending + piece)[:8192]
            if piece.endswith("\n"):
                self._line(self.pending)
                self.pending = ""
        return result

    def flush(self):
        if self.stream is not None:
            self.stream.flush()

    def finish(self):
        if self.pending:
            self._line(self.pending)
            self.pending = ""

    def __getattr__(self, name):
        if self.stream is None:
            if name == "encoding":
                return "utf-8"
            if name == "isatty":
                return lambda: False
            raise AttributeError(name)
        return getattr(self.stream, name)
