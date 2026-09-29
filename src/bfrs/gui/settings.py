"""Persistent, Qt-independent preferences for the BFRS desktop GUI."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import uuid

from bfrs.gui.i18n import DEFAULT_LANGUAGE, normalize_language


@dataclass(frozen=True, slots=True)
class GuiPreferences:
    language: str = DEFAULT_LANGUAGE
    workers: int = 4
    file_workers: int = 1
    last_source: str = ""
    last_output: str = ""
    last_result_report: str = ""


def default_settings_path() -> Path:
    """Return a per-user settings path without requiring Qt."""
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "BFRS" / "gui-settings.json"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "bfrs" / "gui-settings.json"
    return Path.home() / ".config" / "bfrs" / "gui-settings.json"


class GuiSettingsStore:
    """Load/save non-sensitive GUI preferences with tolerant recovery."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else default_settings_path()

    def load(self) -> GuiPreferences:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return GuiPreferences()
        if not isinstance(payload, dict):
            return GuiPreferences()

        return GuiPreferences(
            language=normalize_language(self._text(payload, "language")),
            workers=self._integer(payload, "workers", default=4, minimum=0, maximum=32),
            file_workers=self._integer(
                payload, "file_workers", default=1, minimum=1, maximum=32
            ),
            last_source=self._text(payload, "last_source"),
            last_output=self._text(payload, "last_output"),
            last_result_report=self._text(payload, "last_result_report"),
        )

    def save(self, preferences: GuiPreferences) -> Path:
        payload = asdict(preferences)
        payload["language"] = normalize_language(preferences.language)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(
            f".{self.path.name}.tmp-{uuid.uuid4().hex}"
        )
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(payload, stream, indent=2, ensure_ascii=False, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return self.path

    @staticmethod
    def _text(payload: dict[str, object], key: str) -> str:
        value = payload.get(key, "")
        return value if isinstance(value, str) else ""

    @staticmethod
    def _integer(
        payload: dict[str, object],
        key: str,
        *,
        default: int,
        minimum: int,
        maximum: int,
    ) -> int:
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            return default
        return min(maximum, max(minimum, value))
