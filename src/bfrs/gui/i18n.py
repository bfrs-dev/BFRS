"""Small Qt-independent translation catalog for the BFRS GUI."""

from __future__ import annotations

from collections.abc import Mapping


DEFAULT_LANGUAGE = "pl"
SUPPORTED_LANGUAGES: Mapping[str, str] = {
    "pl": "Polski",
    "en": "English",
}


_TRANSLATIONS: dict[str, dict[str, str]] = {
    "pl": {
        "language": "Język:",
        "tab_scan": "Skanowanie",
        "tab_results": "Wyniki",
        "source_report_group": "Źródło i raport",
        "source_placeholder": "Obraz dysku, plik lub folder",
        "choose_file": "Wybierz plik…",
        "choose_folder": "Wybierz folder…",
        "source": "Źródło:",
        "type": "Typ:",
        "report": "Raport:",
        "auto": "Automatycznie",
        "disk_image": "Obraz dysku",
        "single_file": "Pojedynczy plik",
        "folder": "Folder",
        "report_placeholder": "Plik raportu JSON",
        "choose_report": "Wybierz raport…",
        "scan_scope_group": "Zakres skanowania",
        "target_bitcoin_core": "Bitcoin Core",
        "target_electrum": "Electrum",
        "target_multibit": "MultiBit",
        "target_armory": "Armory",
        "target_secrets": "Klucze / sekrety",
        "search_mnemonic": "Szukaj seed / mnemonic",
        "bitcoin_context": "Rozszerzony kontekst Bitcoin",
        "performance_group": "Wydajność i checkpoint",
        "workers": "Workers:",
        "file_workers": "File workers:",
        "checkpoint": "Checkpoint:",
        "checkpoint_placeholder": "Opcjonalny plik checkpoint",
        "choose": "Wybierz…",
        "resume_checkpoint": "Wznów z istniejącego checkpointu",
        "progress_group": "Postęp",
        "ready": "Gotowy",
        "start_scan": "Rozpocznij skanowanie",
        "stop_safely": "Zatrzymaj bezpiecznie",
        "choose_source_title": "Wybierz źródło",
        "choose_folder_title": "Wybierz folder",
        "choose_report_title": "Wybierz raport",
        "choose_checkpoint_title": "Wybierz checkpoint",
        "new_checkpoint_title": "Nowy checkpoint",
        "invalid_configuration": "Nieprawidłowa konfiguracja",
        "starting_scan": "Uruchamianie skanu…",
        "stopping_scan": "Zatrzymywanie po zakończeniu bezpiecznej jednostki…",
        "scanning": "Skanowanie",
        "none": "brak",
        "scan_phase": "skan",
        "phase": "faza",
        "checkpoint_saved": "Checkpoint zapisany: {path}",
        "scan_stopped": "Skan zatrzymany bezpiecznie",
        "error_prefix": "Błąd: {message}",
        "scan_completed_status": "Skan zakończony — status: {status}",
        "scan_completed_report": "Skan zakończony — raport: {path}",
        "scan_failed": "Skan zakończony błędem",
        "scan_error_title": "Błąd skanowania",
        "results_group": "Przeglądarka wyników",
        "open_report": "Otwórz raport…",
        "report_not_loaded": "Nie wczytano raportu",
        "report_loaded": "Raport: {path} | trafienia: {count}",
        "filter_target": "Target:",
        "filter_state": "Stan:",
        "filter_crypto": "Crypto:",
        "filter_search": "Szukaj:",
        "filter_all": "Wszystkie",
        "quick_filters": "Szybkie filtry:",
        "summary_total": "Pasujące: {count}",
        "render_limit": "Pokazano pierwsze {shown} z {matching} pasujących wyników.",
        "column_priority": "Priorytet",
        "summary_accepted": "Accepted: {count}",
        "summary_review": "Review: {count}",
        "summary_rejected": "Rejected: {count}",
        "summary_crypto_valid": "Crypto-valid: {count}",
        "column_target": "Target",
        "column_artifact": "Artefakt",
        "column_state": "Stan",
        "column_crypto": "Crypto",
        "column_confidence": "Pewność",
        "column_location": "Lokalizacja",
        "details_group": "Szczegóły",
        "details_empty": "Wybierz trafienie z tabeli.",
        "open_report_title": "Otwórz raport BFRS",
        "report_error_title": "Błąd raportu",
        "report_error": "Nie można otworzyć raportu: {message}",
        "reason_codes": "Reason codes",
        "structural_status": "Status strukturalny",
        "validation_status": "Status walidacji",
        "recovery_action": "Zalecana akcja",
        "safe_metadata": "Bezpieczne metadane",
        "validation_source_required": "Wybierz źródło skanowania.",
        "validation_report_required": "Wybierz plik raportu JSON.",
        "validation_target_required": "Wybierz co najmniej jeden typ danych do skanowania.",
        "validation_resume_checkpoint_required": "Wskaż checkpoint, który ma zostać wznowiony.",
        "validation_checkpoint_missing": (
            "Wybrany checkpoint nie istnieje. Wskaż istniejący plik "
            "albo wyłącz opcję wznowienia."
        ),
        "validation_checkpoint_exists": (
            "Checkpoint już istnieje. Wybierz nową nazwę albo zaznacz "
            "„Wznów z istniejącego checkpointu”."
        ),
    },
    "en": {
        "language": "Language:",
        "tab_scan": "Scan",
        "tab_results": "Results",
        "source_report_group": "Source and report",
        "source_placeholder": "Disk image, file, or folder",
        "choose_file": "Choose file…",
        "choose_folder": "Choose folder…",
        "source": "Source:",
        "type": "Type:",
        "report": "Report:",
        "auto": "Automatic",
        "disk_image": "Disk image",
        "single_file": "Single file",
        "folder": "Folder",
        "report_placeholder": "JSON report file",
        "choose_report": "Choose report…",
        "scan_scope_group": "Scan scope",
        "target_bitcoin_core": "Bitcoin Core",
        "target_electrum": "Electrum",
        "target_multibit": "MultiBit",
        "target_armory": "Armory",
        "target_secrets": "Keys / secrets",
        "search_mnemonic": "Search seed / mnemonic",
        "bitcoin_context": "Extended Bitcoin context",
        "performance_group": "Performance and checkpoint",
        "workers": "Workers:",
        "file_workers": "File workers:",
        "checkpoint": "Checkpoint:",
        "checkpoint_placeholder": "Optional checkpoint file",
        "choose": "Choose…",
        "resume_checkpoint": "Resume from existing checkpoint",
        "progress_group": "Progress",
        "ready": "Ready",
        "start_scan": "Start scan",
        "stop_safely": "Stop safely",
        "choose_source_title": "Choose source",
        "choose_folder_title": "Choose folder",
        "choose_report_title": "Choose report",
        "choose_checkpoint_title": "Choose checkpoint",
        "new_checkpoint_title": "New checkpoint",
        "invalid_configuration": "Invalid configuration",
        "starting_scan": "Starting scan…",
        "stopping_scan": "Stopping after the current safe work unit…",
        "scanning": "Scanning",
        "none": "none",
        "scan_phase": "scan",
        "phase": "phase",
        "checkpoint_saved": "Checkpoint saved: {path}",
        "scan_stopped": "Scan stopped safely",
        "error_prefix": "Error: {message}",
        "scan_completed_status": "Scan completed — status: {status}",
        "scan_completed_report": "Scan completed — report: {path}",
        "scan_failed": "Scan failed",
        "scan_error_title": "Scan error",
        "results_group": "Result browser",
        "open_report": "Open report…",
        "report_not_loaded": "No report loaded",
        "report_loaded": "Report: {path} | findings: {count}",
        "filter_target": "Target:",
        "filter_state": "State:",
        "filter_crypto": "Crypto:",
        "filter_search": "Search:",
        "filter_all": "All",
        "quick_filters": "Quick filters:",
        "summary_total": "Matching: {count}",
        "render_limit": "Showing the first {shown} of {matching} matching results.",
        "column_priority": "Priority",
        "summary_accepted": "Accepted: {count}",
        "summary_review": "Review: {count}",
        "summary_rejected": "Rejected: {count}",
        "summary_crypto_valid": "Crypto-valid: {count}",
        "column_target": "Target",
        "column_artifact": "Artifact",
        "column_state": "State",
        "column_crypto": "Crypto",
        "column_confidence": "Confidence",
        "column_location": "Location",
        "details_group": "Details",
        "details_empty": "Select a finding from the table.",
        "open_report_title": "Open BFRS report",
        "report_error_title": "Report error",
        "report_error": "Unable to open report: {message}",
        "reason_codes": "Reason codes",
        "structural_status": "Structural status",
        "validation_status": "Validation status",
        "recovery_action": "Recommended action",
        "safe_metadata": "Safe metadata",
        "validation_source_required": "Choose a scan source.",
        "validation_report_required": "Choose a JSON report file.",
        "validation_target_required": "Choose at least one scan target.",
        "validation_resume_checkpoint_required": "Choose a checkpoint to resume.",
        "validation_checkpoint_missing": (
            "The selected checkpoint does not exist. Choose an existing file "
            "or disable resume mode."
        ),
        "validation_checkpoint_exists": (
            "The checkpoint already exists. Choose a new name or enable "
            "“Resume from existing checkpoint”."
        ),
    },
}


def normalize_language(language: str | None) -> str:
    """Return a supported language code, falling back to Polish."""
    code = (language or DEFAULT_LANGUAGE).casefold()
    return code if code in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def translate(language: str | None, key: str, **values: object) -> str:
    """Translate one catalog key and format named placeholders."""
    code = normalize_language(language)
    try:
        template = _TRANSLATIONS[code][key]
    except KeyError as error:
        raise KeyError(f"unknown GUI translation key: {key}") from error
    return template.format(**values)


def validate_catalogs() -> None:
    """Raise when language catalogs do not expose the same keys."""
    baseline = set(_TRANSLATIONS[DEFAULT_LANGUAGE])
    for code, catalog in _TRANSLATIONS.items():
        missing = baseline - set(catalog)
        extra = set(catalog) - baseline
        if missing or extra:
            raise ValueError(
                f"translation catalog mismatch for {code}: "
                f"missing={sorted(missing)} extra={sorted(extra)}"
            )
