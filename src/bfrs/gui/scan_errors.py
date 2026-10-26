"""Presentation hints; retain the original diagnostic instead of guessing code 3."""
from bfrs.gui.i18n import translate


def explain_scan_error(message: str, language="pl") -> str:
    text = message.casefold()
    if any(s in text for s in ("no space", "disk full", "errno 28", "winerror 112", "brak miejsca")):
        key = "hint_space"
    elif any(s in text for s in ("permission", "access denied", "errno 13", "winerror 5", "odmowa")):
        key = "hint_permission"
    elif "already complete" in text:
        key = "hint_complete"
    elif any(s in text for s in ("source mismatch", "source identity", "source root mismatch", "contents changed", "metadata mismatch")):
        key = "hint_source_identity"
    elif "checkpoint" in text and any(s in text for s in ("version", "legacy", "schema", "format mismatch", "corrupt")):
        key = "hint_checkpoint"
    elif any(s in text for s in ("settings mismatch", "semantic mismatch", "geometry", "range/chunk", "scan range")):
        key = "hint_settings"
    elif "report" in text and any(s in text for s in ("exists", "errno 17", "winerror 183", "winerror 80")):
        key = "hint_report_exists"
    elif "report" in text:
        key = "hint_report"
    elif "checkpoint" in text:
        key = "hint_checkpoint"
    elif any(s in text for s in ("process", "worker", "systemexit")):
        key = "hint_process"
    elif any(s in text for s in ("source", "input error", "errno 2", "winerror 3")):
        key = "hint_source"
    else:
        key = "hint_unknown"
    return f"{message}\n\n{translate(language, key)}"
