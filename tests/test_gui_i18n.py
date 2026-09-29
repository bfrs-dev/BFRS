import pytest

from bfrs.gui.i18n import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    normalize_language,
    translate,
    validate_catalogs,
)


def test_translation_catalogs_have_identical_keys():
    validate_catalogs()


def test_supported_languages_include_polish_and_english():
    assert DEFAULT_LANGUAGE == "pl"
    assert SUPPORTED_LANGUAGES == {"pl": "Polski", "en": "English"}


def test_unknown_language_falls_back_to_polish():
    assert normalize_language("xx") == "pl"
    assert translate("xx", "ready") == "Gotowy"


def test_core_labels_translate_to_english():
    assert translate("en", "source_report_group") == "Source and report"
    assert translate("en", "start_scan") == "Start scan"
    assert translate("en", "stop_safely") == "Stop safely"
    assert translate("en", "resume_checkpoint") == "Resume from existing checkpoint"


def test_format_placeholders_are_supported():
    assert translate("en", "checkpoint_saved", path="scan.sqlite") == (
        "Checkpoint saved: scan.sqlite"
    )


def test_unknown_translation_key_is_explicit():
    with pytest.raises(KeyError, match="unknown GUI translation key"):
        translate("en", "does_not_exist")
