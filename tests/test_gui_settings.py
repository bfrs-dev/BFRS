import json

from bfrs.gui.settings import GuiPreferences, GuiSettingsStore, default_settings_path


def test_settings_round_trip(tmp_path):
    path = tmp_path / "gui-settings.json"
    store = GuiSettingsStore(path)
    preferences = GuiPreferences(
        language="en",
        workers=8,
        file_workers=3,
        last_source=r"C:\\images\\disk.img",
        last_output=r"C:\\reports\\scan.json",
        last_result_report=r"C:\\reports\\previous.json",
    )

    result = store.save(preferences)
    loaded = store.load()

    assert result == path
    assert loaded == preferences


def test_missing_or_invalid_settings_fall_back_to_defaults(tmp_path):
    path = tmp_path / "gui-settings.json"
    store = GuiSettingsStore(path)

    assert store.load() == GuiPreferences()

    path.write_text("{broken", encoding="utf-8")
    assert store.load() == GuiPreferences()

    path.write_text("[]", encoding="utf-8")
    assert store.load() == GuiPreferences()


def test_settings_validate_language_workers_and_types(tmp_path):
    path = tmp_path / "gui-settings.json"
    path.write_text(
        json.dumps({
            "language": "xx",
            "workers": 99,
            "file_workers": 0,
            "last_source": 123,
            "last_output": None,
            "last_result_report": ["bad"],
        }),
        encoding="utf-8",
    )

    loaded = GuiSettingsStore(path).load()

    assert loaded.language == "pl"
    assert loaded.workers == 32
    assert loaded.file_workers == 1
    assert loaded.last_source == ""
    assert loaded.last_output == ""
    assert loaded.last_result_report == ""


def test_settings_reject_bool_as_integer(tmp_path):
    path = tmp_path / "gui-settings.json"
    path.write_text(
        json.dumps({"workers": True, "file_workers": False}),
        encoding="utf-8",
    )

    loaded = GuiSettingsStore(path).load()

    assert loaded.workers == 4
    assert loaded.file_workers == 1


def test_save_creates_parent_directory(tmp_path):
    path = tmp_path / "nested" / "gui-settings.json"

    GuiSettingsStore(path).save(GuiPreferences())

    assert path.exists()


def test_default_settings_path_has_stable_filename():
    assert default_settings_path().name == "gui-settings.json"
