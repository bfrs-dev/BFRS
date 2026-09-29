import builtins
import importlib

import pytest

from bfrs.core.source_types import SourceType
from bfrs.gui.configuration import build_gui_scan_config


def test_gui_config_builds_application_scan_config(tmp_path):
    config = build_gui_scan_config(
        input_path=str(tmp_path / "disk.img"),
        output_path=str(tmp_path / "report.json"),
        source_type="image",
        targets=frozenset({"bitcoin-core", "electrum"}),
        include_mnemonic=True,
        include_bitcoin_context=False,
        workers=4,
        file_workers=2,
    )

    assert config.source_type is SourceType.IMAGE
    assert config.targets == frozenset({"bitcoin-core", "electrum"})
    assert config.skip_mnemonic is False
    assert config.workers == 4
    assert config.file_workers == 2


def test_gui_config_maps_checkpoint_create_and_resume(tmp_path):
    checkpoint = tmp_path / "scan.checkpoint.sqlite"
    base = dict(
        input_path=str(tmp_path / "disk.img"),
        output_path=str(tmp_path / "report.json"),
        source_type=None,
        targets=frozenset({"bitcoin-core"}),
        include_mnemonic=False,
        include_bitcoin_context=False,
        workers=1,
        file_workers=1,
        checkpoint_path=str(checkpoint),
    )

    created = build_gui_scan_config(**base, resume_checkpoint=False)
    resumed = build_gui_scan_config(**base, resume_checkpoint=True)

    assert created.checkpoint == checkpoint
    assert created.resume_checkpoint is None
    assert resumed.checkpoint is None
    assert resumed.resume_checkpoint == checkpoint


@pytest.mark.parametrize(
    ("input_path", "output_path", "targets", "message"),
    [
        ("", "report.json", frozenset({"bitcoin-core"}), "źródło"),
        ("disk.img", "", frozenset({"bitcoin-core"}), "raportu"),
        ("disk.img", "report.json", frozenset(), "co najmniej jeden"),
    ],
)
def test_gui_config_rejects_incomplete_form(
    input_path, output_path, targets, message
):
    with pytest.raises(ValueError, match=message):
        build_gui_scan_config(
            input_path=input_path,
            output_path=output_path,
            source_type=None,
            targets=targets,
            include_mnemonic=False,
            include_bitcoin_context=False,
            workers=1,
            file_workers=1,
        )


def test_gui_configuration_module_does_not_require_qt(monkeypatch):
    # Reload the pure adapter while actively rejecting any PySide6 import.
    # This verifies the real contract without depending on pathlib internals,
    # which changed in Python 3.13.
    import bfrs.gui.configuration as configuration_module

    original_import = builtins.__import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "PySide6" or name.startswith("PySide6."):
            raise AssertionError("configuration adapter must not import PySide6")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    importlib.reload(configuration_module)


def test_gui_config_requires_checkpoint_when_resume_is_selected(tmp_path):
    with pytest.raises(ValueError, match="checkpoint"):
        build_gui_scan_config(
            input_path=str(tmp_path / "disk.img"),
            output_path=str(tmp_path / "report.json"),
            source_type="image",
            targets=frozenset({"bitcoin-core"}),
            include_mnemonic=False,
            include_bitcoin_context=False,
            workers=1,
            file_workers=1,
            resume_checkpoint=True,
        )
