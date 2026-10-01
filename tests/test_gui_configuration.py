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

    # Creating ScanConfig does not write the checkpoint.  Simulate the state
    # after the first scan has actually created it before testing resume mode.
    checkpoint.write_bytes(b"synthetic checkpoint placeholder")
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


def test_gui_config_rejects_existing_checkpoint_in_create_mode(tmp_path):
    checkpoint = tmp_path / "existing.checkpoint.sqlite"
    checkpoint.write_bytes(b"existing")

    with pytest.raises(ValueError, match="Checkpoint już istnieje"):
        build_gui_scan_config(
            input_path=str(tmp_path / "disk.img"),
            output_path=str(tmp_path / "report.json"),
            source_type="image",
            targets=frozenset({"bitcoin-core"}),
            include_mnemonic=False,
            include_bitcoin_context=False,
            workers=1,
            file_workers=1,
            checkpoint_path=str(checkpoint),
            resume_checkpoint=False,
        )


def test_gui_config_rejects_missing_checkpoint_in_resume_mode(tmp_path):
    checkpoint = tmp_path / "missing.checkpoint.sqlite"

    with pytest.raises(ValueError, match="nie istnieje"):
        build_gui_scan_config(
            input_path=str(tmp_path / "disk.img"),
            output_path=str(tmp_path / "report.json"),
            source_type="image",
            targets=frozenset({"bitcoin-core"}),
            include_mnemonic=False,
            include_bitcoin_context=False,
            workers=1,
            file_workers=1,
            checkpoint_path=str(checkpoint),
            resume_checkpoint=True,
        )


def test_gui_config_uses_english_validation_messages(tmp_path):
    with pytest.raises(ValueError, match="Choose a scan source"):
        build_gui_scan_config(
            input_path="",
            output_path=str(tmp_path / "report.json"),
            source_type="image",
            targets=frozenset({"bitcoin-core"}),
            include_mnemonic=False,
            include_bitcoin_context=False,
            workers=1,
            file_workers=1,
            language="en",
        )


def test_gui_config_uses_english_checkpoint_preflight(tmp_path):
    checkpoint = tmp_path / "existing.checkpoint.sqlite"
    checkpoint.write_bytes(b"existing")

    with pytest.raises(ValueError, match="checkpoint already exists"):
        build_gui_scan_config(
            input_path=str(tmp_path / "disk.img"),
            output_path=str(tmp_path / "report.json"),
            source_type="image",
            targets=frozenset({"bitcoin-core"}),
            include_mnemonic=False,
            include_bitcoin_context=False,
            workers=1,
            file_workers=1,
            checkpoint_path=str(checkpoint),
            language="en",
        )


def test_gui_config_maps_advanced_scan_settings(tmp_path):
    recovery = tmp_path / "recovery"
    config = build_gui_scan_config(
        input_path=str(tmp_path / "disk.img"),
        output_path=str(tmp_path / "report.json"),
        source_type="image",
        targets=frozenset({"bitcoin-core"}),
        include_mnemonic=True,
        include_bitcoin_context=True,
        workers=2,
        file_workers=1,
        start_offset="4096",
        end_offset="8192",
        chunk_mib=32,
        overlap_kib=128,
        cluster_mib=4,
        padding_mib=2,
        minimum_hits=3,
        minimum_distinct_types=2,
        recover_wallets=True,
        recovery_dir=str(recovery),
    )

    assert config.start == 4096
    assert config.end == 8192
    assert config.chunk_mib == 32
    assert config.overlap_kib == 128
    assert config.cluster_mib == 4
    assert config.padding_mib == 2
    assert config.minimum_hits == 3
    assert config.minimum_distinct_types == 2
    assert config.recover_wallets is True
    assert config.recovery_dir == recovery


@pytest.mark.parametrize(
    ("start_offset", "end_offset", "message"),
    [
        ("abc", "", "Start offset"),
        ("-1", "", "Start offset"),
        ("100", "abc", "End offset"),
        ("100", "100", "End offset"),
        ("100", "99", "End offset"),
    ],
)
def test_gui_config_rejects_invalid_advanced_ranges(
    tmp_path, start_offset, end_offset, message
):
    with pytest.raises(ValueError, match=message):
        build_gui_scan_config(
            input_path=str(tmp_path / "disk.img"),
            output_path=str(tmp_path / "report.json"),
            source_type="image",
            targets=frozenset({"bitcoin-core"}),
            include_mnemonic=False,
            include_bitcoin_context=False,
            workers=1,
            file_workers=1,
            start_offset=start_offset,
            end_offset=end_offset,
        )


def test_gui_config_requires_recovery_directory(tmp_path):
    with pytest.raises(ValueError, match="katalog odzysku"):
        build_gui_scan_config(
            input_path=str(tmp_path / "disk.img"),
            output_path=str(tmp_path / "report.json"),
            source_type="image",
            targets=frozenset({"bitcoin-core"}),
            include_mnemonic=False,
            include_bitcoin_context=False,
            workers=1,
            file_workers=1,
            recover_wallets=True,
            recovery_dir="",
        )



def test_gui_config_maps_folder_checkpoint_and_resume(tmp_path):
    source = tmp_path / "recovered"
    source.mkdir()
    checkpoint = tmp_path / "folder.checkpoint.sqlite"
    report = tmp_path / "folder-report.json"

    created = build_gui_scan_config(
        input_path=str(source),
        output_path=str(report),
        source_type="folder",
        targets=frozenset({"bitcoin-core", "electrum", "secrets"}),
        include_mnemonic=True,
        include_bitcoin_context=False,
        workers=2,
        file_workers=4,
        checkpoint_path=str(checkpoint),
        resume_checkpoint=False,
    )

    assert created.source_type is SourceType.FOLDER
    assert created.file_workers == 4
    assert created.checkpoint == checkpoint
    assert created.resume_checkpoint is None

    checkpoint.write_bytes(b"checkpoint placeholder")
    resumed = build_gui_scan_config(
        input_path=str(source),
        output_path=str(report),
        source_type="folder",
        targets=frozenset({"bitcoin-core", "electrum", "secrets"}),
        include_mnemonic=True,
        include_bitcoin_context=False,
        workers=2,
        file_workers=4,
        checkpoint_path=str(checkpoint),
        resume_checkpoint=True,
    )

    assert resumed.source_type is SourceType.FOLDER
    assert resumed.checkpoint is None
    assert resumed.resume_checkpoint == checkpoint
