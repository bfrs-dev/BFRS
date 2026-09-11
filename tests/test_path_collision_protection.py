import os
from pathlib import Path

import pytest

from bfrs.cli import (
    _validate_arguments,
    _validate_path_collisions,
    build_parser,
    main,
)
from bfrs.core.path_safety import paths_refer_to_same_file
from bfrs.tools.analyze_electrum_candidate_context import (
    main as context_analysis_main,
)
from bfrs.tools.export_legacy_plaintext_keys import main as key_export_main
from bfrs.tools.export_recovered_mnemonics import main as mnemonic_export_main
from bfrs.tools.revalidate_electrum_candidates import main as electrum_revalidate_main


def _assert_main_rejected(argv, message, capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        main(argv)
    assert raised.value.code == 2
    error = capsys.readouterr().err
    assert message in error
    assert "Traceback" not in error


def _validate_without_running(input_path: Path, output_path: Path) -> None:
    parser = build_parser()
    arguments = parser.parse_args([
        "--input", str(input_path), "--output", str(output_path),
    ])
    _validate_arguments(parser, arguments)
    _validate_path_collisions(parser, arguments)


def test_input_equal_to_output_is_rejected_and_input_is_unchanged(
    tmp_path, capsys,
) -> None:
    source = tmp_path / "source.bin"
    original = b"synthetic-input-must-survive"
    source.write_bytes(original)

    _assert_main_rejected(
        ["--input", str(source), "--output", str(source)],
        "output path resolves to input path",
        capsys,
    )

    assert source.read_bytes() == original


def test_absolute_input_and_equivalent_relative_output_are_rejected(
    tmp_path, monkeypatch, capsys,
) -> None:
    source = tmp_path / "relative-source.bin"
    source.write_bytes(b"synthetic")
    monkeypatch.chdir(tmp_path)

    _assert_main_rejected(
        ["--input", str(source.resolve()), "--output", source.name],
        "output path resolves to input path",
        capsys,
    )


def test_parent_path_component_resolving_to_input_is_rejected(
    tmp_path, capsys,
) -> None:
    source = tmp_path / "parent-source.bin"
    source.write_bytes(b"synthetic")
    nested = tmp_path / "nested"
    nested.mkdir()
    alias = nested / ".." / source.name

    _assert_main_rejected(
        ["--input", str(source), "--output", str(alias)],
        "output path resolves to input path",
        capsys,
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows path comparison requirement")
def test_windows_case_difference_is_rejected(tmp_path, capsys) -> None:
    source = tmp_path / "MixedCaseSource.BIN"
    source.write_bytes(b"synthetic")
    differently_cased = Path(str(source).swapcase())

    _assert_main_rejected(
        ["--input", str(source), "--output", str(differently_cased)],
        "output path resolves to input path",
        capsys,
    )


def test_existing_hardlink_to_input_is_rejected(tmp_path, capsys) -> None:
    source = tmp_path / "hardlink-source.bin"
    alias = tmp_path / "hardlink-alias.bin"
    source.write_bytes(b"synthetic")
    try:
        os.link(source, alias)
    except OSError as error:
        pytest.skip(f"hardlinks unavailable: {error}")

    _assert_main_rejected(
        ["--input", str(source), "--output", str(alias)],
        "output path resolves to input path",
        capsys,
    )


def test_distinct_input_and_output_are_allowed_by_validation(tmp_path) -> None:
    source = tmp_path / "safe-source.bin"
    output = tmp_path / "safe-output.json"
    source.write_bytes(b"synthetic")

    _validate_without_running(source, output)


@pytest.mark.parametrize("checkpoint_flag", ["--checkpoint", "--resume-checkpoint"])
def test_checkpoint_equal_to_input_is_rejected(
    tmp_path, capsys, checkpoint_flag,
) -> None:
    source = tmp_path / "checkpoint-input.bin"
    source.write_bytes(b"synthetic")

    _assert_main_rejected(
        [
            "--input", str(source),
            "--output", str(tmp_path / "report.json"),
            checkpoint_flag, str(source),
        ],
        "checkpoint path resolves to input path",
        capsys,
    )


@pytest.mark.parametrize("checkpoint_flag", ["--checkpoint", "--resume-checkpoint"])
def test_checkpoint_equal_to_report_output_is_rejected(
    tmp_path, capsys, checkpoint_flag,
) -> None:
    source = tmp_path / "checkpoint-source.bin"
    output = tmp_path / "shared-output.json"
    source.write_bytes(b"synthetic")

    _assert_main_rejected(
        [
            "--input", str(source),
            "--output", str(output),
            checkpoint_flag, str(output),
        ],
        "checkpoint path resolves to report output path",
        capsys,
    )


def test_wallet_revalidation_source_report_equal_to_output_is_rejected(
    tmp_path, capsys,
) -> None:
    image = tmp_path / "image.bin"
    report = tmp_path / "source-report.json"
    image.write_bytes(b"synthetic")
    original = b'{"synthetic": true}'
    report.write_bytes(original)

    _assert_main_rejected(
        [
            "--input", str(image),
            "--output", str(report),
            "--revalidate-wallet-records", str(report),
        ],
        "output path resolves to source report path",
        capsys,
    )

    assert report.read_bytes() == original


@pytest.mark.parametrize(
    "tool_main", [electrum_revalidate_main, context_analysis_main]
)
def test_electrum_source_report_equal_to_output_is_rejected(
    tmp_path, capsys, tool_main,
) -> None:
    image = tmp_path / "image.bin"
    report = tmp_path / "electrum-source-report.json"
    image.write_bytes(b"synthetic")
    original = b'{"synthetic": true}'
    report.write_bytes(original)

    with pytest.raises(SystemExit) as raised:
        tool_main([
            "--image", str(image),
            "--report", str(report),
            "--output", str(report),
        ])

    assert raised.value.code == 2
    error = capsys.readouterr().err
    assert "output path resolves to source report path" in error
    assert "Traceback" not in error
    assert report.read_bytes() == original


def test_nonexistent_equivalent_paths_use_normalized_identity(tmp_path) -> None:
    nested = tmp_path / "missing"
    unresolved = nested / ".." / "future-output.json"
    normalized = tmp_path / "future-output.json"
    assert not unresolved.exists()
    assert not normalized.exists()

    assert paths_refer_to_same_file(unresolved, normalized)


@pytest.mark.parametrize(
    ("tool_main", "permission_flag"),
    [
        (mnemonic_export_main, "--allow-seed-export"),
        (key_export_main, "--allow-private-key-export"),
    ],
)
def test_export_input_equal_to_output_is_rejected_before_source_analysis(
    tmp_path, capsys, tool_main, permission_flag,
) -> None:
    source = tmp_path / "export-source.bin"
    original = b"synthetic-invalid-export-source"
    source.write_bytes(original)

    with pytest.raises(SystemExit) as raised:
        tool_main([
            "--input", str(source),
            "--output", str(source),
            permission_flag,
        ])

    assert raised.value.code == 2
    error = capsys.readouterr().err
    assert "output path resolves to input path" in error
    assert "Traceback" not in error
    assert source.read_bytes() == original
