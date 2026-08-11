import json

import pytest

from bfrs.cli import (
    BITCOIN_CORE_SIGNATURES_V1,
    DEFAULT_CHUNK_MIB,
    DEFAULT_CLUSTER_MIB,
    DEFAULT_MINIMUM_DISTINCT_TYPES,
    DEFAULT_MINIMUM_HITS,
    DEFAULT_OVERLAP_KIB,
    DEFAULT_PADDING_MIB,
    build_parser,
    main,
)
from bfrs.validators.berkeley_metadata import BTREE_MAGIC


def basic_arguments(source, output) -> list[str]:
    return [
        "--input",
        str(source),
        "--output",
        str(output),
        "--minimum-hits",
        "1",
        "--minimum-distinct-types",
        "1",
        "--padding-mib",
        "0",
    ]


def structural_metadata() -> bytes:
    result = bytearray(512)
    put = lambda offset, value: result.__setitem__(
        slice(offset, offset + 4), value.to_bytes(4, "little")
    )
    put(12, BTREE_MAGIC)
    put(16, 9)
    put(20, 512)
    result[25] = 9
    put(32, 1000)
    put(48, 0x20)
    put(88, 1)
    return bytes(result)


def test_cli_dry_scan_writes_json_and_short_progress(tmp_path, capsys):
    source = tmp_path / "image.img"
    source.write_bytes(b"prefix\x04ckeysuffix")
    report = tmp_path / "reports" / "scan.json"
    exit_code = main(basic_arguments(source, report))
    assert exit_code == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["source"] == str(source.resolve())
    assert payload["scan_range"] == {"start_offset": 0, "end_offset": 17}
    assert payload["raw_hit_count"] == 1
    assert payload["status"] == "rejected"
    stdout = capsys.readouterr().out
    for label in (
        "source:",
        "range:",
        "raw hits:",
        "hotspots:",
        "accepted hotspots:",
        "direct results:",
        "reconstructed results:",
        "structural results:",
        "fragment results:",
        "report path:",
    ):
        assert label in stdout
    assert "ciphertext" not in stdout


def test_default_policy_accepts_one_structural_metadata_signal(tmp_path):
    source = tmp_path / "metadata-only.img"
    source.write_bytes(structural_metadata())
    report = tmp_path / "metadata-only.json"
    assert main(["--input", str(source), "--output", str(report)]) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["configuration"]["minimum_hits"] == 1
    assert payload["configuration"]["minimum_distinct_types"] == 1
    assert payload["raw_hit_count"] == 1
    assert payload["accepted_hotspot_count"] == 1
    candidates = payload["diagnostics"]["evidence"][
        "physical_metadata_candidates"
    ]
    assert candidates and candidates[0][-1] == "structural"
    assert payload["status"] == "rejected"


def test_default_policy_false_framed_ckey_remains_rejected(tmp_path):
    source = tmp_path / "false-ckey.img"
    source.write_bytes(b"noise\x04ckeynot-a-berkeley-page")
    report = tmp_path / "false-ckey.json"
    assert main(["--input", str(source), "--output", str(report)]) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["raw_hit_count"] == 1
    assert payload["accepted_hotspot_count"] == 1
    assert payload["status"] == "rejected"
    assert payload["structural_result_count"] == 0
    assert payload["fragment_result_count"] == 0


def test_unrelated_magic_ckey_and_mkey_signals_remain_rejected(tmp_path):
    source = tmp_path / "unrelated-signals.img"
    source.write_bytes(
        BTREE_MAGIC.to_bytes(4, "little")
        + b"x" * 32
        + b"\x04ckeyinvalid"
        + b"y" * 32
        + b"\x04mkeyinvalid"
    )
    report = tmp_path / "unrelated-signals.json"
    assert main(["--input", str(source), "--output", str(report)]) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["raw_hit_count"] == 3
    assert payload["accepted_hotspot_count"] >= 1
    assert payload["status"] == "rejected"
    assert payload["reconstructed_databases"] == []


def test_cli_range_is_exact_and_source_remains_read_only(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = source_dir / "disk.img"
    original = b"\x04ckey" + b"x" * 30 + b"\x04mkey" + b"z" * 30
    source.write_bytes(original)
    before_names = tuple(item.name for item in source_dir.iterdir())
    output = tmp_path / "output" / "range.json"
    arguments = basic_arguments(source, output) + [
        "--start",
        "0x20",
        "--end",
        "0x30",
    ]
    assert main(arguments) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["scan_range"] == {"start_offset": 32, "end_offset": 48}
    assert payload["raw_hit_count"] == 1
    assert source.read_bytes() == original
    assert tuple(item.name for item in source_dir.iterdir()) == before_names


@pytest.mark.parametrize(
    "start,end",
    (("10", "10"), ("11", "10"), ("-1", "10")),
)
def test_cli_invalid_range_uses_exit_code_2(tmp_path, start, end):
    source = tmp_path / "image.img"
    source.write_bytes(b"x" * 20)
    with pytest.raises(SystemExit) as raised:
        main(
            [
                "--input",
                str(source),
                "--output",
                str(tmp_path / "report.json"),
                "--start",
                start,
                "--end",
                end,
            ]
        )
    assert raised.value.code == 2


def test_cli_input_and_report_failures_have_distinct_exit_codes(tmp_path):
    missing = tmp_path / "missing.img"
    assert main(basic_arguments(missing, tmp_path / "report.json")) == 3
    source = tmp_path / "image.img"
    source.write_bytes(b"nothing")
    output_directory = tmp_path / "existing-directory"
    output_directory.mkdir()
    assert main(basic_arguments(source, output_directory)) == 4


def test_cli_defaults_and_signature_set_are_explicit():
    parser = build_parser()
    arguments = parser.parse_args(["--input", "E:\\Hp.img", "--output", "report.json"])
    assert (
        arguments.chunk_mib,
        arguments.overlap_kib,
        arguments.cluster_mib,
        arguments.padding_mib,
        arguments.minimum_hits,
        arguments.minimum_distinct_types,
    ) == (
        DEFAULT_CHUNK_MIB,
        DEFAULT_OVERLAP_KIB,
        DEFAULT_CLUSTER_MIB,
        DEFAULT_PADDING_MIB,
        DEFAULT_MINIMUM_HITS,
        DEFAULT_MINIMUM_DISTINCT_TYPES,
    )
    assert arguments.minimum_hits == 1
    assert arguments.minimum_distinct_types == 1
    stricter = parser.parse_args(
        [
            "--input",
            "E:\\Hp.img",
            "--output",
            "report.json",
            "--minimum-hits",
            "3",
            "--minimum-distinct-types",
            "2",
        ]
    )
    assert stricter.minimum_hits == 3
    assert stricter.minimum_distinct_types == 2
    patterns = {item.name: item.pattern for item in BITCOIN_CORE_SIGNATURES_V1}
    assert patterns["berkeley_metadata_little_endian"] == BTREE_MAGIC.to_bytes(4, "little")
    assert patterns["berkeley_metadata_big_endian"] == BTREE_MAGIC.to_bytes(4, "big")
    assert patterns["ntfs_file_record_anchor"] == b"FILE"
    assert set(patterns) == {
        "ntfs_file_record_anchor",
        "berkeley_metadata_little_endian",
        "berkeley_metadata_big_endian",
        "bitcoin_key",
        "bitcoin_wkey",
        "bitcoin_defaultkey",
        "bitcoin_ckey",
        "bitcoin_mkey",
        "bitcoin_keymeta",
        "historical_ec_private_key_der_anchor",
    }


def test_cli_help_is_available(capsys):
    with pytest.raises(SystemExit) as raised:
        main(["--help"])
    assert raised.value.code == 0
    help_text = capsys.readouterr().out
    assert "python -m bfrs.cli" in help_text
    assert "--input" in help_text and "--output" in help_text
