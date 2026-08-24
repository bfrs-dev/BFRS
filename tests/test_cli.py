import base64
import hashlib
import json

import pytest

from bfrs.cli import (
    BITCOIN_CORE_SIGNATURES_V1,
    ELECTRUM_ONLY_SIGNATURES_V1,
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
import bfrs.recovery.full_image_coordinator as coordinator_module
import bfrs.scanners.target_registry as target_registry_module


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


def encrypted_electrum(magic=b"BIE1") -> bytes:
    decoded = magic + b"\x02" + b"P" * 32 + b"C" * 32 + b"M" * 32
    return base64.b64encode(decoded)


def valid_wif() -> bytes:
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    payload = b"\x80" + bytes.fromhex("11" * 32) + b"\x01"
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(raw, "big")
    encoded = bytearray()
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(alphabet[remainder])
    return bytes(reversed(encoded))


def plaintext_electrum() -> tuple[bytes, str, str]:
    seed = "synthetic resident seed must never enter report"
    xprv = "synthetic-xprv-must-never-enter-report"
    payload = {
        "seed_version": 71,
        "wallet_type": "standard",
        "keystore": {
            "type": "bip32",
            "xpub": "synthetic-public-metadata",
            "xprv": xprv,
            "seed": seed,
        },
    }
    return json.dumps(payload, separators=(",", ":")).encode(), seed, xprv


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
    assert patterns["ntfs_indx_record_anchor"] == b"INDX"
    assert set(patterns) == {
        "ntfs_file_record_anchor",
        "ntfs_indx_record_anchor",
        "ntfs_boot_sector_oem_anchor",
        "berkeley_metadata_little_endian",
        "berkeley_metadata_big_endian",
        "bitcoin_key",
        "bitcoin_wkey",
        "bitcoin_defaultkey",
        "bitcoin_ckey",
        "bitcoin_mkey",
        "bitcoin_keymeta",
            "historical_ec_private_key_der_anchor",
            "electrum_bie1_base64_anchor",
            "electrum_bie2_base64_anchor",
            "electrum_bie1_raw_anchor",
            "electrum_bie2_raw_anchor",
            "electrum_seed_version_anchor",
            "electrum_wallet_type_anchor",
            "electrum_keystore_anchor",
            "electrum_legacy_seed_version_single_quote",
            "electrum_legacy_master_public_key_single_quote",
            "electrum_legacy_master_public_keys_single_quote",
            "electrum_legacy_accounts_single_quote",
            "electrum_legacy_use_encryption_single_quote",
        }


def test_cli_help_is_available(capsys):
    with pytest.raises(SystemExit) as raised:
        main(["--help"])
    assert raised.value.code == 0
    help_text = capsys.readouterr().out
    assert "python -m bfrs.cli" in help_text
    assert "--input" in help_text and "--output" in help_text
    assert "--electrum-only" in help_text
    assert "--targets" in help_text
    assert "--skip-mnemonic" in help_text
    assert "BFRS filesystem and wallet recovery scan" in help_text


def test_electrum_only_runs_recovery_and_writes_safe_section(tmp_path):
    source = tmp_path / "electrum.img"
    source.write_bytes(encrypted_electrum())
    report = tmp_path / "electrum.json"
    assert main(basic_arguments(source, report) + ["--electrum-only"]) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    electrum = payload["electrum_raw_recovery"]
    assert payload["configuration"]["electrum_only"] is True
    assert electrum["candidates_total"] == 1
    assert electrum["complete_candidates"] == 1
    assert electrum["candidates"][0]["serialization_type"] == (
        "ELECTRUM_ECIES_BASE64"
    )
    assert set(payload["configuration"]["signature_set"]) == {
        item.name for item in ELECTRUM_ONLY_SIGNATURES_V1
    }


def test_electrum_only_does_not_run_berkeley_recovery(tmp_path, monkeypatch):
    class Forbidden:
        def __init__(self, *args, **kwargs):
            raise AssertionError("Berkeley recovery ran in Electrum-only mode")

    for name in (
        "BerkeleyDatabaseRecoveryPipeline",
        "FragmentedBerkeleyPageReassembler",
        "LogicalBerkeleyDatabaseRecoveryPipeline",
        "ReconstructedBerkeleyWalletPipeline",
    ):
        monkeypatch.setattr(coordinator_module, name, Forbidden)
    source = tmp_path / "electrum.img"
    source.write_bytes(encrypted_electrum())
    assert main(basic_arguments(source, tmp_path / "report.json")
                + ["--electrum-only"]) == 0


def test_electrum_only_does_not_run_plaintext_or_orphan_key_recovery(
    tmp_path, monkeypatch,
):
    class Forbidden:
        def __init__(self, *args, **kwargs):
            raise AssertionError("Bitcoin key recovery ran in Electrum-only mode")

    for name in (
        "MetadataLessBerkeleyFragmentRecoveryPipeline",
        "OrphanBitcoinRecordKeyDiagnosticPipeline",
        "OrphanHistoricalECPrivateKeyRecoveryPipeline",
        "OrphanHistoricalECPrivateKeyFragmentRecoveryPipeline",
        "NtfsHistoricalWalletRecoveryPipeline",
    ):
        monkeypatch.setattr(coordinator_module, name, Forbidden)
    source = tmp_path / "electrum.img"
    source.write_bytes(encrypted_electrum())
    assert main(basic_arguments(source, tmp_path / "report.json")
                + ["--electrum-only"]) == 0


def test_electrum_only_honors_exact_start_and_end(tmp_path):
    token = encrypted_electrum()
    start = 73
    source = tmp_path / "range.img"
    source.write_bytes(b"X" * start + token + b"QklFMQ" + b"A" * 40)
    report = tmp_path / "range.json"
    arguments = basic_arguments(source, report) + [
        "--electrum-only", "--start", str(start),
        "--end", str(start + len(token)), "--chunk-mib", "1",
        "--overlap-kib", "1",
    ]
    assert main(arguments) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["scan_range"] == {
        "start_offset": start,
        "end_offset": start + len(token),
    }
    assert payload["electrum_raw_recovery"]["candidates_total"] == 1


def test_electrum_only_report_never_contains_wallet_secrets(tmp_path):
    raw, seed, xprv = plaintext_electrum()
    source = tmp_path / "plaintext-electrum.img"
    source.write_bytes(raw)
    report = tmp_path / "safe.json"
    assert main(basic_arguments(source, report) + ["--electrum-only"]) == 0
    encoded = report.read_text(encoding="utf-8")
    payload = json.loads(encoded)
    assert payload["electrum_raw_recovery"]["complete_candidates"] == 1
    assert seed not in encoded
    assert xprv not in encoded


def test_standard_mode_keeps_bitcoin_signatures_and_behavior(tmp_path):
    source = tmp_path / "metadata-only.img"
    source.write_bytes(structural_metadata())
    report = tmp_path / "standard.json"
    assert main(["--input", str(source), "--output", str(report)]) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["configuration"]["electrum_only"] is False
    assert "berkeley_metadata_little_endian" in payload["configuration"][
        "signature_set"
    ]
    assert payload["raw_hit_count"] == 1
    assert payload["accepted_hotspot_count"] == 1


def test_cli_targets_all_uses_shared_registry_and_safe_findings(tmp_path):
    multibit = (b"\x0a\x16org.bitcoin.production" +
                b"\x12\x21\x02" + b"P" * 32 +
                b"\x1a\x20" + b"K" * 32)
    armory = b"\xbaWALLET\x00" + (1).to_bytes(4, "little") + b"walletID:x rootKey:y"
    source = tmp_path / "all-targets.img"
    source.write_bytes(
        b"\x04ckey-invalid" + b"X" * 32 + multibit + b"Y" * 32 +
        armory + b"Z" * 32 + b"BIE1")
    report = tmp_path / "all-targets.json"
    assert main(basic_arguments(source, report) + ["--targets", "all"]) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert set(payload["configuration"]["targets"]) == {
        "bitcoin-core", "multibit", "armory", "electrum", "secrets"}
    families = {item["target"] for item in payload["target_findings"]}
    assert {"bitcoin-core", "multibit", "armory", "electrum"} <= families
    assert b"K" * 32 not in report.read_bytes()
    assert all("raw_bytes" not in item for item in payload["target_findings"])


def test_cli_targets_all_runs_mnemonic_by_default(tmp_path, monkeypatch):
    calls = 0
    original = target_registry_module.MnemonicChunkDetector.detect_chunk

    def tracked(self, *args, **kwargs):
        nonlocal calls
        calls += 1
        yield from original(self, *args, **kwargs)

    monkeypatch.setattr(
        target_registry_module.MnemonicChunkDetector, "detect_chunk", tracked)
    source = tmp_path / "default-mnemonic.img"
    source.write_bytes(b"small fixture")

    assert main(basic_arguments(source, tmp_path / "default.json") +
                ["--targets", "all"]) == 0
    assert calls == 1


def test_cli_skip_mnemonic_keeps_all_other_target_detectors(
    tmp_path, monkeypatch, capsys,
):
    def forbidden(*args, **kwargs):
        raise AssertionError("MnemonicChunkDetector ran with --skip-mnemonic")

    monkeypatch.setattr(
        target_registry_module.MnemonicChunkDetector, "detect_chunk", forbidden)
    multibit = (b"\x0a\x16org.bitcoin.production" +
                b"\x12\x21\x02" + b"P" * 32 +
                b"\x1a\x20" + b"K" * 32)
    armory = b"\xbaWALLET\x00" + (1).to_bytes(4, "little") + b"walletID:x rootKey:y"
    source = tmp_path / "skip-mnemonic.img"
    source.write_bytes(
        b"\x04ckey-invalid--" + multibit + b"--" + armory +
        b"--BIE1--" + valid_wif())
    report = tmp_path / "skip-mnemonic.json"

    assert main(basic_arguments(source, report) +
                ["--targets", "all", "--skip-mnemonic"]) == 0

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["configuration"]["skip_mnemonic"] is True
    families = {item["target"] for item in payload["target_findings"]}
    assert {"bitcoin-core", "multibit", "armory", "electrum", "secrets"} <= families
    assert any(item["artifact_kind"] == "WIF_PRIVATE_KEY"
               for item in payload["target_findings"])
    assert "phase=mnemonic" not in capsys.readouterr().err


def test_cli_targets_all_reports_sparse_complete_progress(tmp_path, capsys):
    source = tmp_path / "small.img"
    source.write_bytes(b"nothing")
    report = tmp_path / "small.json"

    assert main(basic_arguments(source, report) + ["--targets", "all"]) == 0

    stderr = capsys.readouterr().err
    assert "Target scan 100.0%" in stderr
    assert "7/7 bytes" in stderr
    assert "MiB/s" in stderr
    assert "ETA 00:00:00" in stderr
    assert "findings=0" in stderr
    for target in ("bitcoin-core", "multibit", "armory", "electrum", "secrets"):
        assert f"{target}=0" in stderr
    assert stderr.count("\rTarget scan") <= 2


def test_cli_progress_handles_empty_input_without_division_by_zero(
    tmp_path, capsys,
):
    source = tmp_path / "empty.img"
    source.write_bytes(b"")
    report = tmp_path / "empty.json"

    assert main(basic_arguments(source, report) + ["--targets", "all"]) == 0

    stderr = capsys.readouterr().err
    assert "Target scan 100.0%" in stderr
    assert "0/0 bytes" in stderr
    assert "0.0 MiB/s" in stderr
    assert "ETA 00:00:00" in stderr


def test_cli_targets_validate_unknown_and_legacy_mode_conflicts(tmp_path):
    source = tmp_path / "source.img"
    source.write_bytes(b"nothing")
    output = tmp_path / "report.json"
    with pytest.raises(SystemExit) as unknown:
        main(["--input", str(source), "--output", str(output),
              "--targets", "unknown-wallet"])
    assert unknown.value.code == 2
    with pytest.raises(SystemExit) as conflict:
        main(["--input", str(source), "--output", str(output),
              "--targets", "electrum", "--electrum-only"])
    assert conflict.value.code == 2


def test_cli_rejects_skip_mnemonic_with_seed_scan_only(tmp_path):
    source = tmp_path / "source.img"
    source.write_bytes(b"nothing")

    with pytest.raises(SystemExit) as raised:
        main([
            "--input", str(source),
            "--output", str(tmp_path / "report.json"),
            "--seed-scan-only",
            "--skip-mnemonic",
        ])

    assert raised.value.code == 2
