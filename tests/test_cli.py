import base64
import hashlib
import json
import re

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
    _ElectrumProgressLine,
    build_parser,
    main,
)
from bfrs.validators.berkeley_metadata import BTREE_MAGIC
import bfrs.recovery.full_image_coordinator as coordinator_module
import bfrs.scanners.target_registry as target_registry_module
from bfrs.recovery.mnemonic.electrum_v1_validator import ElectrumV1Validator


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


def multibit_classic_wallet(*, fragment=False) -> bytes:
    network = b"org.bitcoin.production"
    key = bytearray(b"\x08\x01")
    if not fragment:
        key.extend(b"\x12\x20" + b"\x11" * 32)
    key.extend(b"\x1a\x21\x02" + b"P" * 32)
    return (b"\x0a" + bytes((len(network),)) + network + b"\x1a" +
            bytes((len(key),)) + bytes(key))


def armory_wallet(*, fragment=False) -> bytes:
    result = bytearray(70 if fragment else 2107)
    result[:8] = b"\xbaWALLET\x00"
    result[8:12] = (13_500_000).to_bytes(4, "little")
    result[12:16] = b"\xf9\xbe\xb4\xd9"
    result[16:24] = (1).to_bytes(8, "little")
    result[24:30] = b"ABCDE\x00"
    result[30:38] = (1_500_000_000).to_bytes(8, "little")
    result[38:50] = b"test wallet\x00"
    if not fragment:
        result[846:1083] = bytes((index % 251) + 1 for index in range(237))
    return bytes(result)


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


HISTORICAL_ELECTRUM_SEED = " ".join(ElectrumV1Validator().mn_encode(
    "000102030405060708090a0b0c0d0e0f"))
HISTORICAL_ELECTRUM_MPK = "ab" * 64
HISTORICAL_RECEIVING_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
HISTORICAL_CHANGE_ADDRESS = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
HISTORICAL_IMPORTED_PRIVATE = "synthetic-imported-private-material"


def historical_electrum_wallet(*, address_layout=False, imported=False) -> bytes:
    value = {
        "seed_version": 4,
        "use_encryption": False,
        "seed": HISTORICAL_ELECTRUM_SEED,
        "master_public_key": HISTORICAL_ELECTRUM_MPK,
        "imported_keys": ({HISTORICAL_RECEIVING_ADDRESS:
                           HISTORICAL_IMPORTED_PRIVATE} if imported else {}),
    }
    if address_layout:
        value.update({
            "addresses": [HISTORICAL_RECEIVING_ADDRESS],
            "change_addresses": [HISTORICAL_CHANGE_ADDRESS],
        })
    else:
        value["accounts"] = {0: {0: [HISTORICAL_RECEIVING_ADDRESS], 1: []}}
    return repr(value).encode()


def historical_electrum_tuple() -> bytes:
    return repr((
        1, False, 0.005, "ecdsa.org", 50000, 150000,
        "00" * 16, [HISTORICAL_RECEIVING_ADDRESS], "[]", [0],
        {}, {}, {}, [HISTORICAL_CHANGE_ADDRESS],
    )).encode()


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
    assert payload["raw_hit_counts_by_signature"] == {"bitcoin_ckey": 1}
    assert payload["accepted_hotspot_count"] == 0
    finding = next(
        item
        for item in payload["target_findings"]
        if item["artifact_kind"] == "wallet_record"
    )
    assert finding["validation_status"] == "BITCOIN_RECORD_KEY_SIDE_REJECTED"
    assert finding["reason_codes"] == ["BITCOIN_RECORD_PUBKEY_LENGTH_INVALID"]
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
    assert arguments.include_bitcoin_context is False
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
            "electrum_legacy_addresses_single_quote",
            "electrum_legacy_change_addresses_single_quote",
            "electrum_legacy_imported_keys_single_quote",
            "electrum_legacy_master_public_key_json",
            "electrum_legacy_master_public_keys_json",
            "electrum_legacy_accounts_json",
            "electrum_legacy_use_encryption_json",
            "electrum_legacy_addresses_json",
            "electrum_legacy_change_addresses_json",
            "electrum_legacy_imported_keys_json",
            "electrum_legacy_tuple_plaintext",
            "electrum_legacy_tuple_encrypted",
            "electrum_legacy_list_plaintext",
            "electrum_legacy_list_encrypted",
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
    multibit = multibit_classic_wallet()
    armory = armory_wallet()
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


def raw_wallet_fixture(case: str) -> bytes:
    if case == "multibit_full":
        return b"random-prefix" + multibit_classic_wallet() + b"random-suffix"
    if case == "multibit_boundary":
        wallet = multibit_classic_wallet()
        marker_in_wallet = wallet.index(b"org.bitcoin.production")
        prefix = b"R" * ((1 << 20) - 4 - marker_in_wallet)
        return prefix + wallet + b"tail"
    if case == "multibit_fragment":
        return b"damaged" + multibit_classic_wallet(fragment=True) + b"truncated"
    if case == "armory_full":
        return b"random-prefix" + armory_wallet() + b"random-suffix"
    if case == "armory_boundary":
        wallet = armory_wallet()
        prefix = b"R" * ((1 << 20) - 3)
        return prefix + wallet + b"tail"
    if case == "armory_fragment":
        return b"damaged" + armory_wallet(fragment=True)
    if case == "short_anchors":
        return (b"MZ random org.bitcoin.production PK\x03\x04 Salted__ "
                b"com.google.bitcoin \xbaWALLET\x00 trailing noise")
    raise AssertionError(case)


@pytest.mark.parametrize("case,family,expected_status", [
    ("multibit_full", "multibit", "STRONG"),
    ("multibit_boundary", "multibit", "STRONG"),
    ("multibit_fragment", "multibit", "FRAGMENT"),
    ("armory_full", "armory", "STRONG"),
    ("armory_boundary", "armory", "STRONG"),
    ("armory_fragment", "armory", "FRAGMENT"),
    ("short_anchors", None, None),
])
@pytest.mark.parametrize("target", ["multibit", "armory", "all"])
def test_public_target_pipeline_synthetic_raw_fixtures(
    tmp_path, case, family, expected_status, target,
):
    source = tmp_path / f"{case}-{target}.img"
    report = tmp_path / f"{case}-{target}.json"
    source.write_bytes(raw_wallet_fixture(case))
    arguments = basic_arguments(source, report) + [
        "--targets", target,
        "--chunk-mib", "1",
        "--overlap-kib", "4",
    ]
    if target == "all":
        arguments.append("--skip-mnemonic")

    assert main(arguments) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    accepted = [
        item for item in payload["target_findings"]
        if item["structural_status"] in {"STRONG", "FRAGMENT", "COMPLETE"}
    ]
    if family is not None and target in {family, "all"}:
        matching = [item for item in accepted if item["target"] == family]
        assert matching
        assert expected_status in {item["structural_status"] for item in matching}
        assert all(item["source_kind"] == "RAW_BYTES" for item in matching)
    else:
        assert accepted == []
        if case == "short_anchors":
            assert payload["target_findings"]
            assert all(item["structural_status"] == "REJECTED"
                       for item in payload["target_findings"])


def test_public_progress_counts_accepted_multibit_and_armory_findings(
    tmp_path, capsys,
):
    source = tmp_path / "accepted-targets.img"
    report = tmp_path / "accepted-targets.json"
    source.write_bytes(multibit_classic_wallet() + b"gap" + armory_wallet())

    assert main(basic_arguments(source, report) + [
        "--targets", "all", "--skip-mnemonic",
    ]) == 0

    stderr = capsys.readouterr().err
    assert "multibit=1" in stderr
    assert "armory=1" in stderr


def historical_electrum_raw_fixture(case: str) -> bytes:
    wallet = historical_electrum_wallet()
    if case == "dict_full":
        return b"random-prefix" + wallet + b"random-suffix"
    if case == "tuple_full":
        return b"random-prefix" + historical_electrum_tuple() + b"random-suffix"
    if case == "address_layout":
        return b"random-prefix" + historical_electrum_wallet(
            address_layout=True) + b"random-suffix"
    if case == "boundary":
        marker = b"'seed_version'"
        marker_in_wallet = wallet.index(marker)
        prefix = b"R" * ((1 << 20) - 4 - marker_in_wallet)
        return prefix + wallet + b"tail"
    if case == "damaged_beginning":
        return b"overwritten-prefix" + wallet[1:]
    if case == "damaged_end":
        return b"random-prefix" + wallet[:-28]
    if case == "minimal_fragment":
        return (
            f"'seed': '{HISTORICAL_ELECTRUM_SEED}', 'seed_version': 4, "
            f"'master_public_key': '{HISTORICAL_ELECTRUM_MPK}'"
        ).encode()
    if case == "python2_long":
        value = historical_electrum_wallet()[:-1] + b", 'fee': 100000L}"
        return b"random-prefix" + value
    if case == "non_utf8":
        value = historical_electrum_wallet()[:-1] + b", 'label': 'caf\xe9'}"
        return b"random-prefix" + value
    if case == "imported_keys":
        return historical_electrum_wallet(imported=True)
    if case == "source_code":
        return (
            b'FIELDS = ["master_public_key", "accounts"]\n'
            b'def seed(value): return value\n'
        )
    if case == "random_sequence":
        return repr((1, False, "ordinary", "tuple", 1, 2, 3, 4,
                     5, 6, 7, 8, 9, 10)).encode()
    if case == "single_anchor_json":
        return b'{"master_public_key": !!! damaged unrelated json'
    raise AssertionError(case)


@pytest.mark.parametrize("case,expected_status", [
    ("dict_full", "STRONG"),
    ("tuple_full", "STRONG"),
    ("address_layout", "STRONG"),
    ("boundary", "STRONG"),
    ("damaged_beginning", "FRAGMENT"),
    ("minimal_fragment", "FRAGMENT"),
    ("python2_long", "STRONG"),
    ("non_utf8", "STRONG"),
    ("imported_keys", "STRONG"),
    ("source_code", "REJECTED"),
    ("random_sequence", "REJECTED"),
    ("single_anchor_json", "REJECTED"),
])
@pytest.mark.parametrize("target", ["electrum", "all"])
def test_public_electrum_historical_fixtures(
    tmp_path, capsys, case, expected_status, target,
):
    source = tmp_path / f"historical-electrum-{case}-{target}.img"
    report = tmp_path / f"historical-electrum-{case}-{target}.json"
    source.write_bytes(historical_electrum_raw_fixture(case))

    assert main(basic_arguments(source, report) + [
        "--targets", target,
        "--chunk-mib", "1",
        "--overlap-kib", "4",
    ]) == 0

    payload = json.loads(report.read_text(encoding="utf-8"))
    recovery = payload["electrum_raw_recovery"]
    target_findings = [item for item in payload["target_findings"]
                       if item["target"] == "electrum"]
    wallet_anchors = [item for item in target_findings
                      if item["artifact_kind"] == "electrum_wallet_anchor"]
    assert recovery["anchors_found"] == len(wallet_anchors)
    assert len({(item["physical_start"], item["physical_end"])
                for item in wallet_anchors}) == len(wallet_anchors)
    progress_counts = re.findall(
        r"raw_by_target\[[^\]]*electrum=(\d+)", capsys.readouterr().err)
    assert progress_counts and int(progress_counts[-1]) == len(target_findings)
    assert recovery["structural_status"] == expected_status
    assert payload["status"] == {
        "STRONG": "structural",
        "FRAGMENT": "fragment",
        "REJECTED": "rejected",
    }[expected_status]
    if expected_status == "STRONG":
        assert payload["structural_result_count"] >= 1
    elif expected_status == "FRAGMENT":
        assert payload["fragment_result_count"] >= 1
    if expected_status == "REJECTED":
        assert recovery["candidates_total"] == 0
        assert recovery["reason_codes"]
    else:
        assert recovery["candidates_total"] >= 1
        assert expected_status in {
            item["structural_status"] for item in recovery["candidates"]
        }
        assert all(item["source"] == str(source.resolve())
                   for item in recovery["candidates"])
        identities = {
            (item["candidate_id"], item["physical_start"], item["physical_end"])
            for item in recovery["candidates"]
        }
        assert len(identities) == recovery["candidates_total"]
    encoded = report.read_text(encoding="utf-8")
    assert HISTORICAL_ELECTRUM_SEED not in encoded
    assert HISTORICAL_IMPORTED_PRIVATE not in encoded


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


def test_cli_bitcoin_text_context_requires_explicit_flag(tmp_path, monkeypatch):
    calls = 0
    original = target_registry_module.BitcoinTextContextChunkDetector.detect_chunk

    def tracked(self, *args, **kwargs):
        nonlocal calls
        calls += 1
        yield from original(self, *args, **kwargs)

    monkeypatch.setattr(
        target_registry_module.BitcoinTextContextChunkDetector,
        "detect_chunk",
        tracked,
    )
    source = tmp_path / "bitcoin-context.txt"
    source.write_bytes(b"ordinary text without a Bitcoin context token")

    assert main(basic_arguments(source, tmp_path / "fast.json") + [
        "--targets", "all", "--skip-mnemonic",
    ]) == 0
    assert calls == 0

    assert main(basic_arguments(source, tmp_path / "context.json") + [
        "--targets", "all", "--skip-mnemonic", "--include-bitcoin-context",
    ]) == 0
    assert calls == 1


def test_cli_skip_mnemonic_keeps_all_other_target_detectors(
    tmp_path, monkeypatch, capsys,
):
    def forbidden(*args, **kwargs):
        raise AssertionError("MnemonicChunkDetector ran with --skip-mnemonic")

    monkeypatch.setattr(
        target_registry_module.MnemonicChunkDetector, "detect_chunk", forbidden)
    multibit = multibit_classic_wallet()
    armory = armory_wallet()
    source = tmp_path / "skip-mnemonic.img"
    source.write_bytes(
        structural_metadata() + b"--\x04ckey-invalid--" + multibit + b"--" + armory +
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
    raw_counts = payload["raw_hit_counts_by_signature"]
    assert raw_counts["berkeley_metadata_little_endian"] >= 1
    assert raw_counts["bitcoin_ckey"] == 1
    assert raw_counts["multibit_network_anchor"] == 1
    assert raw_counts["armory_wallet_header"] == 1
    assert raw_counts["electrum_bie1_raw_anchor"] == 1
    assert raw_counts["validated_wif"] == 1
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
    assert "raw_hits=0" in stderr
    assert "raw_by_target[none]" in stderr
    assert "rejected_by_target[none]" in stderr
    assert "pending_validation_by_target[none]" in stderr
    assert "validated_occurrences_by_target[none]" in stderr
    assert "validated_unique_by_target[none]" in stderr
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


def test_electrum_recovery_progress_has_count_percent_and_eta(capsys):
    progress = _ElectrumProgressLine()
    progress(32, 100, 8.0)
    progress(100, 100, 25.0)
    stderr = capsys.readouterr().err
    assert "Electrum recovery 32/100   32.0%  ETA 00:00:17" in stderr
    assert "Electrum recovery 100/100  100.0%  ETA 00:00:00" in stderr


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
