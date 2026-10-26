"""Differential coverage for prepared, non-writing folder file requests."""
from pathlib import Path
import json
import threading

import pytest

from bfrs.application.folder_file_scanner import FolderFileScanner
from bfrs.cli import build_parser, main
from bfrs.scanners.folder_source_scanner import _child_arguments, scan_folder_source
from tests.test_cli import (basic_arguments, structural_metadata, encrypted_electrum,
    multibit_classic_wallet, armory_wallet, valid_wif)
from tests.test_mnemonic_recovery_v1 import bip39_phrase


def stable(value):
    if isinstance(value, dict):
        return {key: stable(item) for key,item in value.items() if key != "elapsed_seconds"}
    if isinstance(value, list):
        return [stable(item) for item in value]
    return value


def arguments(root, report, *, workers=1, options=None):
    return build_parser().parse_args(basic_arguments(root, report) + [
        "--chunk-mib", "1", "--file-workers", str(workers), "--workers", "1",
    ] + (options if options is not None else ["--targets", "all"]))


def fixture(root):
    root.mkdir()
    payloads = {
        "core.dat": structural_metadata(), "electrum.wallet": encrypted_electrum(),
        "multibit.wallet": multibit_classic_wallet(), "armory.bin": armory_wallet(),
        "portfel-żółty.dat": valid_wif(), "słowa.txt": bip39_phrase("english").encode("utf-8"),
        "empty": b"", "corrupt.docx": b"PK\x03\x04truncated", "corrupt.pdf": b"%PDF-1.7\n",
    }
    for folder in ("a", "b"):
        directory = root / folder
        directory.mkdir()
        for name, data in payloads.items():
            (directory / name).write_bytes(data)
    data = bytearray(1024**2 + 256)
    secret = valid_wif()
    offset = 1024**2 - len(secret)//2
    data[offset:offset+len(secret)] = secret
    (root / "large-boundary.bin").write_bytes(data)
    return offset


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_prepared_matches_cli_adapter_for_every_file_and_finding(tmp_path, workers):
    source = tmp_path / "source"
    boundary = fixture(source)
    original = {str(p): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    baseline_args = arguments(source, tmp_path/"baseline.json", workers=workers)
    def fresh_cli(argv):
        reports = []
        code = main(argv, _folder_child=True, _report_sink=reports.append)
        return reports[0] if code == 0 else code
    # A fresh public CLI request has neither the prepared template nor cached
    # detector selection, and is the independent correctness reference.
    assert scan_folder_source(baseline_args, fresh_cli) == 0
    optimized_args = arguments(source, tmp_path/"optimized.json", workers=workers)
    assert scan_folder_source(optimized_args, FolderFileScanner(optimized_args)) == 0
    baseline = json.loads(baseline_args.output.read_text(encoding="utf-8"))
    optimized = json.loads(optimized_args.output.read_text(encoding="utf-8"))
    assert stable(optimized["files"]) == stable(baseline["files"])
    assert optimized["target_findings"] == baseline["target_findings"]
    assert optimized["files_scanned"] == baseline["files_scanned"] == 19
    assert optimized["bytes_scanned"] == baseline["bytes_scanned"]
    findings = optimized["target_findings"]
    assert {row["target"] for row in findings} >= {"bitcoin-core", "electrum", "multibit", "armory", "secrets"}
    assert any(row.get("artifact_kind") == "mnemonic" for row in findings)
    wifs = [row for row in findings if row.get("artifact_kind") == "WIF_PRIVATE_KEY"]
    assert len({row["file_path"] for row in wifs}) == 3
    assert any(row["file_path"].endswith("large-boundary.bin") and row["file_offset_start"] == boundary for row in wifs)
    assert {str(p): p.read_bytes() for p in source.rglob("*") if p.is_file()} == original


@pytest.mark.parametrize("options", [
    ["--electrum-only"], ["--seed-scan-only"], ["--targets", "secrets", "--skip-mnemonic"],
    ["--targets", "all", "--include-bitcoin-context"], [],
])
def test_prepared_preserves_scan_modes_and_configuration(tmp_path, options):
    source = tmp_path / "source"
    source.mkdir()
    for name, data in (("wallet", valid_wif()), ("electrum", encrypted_electrum()),
                       ("seed", bip39_phrase("english").encode())):
        (source / name).write_bytes(data)
    args = arguments(source, tmp_path/"virtual.json", options=options)
    slow, fast = FolderFileScanner(args), FolderFileScanner(args)
    for path in sorted(source.iterdir()):
        expected = slow(_child_arguments(args, path, args.output))
        actual = fast.scan_file(path, args.output)
        assert isinstance(expected, dict) and isinstance(actual, dict)
        assert stable(actual) == stable(expected)
    assert not args.output.exists()


def test_parser_and_selection_are_reused_but_namespace_and_reports_are_isolated(tmp_path, monkeypatch):
    import bfrs.cli as cli
    source = tmp_path/"source"
    source.mkdir()
    for index in range(5):
        (source/f"file-{index}").write_bytes(bip39_phrase("english").encode())
    args = arguments(source, tmp_path/"virtual.json")
    counts = {"build": 0, "parse": 0, "selection": 0}
    namespaces = []
    build, select, run = cli.build_parser, cli._selection, cli._run_scan
    def build_once():
        counts["build"] += 1
        parser = build()
        parse = parser.parse_args
        def parsed(*a, **kw):
            counts["parse"] += 1
            return parse(*a, **kw)
        parser.parse_args = parsed
        return parser
    def selected(*a, **kw):
        counts["selection"] += 1
        return select(*a, **kw)
    def executed(namespace, *a, **kw):
        namespaces.append(namespace)
        return run(namespace, *a, **kw)
    monkeypatch.setattr(cli, "build_parser", build_once)
    monkeypatch.setattr(cli, "_selection", selected)
    monkeypatch.setattr(cli, "_run_scan", executed)
    scanner = FolderFileScanner(args)
    for path in sorted(source.iterdir()):
        report = scanner.scan_file(path, args.output)
        assert report["configuration"]["source_root"] == str(path.resolve())
        assert "POISON" not in report["configuration"]["targets"]
        report["configuration"]["targets"].append("POISON")
        for selection in scanner._local.selections.values():
            for detector in selection.chunk_detectors:
                cached = getattr(detector, "scanner", None)
                if cached is not None:
                    assert cached._normalize_token.cache_info().currsize == 0
    assert counts == {"build": 1, "parse": 1, "selection": 1}
    assert len({id(value) for value in namespaces}) == 5
    assert len({value.input for value in namespaces}) == 5


@pytest.mark.parametrize("chunk_workers", [1, 2])
def test_selection_cache_uses_effective_settings_across_size_classes(tmp_path, monkeypatch, chunk_workers):
    import bfrs.cli as cli
    source = tmp_path/"source"
    source.mkdir()
    small, large = source/"small", source/"large"
    small.write_bytes(b"synthetic bytes")
    with large.open("wb") as stream:
        stream.truncate(1024**2 + 1)
    args = arguments(source, tmp_path/"virtual.json")
    args.workers = chunk_workers
    selections = []
    settings = []
    original = cli._selection
    def selected(parser, arguments):
        settings.append(arguments.workers)
        return original(parser, arguments)
    def ran(namespace, parser, **options):
        selections.append(options["_selection_override"])
        options["_report_sink"]({"target_findings": []})
        return 0
    monkeypatch.setattr(cli, "_selection", selected)
    monkeypatch.setattr(cli, "_run_scan", ran)
    scanner = FolderFileScanner(args)
    for path in (small, large, small):
        scanner.scan_file(path, args.output)
    assert selections[0] is selections[2]
    if chunk_workers == 1:
        assert selections[0] is selections[1]
        assert settings == [1]
    else:
        assert selections[0] is not selections[1]
        assert settings == [1, 2]


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_sensitive_token_cache_is_cleared_when_engine_raises(tmp_path, monkeypatch, error):
    import bfrs.cli as cli
    source = tmp_path/"source"
    source.mkdir()
    path = source/"file"
    path.write_bytes(b"synthetic bytes")
    args = arguments(source, tmp_path/"virtual.json")
    scanner = FolderFileScanner(args)
    touched = []
    def fail(namespace, parser, **options):
        for detector in options["_selection_override"].chunk_detectors:
            cached = getattr(detector, "scanner", None)
            if cached is not None:
                cached._normalize_token("synthetic")
                touched.append(cached)
        raise error("synthetic failure")
    monkeypatch.setattr(cli, "_run_scan", fail)
    with pytest.raises(error):
        scanner.scan_file(path, args.output)
    assert touched
    assert all(item._normalize_token.cache_info().currsize == 0 for item in touched)


def test_prepared_child_rejects_write_policy_before_running_engine(tmp_path, monkeypatch):
    import bfrs.scanners.folder_source_scanner as folder
    source = tmp_path/"source"
    source.mkdir()
    path = source/"file"
    path.write_bytes(b"synthetic bytes")
    args = arguments(source, tmp_path/"virtual.json")
    original = folder._child_arguments
    checkpoint = tmp_path/"unexpected.sqlite"
    monkeypatch.setattr(folder, "_child_arguments", lambda *a: original(*a)+["--checkpoint", str(checkpoint)])
    with pytest.raises(ValueError, match="non-writing"):
        FolderFileScanner(args).scan_file(path, args.output)
    assert not checkpoint.exists() and not args.output.exists()


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_unreadable_file_has_same_failure_as_cli_adapter(tmp_path, monkeypatch, workers):
    source = tmp_path/"source"
    source.mkdir()
    blocked = source/"niedostępny-ź.bin"
    blocked.write_bytes(b"synthetic bytes")
    (source/"readable").write_bytes(valid_wif())
    original = Path.open
    def denied(self, *a, **kw):
        if self == blocked:
            raise PermissionError("synthetic access denied")
        return original(self, *a, **kw)
    monkeypatch.setattr(Path, "open", denied)
    reports = []
    for prepared in (False, True):
        args = arguments(source, tmp_path/f"report-{prepared}.json", workers=workers)
        scanner = FolderFileScanner(args)
        child = scanner if prepared else lambda argv: scanner(argv)
        assert scan_folder_source(args, child) == 0
        reports.append(json.loads(args.output.read_text(encoding="utf-8")))
    assert stable(reports[0]["files"]) == stable(reports[1]["files"])
    assert reports[0]["target_findings"] == reports[1]["target_findings"]
    assert reports[1]["files_failed"] == 1


@pytest.mark.parametrize("workers", [1, 2, 4])
@pytest.mark.parametrize("stop_kind", ["cooperative", "keyboard"])
def test_prepared_checkpoint_stop_resume_preserves_all_positive_findings(tmp_path, workers, stop_kind):
    source = tmp_path/"source"
    fixture(source)
    baseline = tmp_path/"baseline.json"
    args = arguments(source, baseline, workers=workers)
    assert scan_folder_source(args, FolderFileScanner(args)) == 0
    checkpoint = tmp_path/"checkpoint.sqlite"
    report = tmp_path/"resumed.json"
    stop = threading.Event()
    args = arguments(source, report, workers=workers)
    args.checkpoint = checkpoint
    args._scan_should_stop = stop.is_set
    def update(event):
        if event.stage == "folder-scan" and event.scanned_files >= 3 and not stop.is_set():
            stop.set()
            if stop_kind == "keyboard":
                raise KeyboardInterrupt
    assert scan_folder_source(args, FolderFileScanner(args, should_stop=stop.is_set), progress_callback=update) == 130
    assert not report.exists()
    args = arguments(source, report, workers=workers)
    args.resume_checkpoint = checkpoint
    assert scan_folder_source(args, FolderFileScanner(args)) == 0
    expected = json.loads(baseline.read_text(encoding="utf-8"))
    actual = json.loads(report.read_text(encoding="utf-8"))
    assert stable(actual["files"]) == stable(expected["files"])
    assert actual["target_findings"] == expected["target_findings"]
    assert actual["checkpoint"]["resumed_files"] >= 3


def test_small_files_do_not_start_mnemonic_process_pool(tmp_path, monkeypatch):
    import bfrs.scanners.target_registry as registry
    def forbidden(*args, **kwargs):
        raise AssertionError("small file started an extra process pool")
    monkeypatch.setattr(registry, "ProcessPoolExecutor", forbidden)
    source = tmp_path/"source"
    source.mkdir()
    path = source/"seed"
    path.write_bytes(bip39_phrase("english").encode())
    args = arguments(source, tmp_path/"virtual.json")
    args.workers = 4
    assert isinstance(FolderFileScanner(args).scan_file(path, args.output), dict)


def test_no_secret_is_joined_across_source_file_boundary(tmp_path):
    source = tmp_path/"source"
    source.mkdir()
    secret = valid_wif()
    (source/"a").write_bytes(secret[:len(secret)//2])
    (source/"b").write_bytes(secret[len(secret)//2:])
    args = arguments(source, tmp_path/"report.json", workers=4)
    assert scan_folder_source(args, FolderFileScanner(args)) == 0
    payload = json.loads(args.output.read_text(encoding="utf-8"))
    assert not any(row.get("artifact_kind") == "WIF_PRIVATE_KEY" for row in payload["target_findings"])
