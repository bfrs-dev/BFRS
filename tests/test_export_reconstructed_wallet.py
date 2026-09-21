"""Only synthetic pages and the public scalar-one test vector are used here."""
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from bfrs.recovery.physical_berkeley_reconstructor import ExportRefused, export_wallet
from bfrs.recovery.logical_berkeley_database_pipeline import LogicalBerkeleyDatabaseRecoveryPipeline
from bfrs.recovery.logical_page_map import LogicalBerkeleyPageMap, LogicalPageLocation
from bfrs.tools.export_reconstructed_wallet import main
from tests.test_logical_berkeley_database_pipeline import (
    metadata, leaf, internal, plain_pair, string, vector, PUBLIC_KEY,
    MemoryRangeReader, private_der,
)

SIZE = 512


@pytest.fixture
def case(tmp_path):
    source = tmp_path / "synthetic.img"
    report_path = tmp_path / "synthetic.json"
    pages = {
        0: metadata(0, 1),
        1: leaf(1, (b"main", (2).to_bytes(4, "big"))),
        2: metadata(2, 3),
        3: internal(3, 2, 4, 5, 6),
        4: leaf(4, plain_pair()),
        5: leaf(5, (string("keymeta") + vector(PUBLIC_KEY),
                    (1).to_bytes(4, "little") + (123).to_bytes(8, "little"),
                    string("defaultkey"), vector(PUBLIC_KEY))),
        6: leaf(6, (string("version"), (60000).to_bytes(4, "little"),
                    string("minversion"), (60000).to_bytes(4, "little"))),
    }
    for n in (0, 2):
        p = bytearray(pages[n])
        p[32:36] = (6 if n == 0 else 2).to_bytes(4, "little")
        p[52:72] = b"synthetic-file-id-01"
        pages[n] = bytes(p)
    for n in (4, 5, 6):
        p = bytearray(pages[n])
        p[12:16] = (n - 1 if n > 4 else 0).to_bytes(4, "little")
        p[16:20] = (n + 1 if n < 6 else 0).to_bytes(4, "little")
        pages[n] = bytes(p)
    # Deliberately fragmented and physically reversed: never infer a source grid.
    offsets = {n: (15 - n * 2) * SIZE for n in pages}
    image = bytearray(16 * SIZE)
    for n, data in pages.items():
        image[offsets[n]:offsets[n] + SIZE] = data
    source.write_bytes(image)
    logical = f"reconstructed-{offsets[2]:x}-3"
    page_map = LogicalBerkeleyPageMap(str(source), SIZE, "little",
        [LogicalPageLocation(n, offsets[n], SIZE, str(source)) for n in pages])
    recovered = LogicalBerkeleyDatabaseRecoveryPipeline(page_map, logical_file_id=logical,
        range_reader=MemoryRangeReader({offsets[n]:p for n,p in pages.items()})).run()
    candidate = recovered.wallet_candidate_reports[0]
    candidate["normalized_state"] = {"discovery_state": "ACCEPTED"}
    databases = []
    for meta, root, selected in ((0, 1, [1]), (2, 3, [3, 4, 5, 6])):
        identity = dict(source=str(source), metadata_page_number=meta,
                        metadata_physical_offset=offsets[meta], root_page_number=root,
                        page_size=SIZE, byte_order="little")
        databases.append(dict(identity=identity, status="structural",
            normalized_state={"structural_state": "COMPLETE"},
            missing_page_numbers=[], ambiguous_page_numbers=[], rejected_page_numbers=[],
            selected_pages=[dict(page_number=n,physical_offset=offsets[n],page_size=SIZE,
                                 validation_status="structural") for n in selected]))
    report = dict(legacy_wallet_recovery={"candidates": [candidate]}, reconstructed_databases=databases,
        reconstructed_wallet_results=[dict(identity=databases[1]["identity"], status="structural",
            database_status="structural", record_pair_count=5,
            safe_locations=dict(read_failure_page_numbers=[], rejected_extraction_page_numbers=[]))])
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return source, report_path, candidate["candidate_id"], tmp_path / "wallet.dat", pages, offsets, report


def run(case):
    return export_wallet(*case[:4], allow_private_key_export=True)


def rewrite(case):
    case[1].write_text(json.dumps(case[6]), encoding="utf-8")


def mutate_page(case, n, start, value):
    with case[0].open("r+b") as stream:
        stream.seek(case[5][n] + start)
        stream.write(value)


def test_complete_reparses_exact_deterministic_secret_free(case, capsys):
    before = hashlib.sha256(case[0].read_bytes()).digest()
    args = ["--input",str(case[0]),"--report",str(case[1]),"--candidate-id",case[2],
            "--output",str(case[3]),"--allow-private-key-export"]
    assert main(args) == 0
    stdout = capsys.readouterr().out
    manifest = case[3].with_name("wallet.dat.manifest.json").read_text()
    result = json.loads(manifest)
    assert result["structural_validation_status"] == "BFRS_PHYSICAL_RECONSTRUCTION_VALID"
    assert result["crypto_summary"]["unique_crypto_valid_plain_keys"] == 1
    assert result["record_counts"]["keymeta"] == 1
    actual = case[3].read_bytes()
    assert actual == b"".join(case[4][n] for n in range(7))
    assert result["sha256"] == hashlib.sha256(actual).hexdigest()
    assert stdout.count("match=YES") == 7
    for secret in (private_der(1).hex(), (1).to_bytes(32,"big").hex()):
        assert secret not in stdout + manifest
    assert set(result) == {"structural_validation_status","record_counts","crypto_summary",
                          "record_pair_count","sha256","size","page_count","page_size",
                          "candidate_id","source_image_basename"}
    other = case[3].with_name("copy.dat")
    export_wallet(case[0],case[1],case[2],other,allow_private_key_export=True)
    assert other.read_bytes() == actual
    assert hashlib.sha256(case[0].read_bytes()).digest() == before


@pytest.mark.parametrize("change,code", [
    ("missing", "MISSING_PAGE"), ("ambiguous", "AMBIGUOUS_PAGE"),
    ("size", "CONFLICTING_PAGE_SIZE"), ("order", "CONFLICTING_BYTE_ORDER"),
    ("mapping", "AMBIGUOUS_PAGE"), ("not_accepted", "CANDIDATE_NOT_ACCEPTED"),
    ("incomplete", "DATABASE_INCOMPLETE"), ("read_failure", "READ_FAILURE"),
    ("counts", "RECORD_COUNTS_MISMATCH"), ("crypto", "CRYPTO_COUNTS_MISMATCH"),
    ("outer_missing", "OUTER_RELATION_UNPROVEN"), ("short_read", "READ_FAILURE"),
])
def test_report_refusals(case, change, code):
    report = case[6]
    db = report["reconstructed_databases"][1]
    if change == "missing": db["selected_pages"].pop()
    if change == "ambiguous": db["ambiguous_page_numbers"] = [5]
    if change == "size": db["selected_pages"][0]["page_size"] = 1024
    if change == "order": report["reconstructed_databases"][0]["identity"]["byte_order"] = "big"
    if change == "mapping": db["selected_pages"].append(copy.deepcopy(db["selected_pages"][0]))
    if change == "not_accepted": report["legacy_wallet_recovery"]["candidates"][0]["normalized_state"]["discovery_state"] = "REJECTED"
    if change == "incomplete": db["normalized_state"]["structural_state"] = "FRAGMENT"
    if change == "read_failure": report["reconstructed_wallet_results"][0]["safe_locations"]["read_failure_page_numbers"] = [5]
    if change == "counts": report["legacy_wallet_recovery"]["candidates"][0]["record_counts"]["key"] = 2
    if change == "crypto": report["legacy_wallet_recovery"]["candidates"][0]["crypto_summary"]["unique_crypto_valid_plain_keys"] = 2
    if change == "outer_missing": report["reconstructed_databases"].pop(0)
    if change == "short_read": db["selected_pages"][0]["physical_offset"] = case[0].stat().st_size
    rewrite(case)
    with pytest.raises(ExportRefused, match=code): run(case)
    assert not case[3].exists()
    assert not list(case[3].parent.glob(".wallet-*.tmp"))


@pytest.mark.parametrize("n,start,value,code", [
    (2,12,bytes(4),"INVALID_METADATA"),
    (0,32,(7).to_bytes(4,"little"),"MISSING_PAGE"),
    (0,28,(5).to_bytes(4,"little"),"FREE_LIST_UNSUPPORTED"),
    (2,26,b"\x01","UNSUPPORTED_METADATA_FEATURES"),
    (2,52,b"different-uid-value!!","OUTER_RELATION_UNPROVEN"),
    (5,12,bytes(4),"PAGE_CHAIN_INVALID"),
    (1,508,(3).to_bytes(4,"big"),"OUTER_RELATION_UNPROVEN"),
])
def test_source_refusals(case, n, start, value, code):
    mutate_page(case,n,start,value)
    with pytest.raises(ExportRefused, match=code): run(case)
    assert not case[3].exists()


@pytest.mark.parametrize("kind", ["existing", "same", "hardlink", "symlink", "manifest", "report"])
def test_path_safety(case, kind):
    source, report, candidate, output = case[:4]
    if kind == "existing": output.write_bytes(b"keep")
    if kind == "same": output = source
    if kind == "hardlink": os.link(source,output)
    if kind == "symlink":
        try: output.symlink_to(source)
        except OSError: pytest.skip("symlink privilege unavailable")
    if kind == "manifest": output.with_name(output.name + ".manifest.json").write_text("keep")
    if kind == "report": output = report
    before = source.read_bytes()
    with pytest.raises(ExportRefused,match="PATH_COLLISION|OUTPUT_EXISTS"):
        export_wallet(source,report,candidate,output,allow_private_key_export=True)
    assert source.read_bytes() == before
    if kind == "existing": assert output.read_bytes() == b"keep"


def test_requires_explicit_opt_in(case, capsys):
    with pytest.raises(ExportRefused,match="PRIVATE_KEY_EXPORT_NOT_ALLOWED"):
        export_wallet(*case[:4])
    assert main(["--input",str(case[0]),"--report",str(case[1]),"--candidate-id",case[2],
                 "--output",str(case[3])]) == 2
    assert capsys.readouterr().out.strip() == "REFUSE_EXPORT: PRIVATE_KEY_EXPORT_NOT_ALLOWED"
    assert not case[3].exists()


def test_publish_race_never_overwrites(case, monkeypatch):
    from bfrs.recovery import physical_berkeley_reconstructor as module
    original = module._publish
    def race(temp,target):
        target.write_bytes(b"racer")
        original(temp,target)
    monkeypatch.setattr(module,"_publish",race)
    with pytest.raises(ExportRefused,match="IO_OR_PUBLICATION_FAILURE"): run(case)
    assert case[3].read_bytes() == b"racer"
    assert not list(case[3].parent.glob(".wallet-*.tmp"))


def test_source_change_after_copy_refused(case, monkeypatch):
    from bfrs.recovery import physical_berkeley_reconstructor as module
    original = module._read_pages
    def changed(stream,offsets,size):
        values = original(stream,offsets,size)
        if Path(stream.name).name.startswith(".wallet-export-"):
            mutate_page(case,4,0,b"\x01")
        return values
    monkeypatch.setattr(module,"_read_pages",changed)
    with pytest.raises(ExportRefused,match="PAGE_HASH_MISMATCH"): run(case)
    assert not case[3].exists()
    assert not list(case[3].parent.glob(".wallet-*.tmp"))




def test_output_corruption_is_detected_before_publish(case, monkeypatch):
    from bfrs.recovery import physical_berkeley_reconstructor as module
    original = module._read_pages
    def corrupt(stream,offsets,size):
        values = original(stream,offsets,size)
        if Path(stream.name).name.startswith(".wallet-export-"):
            values[4] = bytes([values[4][0] ^ 1]) + values[4][1:]
        return values
    monkeypatch.setattr(module,"_read_pages",corrupt)
    with pytest.raises(ExportRefused,match="PAGE_HASH_MISMATCH"): run(case)
    assert not case[3].exists()
    assert not list(case[3].parent.glob(".wallet-*.tmp"))


def test_fsync_failure_leaves_no_output(case, monkeypatch):
    from bfrs.recovery import physical_berkeley_reconstructor as module
    def fail(fd):
        raise OSError("synthetic error")
    monkeypatch.setattr(module.os,"fsync",fail)
    with pytest.raises(ExportRefused,match="IO_OR_PUBLICATION_FAILURE"): run(case)
    assert not case[3].exists()
    assert not list(case[3].parent.glob(".wallet-*.tmp"))


def test_unknown_records_preserved_verbatim(case):
    n = 6
    payloads = (string("version"),(60000).to_bytes(4,"little"),
                string("minversion"),(60000).to_bytes(4,"little"),
                string("custom_synthetic"),b"synthetic opaque record")
    data = bytearray(leaf(n,payloads))
    data[12:16] = (5).to_bytes(4,"little")
    mutate_page(case,n,0,data)
    case[6]["reconstructed_wallet_results"][0]["record_pair_count"] = 6
    rewrite(case)
    run(case)
    assert case[3].read_bytes()[n*SIZE:(n+1)*SIZE] == bytes(data)


def test_cli_malformed_report_never_echoes_values(case,capsys):
    marker = "SYNTHETIC_DO_NOT_ECHO"
    case[1].write_text('{"private": "' + marker,encoding="utf-8")
    assert main(["--input",str(case[0]),"--report",str(case[1]),"--candidate-id",case[2],
                 "--output",str(case[3]),"--allow-private-key-export"]) == 2
    output = capsys.readouterr()
    assert marker not in output.out + output.err
    assert output.out.strip() == "REFUSE_EXPORT: INVALID_REPORT_OR_STRUCTURE"


def test_manifest_race_reports_created_wallet_without_overwrite(case,monkeypatch):
    from bfrs.recovery import physical_berkeley_reconstructor as module
    original = module._publish
    def race(temp,target):
        if target.name.endswith(".manifest.json"):
            target.write_bytes(b"racer")
        original(temp,target)
    monkeypatch.setattr(module,"_publish",race)
    with pytest.raises(ExportRefused,match="MANIFEST_PUBLICATION_FAILED_WALLET_CREATED"): run(case)
    assert case[3].exists()
    assert case[3].with_name("wallet.dat.manifest.json").read_bytes() == b"racer"
    assert not list(case[3].parent.glob(".wallet-*.tmp"))
