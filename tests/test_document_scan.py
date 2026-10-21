import json
import sqlite3
from pathlib import Path
import zipfile

import pytest

from bfrs.cli import main
from bfrs.recovery import document_scan as module
from tests.test_cli import basic_arguments, valid_wif
from tests.test_mnemonic_recovery_v1 import bip39_phrase


def docx(path, text=None):
    key = (text or valid_wif().decode())
    xml = ('<w:document xmlns:w="' + module.W[1:-1] + '"><w:body><w:p>'
           '<w:r><w:t>' + key[:20] + '</w:t></w:r><w:r><w:t>' + key[20:] +
           '</w:t></w:r></w:p></w:body></w:document>')
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('word/document.xml', xml)
    return path


def test_non_document_has_zero_extra_io(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('unnecessary filesystem access')
    monkeypatch.setattr(Path, 'stat', forbidden)
    monkeypatch.setattr(Path, 'open', forbidden)
    assert module.scan_document('anything.bin', targets={'secrets'}, mnemonic_standards=()) == ((), None)


def test_docx_wif_across_runs_and_no_secret_in_report(tmp_path):
    path = docx(tmp_path / 'copy.docx')
    hits, coverage = module.scan_document(path, targets={'secrets'}, mnemonic_standards=())
    assert coverage['status'] == 'SCANNED'
    assert len(hits) == 1
    row = hits[0].safe_dict()
    assert row['physical_start'] is None
    assert row['safe_metadata']['logical_text_start'] == 0
    assert valid_wif().decode() not in json.dumps(row)


def test_xlsx_resolves_shared_strings_in_cell_order(tmp_path):
    words = bip39_phrase('english').split()
    path = tmp_path / 'seed.xlsx'
    ns = module.S[1:-1]
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('xl/workbook.xml', '<workbook/>')
        archive.writestr('xl/sharedStrings.xml', f'<sst xmlns="{ns}">' +
            ''.join('<si><t>' + w + '</t></si>' for w in reversed(words)) + '</sst>')
        archive.writestr('xl/worksheets/sheet1.xml', f'<worksheet xmlns="{ns}"><sheetData><row>' +
            ''.join(f'<c t="s"><v>{i}</v></c>' for i in reversed(range(len(words)))) +
            '</row></sheetData></worksheet>')
    hits, coverage = module.scan_document(path, targets={'secrets'}, mnemonic_standards={'BIP39'})
    assert coverage['status'] == 'SCANNED'
    assert any(h.artifact_kind == 'mnemonic' for h in hits)


@pytest.mark.parametrize('case', ['oversize', 'badzip', 'entity', 'ole'])
def test_skips_reported_instead_of_silent_clean_result(tmp_path, monkeypatch, case):
    path = docx(tmp_path / 'bad.docx')
    if case == 'oversize':
        monkeypatch.setattr(module, 'MAX_XML_BYTES', 10)
    elif case == 'badzip':
        path.write_bytes(b'PK\x03\x04broken')
    elif case == 'ole':
        path.write_bytes(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')
    else:
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('word/document.xml', '<!DOCTYPE x [<!ENTITY a "x">]><x/>')
    hits, coverage = module.scan_document(path, targets={'secrets'}, mnemonic_standards=())
    assert not hits
    assert coverage['status'] != 'SCANNED'
    assert coverage['reason']


def test_cli_file_and_folder_checkpoint_resume(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    path = docx(root / 'wallet.docx')
    report = tmp_path / 'file.json'
    args = ['--targets', 'secrets', '--skip-mnemonic', '--workers', '1']
    assert main(basic_arguments(path, report) + args) == 0
    payload = json.loads(report.read_text())
    hits = [h for h in payload['target_findings'] if h['source_kind'] == 'DOCUMENT_EXTRACTED_TEXT']
    assert len(hits) == 1
    assert hits[0]['file_offset_start'] is None
    assert payload['document_scan']['status'] == 'SCANNED'
    checkpoint = tmp_path / 'checkpoint.sqlite'
    folder_report = tmp_path / 'folder.json'
    assert main(basic_arguments(root, folder_report) + args + ['--checkpoint', str(checkpoint)]) == 0
    before = json.loads(folder_report.read_text())
    # Simulate interruption after the last durable file, before final completion.
    with sqlite3.connect(checkpoint) as connection:
        connection.execute("UPDATE metadata SET value='RUNNING' WHERE key='state'")
    assert main(basic_arguments(root, folder_report) + args + ['--resume-checkpoint', str(checkpoint)]) == 0
    after = json.loads(folder_report.read_text())
    assert before['target_findings'] == after['target_findings']
    assert len(after['target_findings']) == 1


def test_skip_mnemonic_and_target_selection(tmp_path):
    path = docx(tmp_path / 'seed.docx', bip39_phrase('english'))
    hits, coverage = module.scan_document(path, targets={'secrets'}, mnemonic_standards=())
    assert hits == ()
    assert coverage['status'] == 'SCANNED'
    assert module.scan_document(path, targets={'bitcoin-core'}, mnemonic_standards=()) == ((), None)


def test_gui_configuration_routes_document_seed_to_target_report(tmp_path):
    from bfrs.gui.configuration import build_gui_scan_config
    from bfrs.application.scan_service import build_cli_arguments
    path = docx(tmp_path / 'seed.docx', bip39_phrase('english'))
    report = tmp_path / 'report.json'
    config = build_gui_scan_config(
        input_path=str(path), output_path=str(report), source_type='FILE',
        targets=frozenset({'secrets'}), include_mnemonic=True,
        include_bitcoin_context=False, workers=1, file_workers=1,
    )
    assert main(build_cli_arguments(config)) == 0
    payload = json.loads(report.read_text())
    assert any(h['artifact_kind'] == 'mnemonic' and
               h['source_kind'] == 'DOCUMENT_EXTRACTED_TEXT'
               for h in payload['target_findings'])
    assert payload['document_scan']['mnemonic_recovery']['bip39_valid'] >= 1


def test_old_checkpoint_does_not_skip_new_document_pass(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    docx(root / 'wallet.docx')
    report = tmp_path / 'report.json'
    checkpoint = tmp_path / 'checkpoint.sqlite'
    args = basic_arguments(root, report) + ['--targets', 'secrets', '--skip-mnemonic']
    assert main(args + ['--checkpoint', str(checkpoint)]) == 0
    with sqlite3.connect(checkpoint) as connection:
        settings = json.loads(connection.execute(
            "SELECT value FROM metadata WHERE key='semantics_json'").fetchone()[0])
        settings.pop('document_scan_version')
        connection.execute("UPDATE metadata SET value=? WHERE key='semantics_json'",
                           (json.dumps(settings),))
        connection.execute("UPDATE metadata SET value='RUNNING' WHERE key='state'")
    assert main(args + ['--resume-checkpoint', str(checkpoint)]) == 3


def test_unselected_large_embedded_object_is_not_decompressed(tmp_path, monkeypatch):
    path = docx(tmp_path / 'copy.docx')
    with zipfile.ZipFile(path, 'a', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('word/embeddings/large.bin', b'x' * (module.MAX_XML_BYTES + 1))
    hits, coverage = module.scan_document(path, targets={'secrets'}, mnemonic_standards=())
    assert len(hits) == 1
    assert coverage['status'] == 'SCANNED'
    assert coverage['xml_bytes'] < 1024
