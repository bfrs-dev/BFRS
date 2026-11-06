import json
import sqlite3
import zipfile

from bfrs.recovery.archive_name_hints import NameHints, name_hint
from bfrs.recovery.container_inventory import inspect_file
from tests.test_container_inventory import runner
from tests.test_zip_inventory_recovery import local_entry


def test_casefold_path_clues_are_labels_not_wallet_validation():
    assert name_hint('BACKUP/ELECTRUM/default_wallet')['category'] == 'WALLET_NAME'
    assert name_hint('ordinary/photo.jpg') is None
    assert name_hint('BACKUP/photo.jpg')['category'] == 'BACKUP_NAME'
    assert name_hint('mój/PORTFEL.txt')['terms'] == ['portfel']


def test_every_member_is_checked_even_after_the_name_display_limit(tmp_path):
    path = tmp_path / 'renamed.bin'
    with zipfile.ZipFile(path, 'w') as archive:
        for index in range(200):
            archive.writestr(f'ordinary-{index}.txt', b'')
        archive.writestr('hidden/wallet.dat', b'synthetic')
    row = inspect_file(path)
    assert 'hidden/wallet.dat' not in row['member_names']
    assert row['zip_name_hint_count'] == row['zip_wallet_name_hint_count'] == 1
    assert row['zip_names_checked_for_hints'] == 201
    assert row['zip_name_hints_complete']
    assert row['zip_name_hints'][0]['name'] == 'hidden/wallet.dat'
    assert row['zip_name_hints'][0]['member_index'] == 200
    offset = row['zip_name_hints'][0]['header_offset']
    assert path.read_bytes()[offset:offset+4] == b'PK\x01\x02'
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'


def test_stronger_hints_survive_many_generic_backups_and_remain_bounded():
    hints = NameHints()
    for index in range(1000):
        hints.add(f'backup-{index}', header_offset=index, member_index=index)
    hints.add('wallet.dat', header_offset=1000, member_index=1000)
    result = hints.report(complete=True)
    assert len(result['zip_name_hints']) == 50
    assert result['zip_name_hints'][0]['name'] == 'wallet.dat'
    assert result['zip_name_hint_count'] == 1001 and result['zip_name_hints_truncated']


def test_long_name_matching_precedes_display_truncation():
    hint = name_hint('x' * 1000 + '/wallet.dat')
    assert hint['category'] == 'WALLET_NAME' and hint['name_truncated']
    assert len(hint['name']) == 512


def test_lost_directory_keeps_partial_name_clues(tmp_path):
    path = tmp_path / 'partial.zip'
    path.write_bytes(local_entry(name=b'first/backup.txt', flags=0) + local_entry())
    row = inspect_file(path)
    assert row['zip_name_hint_count'] == 2 and not row['zip_name_hints_complete']
    assert row['zip_name_hints'][0]['name'] == 'wallet.dat'


def test_checkpoint_revision_refreshes_pre_hint_zip_results(tmp_path, monkeypatch):
    source, output = tmp_path / 'source', tmp_path / 'report'
    source.mkdir()
    with zipfile.ZipFile(source / 'renamed.bin', 'w') as archive:
        archive.writestr('wallet.dat', b'synthetic')
    (source / 'ordinary.txt').write_text('ordinary')
    runner.inventory(source, output)
    with sqlite3.connect(output / 'inventory.sqlite') as db:
        db.execute("UPDATE metadata SET value='2' WHERE key='zip_inventory_revision'")
        old = json.loads(db.execute("SELECT result FROM files WHERE path='renamed.bin'").fetchone()[0])
        old = {key: value for key, value in old.items() if 'hint' not in key}
        db.execute("UPDATE files SET result=? WHERE path='renamed.bin'", (json.dumps(old),))
    result = runner.inventory(source, output, resume=True)
    assert result['run']['inspected'] == 1 and result['run']['reused'] == 1
    row = json.loads((output / 'inventory.jsonl').read_text())
    assert row['zip_wallet_name_hint_count'] == 1
    assert runner.inventory(source, output, resume=True)['run']['reused'] == 2
