import json
import sqlite3

import pytest

from bfrs.application.raw_zip_view import PAGE_SIZE, read_raw_zip_page
from bfrs.recovery.raw_zip_inventory import scan_image
from tests.test_raw_zip_inventory import zip_bytes


def test_pages_prioritize_and_work_without_source(tmp_path):
    source, output = tmp_path / 'image.bin', tmp_path / 'report'
    source.write_bytes(zip_bytes(tuple(f'wallet-{n}.dat' for n in range(120))) +
                       zip_bytes(('ordinary.txt',)))
    scan_image(source, output)
    source.unlink()
    database = output / 'zip_scan.sqlite'
    before = database.read_bytes()
    pages = [read_raw_zip_page(database, offset=n * PAGE_SIZE) for n in range(3)]
    rows = [row for page in pages for row in page.rows]
    assert len(rows) == 241
    assert len({row['offset'] for row in rows}) == 241
    assert all(row['priority'] == 3 for row in rows)
    assert pages[0].has_next and not pages[-1].has_next
    all_rows = [row for n in range(3) for row in read_raw_zip_page(
        database, priority_only=False, offset=n * PAGE_SIZE).rows]
    assert len(all_rows) == 244
    assert database.read_bytes() == before
    assert not source.exists()


def test_partial_checkpoint_is_not_presented_as_complete(tmp_path):
    source, output = tmp_path / 'disk.img', tmp_path / 'report'
    source.write_bytes(zip_bytes())
    summary = scan_image(source, output, max_candidates=1)
    page = read_raw_zip_page(output / 'zip_scan.sqlite')
    assert page.scanned_bytes == summary['scanned_prefix_end'] < page.total_bytes
    assert len(page.rows) == 1


@pytest.mark.parametrize('offset', [-1, 1, True, '0'])
def test_invalid_pages_rejected(tmp_path, offset):
    with pytest.raises(ValueError, match='INVALID_REPORT_PAGE'):
        read_raw_zip_page(tmp_path / 'absent.sqlite', offset=offset)


def test_wrong_report_and_missing_file_are_read_only(tmp_path):
    database = tmp_path / 'report.sqlite'
    with pytest.raises(sqlite3.OperationalError):
        read_raw_zip_page(database)
    assert not database.exists()
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE metadata(key,value)')
        db.execute('INSERT INTO metadata VALUES (?,?)', ('format', json.dumps('wrong')))
    before = database.read_bytes()
    with pytest.raises(ValueError, match='UNSUPPORTED_RAW_ZIP_REPORT'):
        read_raw_zip_page(database)
    assert database.read_bytes() == before


@pytest.mark.parametrize('change', [dict(priority=9), dict(zip_name_hints=[None]),
                                    dict(member_name=42), dict(encryption='unexpected')])
def test_malformed_records_fail_before_reaching_gui(tmp_path, change):
    source, output = tmp_path / 'disk.img', tmp_path / 'report'
    source.write_bytes(zip_bytes())
    scan_image(source, output)
    database = output / 'zip_scan.sqlite'
    with sqlite3.connect(database) as db:
        offset, payload = db.execute('SELECT offset,result FROM hits LIMIT 1').fetchone()
        row = json.loads(payload)
        row.update(change)
        db.execute('UPDATE hits SET result=? WHERE offset=?', (json.dumps(row), offset))
    with pytest.raises(ValueError, match='INVALID_RAW_ZIP_RECORD'):
        read_raw_zip_page(database)
