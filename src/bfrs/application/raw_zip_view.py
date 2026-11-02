"""Read-only pages of raw ZIP header candidates, without opening the image."""
from contextlib import closing
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
import time

from bfrs.recovery.raw_zip_inventory import FORMAT

PAGE_SIZE = 100
MAX_RECORD_CHARS = 256 * 1024


@dataclass(frozen=True)
class RawZipPage:
    source: str
    scanned_bytes: int
    total_bytes: int
    rows: tuple[dict, ...]
    offset: int
    has_next: bool


def read_raw_zip_page(database, *, priority_only=True, offset=0, _efs=False):
    if _efs:
        from bfrs.recovery.raw_efs_inventory import FORMAT as expected_format, STATUSES
    else:
        expected_format = FORMAT
    if type(offset) is not int or offset < 0 or offset % PAGE_SIZE:
        raise ValueError('INVALID_REPORT_PAGE')
    deadline = time.monotonic() + 15
    uri = Path(database).absolute().as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
        db.execute('BEGIN')
        metadata = {k: json.loads(v) for k, v in db.execute('SELECT key,value FROM metadata')}
        if metadata.get('format') != expected_format:
            raise ValueError('UNSUPPORTED_RAW_ZIP_REPORT')
        source = metadata['source']
        scanned, total = metadata['next_offset'], source['stat'][0]
        if (not isinstance(source['path'], str) or type(scanned) is not int
                or type(total) is not int or not 0 <= scanned <= total):
            raise ValueError('INVALID_RAW_ZIP_REPORT')
        where = ('WHERE priority=4' if _efs else 'WHERE priority>0') if priority_only else ''
        records = db.execute(f'SELECT offset,substr(result,1,?) FROM hits {where} '
                             'ORDER BY priority DESC,offset LIMIT ? OFFSET ?',
                             (MAX_RECORD_CHARS + 1, PAGE_SIZE + 1, offset)).fetchall()
        rows = []
        for physical_offset, payload in records[:PAGE_SIZE]:
            if len(payload) > MAX_RECORD_CHARS:
                raise ValueError('RAW_ZIP_RECORD_TOO_LARGE')
            row = json.loads(payload)
            if _efs:
                if (not isinstance(row, dict) or type(row.get('offset')) is not int
                        or row['offset'] != physical_offset or not 0 <= physical_offset < scanned
                        or type(row.get('priority')) is not int or row['priority'] not in (1, 2, 4)
                        or row.get('record_type') not in ('FILE_RECORD', 'DIRECTORY_RECORD', 'EXTENSION_RECORD')
                        or row.get('record_status') not in STATUSES
                        or row.get('encryption') not in ('ENCRYPTION_DEFAULT', 'ENCRYPTED_METADATA', 'HINT_ONLY')
                        or not isinstance(row.get('display_name'), str)):
                    raise ValueError('INVALID_RAW_EFS_RECORD')
                rows.append(row)
                continue
            if (not isinstance(row, dict) or row.get('offset') != physical_offset
                    or type(row.get('priority')) is not int or not 0 <= row['priority'] <= 4
                    or row.get('record_type') not in ('LOCAL_HEADER', 'CENTRAL_HEADER', 'END_DIRECTORY')
                    or row.get('encryption') not in ('ENCRYPTED', 'UNKNOWN', 'NO_ENCRYPTION_INDICATOR')
                    or not isinstance(row.get('member_name', ''), str)):
                raise ValueError('INVALID_RAW_ZIP_RECORD')
            hints = row.get('zip_name_hints', [])
            if (not isinstance(hints, list) or len(hints) > 50 or any(
                    not isinstance(hint, dict) or not isinstance(hint.get('name'), str) for hint in hints)):
                raise ValueError('INVALID_RAW_ZIP_RECORD')
            rows.append(row)
        return RawZipPage(source['path'], scanned, total, tuple(rows), offset,
                          len(records) > PAGE_SIZE)


def read_raw_efs_page(database, *, priority_only=False, offset=0):
    return read_raw_zip_page(database, priority_only=priority_only, offset=offset, _efs=True)
