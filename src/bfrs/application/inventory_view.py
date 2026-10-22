"""Read-only, paged access to the standalone inventory checkpoint."""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import json
from pathlib import Path, PureWindowsPath
import re
import sqlite3
import stat
import time


PAGE_SIZE = 200
STATES = ('ENCRYPTED', 'UNKNOWN', 'NO_ENCRYPTION_INDICATOR')


@dataclass(frozen=True)
class InventoryPage:
    source: str
    run_id: int
    counts: dict[str, int]
    rows: tuple[dict, ...]
    offset: int
    has_next: bool


def read_inventory_page(database, state='ENCRYPTED', search='', offset=0):
    """Touch only SQLite; no source-file stats, reads or writes during browsing."""
    if state is not None and state not in STATES:
        raise ValueError('Nieznany filtr wyników.')
    if offset < 0 or offset % PAGE_SIZE:
        raise ValueError('Nieprawidłowa strona wyników.')
    database = Path(database).absolute()
    deadline = time.monotonic() + 15
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
        db.create_function('casefold', 1, lambda text: str(text).casefold(), deterministic=True)
        # A short snapshot per page, released before returning to the GUI.
        db.execute('BEGIN')
        metadata = dict(db.execute('SELECT key,value FROM metadata'))
        if metadata.get('version') != '1' or not metadata.get('source'):
            raise ValueError('To nie jest obsługiwany raport inwentaryzacji BFRS.')
        run_id = int(metadata['run_id'])
        where = 'run_id=? AND result IS NOT NULL'
        counts = dict(db.execute(
            f"SELECT json_extract(result,'$.encryption'),count(*) FROM files WHERE {where} "
            "GROUP BY json_extract(result,'$.encryption')", (run_id,)))
        params = [run_id]
        if state:
            where += " AND json_extract(result,'$.encryption')=?"
            params.append(state)
        if search.strip():
            where += ' AND instr(casefold(path),?)>0'
            params.append(search.strip().casefold())
        payloads = db.execute(f'SELECT path,result FROM files WHERE {where} '
                              'ORDER BY path LIMIT ? OFFSET ?',
                              (*params, PAGE_SIZE+1, offset)).fetchall()
        rows = []
        for path, payload in payloads[:PAGE_SIZE]:
            row = json.loads(payload)
            if not isinstance(row, dict) or row.get('path') != path or row.get('encryption') not in STATES:
                raise ValueError('Nieprawidłowy wpis w raporcie inwentaryzacji.')
            rows.append(row)
        return InventoryPage(metadata['source'], run_id, counts, tuple(rows),
                             offset, len(payloads) > PAGE_SIZE)


def source_path(source, relative):
    """Resolve relative report names lexically, without accessing the source."""
    source = Path(source)
    if not source.is_absolute():
        raise ValueError('Wskaż folder źródłowy na tym komputerze.')
    name = PureWindowsPath(relative)
    parts = re.split(r'[\\/]', relative)
    if (not relative or name.drive or name.root or any(
            part in ('', '.', '..') or ':' in part or part.endswith((' ', '.'))
            or any(ord(char) < 32 for char in part) for part in parts)):
        raise ValueError('Nieprawidłowa ścieżka względna w raporcie.')
    return source.joinpath(*parts)


def checked_source_path(source, relative):
    """Before revealing, reject missing files and links/reparse points."""
    target = source_path(source, relative)
    source = Path(source)
    # Inspect every ancestor too: a remapped root may itself sit below a link.
    components = list(reversed(source.parents)) + [source]
    current = source
    for part in target.relative_to(source).parts:
        current = current / part
        components.append(current)
    for path in components:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Ta lokalizacja zawiera dowiązanie lub punkt ponownej analizy.')
        if path != target and not stat.S_ISDIR(info.st_mode):
            raise ValueError('Folder źródłowy jest niedostępny.')
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Wybrana pozycja nie jest zwykłym plikiem.')
    return target
