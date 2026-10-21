"""Fast, restartable metadata inventory of recovered documents and archives."""
from __future__ import annotations
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from bfrs.recovery.container_inventory import VERSION, inspect_file

EXTENSIONS = {'.zip', '.rar', '.7z', '.doc', '.docx', '.xls', '.xlsx', '.rtf', '.pdf', '.ppt', '.pptx'}


def _link(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def walk(root, depth=0):
    """Streaming traversal: no full directory tree or file list in memory."""
    if depth >= 128:
        yield root, None, 'DIRECTORY_DEPTH_LIMIT'
        return
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                path = Path(entry.path)
                try:
                    info = entry.stat(follow_symlinks=False)
                    if _link(info):
                        yield path, info, 'LINK_OR_REPARSE_POINT_SKIPPED'
                    elif stat.S_ISDIR(info.st_mode):
                        yield from walk(path, depth+1)
                    elif stat.S_ISREG(info.st_mode):
                        yield path, info, None
                    else:
                        yield path, info, 'NOT_REGULAR_FILE'
                except OSError as error:
                    yield path, None, type(error).__name__
    except OSError as error:
        yield root, None, type(error).__name__


def export_reports(connection, output, run_id, complete, counters):
    counts = Counter()
    report = output / 'inventory.jsonl'
    temporary = output / 'inventory.jsonl.tmp'
    with temporary.open('w', encoding='utf-8') as stream:
        for (payload,) in connection.execute('SELECT result FROM files WHERE run_id=? AND result IS NOT NULL ORDER BY path', (run_id,)):
            row = json.loads(payload)
            counts[row['encryption']] += 1
            stream.write(json.dumps(row, ensure_ascii=False) + '\n')
    os.replace(temporary, report)
    summary = {'version': VERSION, 'complete': complete, 'encryption_counts': dict(counts),
               'run': counters, 'scope': 'FILE_START_SIGNATURES_AND_BOUNDED_METADATA',
               'limitations': ['NO_EXTRACTION_OR_PASSWORD_ATTEMPTS', 'NO_PAYLOAD_INTEGRITY_TEST',
                              'PDF_AND_7Z_ENCRYPTION_MAY_REMAIN_UNKNOWN', 'NO_SFX_OR_EMBEDDED_SIGNATURE_SEARCH',
                              'RESUME_USES_SIZE_MTIME_AND_FILE_ID_NOT_CONTENT_HASH']}
    temporary = output / 'summary.json.tmp'
    temporary.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
    os.replace(temporary, output / 'summary.json')
    return summary


def inventory(source, output, *, resume=False, progress=None, should_stop=None):
    source, output = Path(source).absolute(), Path(output).absolute()
    if _link(source.lstat()) or not source.is_dir():
        raise ValueError('Zrodlo musi byc zwyklym folderem, bez dowiazania/junction.')
    source, output = source.resolve(), output.resolve()
    if output == source or output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError('Folder wynikow musi znajdowac sie poza folderem zrodlowym.')
    database = output / 'inventory.sqlite'
    if resume and not database.is_file():
        raise ValueError('Brak checkpointu inventory.sqlite.')
    if not resume and output.exists():
        raise ValueError('Wybierz nowy folder wynikow albo uzyj --resume.')
    output.mkdir(parents=True, exist_ok=True)
    counters = {'visited': 0, 'inspected': 0, 'reused': 0, 'bytes_read': 0, 'errors_or_skips': 0}
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)')
        connection.execute('CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, identity TEXT, result TEXT, run_id INTEGER)')
        metadata = dict(connection.execute('SELECT key,value FROM metadata'))
        if resume:
            if metadata.get('source') != str(source) or metadata.get('version') != str(VERSION):
                raise ValueError('Checkpoint dotyczy innego zrodla lub wersji skanera.')
        run_id = int(metadata.get('run_id', '0')) + 1
        for key, value in {'source': str(source), 'version': str(VERSION), 'run_id': str(run_id)}.items():
            connection.execute('INSERT OR REPLACE INTO metadata VALUES (?,?)', (key, value))
        connection.commit()
        complete = False
        try:
            for path, info, error in walk(source):
                if should_stop and should_stop():
                    break
                relative = str(path.relative_to(source))
                identity = json.dumps([info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino]) if info else None
                counters['visited'] += 1
                previous = connection.execute('SELECT identity FROM files WHERE path=?', (relative,)).fetchone()
                if not error and previous and previous[0] == identity:
                    connection.execute('UPDATE files SET run_id=? WHERE path=?', (run_id, relative))
                    counters['reused'] += 1
                else:
                    if not error:
                        try:
                            # Recheck reparse/link state immediately before opening.
                            if _link(path.lstat()):
                                error = 'LINK_OR_REPARSE_POINT_SKIPPED'
                            else:
                                row = inspect_file(path)
                                counters['inspected'] += 1
                                counters['bytes_read'] += row['bytes_read']
                        except OSError as exception:
                            error = type(exception).__name__
                    if error:
                        counters['errors_or_skips'] += 1
                        row = {'format': None, 'encryption': 'UNKNOWN', 'structure': 'SKIPPED', 'reason': error}
                    candidate = bool(error or row['format'] or path.suffix.lower() in EXTENSIONS)
                    payload = json.dumps({'path': relative, 'size': info.st_size if info else None, **row}, ensure_ascii=False) if candidate else None
                    # Failed reads are retried on resume; do not cache them as complete.
                    cache_identity = identity if (not error and row.get('structure') != 'SOURCE_CHANGED'
                        and not (row.get('format') and row.get('encryption') == 'UNKNOWN')) else None
                    connection.execute('INSERT OR REPLACE INTO files VALUES (?,?,?,?)',
                                       (relative, cache_identity, payload, run_id))
                if counters['visited'] % 100 == 0:
                    connection.commit()
                if progress:
                    progress(counters)
            else:
                complete = True
        except KeyboardInterrupt:
            pass
        finally:
            connection.commit()
        return export_reports(connection, output, run_id, complete, counters)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Szybki przeglad dokumentow i archiwow bez skanowania portfeli.')
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args(argv)
    last = 0
    def progress(counts):
        nonlocal last
        now = time.monotonic()
        if now-last >= 2:
            print(f"Pliki: {counts['visited']} | odczytano: {counts['inspected']} | wznowiono: {counts['reused']} | odczyt MiB: {counts['bytes_read']/1048576:.1f}", flush=True)
            last = now
    try:
        result = inventory(args.source, args.output, resume=args.resume, progress=progress)
    except (OSError, ValueError, sqlite3.Error) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"Raport: {args.output / 'inventory.jsonl'}")
    return 0 if result['complete'] else 130


if __name__ == '__main__':
    raise SystemExit(main())
