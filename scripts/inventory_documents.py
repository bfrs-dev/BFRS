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
from bfrs.recovery.container_inventory import VERSION, OLE_INVENTORY_REVISION, inspect_file

EXTENSIONS = {'.zip', '.rar', '.7z', '.doc', '.docx', '.xls', '.xlsx', '.rtf', '.pdf', '.ppt', '.pptx'}
FILE_ATTRIBUTE_ENCRYPTED = 0x4000


def _link(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def _efs(info):
    return bool(info and not _link(info)
                and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                and getattr(info, 'st_file_attributes', 0) & FILE_ATTRIBUTE_ENCRYPTED)


def _identity(info):
    if info is None:
        return None
    values = [info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino]
    # Keep old ordinary-file checkpoints reusable. Adding/removing EFS must
    # invalidate a cached result even when size, mtime and file ID are unchanged.
    if _efs(info):
        values += ['EFS_ATTRIBUTE_V1', 'directory' if stat.S_ISDIR(info.st_mode) else 'file']
    return json.dumps(values)


def _efs_result(info):
    directory = stat.S_ISDIR(info.st_mode)
    return {'format': 'WINDOWS_EFS', 'encryption': 'ENCRYPTED',
            'entry_kind': 'directory' if directory else 'file',
            'structure': 'FILESYSTEM_ATTRIBUTE_ONLY',
            'reason': 'WINDOWS_EFS_DIRECTORY_DEFAULT' if directory else 'WINDOWS_EFS_FILE_ATTRIBUTE',
            'filesystem_encryption': 'EFS', 'bytes_read': 0,
            'content_inspection': 'NOT_PERFORMED'}


def walk(root, depth=0, root_info=None):
    """Streaming traversal: no full directory tree or file list in memory."""
    if root_info is None:
        try:
            root_info = root.lstat()
        except OSError as error:
            yield root, None, type(error).__name__
            return
    if _link(root_info):
        yield root, root_info, 'LINK_OR_REPARSE_POINT_SKIPPED'
        return
    if depth >= 128:
        yield root, root_info, 'DIRECTORY_DEPTH_LIMIT'
        return
    directory_error = None
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                path = Path(entry.path)
                try:
                    info = entry.stat(follow_symlinks=False)
                    if _link(info):
                        yield path, info, 'LINK_OR_REPARSE_POINT_SKIPPED'
                    elif stat.S_ISDIR(info.st_mode):
                        yield from walk(path, depth+1, info)
                    elif stat.S_ISREG(info.st_mode):
                        yield path, info, None
                    else:
                        yield path, info, 'NOT_REGULAR_FILE'
                except OSError as error:
                    yield path, None, type(error).__name__
    except OSError as error:
        directory_error = type(error).__name__
    # Emit once, including empty folders and the scan root. Retain a positive
    # attribute observation even if directory enumeration was denied.
    if _efs(root_info) or directory_error:
        yield root, root_info, directory_error


def export_reports(connection, output, run_id, complete, counters, filesystem_check):
    counts = Counter()
    efs_counts = {'files': 0, 'directories': 0}
    report = output / 'inventory.jsonl'
    temporary = output / 'inventory.jsonl.tmp'
    with temporary.open('w', encoding='utf-8') as stream:
        for (payload,) in connection.execute('SELECT result FROM files WHERE run_id=? AND result IS NOT NULL ORDER BY path', (run_id,)):
            row = json.loads(payload)
            counts[row['encryption']] += 1
            if row.get('filesystem_encryption') == 'EFS':
                efs_counts['directories' if row.get('entry_kind') == 'directory' else 'files'] += 1
            stream.write(json.dumps(row, ensure_ascii=False) + '\n')
    os.replace(temporary, report)
    summary = {'version': VERSION, 'complete': complete, 'encryption_counts': dict(counts),
               'efs_counts': efs_counts, 'filesystem_encryption_check': filesystem_check,
               'run': counters, 'scope': 'FILE_START_SIGNATURES_BOUNDED_METADATA_AND_EFS_ATTRIBUTES',
               'limitations': ['NO_EXTRACTION_OR_PASSWORD_ATTEMPTS', 'NO_PAYLOAD_INTEGRITY_TEST',
                              'EFS_CURRENT_ATTRIBUTES_ONLY_NOT_HISTORICAL_ENCRYPTION',
                              'EFS_DIRECTORY_FLAG_DOES_NOT_PROVE_ALL_CHILDREN_ENCRYPTED',
                              'EFS_CONTENT_NOT_READ_OR_DECRYPTED',
                              '7Z_ENCRYPTION_MAY_REMAIN_UNKNOWN',
                              '7Z_BOUNDED_HEADER_DECODING_NO_MEMBER_EXTRACTION',
                              'PDF_METADATA_ONLY_NO_PASSWORD_OR_PAYLOAD_CHECK',
                              'NO_SFX_OR_EMBEDDED_SIGNATURE_SEARCH',
                              'RESUME_USES_SIZE_MTIME_AND_FILE_ID_NOT_CONTENT_HASH']}
    temporary = output / 'summary.json.tmp'
    temporary.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
    os.replace(temporary, output / 'summary.json')
    return summary


def inventory(source, output, *, resume=False, progress=None, should_stop=None):
    source, output = Path(source).absolute(), Path(output).absolute()
    source_info = source.lstat()
    if _link(source_info) or not stat.S_ISDIR(source_info.st_mode):
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
    filesystem_check = ('WINDOWS_FILE_ATTRIBUTES' if hasattr(source_info, 'st_file_attributes')
                        else 'UNAVAILABLE_ON_THIS_PLATFORM')
    counters = {'visited': 0, 'inspected': 0, 'reused': 0, 'bytes_read': 0,
                'errors_or_skips': 0, 'metadata_only': 0, 'reported_directories': 0}
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)')
        connection.execute('CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, identity TEXT, result TEXT, run_id INTEGER)')
        metadata = dict(connection.execute('SELECT key,value FROM metadata'))
        if resume:
            if metadata.get('source') != str(source) or metadata.get('version') != str(VERSION):
                raise ValueError('Checkpoint dotyczy innego zrodla lub wersji skanera.')
        columns = {row[1] for row in connection.execute('PRAGMA table_info(files)')}
        if 'inspection_revision' not in columns:
            connection.execute('ALTER TABLE files ADD COLUMN inspection_revision INTEGER NOT NULL DEFAULT 0')
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
                identity = _identity(info)
                counters['visited'] += 1
                counters['reported_directories'] += bool(info and stat.S_ISDIR(info.st_mode))
                previous = connection.execute('SELECT identity,inspection_revision FROM files WHERE path=?', (relative,)).fetchone()
                if (not error and previous and previous[0] == identity
                        and previous[1] in (0, OLE_INVENTORY_REVISION)):
                    connection.execute('UPDATE files SET run_id=? WHERE path=?', (run_id, relative))
                    counters['reused'] += 1
                else:
                    row = _efs_result(info) if _efs(info) else None
                    if not error and row is None:
                        try:
                            # Recheck reparse/link state immediately before opening.
                            current_info = path.lstat()
                            if _link(current_info):
                                error = 'LINK_OR_REPARSE_POINT_SKIPPED'
                            elif _efs(current_info):
                                info = current_info
                                identity = _identity(info)
                                row = _efs_result(info)
                            else:
                                row = inspect_file(path)
                                counters['inspected'] += 1
                                counters['bytes_read'] += row['bytes_read']
                        except OSError as exception:
                            error = type(exception).__name__
                    if error:
                        counters['errors_or_skips'] += 1
                        if row is not None and row.get('filesystem_encryption') == 'EFS':
                            row['scan_error'] = error
                        else:
                            row = {'format': None, 'encryption': 'UNKNOWN', 'structure': 'SKIPPED', 'reason': error}
                    if row.get('filesystem_encryption') == 'EFS':
                        counters['metadata_only'] += 1
                    candidate = bool(error or row['format'] or path.suffix.lower() in EXTENSIONS)
                    directory = bool(info and stat.S_ISDIR(info.st_mode))
                    payload = json.dumps({'path': relative,
                        'entry_kind': 'directory' if directory else 'file',
                        'size': info.st_size if info and not directory else None, **row}, ensure_ascii=False) if candidate else None
                    # A checked but unidentified OLE directory can be reused without
                    # implying anything about encryption. Refresh it on parser changes.
                    stable_ole = (row.get('format') == 'OLE'
                        and row.get('encryption') == 'UNKNOWN'
                        and row.get('reason') == 'OLE_TYPE_UNDETERMINED'
                        and row.get('structure') == 'DIRECTORY_CHECKED'
                        and row.get('ole_inventory_revision') == OLE_INVENTORY_REVISION)
                    # Failed/limited reads and other unknown formats are still retried.
                    cache_identity = identity if (not error and row.get('structure') != 'SOURCE_CHANGED'
                        and (stable_ole or not (row.get('format') and row.get('encryption') == 'UNKNOWN'))) else None
                    connection.execute('INSERT OR REPLACE INTO files '
                                       '(path,identity,result,run_id,inspection_revision) VALUES (?,?,?,?,?)',
                                       (relative, cache_identity, payload, run_id,
                                        OLE_INVENTORY_REVISION if stable_ole else 0))
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
        return export_reports(connection, output, run_id, complete, counters, filesystem_check)


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
            print(f"Pozycje: {counts['visited']} | odczytano: {counts['inspected']} | wznowiono: {counts['reused']} | tylko metadane EFS: {counts['metadata_only']} | odczyt MiB: {counts['bytes_read']/1048576:.1f}", flush=True)
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
