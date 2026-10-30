"""Restartable physical ZIP-header inventory; no extraction or wallet validation.

Every offset is a byte offset in the input image. A local/central header is a
record candidate, not a recovered archive. EOCD associations assume contiguous
classic ZIP layout and remain hypotheses even when the first local header fits.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import struct
import tempfile

from .archive_name_hints import name_hint
from .container_inventory import BoundedReader, InventoryLimit, _zip_directory

FORMAT = 'BFRS_RAW_ZIP_INVENTORY_V1'
CHUNK_BYTES = 8 * 1024 * 1024
MAX_CHUNK_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_CANDIDATES = 1_000_000
SIGNATURES = re.compile(rb'PK(?:\x03\x04|\x01\x02|\x05\x06)')
METHODS = {0, 8, 9, 12, 14, 93, 98, 99}
SAMPLE_BYTES = 64 * 1024
PRIORITIES = ('OTHER_METADATA', 'BACKUP_NAME', 'PASSWORD_MARKER',
              'WALLET_NAME', 'WALLET_NAME_AND_PASSWORD_MARKER')


class SourceChanged(OSError):
    pass


def _stat_key(info):
    return [info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_dev, info.st_ino]


def _ordinary(info, *, directory=False):
    return ((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and not getattr(info, 'st_file_attributes', 0) & 0x400)


def _check_source(stream, path, expected):
    opened, current = os.fstat(stream.fileno()), path.lstat()
    if (not _ordinary(opened) or not _ordinary(current)
            or _stat_key(opened) != expected or _stat_key(current) != expected):
        raise SourceChanged('SOURCE_CHANGED_DURING_SCAN')


def _identity(stream, path, info, io_counts=None):
    key = _stat_key(info)
    digest = hashlib.sha256(b'BFRS-RAW-ZIP-SAMPLED-IDENTITY-V1\0')
    size = info.st_size
    offsets = sorted({0, max(0, size // 2 - SAMPLE_BYTES // 2), max(0, size - SAMPLE_BYTES)})
    for offset in offsets:
        stream.seek(offset)
        count = min(SAMPLE_BYTES, size - offset)
        data = stream.read(count)
        if io_counts is not None:
            io_counts['identity_read_bytes'] += len(data)
        if len(data) != count:
            raise OSError('SHORT_SOURCE_IDENTITY_READ')
        digest.update(struct.pack('<QQ', offset, count))
        digest.update(data)
    _check_source(stream, path, key)
    return {'path': str(path), 'stat': key, 'sample_sha256': digest.hexdigest(),
            'identity_scope': 'STAT_AND_THREE_SAMPLES_NOT_FULL_CONTENT_HASH'}


class _ImageView:
    """Reuse the current scan block for metadata; count extra physical I/O."""
    def __init__(self, stream, size, cache_start, cache, io_counts):
        self.stream, self.size = stream, size
        self.cache_start, self.cache = cache_start, cache
        self.io_counts = io_counts
        self.position = 0

    def tell(self):
        return self.position

    def seek(self, offset):
        self.position = offset
        return offset

    def read(self, count):
        index = self.position - self.cache_start
        if 0 <= index and index + count <= len(self.cache):
            data = self.cache[index:index + count]
        else:
            self.stream.seek(self.position)
            data = self.stream.read(count)
            self.io_counts['metadata_read_bytes'] += len(data)
            if len(data) != count:
                raise OSError('SHORT_IMAGE_METADATA_READ')
        self.position += len(data)
        return data


class _RelativeReader:
    """Archive-relative metadata view sharing one candidate's read budget."""
    def __init__(self, reader, base, size):
        self.reader, self.base, self.size = reader, base, size

    @property
    def bytes_read(self):
        return self.reader.bytes_read

    def at(self, offset, count):
        if offset < 0 or count < 0 or offset + count > self.size:
            raise ValueError('TRUNCATED_METADATA')
        return self.reader.at(self.base + offset, count)


def _extra_ids(extra):
    position = 0
    ids = set()
    while position < len(extra):
        if position + 4 > len(extra):
            raise ValueError('ZIP_INVALID_EXTRA_FIELD')
        kind, length = struct.unpack_from('<HH', extra, position)
        position += 4 + length
        if position > len(extra):
            raise ValueError('ZIP_INVALID_EXTRA_FIELD')
        ids.add(kind)
    return ids


def _member(reader, offset, central):
    fixed = 46 if central else 30
    header = reader.at(offset, fixed)
    expected = b'PK\x01\x02' if central else b'PK\x03\x04'
    if header[:4] != expected:
        raise ValueError('ZIP_HEADER_SIGNATURE_MISMATCH')
    version, flags, method = struct.unpack_from('<3H', header, 6 if central else 4)
    crc, packed, unpacked = struct.unpack_from('<3L', header, 16 if central else 14)
    name_size, extra_size = struct.unpack_from('<2H', header, 28 if central else 26)
    if not 10 <= version <= 63 or method not in METHODS or flags & ~0x287f or not name_size:
        raise ValueError('ZIP_IMPLAUSIBLE_HEADER')
    comment_size = struct.unpack_from('<H', header, 32)[0] if central else 0
    end = offset + fixed + name_size + extra_size + comment_size
    if end > reader.size:
        raise ValueError('ZIP_TRUNCATED_VARIABLE_HEADER')
    variable = reader.at(offset + fixed, name_size + extra_size)
    raw_name = variable[:name_size]
    if b'\0' in raw_name:
        raise ValueError('ZIP_INVALID_NAME')
    name = raw_name.decode('utf-8' if flags & 2048 else 'cp437', 'strict')
    extra_ids = _extra_ids(variable[name_size:])
    disk, local_offset = (struct.unpack_from('<H', header, 34)[0],
                          struct.unpack_from('<L', header, 42)[0]) if central else (0, None)
    zip64 = 1 in extra_ids or 0xffffffff in (packed, unpacked, local_offset) or disk == 65535
    supported = not (zip64 or disk or flags & ~0x080f or method not in (0, 8))
    if supported and flags & 1 and not flags & 8 and packed < 12:
        raise ValueError('ZIP_INVALID_ENCRYPTED_SIZE')
    row = {'record_type': 'CENTRAL_HEADER' if central else 'LOCAL_HEADER',
           'record_status': 'HEADER_ONLY' if supported else 'UNSUPPORTED_LAYOUT',
           'encryption': ('ENCRYPTED' if flags & 1 else 'NO_ENCRYPTION_INDICATOR') if supported else 'UNKNOWN',
           'flags': flags, 'method': method, 'crc32': crc,
           'declared_compressed_size': packed, 'declared_uncompressed_size': unpacked,
           'member_name': name[:512], 'member_name_truncated': len(name) > 512,
           'name_hint': name_hint(name), 'header_end_offset': end,
           'zip64_marker': zip64, 'disk_start': disk,
           'encryption_scope': 'THIS_HEADER_ONLY_NOT_ARCHIVE_OR_PAYLOAD'}
    if central:
        row['declared_local_header_offset'] = local_offset
    else:
        row['data_offset'] = end
        row['declared_data_end_offset'] = end + packed if supported and not flags & 8 else None
        row['declared_data_fits_image'] = end + packed <= reader.size if supported and not flags & 8 else None
    # Full raw name is returned only for corroborating header pairs; not retained.
    return row, raw_name


def _end_directory(reader, offset):
    header = reader.at(offset, 22)
    disk, cd_disk, disk_count, count, size, relative, comment = struct.unpack_from('<4H2LH', header, 4)
    end = offset + 22 + comment
    if end > reader.size:
        raise ValueError('ZIP_TRUNCATED_END_COMMENT')
    row = {'record_type': 'END_DIRECTORY', 'record_status': 'END_RECORD_ONLY',
           'encryption': 'UNKNOWN', 'declared_members': count,
           'declared_directory_size': size, 'archive_end_candidate': end,
           'archive_origin_status': 'NOT_ESTABLISHED'}
    if disk or cd_disk or disk_count != count or count == 65535 or 0xffffffff in (size, relative):
        row.update(record_status='UNSUPPORTED_LAYOUT', reason='ZIP64_OR_MULTIVOLUME_UNSUPPORTED')
        return row
    base = offset - size - relative
    if base < 0 or count * 46 > size or (not count and size):
        raise ValueError('ZIP_IMPLAUSIBLE_END_RECORD')
    row['archive_start_candidate'] = base
    metadata = {'format': 'ZIP', 'encryption': 'UNKNOWN'}
    try:
        _zip_directory(_RelativeReader(reader, base, end - base), metadata)
    except (InventoryLimit, ValueError, struct.error) as error:
        row.update(reason=str(error), record_status='DIRECTORY_UNRESOLVED')
        # Keep observed filename clues, but never promote incomplete encryption counts.
        row.update({key: value for key, value in metadata.items() if key.startswith('zip_name')
                    or key in ('zip_wallet_name_hint_count', 'zip_encrypted_wallet_name_hint_count')})
    else:
        row.update(metadata)
        row['record_status'] = 'CENTRAL_DIRECTORY_CHECKED'
        row['encryption_scope'] = 'CENTRAL_DIRECTORY_ONLY_NOT_PAYLOAD_INTEGRITY'
        if count:
            try:
                first, cd_name = _member(reader, offset - size, True)
                local_pos = base + first['declared_local_header_offset']
                if not base <= local_pos < offset - size:
                    raise ValueError('ZIP_LOCAL_REFERENCE_OUTSIDE_MEMBER_AREA')
                local, local_name = _member(reader, local_pos, False)
                match = (cd_name == local_name and first['flags'] == local['flags']
                         and first['method'] == local['method'])
                if not local['flags'] & 8:
                    match &= all(first[key] == local[key] for key in (
                        'crc32', 'declared_compressed_size', 'declared_uncompressed_size'))
                row['archive_origin_status'] = 'FIRST_LOCAL_HEADER_MATCHED' if match else 'FIRST_LOCAL_HEADER_MISMATCH'
                row['first_local_header_offset'] = local_pos
            except (InventoryLimit, ValueError, struct.error) as error:
                row['archive_origin_status'] = 'FIRST_LOCAL_HEADER_UNRESOLVED'
                row['local_reference_reason'] = str(error)
    # Directory parser offsets are archive-relative; image reports use physical bytes.
    for hint in row.get('zip_name_hints', []):
        hint['header_offset'] += base
    return row


def _priority(row):
    hint = row.get('name_hint')
    wallet = ((hint or {}).get('category') == 'WALLET_NAME'
              or row.get('zip_wallet_name_hint_count', 0) > 0)
    backup = bool(hint or row.get('zip_name_hint_count', 0))
    encrypted = row.get('encryption') == 'ENCRYPTED'
    if wallet:
        same_member = ((hint or {}).get('category') == 'WALLET_NAME'
                       or row.get('zip_encrypted_wallet_name_hint_count', 0) > 0)
        return 4 if encrypted and same_member else 3
    if encrypted:
        return 2
    return 1 if backup else 0


def inspect_record(reader, offset, signature):
    """Reject implausible signatures; preserve structurally bounded candidates."""
    try:
        if signature == b'PK\x05\x06':
            row = _end_directory(reader, offset)
        else:
            row, _ = _member(reader, offset, signature == b'PK\x01\x02')
    except InventoryLimit as error:
        row = {'record_type': 'END_DIRECTORY' if signature == b'PK\x05\x06' else
               'CENTRAL_HEADER' if signature == b'PK\x01\x02' else 'LOCAL_HEADER',
               'record_status': 'METADATA_LIMIT', 'encryption': 'UNKNOWN', 'reason': str(error)}
    except (ValueError, struct.error):
        return None
    priority = _priority(row)
    row.update(offset=offset, offset_hex=hex(offset), priority=priority,
               priority_label=PRIORITIES[priority],
               scope='PHYSICAL_METADATA_CANDIDATE_NOT_RECOVERED_WALLET')
    return row


@contextmanager
def _lock(output):
    path = output / '.zip_scan.lock'
    if path.is_symlink() or (path.exists() and not _ordinary(path.lstat())):
        raise ValueError('INVALID_LOCK_PATH')
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'r+b', buffering=0) as handle:
        if os.fstat(handle.fileno()).st_size == 0:
            handle.write(b'0')
        handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise ValueError('SCAN_ALREADY_RUNNING_FOR_THIS_REPORT') from error
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _put(connection, key, value):
    connection.execute('INSERT OR REPLACE INTO metadata VALUES (?,?)', (key, json.dumps(value)))


@contextmanager
def _atomic_text(output, filename):
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=output, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException:
            handle.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, output / filename)
    finally:
        temporary.unlink(missing_ok=True)


def _export(connection, output, identity, reason, io_counts, source_unchanged):
    metadata = {key: json.loads(value) for key, value in connection.execute('SELECT key,value FROM metadata')}
    next_offset = metadata['next_offset']
    counts = dict(connection.execute('SELECT record_type,count(*) FROM hits GROUP BY record_type'))
    unresolved = connection.execute("SELECT count(*) FROM hits WHERE status IN "
        "('UNSUPPORTED_LAYOUT','DIRECTORY_UNRESOLVED','END_RECORD_ONLY','METADATA_LIMIT')").fetchone()[0]
    for filename, condition in [('zip_hits.jsonl', ''), ('zip_priority.jsonl', 'WHERE priority>0')]:
        with _atomic_text(output, filename) as stream:
            for (payload,) in connection.execute(
                    f'SELECT result FROM hits {condition} ORDER BY priority DESC,offset'):
                stream.write(payload + '\n')
    summary = {'format': FORMAT, 'source': identity,
               'scan_complete': next_offset == identity['stat'][0] and source_unchanged and reason == 'COMPLETE',
               'source_unchanged': source_unchanged, 'stop_reason': reason,
               'scanned_prefix_end': next_offset, 'source_size': identity['stat'][0],
               'signature_counts': metadata['counters'], 'record_counts': counts,
               'unresolved_record_count': unresolved,
               'priority_record_count': connection.execute('SELECT count(*) FROM hits WHERE priority>0').fetchone()[0],
               'io_this_run': io_counts,
               'count_scope': 'HEADER_RECORDS_NOT_UNIQUE_ARCHIVES',
               'limitations': ['NO_EXTRACTION_OR_PASSWORD_ATTEMPTS', 'NO_PAYLOAD_INTEGRITY_VALIDATION',
                   'NO_FILESYSTEM_ALLOCATION_OR_DELETION_STATUS', 'NO_FRAGMENTED_ARCHIVE_REASSEMBLY',
                   'NAMES_ARE_HINTS_NOT_WALLET_CONFIRMATION', 'CONTIGUOUS_CLASSIC_ZIP_ASSOCIATIONS_ONLY',
                   'FULL_BYTE_COVERAGE_DOES_NOT_MEAN_ALL_METADATA_SUPPORTED',
                   'RAW_FILE_BYTES_NO_IMAGE_CONTAINER_DECODING',
                   'SOURCE_IDENTITY_SAMPLED_NOT_FULL_HASH']}
    with _atomic_text(output, 'summary.json') as stream:
        json.dump(summary, stream, ensure_ascii=False, indent=2)
    return summary


def scan_image(source, output, *, resume=False, chunk_size=CHUNK_BYTES,
               max_candidates=DEFAULT_MAX_CANDIDATES, should_stop=None, progress=None):
    """Commit each scanned prefix and its hits atomically; stop rather than skip."""
    if not isinstance(chunk_size, int) or not 4 <= chunk_size <= MAX_CHUNK_BYTES:
        raise ValueError('INVALID_CHUNK_SIZE')
    if not isinstance(max_candidates, int) or max_candidates < 1:
        raise ValueError('INVALID_CANDIDATE_LIMIT')
    source, output = Path(source).absolute(), Path(output).absolute()
    if not _ordinary(source.lstat()):
        raise ValueError('SOURCE_MUST_BE_REGULAR_FILE_WITHOUT_REPARSE_POINT')
    if output.is_symlink() or (output.exists() and not _ordinary(output.lstat(), directory=True)):
        raise ValueError('OUTPUT_MUST_BE_ORDINARY_DIRECTORY')
    source, output = source.resolve(), output.resolve()
    if source == output or source.is_relative_to(output):
        raise ValueError('OUTPUT_MUST_NOT_CONTAIN_SOURCE')
    if not resume and output.exists():
        raise ValueError('OUTPUT_EXISTS_USE_RESUME_OR_NEW_DIRECTORY')
    database = output / 'zip_scan.sqlite'
    if resume and (not database.exists() or not _ordinary(database.lstat())):
        raise ValueError('NO_REGULAR_ZIP_CHECKPOINT')
    descriptor = os.open(source, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb', buffering=0) as stream:
        info = os.fstat(stream.fileno())
        io_counts = {'linear_read_bytes': 0, 'metadata_read_bytes': 0, 'identity_read_bytes': 0}
        identity = _identity(stream, source, info, io_counts)
        output.mkdir(parents=True, exist_ok=True)
        with _lock(output), sqlite3.connect(database) as connection:
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.execute('PRAGMA synchronous=FULL')
            if resume:
                metadata = {key: json.loads(value) for key, value in connection.execute('SELECT key,value FROM metadata')}
                if metadata.get('format') != FORMAT or metadata.get('source') != identity:
                    raise ValueError('CHECKPOINT_SOURCE_OR_VERSION_MISMATCH')
                cursor = metadata['next_offset']
                counters = metadata['counters']
                if (type(cursor) is not int or not 0 <= cursor <= info.st_size or not isinstance(counters, dict)
                        or any(type(counters.get(key)) is not int or counters[key] < 0
                               for key in ('signatures_seen', 'rejected_signatures'))):
                    raise ValueError('INVALID_CHECKPOINT_PROGRESS')
                count, last_offset = connection.execute('SELECT count(*),max(offset) FROM hits').fetchone()
                if ((last_offset is not None and last_offset >= cursor)
                        or count + counters['rejected_signatures'] != counters['signatures_seen']):
                    raise ValueError('CHECKPOINT_HITS_AND_PROGRESS_MISMATCH')
            else:
                connection.execute('CREATE TABLE metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL)')
                connection.execute('CREATE TABLE hits (offset INTEGER PRIMARY KEY,record_type TEXT NOT NULL,'
                                   'priority INTEGER NOT NULL,status TEXT NOT NULL,result TEXT NOT NULL)')
                connection.execute('CREATE INDEX hits_priority ON hits(priority DESC,offset)')
                cursor, counters = 0, {'signatures_seen': 0, 'rejected_signatures': 0}
                for key, value in [('format', FORMAT), ('source', identity), ('next_offset', cursor), ('counters', counters)]:
                    _put(connection, key, value)
                connection.commit()
            seen_this_run = 0
            reason, unchanged = 'COMPLETE', True
            try:
                while cursor < info.st_size:
                    if should_stop and should_stop():
                        reason = 'STOP_REQUESTED'
                        break
                    _check_source(stream, source, identity['stat'])
                    owned_end = min(cursor + chunk_size, info.st_size)
                    read_end = min(owned_end + 3, info.st_size)
                    stream.seek(cursor)
                    data = stream.read(read_end - cursor)
                    io_counts['linear_read_bytes'] += len(data)
                    if len(data) != read_end - cursor:
                        raise OSError('SHORT_IMAGE_SCAN_READ')
                    view = _ImageView(stream, info.st_size, cursor, data, io_counts)
                    next_offset = owned_end
                    new_counters = dict(counters)
                    connection.execute('BEGIN IMMEDIATE')
                    for match in SIGNATURES.finditer(data):
                        offset = cursor + match.start()
                        if offset >= owned_end:
                            break
                        if seen_this_run >= max_candidates or (should_stop and should_stop()):
                            next_offset = offset
                            reason = 'CANDIDATE_LIMIT' if seen_this_run >= max_candidates else 'STOP_REQUESTED'
                            break
                        seen_this_run += 1
                        new_counters['signatures_seen'] += 1
                        reader = BoundedReader(view, info.st_size)
                        row = inspect_record(reader, offset, match.group())
                        if row is None:
                            new_counters['rejected_signatures'] += 1
                        else:
                            connection.execute('INSERT OR REPLACE INTO hits VALUES (?,?,?,?,?)',
                                (offset, row['record_type'], row['priority'], row['record_status'], json.dumps(row, ensure_ascii=False)))
                    _check_source(stream, source, identity['stat'])
                    _put(connection, 'next_offset', next_offset)
                    _put(connection, 'counters', new_counters)
                    connection.commit()
                    cursor, counters = next_offset, new_counters
                    if progress:
                        progress({'scanned_bytes': cursor, 'total_bytes': info.st_size,
                                  **counters, **io_counts})
                    if reason != 'COMPLETE':
                        break
                if _identity(stream, source, info, io_counts) != identity:
                    raise SourceChanged('SOURCE_SAMPLES_CHANGED_DURING_SCAN')
            except KeyboardInterrupt:
                connection.rollback()
                reason = 'INTERRUPTED'
            except OSError as error:
                connection.rollback()
                reason = str(error)[:160]
                unchanged = False
            return _export(connection, output, identity, reason, io_counts, unchanged)
