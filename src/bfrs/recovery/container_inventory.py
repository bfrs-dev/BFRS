"""Metadata-only, bounded document/archive identification; no extraction/passwords."""
import os
import re
import struct
import stat
import zlib

from bfrs.recovery.pdf_inventory import PDFMetadataLimit, inspect_pdf
from bfrs.recovery.seven_zip_inventory import SevenZipLimit, inspect_7z
from bfrs.recovery.ole_type_hints import ole_type_hint
from bfrs.recovery.ppt_inventory import PPTMetadataLimit, inspect_ppt

VERSION = 1
# Bump when unknown-OLE inspection changes, so cached metadata is refreshed.
OLE_INVENTORY_REVISION = 1
# Refresh cached ZIP/OOXML classifications after changing directory semantics.
ZIP_INVENTORY_REVISION = 2
MAX_READ_BYTES = 2 * 1024 * 1024
MAX_READ_CALLS = 4096
MAX_MEMBERS = 4096
ZIP_DIRECTORY_BLOCK_BYTES = 64 * 1024
MAX_NAMES = 50
MAX_OLE_METADATA_BYTES = 1024 * 1024
OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'


class InventoryLimit(ValueError):
    pass


class BoundedReader:
    def __init__(self, stream, size):
        self.stream, self.size = stream, size
        self.bytes_read = self.calls = 0

    def read(self, count=-1):
        if count < 0:
            count = self.size - self.tell()
        if count > MAX_READ_BYTES - self.bytes_read or self.calls >= MAX_READ_CALLS:
            raise InventoryLimit('METADATA_READ_LIMIT')
        self.calls += 1
        result = self.stream.read(count)
        self.bytes_read += len(result)
        return result

    def seek(self, offset, whence=0):
        pos = offset if whence == 0 else (self.tell() if whence == 1 else self.size) + offset
        if not 0 <= pos <= self.size:
            raise ValueError('OFFSET_OUT_OF_RANGE')
        return self.stream.seek(pos)

    @property
    def closed(self):
        return self.stream.closed

    def tell(self):
        return self.stream.tell()

    def at(self, offset, count):
        if offset < 0 or count < 0 or offset + count > self.size:
            raise ValueError('TRUNCATED_METADATA')
        self.seek(offset)
        data = self.read(count)
        if len(data) != count:
            raise ValueError('SHORT_READ')
        return data


class _ZipDirectoryReader:
    """Forward-only central-directory window; never buffer the whole directory."""

    def __init__(self, reader, offset, size):
        self.reader, self.offset, self.size = reader, offset, size
        self.position = self.buffer_start = 0
        self.buffer = b''

    def read(self, count):
        if count < 0 or self.position + count > self.size:
            raise ValueError('ZIP_TRUNCATED_DIRECTORY_ENTRY')
        index = self.position - self.buffer_start
        if 0 <= index and index + count <= len(self.buffer):
            self.position += count
            return self.buffer[index:index + count]
        chunks = []
        remaining = count
        while remaining:
            index = self.position - self.buffer_start
            if not 0 <= index < len(self.buffer):
                self.buffer_start = self.position
                self.buffer = self.reader.at(self.offset + self.position,
                    min(ZIP_DIRECTORY_BLOCK_BYTES, self.size - self.position))
                index = 0
            take = min(remaining, len(self.buffer) - index)
            chunks.append(self.buffer[index:index + take])
            self.position += take
            remaining -= take
        return b''.join(chunks)

    def skip(self, count):
        if count < 0 or self.position + count > self.size:
            raise ValueError('ZIP_TRUNCATED_DIRECTORY_ENTRY')
        # Extra fields/comments are not interpreted. Reuse prefetched bytes if
        # the next record is still in the current block; otherwise seek ahead.
        self.position += count


def _zip_local_password_marker(reader, result):
    """Positive-only fallback for classic local headers when the EOCD is lost.

    Follow declared stored/Deflate member boundaries from byte zero. Never
    search payload bytes for signatures or infer a negative from partial data.
    A data descriptor prevents walking further, but not observing this header's
    password flag. Payloads (including encryption headers) are not validated.
    """
    offset = 0
    for index in range(MAX_MEMBERS):
        header = reader.at(offset, 30)
        if header[:4] != b'PK\x03\x04':
            raise ValueError('ZIP_LOCAL_HEADER_MISSING')
        version, flags, method = struct.unpack_from('<3H', header, 4)
        packed, unpacked = struct.unpack_from('<2L', header, 18)
        name_size, extra_size = struct.unpack_from('<2H', header, 26)
        if not 10 <= version <= 63 or method not in (0, 8) or flags & ~0x080f:
            raise InventoryLimit('ZIP_LOCAL_LAYOUT_UNSUPPORTED')
        if packed == 0xffffffff or unpacked == 0xffffffff:
            raise InventoryLimit('ZIP64_UNSUPPORTED')
        metadata = reader.at(offset + 30, name_size + extra_size)
        name = metadata[:name_size]
        if not name or b'\x00' in name:
            raise ValueError('ZIP_INVALID_LOCAL_NAME')
        extra_pos = name_size
        while extra_pos < len(metadata):
            if len(metadata) - extra_pos < 4:
                raise ValueError('ZIP_INVALID_LOCAL_EXTRA')
            kind, size = struct.unpack_from('<2H', metadata, extra_pos)
            extra_pos += 4 + size
            if extra_pos > len(metadata):
                raise ValueError('ZIP_INVALID_LOCAL_EXTRA')
            if kind == 1:
                raise InventoryLimit('ZIP64_UNSUPPORTED')
        result['zip_local_headers_checked'] = index + 1
        if flags & 1:
            if not flags & 8 and packed < 12:
                raise ValueError('ZIP_INVALID_LOCAL_ENCRYPTED_SIZE')
            result.update(encryption='ENCRYPTED', structure='PARTIAL_LOCAL_HEADER_ONLY',
                          reason='ZIP_LOCAL_PASSWORD_FLAG',
                          zip_directory_error='ZIP_END_DIRECTORY_MISSING',
                          zip_local_header_offset=offset,
                          zip_local_member_name=name.decode('utf-8' if flags & 2048 else 'cp437', 'replace')[:512],
                          zip_local_flags=flags)
            return
        if flags & 8:
            raise InventoryLimit('ZIP_LOCAL_DESCRIPTOR_BOUNDARY_UNKNOWN')
        offset += 30 + name_size + extra_size + packed
        if offset >= reader.size:
            raise ValueError('ZIP_LOCAL_CHAIN_ENDED_WITHOUT_PASSWORD_MARKER')
    raise InventoryLimit('ZIP_LOCAL_MEMBER_LIMIT')


def _zip(reader, result):
    try:
        _zip_directory(reader, result)
    except ValueError as error:
        # Retain the existing UNKNOWN policy for inconsistent directories,
        # limits, ZIP64 and split layouts. Only a lost EOCD enables fallback.
        if str(error) != 'ZIP_END_DIRECTORY_MISSING':
            raise
        try:
            _zip_local_password_marker(reader, result)
        except (ValueError, OSError, struct.error) as local_error:
            result['zip_local_scan_reason'] = str(local_error)[:160]
            raise error


def _zip_directory(reader, result):
    length = min(reader.size, 65557)
    tail = reader.at(reader.size - length, length)
    candidate = tail.rfind(b'PK\x05\x06')
    pos = None
    while candidate >= 0:
        if (candidate + 22 <= len(tail)
                and candidate + 22 + struct.unpack_from('<H', tail, candidate+20)[0] == len(tail)):
            if pos is not None:
                raise ValueError('ZIP_AMBIGUOUS_END_DIRECTORY')
            pos = candidate
        candidate = tail.rfind(b'PK\x05\x06', 0, candidate)
    if pos is None:
        raise ValueError('ZIP_END_DIRECTORY_MISSING')
    disk, cd_disk, disk_count, count, size, offset, comment = struct.unpack_from('<4H2LH', tail, pos+4)
    if disk or cd_disk or disk_count != count:
        raise InventoryLimit('ZIP_MULTIVOLUME_UNSUPPORTED')
    if count == 65535 or size == 0xffffffff or offset == 0xffffffff:
        raise InventoryLimit('ZIP64_UNSUPPORTED')
    result.update(zip_declared_members=count, zip_directory_size=size, zip_members_checked=0)
    if offset + size != reader.size - length + pos:
        raise InventoryLimit('ZIP_DIRECTORY_LAYOUT_UNSUPPORTED')
    if count * 46 > size:
        raise ValueError('ZIP_BAD_DIRECTORY_ENTRY')
    # Reject known over-budget directories before reading them. Classic ZIP's
    # 16-bit count bounds work to 65534 entries (65535 is the ZIP64 sentinel).
    if size > MAX_READ_BYTES - reader.bytes_read:
        raise InventoryLimit('METADATA_READ_LIMIT')
    central = _ZipDirectoryReader(reader, offset, size)
    encrypted = 0
    names = []
    markers = set()
    for index in range(count):
        if central.position + 46 > size:
            raise ValueError('ZIP_BAD_DIRECTORY_ENTRY')
        header = central.read(46)
        if header[:4] != b'PK\x01\x02':
            raise ValueError('ZIP_BAD_DIRECTORY_ENTRY')
        flags, method = struct.unpack_from('<HH', header, 8)
        name_size, extra_size, comment_size = struct.unpack_from('<HHH', header, 28)
        disk_start = struct.unpack_from('<H', header, 34)[0]
        packed, unpacked = struct.unpack_from('<2L', header, 20)
        local_offset = struct.unpack_from('<L', header, 42)[0]
        if disk_start == 0xffff or 0xffffffff in (packed, unpacked, local_offset):
            raise InventoryLimit('ZIP64_UNSUPPORTED')
        if disk_start:
            raise InventoryLimit('ZIP_MULTIVOLUME_UNSUPPORTED')
        if central.position + name_size + extra_size + comment_size > size:
            raise ValueError('ZIP_TRUNCATED_DIRECTORY_ENTRY')
        encrypted += bool(flags & 0x2041 or method == 99)
        name = central.read(name_size).decode('utf-8' if flags & 2048 else 'cp437', 'replace')
        if len(names) < MAX_NAMES:
            names.append(name[:512])
        if name in {'[Content_Types].xml', 'word/document.xml', 'xl/workbook.xml', 'ppt/presentation.xml'}:
            markers.add(name)
        central.skip(extra_size + comment_size)
        result['zip_members_checked'] = index + 1
    if central.position != size:
        raise InventoryLimit('ZIP_DIRECTORY_TRAILER_UNSUPPORTED')
    if '[Content_Types].xml' in markers:
        for name, kind in [('word/document.xml', 'DOCX'), ('xl/workbook.xml', 'XLSX'), ('ppt/presentation.xml', 'PPTX')]:
            if name in markers:
                result['format'] = kind
                break
    result.update(encryption='ENCRYPTED' if encrypted else 'NO_ENCRYPTION_INDICATOR',
                  structure='HEADERS_CHECKED', member_count=count, encrypted_members=encrypted,
                  member_names=names, names_truncated=count > len(names))


def _vint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise ValueError('RAR_TRUNCATED_INTEGER')
        byte = data[pos]
        pos += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, pos
    raise ValueError('RAR_INTEGER_LIMIT')


def _rar(reader, result, modern):
    offset = 8 if modern else 7
    count = 0
    service_count = 0
    main_seen = split = False
    for _ in range(MAX_MEMBERS):
        if offset == reader.size and main_seen and not modern:
            break
        if modern:
            prefix = reader.at(offset, min(14, reader.size-offset))
            header_size, base = _vint(prefix, 4)
            if header_size > 65536:
                raise InventoryLimit('RAR_HEADER_LIMIT')
            block = reader.at(offset, base + header_size)
            if zlib.crc32(block[4:]) & 0xffffffff != struct.unpack_from('<L', block)[0]:
                raise ValueError('RAR_HEADER_CRC_MISMATCH')
            kind, pos = _vint(block, base)
            flags, pos = _vint(block, pos)
            extra, data_size = 0, 0
            if flags & 1:
                extra, pos = _vint(block, pos)
            if flags & 2:
                data_size, pos = _vint(block, pos)
            if extra > len(block)-pos:
                raise ValueError('RAR_INVALID_EXTRA_AREA')
            if kind == 4:
                version, check = _vint(block, pos)
                enc_flags, check = _vint(block, check)
                if version != 0 or enc_flags & ~1:
                    raise InventoryLimit('RAR_ENCRYPTION_VERSION_UNSUPPORTED')
                if len(block)-check < 17 + (12 if enc_flags & 1 else 0):
                    raise ValueError('RAR_TRUNCATED_ENCRYPTION_HEADER')
                result.update(encryption='ENCRYPTED', reason='RAR_ENCRYPTED_HEADERS', structure='HEADER_CHECKED')
                return
            if kind == 1:
                main_seen = True
                main_flags, _ = _vint(block, pos)
                split |= bool(main_flags & 1)
            elif kind in (2, 3):
                if not main_seen:
                    raise ValueError('RAR_MAIN_HEADER_MISSING')
                count += kind == 2
                split |= bool(flags & 24)
                pos = len(block)-extra
                while pos < len(block):
                    record_size, record_start = _vint(block, pos)
                    end = record_start + record_size
                    if record_size < 1 or end > len(block):
                        raise ValueError('RAR_INVALID_EXTRA_RECORD')
                    record_type, check = _vint(block, record_start)
                    if record_type == 1:
                        version, check = _vint(block, check)
                        enc_flags, check = _vint(block, check)
                        if version != 0 or enc_flags & ~3:
                            raise InventoryLimit('RAR_ENCRYPTION_VERSION_UNSUPPORTED')
                        if end-check < 33 + (12 if enc_flags & 1 else 0):
                            raise ValueError('RAR_TRUNCATED_ENCRYPTION_RECORD')
                        result.update(encryption='ENCRYPTED', reason='RAR_FILE_ENCRYPTION_RECORD', structure='HEADER_CHECKED')
                        return
                    pos = end
            elif kind == 5 and main_seen:
                break
            else:
                raise InventoryLimit('RAR_BLOCK_UNSUPPORTED')
            offset += len(block) + data_size
        else:
            prefix = reader.at(offset, 7)
            crc, kind, flags, size = struct.unpack('<HBHH', prefix)
            if size < 7:
                raise ValueError('RAR_INVALID_HEADER_SIZE')
            block = reader.at(offset, size)
            if zlib.crc32(block[2:]) & 65535 != crc:
                raise ValueError('RAR_HEADER_CRC_MISMATCH')
            data_size = struct.unpack_from('<L', block, 7)[0] if flags & 0x8000 else 0
            if kind == 0x73:
                if size < 13:
                    raise ValueError('RAR_SHORT_MAIN_HEADER')
                main_seen = True
                split |= bool(flags & 1)
                if flags & 0x80:
                    result.update(encryption='ENCRYPTED', reason='RAR_ENCRYPTED_HEADERS', structure='HEADER_CHECKED')
                    return
            elif kind in (0x74, 0x7a):
                if not main_seen or size < 32:
                    raise ValueError('RAR_INVALID_FILE_HEADER')
                # RAR3 service blocks share the file-header layout. Their
                # payload (comments, recovery data, alternate streams, etc.)
                # is skipped by size, but its password flag must be checked.
                if kind == 0x7a:
                    fixed_size = 40 if flags & 0x100 else 32
                    name_size = struct.unpack_from('<H', block, 26)[0]
                    salt_size = 8 if flags & 0x400 else 0
                    if (not flags & 0x8000 or not name_size
                            or fixed_size + name_size + salt_size > size):
                        raise ValueError('RAR_INVALID_SERVICE_HEADER')
                    service_count += 1
                    result['rar_service_headers_checked'] = service_count
                else:
                    count += 1
                split |= bool(flags & 3)
                if flags & 4:
                    reason = 'RAR_SERVICE_PASSWORD_FLAG' if kind == 0x7a else 'RAR_FILE_PASSWORD_FLAG'
                    result.update(encryption='ENCRYPTED', reason=reason, structure='HEADER_CHECKED')
                    return
                data_size = struct.unpack_from('<L', block, 7)[0]
                if flags & 0x100:
                    data_size += struct.unpack_from('<L', block, 32)[0] << 32
            elif kind == 0x7b and main_seen:
                break
            else:
                raise InventoryLimit('RAR_BLOCK_UNSUPPORTED')
            offset += size + data_size
        if offset > reader.size:
            raise ValueError('RAR_TRUNCATED_PAYLOAD')
    else:
        raise InventoryLimit('RAR_BLOCK_LIMIT')
    if not main_seen:
        raise ValueError('RAR_MAIN_HEADER_MISSING')
    if split:
        raise InventoryLimit('RAR_MULTIVOLUME_INCOMPLETE_SCOPE')
    result.update(encryption='NO_ENCRYPTION_INDICATOR', structure='HEADERS_CHECKED', member_count=count)


def _ole_directory_metadata(ole, result):
    """Describe already-loaded, reachable entries without opening any streams."""
    if len(ole.direntries) > MAX_MEMBERS:
        raise InventoryLimit('OLE_DIRECTORY_ENTRY_LIMIT')
    entries = []
    count = 0
    for index, entry in enumerate(ole.direntries):
        if entry is None or index == 0:
            continue
        count += 1
        if len(entries) < MAX_NAMES:
            entries.append({'id': index, 'name': entry.name[:64],
                            'type': entry.entry_type, 'size': entry.size,
                            'clsid': entry.clsid})
    warnings = bool(ole.parsing_issues)
    result.update(ole_root_clsid=ole.root.clsid, ole_directory_entries=entries,
                  ole_directory_entry_count=count,
                  ole_directory_entries_truncated=count > len(entries),
                  ole_directory_warnings=warnings,
                  ole_inventory_revision=OLE_INVENTORY_REVISION,
                  structure='DIRECTORY_CHECKED_WITH_WARNINGS' if warnings else 'DIRECTORY_CHECKED')
    result.update(ole_type_hint(result))


class _OleMetadataStream:
    """Sequential prefix reader for regular FAT streams, not a chain validator.

    olefile has already loaded the directory and FAT. Its openstream() eagerly
    copies the entire stream; here only sectors needed for metadata are read.
    """
    def __init__(self, reader, ole, entry):
        self.reader, self.ole, self.entry = reader, ole, entry
        self.position = 0
        self.sector = entry.isectStart
        self.seen = set()
        self.buffer = b''
        self.cursor = 0

    def read(self, count):
        if count < 0:
            raise ValueError('OLE_UNBOUNDED_READ')
        count = min(count, self.entry.size - self.position)
        if self.position + count > MAX_OLE_METADATA_BYTES:
            raise InventoryLimit('OLE_METADATA_PREFIX_LIMIT')
        parts = []
        while count:
            if self.cursor == len(self.buffer):
                if self.buffer:
                    self.sector = int(self.ole.fat[self.sector])
                if self.sector in self.seen:
                    raise ValueError('OLE_METADATA_CHAIN_CYCLE')
                if not 0 <= self.sector < len(self.ole.fat):
                    raise ValueError('OLE_METADATA_CHAIN_OUT_OF_RANGE')
                self.seen.add(self.sector)
                length = min(self.ole.sectorsize, self.entry.size - self.position)
                self.buffer = self.reader.at((self.sector+1)*self.ole.sectorsize, length)
                self.cursor = 0
            take = min(count, len(self.buffer)-self.cursor)
            parts.append(self.buffer[self.cursor:self.cursor+take])
            self.cursor += take
            self.position += take
            count -= take
        return b''.join(parts)


def _ole_metadata_stream(reader, ole, name):
    entry = ole.direntries[ole._find(name)]
    if entry.entry_type != 2:
        raise ValueError('OLE_EXPECTED_STREAM')
    if entry.size < ole.minisectorcutoff:
        # Keep olefile's MiniFAT handling; its backing reads still use the
        # shared byte/call budget, including loading the root mini stream.
        return ole.openstream(name)
    return _OleMetadataStream(reader, ole, entry)


def _ole(reader, result):
    try:
        import olefile
    except ImportError:
        raise InventoryLimit('INSTALL_INVENTORY_EXTRA_FOR_OLE')
    reader.seek(0)
    with olefile.OleFileIO(reader, raise_defects=olefile.DEFECT_INCORRECT) as ole:
        if ole.exists('EncryptionInfo') and ole.exists('EncryptedPackage'):
            version = _ole_metadata_stream(reader, ole, 'EncryptionInfo').read(8)
            if len(version) < 8 or ole.get_size('EncryptedPackage') < 8:
                raise ValueError('OFFICE_TRUNCATED_ENCRYPTION_METADATA')
            if struct.unpack_from('<HH', version) not in {(2, 2), (3, 2), (4, 2), (4, 4)}:
                raise InventoryLimit('OFFICE_ENCRYPTION_VERSION_UNSUPPORTED')
            result.update(format='OFFICE_ENCRYPTED', encryption='ENCRYPTED',
                          structure='DIRECTORY_CHECKED', reason='OFFICE_ENCRYPTION_STREAMS',
                          ole_stream_scope='METADATA_PREFIX_ONLY')
        elif ole.exists('WordDocument'):
            result['format'] = 'DOC'
            fib = _ole_metadata_stream(reader, ole, 'WordDocument').read(32)
            if len(fib) < 32:
                raise ValueError('DOC_INVALID_FIB')
            ident, version = struct.unpack_from('<HH', fib)
            if ident == 0xa5dc:
                if version != 0x65:
                    raise InventoryLimit('DOC_LEGACY_FIB_VERSION_UNSUPPORTED')
            elif ident != 0xa5ec:
                raise ValueError('DOC_INVALID_FIB')
            flags = struct.unpack_from('<H', fib, 10)[0]
            result.update(encryption='ENCRYPTED' if flags & 0x100 else 'NO_ENCRYPTION_INDICATOR',
                          structure='FIB_CHECKED', doc_fib_ident=ident,
                          doc_fib_version=version, ole_stream_scope='METADATA_PREFIX_ONLY')
        elif ole.exists('Workbook') or ole.exists('Book'):
            result['format'] = 'XLS'
            name = 'Workbook' if ole.exists('Workbook') else 'Book'
            stream = _ole_metadata_stream(reader, ole, name)
            for index in range(MAX_MEMBERS):
                header = stream.read(4)
                if len(header) != 4:
                    raise ValueError('XLS_TRUNCATED_GLOBALS')
                record, length = struct.unpack('<HH', header)
                data = stream.read(length)
                if len(data) != length:
                    raise ValueError('XLS_TRUNCATED_RECORD')
                if index == 0:
                    if record != 0x0809 or length < 4 or data[:4] != b'\x00\x06\x05\x00':
                        raise InventoryLimit('XLS_BIFF_VERSION_UNSUPPORTED')
                elif record == 0x0809:
                    raise ValueError('XLS_UNEXPECTED_BOF')
                if record == 0x2f:
                    if length < 6:
                        raise ValueError('XLS_TRUNCATED_FILEPASS')
                    result.update(encryption='ENCRYPTED', structure='GLOBALS_CHECKED', reason='XLS_FILEPASS',
                                  ole_stream_scope='METADATA_PREFIX_ONLY')
                    return
                if record == 0x0a:
                    if length:
                        raise ValueError('XLS_INVALID_EOF')
                    result.update(encryption='NO_ENCRYPTION_INDICATOR', structure='GLOBALS_CHECKED',
                                  ole_stream_scope='METADATA_PREFIX_ONLY')
                    return
            raise InventoryLimit('XLS_RECORD_LIMIT')
        elif ole.exists('PowerPoint Document') or ole.exists('Current User'):
            _ole_directory_metadata(ole, result)
            result['format'] = 'PPT'
            if ole.parsing_issues:
                raise ValueError('PPT_OLE_DIRECTORY_WARNINGS')
            result.update(inspect_ppt(reader, ole))
        else:
            _ole_directory_metadata(ole, result)
            result['reason'] = 'OLE_TYPE_UNDETERMINED'


def inspect_file(path):
    result = {'format': None, 'encryption': 'UNKNOWN', 'structure': 'UNDETERMINED',
              'reason': None, 'bytes_read': 0, 'scope': 'METADATA_ONLY_NO_PAYLOAD_VALIDATION'}
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb', buffering=0) as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or getattr(before, 'st_file_attributes', 0) & 0x400:
            raise OSError('NOT_REGULAR_FILE_OR_REPARSE_POINT')
        reader = BoundedReader(stream, before.st_size)
        try:
            prefix = reader.at(0, min(512, reader.size))
            if prefix.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')):
                result['format'] = 'ZIP'
                _zip(reader, result)
            elif prefix.startswith(b'Rar!\x1a\x07\x01\x00'):
                result['format'] = 'RAR5'
                _rar(reader, result, True)
            elif prefix.startswith(b'Rar!\x1a\x07\x00'):
                result['format'] = 'RAR'
                _rar(reader, result, False)
            elif prefix.startswith(b'7z\xbc\xaf\x27\x1c'):
                result['format'] = '7Z'
                result.update(inspect_7z(reader, prefix))
            elif prefix.startswith(OLE_MAGIC):
                result['format'] = 'OLE'
                _ole(reader, result)
            elif re.match(rb'^\{\\rtf1(?:[^0-9]|$)', prefix):
                result.update(format='RTF', encryption='NO_ENCRYPTION_INDICATOR', structure='SIGNATURE_ONLY')
            elif prefix.startswith(b'%PDF-'):
                result['format'] = 'PDF'
                result.update(inspect_pdf(reader))
            else:
                result.update(structure='NOT_RECOGNIZED', reason='NO_SUPPORTED_START_SIGNATURE')
        except (InventoryLimit, PDFMetadataLimit, SevenZipLimit, PPTMetadataLimit) as error:
            result.update(encryption='UNKNOWN', reason=str(error), structure='LIMIT_OR_UNSUPPORTED')
        except (ValueError, OSError, struct.error, IndexError, RecursionError) as error:
            result.update(encryption='UNKNOWN', structure='INVALID_OR_UNSUPPORTED_METADATA',
                          reason=str(error)[:160])
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            result.update(encryption='UNKNOWN', structure='SOURCE_CHANGED', reason='SOURCE_CHANGED_DURING_READ')
        result['bytes_read'] = reader.bytes_read
    return result
