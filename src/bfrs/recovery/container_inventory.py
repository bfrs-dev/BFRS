"""Metadata-only, bounded document/archive identification; no extraction/passwords."""
import os
import re
import struct
import stat
import zlib

VERSION = 1
MAX_READ_BYTES = 2 * 1024 * 1024
MAX_READ_CALLS = 4096
MAX_MEMBERS = 4096
MAX_NAMES = 50
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


def _zip(reader, result):
    length = min(reader.size, 65557)
    tail = reader.at(reader.size - length, length)
    pos = tail.rfind(b'PK\x05\x06')
    while pos >= 0:
        if pos + 22 <= len(tail) and pos + 22 + struct.unpack_from('<H', tail, pos+20)[0] == len(tail):
            break
        pos = tail.rfind(b'PK\x05\x06', 0, pos)
    if pos < 0:
        raise ValueError('ZIP_END_DIRECTORY_MISSING')
    disk, cd_disk, disk_count, count, size, offset, comment = struct.unpack_from('<4H2LH', tail, pos+4)
    if disk or cd_disk or disk_count != count:
        raise InventoryLimit('ZIP_MULTIVOLUME_UNSUPPORTED')
    if count == 65535 or size == 0xffffffff or offset == 0xffffffff:
        raise InventoryLimit('ZIP64_UNSUPPORTED')
    if count > MAX_MEMBERS:
        raise InventoryLimit('ZIP_MEMBER_LIMIT')
    if offset + size != reader.size - length + pos:
        raise InventoryLimit('ZIP_DIRECTORY_LAYOUT_UNSUPPORTED')
    central = reader.at(offset, size)
    cursor = encrypted = 0
    names = []
    markers = set()
    for _ in range(count):
        if central[cursor:cursor+4] != b'PK\x01\x02' or cursor+46 > len(central):
            raise ValueError('ZIP_BAD_DIRECTORY_ENTRY')
        flags, method = struct.unpack_from('<HH', central, cursor+8)
        name_size, extra_size, comment_size = struct.unpack_from('<HHH', central, cursor+28)
        disk_start = struct.unpack_from('<H', central, cursor+34)[0]
        if disk_start:
            raise InventoryLimit('ZIP_MULTIVOLUME_UNSUPPORTED')
        end = cursor+46+name_size+extra_size+comment_size
        if end > len(central):
            raise ValueError('ZIP_TRUNCATED_DIRECTORY_ENTRY')
        encrypted += bool(flags & 0x2041 or method == 99)
        name = central[cursor+46:cursor+46+name_size].decode('utf-8' if flags & 2048 else 'cp437', 'replace')
        if len(names) < MAX_NAMES:
            names.append(name[:512])
        if name in {'[Content_Types].xml', 'word/document.xml', 'xl/workbook.xml', 'ppt/presentation.xml'}:
            markers.add(name)
        cursor = end
    if cursor != len(central):
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
            elif kind == 0x74:
                if not main_seen or size < 32:
                    raise ValueError('RAR_INVALID_FILE_HEADER')
                count += 1
                split |= bool(flags & 3)
                if flags & 4:
                    result.update(encryption='ENCRYPTED', reason='RAR_FILE_PASSWORD_FLAG', structure='HEADER_CHECKED')
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


def _ole(reader, result):
    try:
        import olefile
    except ImportError:
        raise InventoryLimit('INSTALL_INVENTORY_EXTRA_FOR_OLE')
    reader.seek(0)
    with olefile.OleFileIO(reader, raise_defects=olefile.DEFECT_INCORRECT) as ole:
        if ole.exists('EncryptionInfo') and ole.exists('EncryptedPackage'):
            if ole.get_size('EncryptionInfo') > 1024 * 1024:
                raise InventoryLimit('OLE_STREAM_LIMIT')
            version = ole.openstream('EncryptionInfo').read(8)
            if len(version) < 8 or ole.get_size('EncryptedPackage') < 8:
                raise ValueError('OFFICE_TRUNCATED_ENCRYPTION_METADATA')
            if struct.unpack_from('<HH', version) not in {(2, 2), (3, 2), (4, 2), (4, 4)}:
                raise InventoryLimit('OFFICE_ENCRYPTION_VERSION_UNSUPPORTED')
            result.update(format='OFFICE_ENCRYPTED', encryption='ENCRYPTED',
                          structure='DIRECTORY_CHECKED', reason='OFFICE_ENCRYPTION_STREAMS')
        elif ole.exists('WordDocument'):
            result['format'] = 'DOC'
            if ole.get_size('WordDocument') > 1024 * 1024:
                raise InventoryLimit('OLE_STREAM_LIMIT')
            fib = ole.openstream('WordDocument').read(32)
            if len(fib) < 32 or fib[:2] != b'\xec\xa5':
                raise ValueError('DOC_INVALID_FIB')
            flags = struct.unpack_from('<H', fib, 10)[0]
            result.update(encryption='ENCRYPTED' if flags & 0x100 else 'NO_ENCRYPTION_INDICATOR',
                          structure='FIB_CHECKED')
        elif ole.exists('Workbook') or ole.exists('Book'):
            result['format'] = 'XLS'
            name = 'Workbook' if ole.exists('Workbook') else 'Book'
            if ole.get_size(name) > 1024 * 1024:
                raise InventoryLimit('OLE_STREAM_LIMIT')
            stream = ole.openstream(name)
            if stream.read(2) != b'\x09\x08':
                raise InventoryLimit('XLS_BIFF_VERSION_UNSUPPORTED')
            stream.seek(0)
            for _ in range(MAX_MEMBERS):
                header = stream.read(4)
                if len(header) != 4:
                    raise ValueError('XLS_TRUNCATED_GLOBALS')
                record, length = struct.unpack('<HH', header)
                if len(stream.read(length)) != length:
                    raise ValueError('XLS_TRUNCATED_RECORD')
                if record == 0x2f:
                    if length < 6:
                        raise ValueError('XLS_TRUNCATED_FILEPASS')
                    result.update(encryption='ENCRYPTED', structure='GLOBALS_CHECKED', reason='XLS_FILEPASS')
                    return
                if record == 0x0a:
                    result.update(encryption='NO_ENCRYPTION_INDICATOR', structure='GLOBALS_CHECKED')
                    return
            raise InventoryLimit('XLS_RECORD_LIMIT')
        else:
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
                if len(prefix) < 32 or zlib.crc32(prefix[12:32]) & 0xffffffff != struct.unpack_from('<L', prefix, 8)[0]:
                    raise ValueError('7Z_START_CRC_MISMATCH')
                offset, size, crc = struct.unpack_from('<QQL', prefix, 12)
                header = reader.at(32+offset, size)
                if zlib.crc32(header) & 0xffffffff != crc:
                    raise ValueError('7Z_NEXT_HEADER_CRC_MISMATCH')
                result.update(structure='HEADER_CRC_CHECKED', reason='7Z_ENCRYPTION_REQUIRES_DEEPER_PARSER')
            elif prefix.startswith(OLE_MAGIC):
                result['format'] = 'OLE'
                _ole(reader, result)
            elif re.match(rb'^\{\\rtf1(?:[^0-9]|$)', prefix):
                result.update(format='RTF', encryption='NO_ENCRYPTION_INDICATOR', structure='SIGNATURE_ONLY')
            elif prefix.startswith(b'%PDF-'):
                result.update(format='PDF', structure='SIGNATURE_ONLY', reason='PDF_ENCRYPTION_REQUIRES_DEEPER_PARSER')
            else:
                result.update(structure='NOT_RECOGNIZED', reason='NO_SUPPORTED_START_SIGNATURE')
        except InventoryLimit as error:
            result.update(encryption='UNKNOWN', reason=str(error), structure='LIMIT_OR_UNSUPPORTED')
        except (ValueError, OSError, struct.error, IndexError, RecursionError) as error:
            result.update(encryption='UNKNOWN', structure='INVALID_OR_UNSUPPORTED_METADATA',
                          reason=str(error)[:160])
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            result.update(encryption='UNKNOWN', structure='SOURCE_CHANGED', reason='SOURCE_CHANGED_DURING_READ')
        result['bytes_read'] = reader.bytes_read
    return result
