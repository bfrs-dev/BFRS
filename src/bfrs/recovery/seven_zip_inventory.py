"""Bounded 7z coder metadata inspection; no member extraction or password work.

Reference: ip7z/7zip DOC/7zFormat.txt and DOC/Methods.txt.
Only single-input/output coder chains and inline file metadata are supported.
"""
from dataclasses import dataclass
import struct
import zlib


MAX_HEADER_BYTES = 1024 * 1024
MAX_DICTIONARY_BYTES = 16 * 1024 * 1024
MAX_FOLDERS = 256
MAX_CODERS = 8
MAX_FILES = 65536
MAX_PROPERTIES = 32
AES = bytes.fromhex('06f10701')
COPY = b'\x00'
LZMA = bytes.fromhex('030101')
LZMA2 = b'\x21'
# Unknown methods must not produce a negative encryption classification.
PLAIN_METHODS = {COPY, LZMA, LZMA2, b'\x03', *(bytes([value]) for value in range(4, 12)), bytes.fromhex('040108'),
                 bytes.fromhex('040202'), bytes.fromhex('030401'),
                 *(bytes.fromhex(value) for value in
                   ('03030103', '03030205', '03030401', '03030501', '03030701', '03030805'))}


class SevenZipLimit(ValueError):
    pass


def _require(condition, reason='7Z_INVALID_HEADER'):
    if not condition:
        raise ValueError(reason)


class _Cursor:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, count):
        _require(0 <= count <= len(self.data) - self.pos, '7Z_TRUNCATED_HEADER')
        result = self.data[self.pos:self.pos + count]
        self.pos += count
        return result

    def byte(self):
        return self.take(1)[0]

    def number(self):
        first, value, mask = self.byte(), 0, 0x80
        for index in range(8):
            if not first & mask:
                return value | ((first & (mask - 1)) << (8 * index))
            value |= self.byte() << (8 * index)
            mask >>= 1
        return value

    def bounded(self, maximum, reason):
        value = self.number()
        if value > maximum:
            raise SevenZipLimit(reason)
        return value

    def expect(self, value):
        _require(self.byte() == value)

    def done(self):
        _require(self.pos == len(self.data), '7Z_HEADER_TRAILING_DATA')


def _bits(cursor, count):
    data = cursor.take((count + 7) // 8)
    return [bool(data[index // 8] & (0x80 >> (index % 8))) for index in range(count)]


def _defined(cursor, count):
    all_defined = cursor.byte()
    _require(all_defined in (0, 1))
    return [True] * count if all_defined else _bits(cursor, count)


def _digests(cursor, count):
    return [struct.unpack('<L', cursor.take(4))[0] if defined else None
            for defined in _defined(cursor, count)]


@dataclass
class _Folder:
    coders: list
    final_output: int
    unpack_size: int = 0
    crc: int | None = None
    substreams: int = 1


@dataclass
class _Streams:
    pack_pos: int
    sizes: list
    crcs: list
    folders: list


def _folder(cursor):
    count = cursor.bounded(MAX_CODERS, '7Z_CODER_LIMIT')
    _require(count > 0)
    coders = []
    for _ in range(count):
        flags = cursor.byte()
        if flags & 0xc0:
            raise SevenZipLimit('7Z_CODER_FLAGS_UNSUPPORTED')
        length = flags & 15
        _require(1 <= length <= 8)
        method = cursor.take(length)
        if flags & 0x10:
            inputs, outputs = cursor.number(), cursor.number()
            if (inputs, outputs) != (1, 1):
                raise SevenZipLimit('7Z_COMPLEX_CODER_UNSUPPORTED')
        props = cursor.take(cursor.bounded(64, '7Z_CODER_PROPERTIES_LIMIT')) if flags & 0x20 else b''
        if method in (COPY, bytes.fromhex('040108'), bytes.fromhex('040202')):
            _require(not props, '7Z_INVALID_CODER_PROPERTIES')
        elif method == LZMA:
            _require(len(props) == 5 and props[0] < 225, '7Z_INVALID_LZMA_PROPERTIES')
        elif method == LZMA2:
            _require(len(props) == 1 and props[0] <= 40, '7Z_INVALID_LZMA_PROPERTIES')
        elif method == b'\x03':
            _require(len(props) == 1, '7Z_INVALID_CODER_PROPERTIES')
        elif method == bytes.fromhex('030401'):
            _require(len(props) == 5, '7Z_INVALID_CODER_PROPERTIES')
        elif method in PLAIN_METHODS:
            _require(len(props) in (0, 4), '7Z_INVALID_CODER_PROPERTIES')
        if method == AES and props:
            if props[0] & 0xc0:
                _require(len(props) >= 2, '7Z_INVALID_AES_PROPERTIES')
                salt = ((props[0] >> 7) & 1) + (props[1] >> 4)
                iv = ((props[0] >> 6) & 1) + (props[1] & 15)
                _require(len(props) == 2 + salt + iv, '7Z_INVALID_AES_PROPERTIES')
            else:
                _require(len(props) == 1, '7Z_INVALID_AES_PROPERTIES')
        coders.append((method, props))
    bound_inputs, bound_outputs, links = set(), set(), {}
    for _ in range(count - 1):
        incoming, outgoing = cursor.number(), cursor.number()
        _require(incoming < count and outgoing < count
                 and incoming not in bound_inputs and outgoing not in bound_outputs,
                 '7Z_INVALID_CODER_BINDINGS')
        bound_inputs.add(incoming)
        bound_outputs.add(outgoing)
        links[outgoing] = incoming
    # For supported 1-in/1-out coders there is exactly one implicit packed input.
    current = next(iter(set(range(count)) - bound_inputs))
    final = next(iter(set(range(count)) - bound_outputs))
    visited = set()
    while current not in visited:
        visited.add(current)
        if current not in links:
            break
        current = links[current]
    _require(len(visited) == count and current == final, '7Z_INVALID_CODER_BINDINGS')
    return _Folder(coders, final)


def _substreams(cursor, folders):
    token = cursor.byte()
    if token == 0x0d:
        for folder in folders:
            folder.substreams = cursor.bounded(MAX_FILES, '7Z_SUBSTREAM_LIMIT')
        token = cursor.byte()
    if sum(folder.substreams for folder in folders) > MAX_FILES:
        raise SevenZipLimit('7Z_SUBSTREAM_LIMIT')
    needs_sizes = any(folder.substreams > 1 for folder in folders)
    _require(not needs_sizes or token == 0x09)
    if token == 0x09:
        for folder in folders:
            total = sum(cursor.number() for _ in range(max(0, folder.substreams - 1)))
            _require(total <= folder.unpack_size, '7Z_INVALID_SUBSTREAM_SIZES')
        token = cursor.byte()
    if token == 0x0a:
        count = sum(folder.substreams for folder in folders
                    if not (folder.substreams == 1 and folder.crc is not None))
        digests = iter(_digests(cursor, count))
        for folder in folders:
            if folder.substreams == 1 and folder.crc is not None:
                continue
            for _ in range(folder.substreams):
                crc = next(digests)
                if folder.substreams == 1:
                    folder.crc = crc
        token = cursor.byte()
    _require(token == 0)


def _streams(cursor, packed_limit):
    token = cursor.byte()
    pack_pos, sizes, crcs, folders = 0, [], [], []
    if token == 0x06:
        pack_pos = cursor.number()
        count = cursor.bounded(MAX_FOLDERS, '7Z_PACK_STREAM_LIMIT')
        cursor.expect(0x09)
        sizes = [cursor.number() for _ in range(count)]
        _require(pack_pos + sum(sizes) <= packed_limit, '7Z_PACK_RANGE_INVALID')
        crcs = [None] * count
        token = cursor.byte()
        if token == 0x0a:
            crcs = _digests(cursor, count)
            token = cursor.byte()
        _require(token == 0)
        token = cursor.byte()
    if token == 0x07:
        cursor.expect(0x0b)
        count = cursor.bounded(MAX_FOLDERS, '7Z_FOLDER_LIMIT')
        if cursor.byte() != 0:
            raise SevenZipLimit('7Z_EXTERNAL_FOLDERS_UNSUPPORTED')
        folders = [_folder(cursor) for _ in range(count)]
        cursor.expect(0x0c)
        for folder in folders:
            unpack_sizes = [cursor.number() for _ in folder.coders]
            folder.unpack_size = unpack_sizes[folder.final_output]
        token = cursor.byte()
        if token == 0x0a:
            for folder, crc in zip(folders, _digests(cursor, count)):
                folder.crc = crc
            token = cursor.byte()
        _require(token == 0)
        token = cursor.byte()
    _require(len(sizes) == len(folders), '7Z_PACK_STREAM_COUNT_MISMATCH')
    if token == 0x08:
        _substreams(cursor, folders)
        token = cursor.byte()
    _require(token == 0)
    return _Streams(pack_pos, sizes, crcs, folders)


def _files(cursor, expected_streams):
    count = cursor.bounded(MAX_FILES, '7Z_FILE_LIMIT')
    empty_count, seen = 0, set()
    for _ in range(MAX_PROPERTIES):
        token = cursor.byte()
        if token == 0:
            _require(count - empty_count == expected_streams, '7Z_FILE_STREAM_COUNT_MISMATCH')
            return count
        _require(token not in seen, '7Z_DUPLICATE_PROPERTY')
        seen.add(token)
        value = _Cursor(cursor.take(cursor.number()))
        if token in (0x0e, 0x0f, 0x10):
            bits = _bits(value, count if token == 0x0e else empty_count)
            if token == 0x0e:
                empty_count = sum(bits)
        elif token == 0x11:
            if value.byte() != 0:
                raise SevenZipLimit('7Z_EXTERNAL_FILE_METADATA_UNSUPPORTED')
            names = value.take(len(value.data) - value.pos).decode('utf-16-le')
            _require(names.count('\0') == count and (not count or names.endswith('\0')),
                     '7Z_INVALID_FILE_NAMES')
        elif token in (0x12, 0x13, 0x14, 0x15, 0x18):
            defined = sum(_defined(value, count))
            if value.byte() != 0:
                raise SevenZipLimit('7Z_EXTERNAL_FILE_METADATA_UNSUPPORTED')
            value.take(defined * (4 if token == 0x15 else 8))
        elif token == 0x19:
            _require(not any(value.take(len(value.data))), '7Z_INVALID_DUMMY_PROPERTY')
        else:
            raise SevenZipLimit('7Z_FILE_PROPERTY_UNSUPPORTED')
        value.done()
    raise SevenZipLimit('7Z_PROPERTY_LIMIT')


def _header(data, packed_limit):
    cursor = _Cursor(data)
    cursor.expect(0x01)
    token = cursor.byte()
    if token == 0x02:
        for _ in range(MAX_PROPERTIES):
            if cursor.byte() == 0:
                break
            cursor.take(cursor.number())
        else:
            raise SevenZipLimit('7Z_PROPERTY_LIMIT')
        token = cursor.byte()
    if token == 0x03:
        raise SevenZipLimit('7Z_ADDITIONAL_STREAMS_UNSUPPORTED')
    streams = _Streams(0, [], [], [])
    if token == 0x04:
        streams = _streams(cursor, packed_limit)
        token = cursor.byte()
    expected_streams = sum(folder.substreams for folder in streams.folders)
    count = 0
    if token == 0x05:
        count = _files(cursor, expected_streams)
        token = cursor.byte()
    else:
        _require(not expected_streams, '7Z_FILE_STREAM_COUNT_MISMATCH')
    _require(token == 0)
    cursor.done()
    return streams, count


def _methods(streams):
    return {method for folder in streams.folders for method, _ in folder.coders}


def _decode_header(reader, streams):
    if len(streams.folders) != 1 or len(streams.folders[0].coders) != 1:
        raise SevenZipLimit('7Z_ENCODED_HEADER_CHAIN_UNSUPPORTED')
    folder = streams.folders[0]
    if folder.substreams != 1:
        raise SevenZipLimit('7Z_ENCODED_HEADER_CHAIN_UNSUPPORTED')
    if folder.unpack_size > MAX_HEADER_BYTES or streams.sizes[0] > MAX_HEADER_BYTES:
        raise SevenZipLimit('7Z_HEADER_SIZE_LIMIT')
    method, props = folder.coders[0]
    if method not in (COPY, LZMA, LZMA2):
        raise SevenZipLimit('7Z_HEADER_CODEC_UNSUPPORTED')
    if method == COPY:
        _require(not props and streams.sizes[0] == folder.unpack_size)
        filters = None
        encoding = 'COPY'
    else:
        try:
            import lzma
        except ImportError as error:
            raise SevenZipLimit('7Z_LZMA_UNAVAILABLE') from error
        if method == LZMA:
            _require(len(props) == 5 and props[0] < 225, '7Z_INVALID_LZMA_PROPERTIES')
            lc, remainder = props[0] % 9, props[0] // 9
            lp, pb = remainder % 5, remainder // 5
            if lc + lp > 4:
                raise SevenZipLimit('7Z_LZMA_PROPERTIES_UNSUPPORTED')
            dictionary = max(4096, int.from_bytes(props[1:], 'little'))
            filters = [dict(id=lzma.FILTER_LZMA1, dict_size=dictionary, lc=lc, lp=lp, pb=pb)]
            encoding = 'LZMA'
        else:
            _require(len(props) == 1 and props[0] <= 40, '7Z_INVALID_LZMA_PROPERTIES')
            dictionary = 0xffffffff if props[0] == 40 else (2 | (props[0] & 1)) << (props[0] // 2 + 11)
            filters = [dict(id=lzma.FILTER_LZMA2, dict_size=dictionary)]
            encoding = 'LZMA2'
        if dictionary > MAX_DICTIONARY_BYTES:
            raise SevenZipLimit('7Z_HEADER_DICTIONARY_LIMIT')
    # Only the encoded header stream is read here, never archive member data.
    packed = reader.at(32 + streams.pack_pos, streams.sizes[0])
    if streams.crcs[0] is not None:
        _require(zlib.crc32(packed) == streams.crcs[0], '7Z_PACKED_HEADER_CRC_MISMATCH')
    if filters is None:
        decoded = packed
    else:
        try:
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
            decoded = decoder.decompress(packed, max_length=folder.unpack_size + 1)
        except lzma.LZMAError as error:
            raise ValueError('7Z_INVALID_COMPRESSED_HEADER') from error
        _require(not decoder.unused_data, '7Z_COMPRESSED_HEADER_TRAILING_DATA')
        # LZMA1 in 7z may omit EOS: accept that case only with a decoded CRC.
        _require(decoder.eof or (method == LZMA and decoder.needs_input and folder.crc is not None),
                 '7Z_INCOMPLETE_COMPRESSED_HEADER')
    _require(len(decoded) == folder.unpack_size, '7Z_DECODED_HEADER_SIZE_MISMATCH')
    if folder.crc is not None:
        _require(zlib.crc32(decoded) == folder.crc, '7Z_DECODED_HEADER_CRC_MISMATCH')
    return decoded, encoding


def inspect_7z(reader, prefix):
    _require(len(prefix) >= 32, '7Z_TRUNCATED_START_HEADER')
    _require(zlib.crc32(prefix[12:32]) == struct.unpack_from('<L', prefix, 8)[0],
             '7Z_START_CRC_MISMATCH')
    if prefix[6] != 0 or prefix[7] > 4:
        raise SevenZipLimit('7Z_VERSION_UNSUPPORTED')
    offset, size, crc = struct.unpack_from('<QQL', prefix, 12)
    if size > MAX_HEADER_BYTES:
        raise SevenZipLimit('7Z_HEADER_SIZE_LIMIT')
    data = reader.at(32 + offset, size)
    _require(zlib.crc32(data) == crc, '7Z_NEXT_HEADER_CRC_MISMATCH')
    result = dict(seven_zip_scope='CODER_METADATA_ONLY_NO_PAYLOAD_CHECK',
                  seven_zip_header_encoding='PLAIN', seven_zip_header_encrypted=False,
                  seven_zip_data_encrypted=None, structure='7Z_HEADERS_CHECKED')
    if not data:
        _require(offset == 0 and reader.size == 32, '7Z_EMPTY_HEADER_WITH_DATA')
        result.update(encryption='NO_ENCRYPTION_INDICATOR', reason='7Z_NO_ENCRYPTION_CODER',
                      member_count=0, seven_zip_data_encrypted=False, seven_zip_methods=[])
        return result
    packed_limit = offset
    if data[0] == 0x17:
        cursor = _Cursor(data[1:])
        encoded = _streams(cursor, offset)
        cursor.done()
        if AES in _methods(encoded):
            result.update(encryption='ENCRYPTED', reason='7Z_AES_HEADER',
                          seven_zip_header_encoding='ENCRYPTED', seven_zip_header_encrypted=True,
                          seven_zip_methods=sorted(method.hex() for method in _methods(encoded)))
            return result
        data, encoding = _decode_header(reader, encoded)
        result['seven_zip_header_encoding'] = encoding
        packed_limit = encoded.pack_pos
    streams, count = _header(data, packed_limit)
    methods = _methods(streams)
    encrypted = AES in methods
    if not encrypted and methods - PLAIN_METHODS:
        raise SevenZipLimit('7Z_UNKNOWN_CODER')
    result.update(encryption='ENCRYPTED' if encrypted else 'NO_ENCRYPTION_INDICATOR',
                  reason='7Z_AES_DATA' if encrypted else '7Z_NO_ENCRYPTION_CODER',
                  seven_zip_data_encrypted=encrypted, member_count=count,
                  seven_zip_methods=sorted(method.hex() for method in methods))
    return result
