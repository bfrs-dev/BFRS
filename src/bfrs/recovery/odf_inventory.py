"""Bounded OpenDocument package metadata; never decrypt or read document XML.

ODF encrypts member contents independently of ZIP's password flags. Only the
small mimetype member and META-INF/manifest.xml are decoded here.
"""
import struct
from xml.parsers import expat
import zlib

NAMESPACE = 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0'
MIME_PREFIX = 'application/vnd.oasis.opendocument.'
FORMATS = {
    'text': 'ODT', 'spreadsheet': 'ODS', 'presentation': 'ODP',
    'graphics': 'ODG', 'chart': 'ODC', 'formula': 'ODF', 'database': 'ODB',
    'image': 'ODI', 'text-master': 'ODM', 'text-web': 'OTH',
    'text-template': 'OTT', 'spreadsheet-template': 'OTS',
    'presentation-template': 'OTP', 'graphics-template': 'OTG',
    'chart-template': 'OTC', 'formula-template': 'OTF', 'image-template': 'OTI',
    'text-master-template': 'OTM',
}
ODF_FORMATS = frozenset(FORMATS.values()) | {'ODF_PACKAGE'}
ODF_EXTENSIONS = frozenset('.' + name.lower() for name in FORMATS.values())
MAX_PACKED_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 512 * 1024
MAX_XML_ELEMENTS = 8192
MAX_XML_DEPTH = 32


def _metadata(reader, name, entry, directory_offset, limit):
    offset, flags, method, crc, packed, unpacked = entry
    if flags & ~0x080e or method not in (0, 8):
        raise ValueError('ODF_METADATA_ENCODING_UNSUPPORTED')
    if packed > MAX_PACKED_BYTES or unpacked > limit:
        raise ValueError('ODF_METADATA_SIZE_LIMIT')
    if offset + 30 > directory_offset:
        raise ValueError('ODF_LOCAL_HEADER_OUT_OF_BOUNDS')
    header = reader.at(offset, 30)
    if header[:4] != b'PK\x03\x04' or struct.unpack_from('<HH', header, 6) != (flags, method):
        raise ValueError('ODF_LOCAL_HEADER_MISMATCH')
    name_size, extra_size = struct.unpack_from('<HH', header, 26)
    start = offset + 30 + name_size + extra_size
    if start + packed > directory_offset or name_size != len(name):
        raise ValueError('ODF_METADATA_OUT_OF_BOUNDS')
    if reader.at(offset + 30, name_size) != name.encode('ascii'):
        raise ValueError('ODF_LOCAL_NAME_MISMATCH')
    local_sizes = struct.unpack_from('<3L', header, 14)
    if (not flags & 8 and local_sizes != (crc, packed, unpacked)
            or flags & 8 and any(a not in (0, b) for a, b in zip(local_sizes, (crc, packed, unpacked)))):
        raise ValueError('ODF_LOCAL_SIZE_MISMATCH')
    data = reader.at(start, packed)
    if method == 8:
        decoder = zlib.decompressobj(-15)
        try:
            data = decoder.decompress(data, min(unpacked, limit) + 1)
        except zlib.error as error:
            raise ValueError('ODF_INVALID_DEFLATE') from error
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('ODF_DEFLATE_LIMIT_OR_TRUNCATION')
    if len(data) != unpacked or zlib.crc32(data) & 0xffffffff != crc:
        raise ValueError('ODF_METADATA_SIZE_OR_CRC_MISMATCH')
    return data


def _manifest(data):
    """Parse namespaces and hierarchy, with no DTD/entity expansion or XML tree."""
    parser = expat.ParserCreate(namespace_separator='|')
    tag = lambda name: NAMESPACE + '|' + name
    stack, paths, encrypted_names = [], set(), []
    count = encrypted = 0
    root_mime = None
    entry_path = None
    entry_encrypted = False
    encryption_children = set()

    def reject_dtd(*args):
        raise ValueError('ODF_XML_DTD_OR_ENTITY_UNSUPPORTED')

    def start(name, attrs):
        nonlocal count, root_mime, entry_path, entry_encrypted, encryption_children
        count += 1
        if count > MAX_XML_ELEMENTS or len(stack) >= MAX_XML_DEPTH:
            raise ValueError('ODF_XML_STRUCTURE_LIMIT')
        parent = stack[-1] if stack else None
        if not stack and name != tag('manifest'):
            raise ValueError('ODF_MANIFEST_NAMESPACE_UNSUPPORTED')
        if name == tag('file-entry'):
            if stack != [tag('manifest')]:
                raise ValueError('ODF_INVALID_FILE_ENTRY')
            entry_path = attrs.get(tag('full-path'))
            if not entry_path or entry_path in paths or tag('media-type') not in attrs:
                raise ValueError('ODF_INVALID_OR_DUPLICATE_PATH')
            paths.add(entry_path)
            entry_encrypted = False
            if entry_path == '/':
                root_mime = attrs[tag('media-type')]
        elif name == tag('encryption-data'):
            if parent != tag('file-entry') or entry_encrypted or entry_path.endswith('/'):
                raise ValueError('ODF_INVALID_ENCRYPTION_ENTRY')
            entry_encrypted = True
            encryption_children = set()
        elif parent == tag('encryption-data'):
            local = name.removeprefix(NAMESPACE + '|')
            required = {'algorithm': 'algorithm-name', 'key-derivation': 'key-derivation-name',
                        'start-key-generation': 'start-key-generation-name'}
            if local not in required or local in encryption_children or not attrs.get(tag(required[local])):
                raise ValueError('ODF_ENCRYPTION_METADATA_UNSUPPORTED')
            encryption_children.add(local)
        elif parent in (tag('manifest'), tag('file-entry')):
            # An unknown extension could carry encryption information.
            raise ValueError('ODF_MANIFEST_EXTENSION_UNSUPPORTED')
        stack.append(name)

    def end(name):
        nonlocal encrypted
        if name == tag('encryption-data'):
            if not {'algorithm', 'key-derivation'} <= encryption_children:
                raise ValueError('ODF_INCOMPLETE_ENCRYPTION_METADATA')
            encrypted += 1
            if len(encrypted_names) < 50:
                encrypted_names.append(entry_path[:512])
        stack.pop()

    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.StartDoctypeDeclHandler = reject_dtd
    parser.EntityDeclHandler = reject_dtd
    parser.ExternalEntityRefHandler = reject_dtd
    try:
        parser.Parse(data, True)
    except expat.ExpatError as error:
        raise ValueError('ODF_INVALID_MANIFEST_XML') from error
    if not paths:
        raise ValueError('ODF_EMPTY_MANIFEST')
    return root_mime, encrypted, encrypted_names, len(paths)


def inspect_odf_package(reader, result, entries, directory_offset):
    mime = None
    if 'mimetype' in entries:
        raw = _metadata(reader, 'mimetype', entries['mimetype'], directory_offset, 256)
        try:
            mime = raw.decode('ascii')
        except UnicodeDecodeError as error:
            raise ValueError('ODF_INVALID_MIMETYPE') from error
        if mime.startswith(MIME_PREFIX):
            result['format'] = FORMATS.get(mime[len(MIME_PREFIX):], 'ODF_PACKAGE')
        elif 'META-INF/manifest.xml' not in entries:
            return  # e.g. EPUB: keep the ZIP classification.
    if 'META-INF/manifest.xml' not in entries:
        raise ValueError('ODF_MANIFEST_MISSING')
    data = _metadata(reader, 'META-INF/manifest.xml', entries['META-INF/manifest.xml'],
                     directory_offset, MAX_MANIFEST_BYTES)
    root_mime, encrypted, names, checked = _manifest(data)
    if mime is not None and root_mime != mime:
        raise ValueError('ODF_MIMETYPE_MISMATCH')
    media_type = mime or root_mime
    if media_type and not media_type.startswith(MIME_PREFIX):
        raise ValueError('ODF_MEDIA_TYPE_UNSUPPORTED')
    kind = FORMATS.get(media_type[len(MIME_PREFIX):], 'ODF_PACKAGE') if media_type else 'ODF_PACKAGE'
    result.update(format=kind, odf_manifest_entries_checked=checked,
                  odf_encrypted_members=encrypted, odf_encrypted_member_names=names,
                  odf_encrypted_names_truncated=encrypted > len(names),
                  odf_password_required='NOT_CHECKED', odf_metadata_scope='MANIFEST_ONLY_NO_PAYLOAD_VALIDATION',
                  structure='ODF_MANIFEST_CHECKED')
    if encrypted:
        result.update(encryption='ENCRYPTED', reason='ODF_MANIFEST_ENCRYPTION_DATA')
    elif result['encryption'] != 'ENCRYPTED':
        result.update(encryption='NO_ENCRYPTION_INDICATOR', reason='ODF_NO_ENCRYPTION_MARKER')
