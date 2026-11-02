"""Synthetic NTFS metadata only; no real encrypted user files or credentials."""
import struct


def resident(kind, value, name='', flags=0):
    encoded = name.encode('utf-16-le')
    start = (24 + len(encoded) + 7) & ~7
    length = (start + len(value) + 7) & ~7
    result = bytearray(length)
    struct.pack_into('<IIBBHHH', result, 0, kind, length, 0, len(encoded) // 2, 24 if name else 0, flags, 0)
    struct.pack_into('<IH', result, 16, len(value), start)
    result[24:24 + len(encoded)] = encoded
    result[start:start + len(value)] = value
    return bytes(result)


def nonresident(kind=0x80, name='', flags=0):
    encoded = name.encode('utf-16-le')
    start = (64 + len(encoded) + 7) & ~7
    result = bytearray(start + 8)
    struct.pack_into('<IIBBHHH', result, 0, kind, len(result), 1, len(encoded) // 2, 64 if name else 0, flags, 0)
    struct.pack_into('<QQH', result, 16, 0, 0, start)
    struct.pack_into('<QQQ', result, 40, 4096, 128, 128)
    result[64:64 + len(encoded)] = encoded
    result[start:start + 4] = b'\x11\x01\x32\x00'
    return bytes(result)


def standard(flags=0x4000, size=72):
    value = bytearray(size)
    struct.pack_into('<I', value, 32, flags)
    return resident(0x10, value)


def filename(name='żółty portfel', flags=0, namespace=1, parent=5, sequence=1):
    encoded = name.encode('utf-16-le')
    value = bytearray(66 + len(encoded))
    struct.pack_into('<Q', value, 0, parent | sequence << 48)
    struct.pack_into('<I', value, 56, flags)
    value[64:66] = bytes((len(encoded) // 2, namespace))
    value[66:] = encoded
    return resident(0x30, value)


def protect(raw, stride=512):
    raw = bytearray(raw)
    usa = struct.unpack_from('<H', raw, 4)[0]
    raw[usa:usa + 2] = b'\x5a\xa5'
    for index, end in enumerate(range(stride - 2, len(raw), stride), 1):
        raw[usa + 2 * index:usa + 2 * index + 2] = raw[end:end + 2]
        raw[end:end + 2] = b'\x5a\xa5'
    return bytes(raw)


def record(*attributes, directory=True, active=True, size=1024, stride=512, base=0, number=42):
    if not attributes:
        attributes = (standard(), filename())
    raw = bytearray(size)
    usa, count = 48, size // stride + 1
    first = (usa + count * 2 + 7) & ~7
    raw[:4] = b'FILE'
    struct.pack_into('<HH', raw, 4, usa, count)
    struct.pack_into('<HHHH', raw, 16, 3, 1, first, int(active) | (2 if directory else 0))
    struct.pack_into('<I', raw, 28, size)
    struct.pack_into('<Q', raw, 32, base)
    struct.pack_into('<I', raw, 44, number)
    offset = first
    for instance, attr in enumerate(attributes):
        raw[offset:offset + len(attr)] = attr
        struct.pack_into('<H', raw, offset + 14, instance)
        offset += len(attr)
    assert offset + 8 <= size
    struct.pack_into('<II', raw, offset, 0xffffffff, 0)
    struct.pack_into('<I', raw, 24, offset + 8)
    return protect(raw, stride)
