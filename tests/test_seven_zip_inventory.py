"""Metadata-only 7z cases, including bounded decoding of header streams."""

import io
import json
import lzma
import struct
import zlib

import pytest

from tests.sparse_files import sparse_file

from bfrs.recovery import container_inventory as inventory
from bfrs.recovery import seven_zip_inventory as module
from tests.test_container_inventory import runner


def number(value):
    for extra in range(8):
        if value < (1 << (7 + 7 * extra)):
            return bytes([((0xff << (8 - extra)) & 0xff) | (value >> (8 * extra))]) + value.to_bytes(8, 'little')[:extra]
    return b'\xff' + value.to_bytes(8, 'little')


def crc(data):
    return struct.pack('<L', zlib.crc32(data))


def coder(method=module.COPY, props=b''):
    return bytes([len(method) | (0x20 if props else 0)]) + method + (number(len(props)) + props if props else b'')


def streams(method=module.COPY, props=b'', *, pack_pos=0, packed_size=8,
            unpacked_size=8, digest=None, packed_digest=None, chain=None, binds=None):
    coders = chain or [coder(method, props)]
    folder = number(len(coders)) + b''.join(coders)
    pairs = binds if binds is not None else [(index + 1, index) for index in range(len(coders) - 1)]
    folder += b''.join(number(incoming) + number(outgoing) for incoming, outgoing in pairs)
    pack = b'\x06' + number(pack_pos) + b'\x01\x09' + number(packed_size)
    if packed_digest is not None:
        pack += b'\x0a\x01' + struct.pack('<L', packed_digest)
    pack += b'\x00'
    unpack = b'\x07\x0b\x01\x00' + folder + b'\x0c' + number(unpacked_size) * len(coders)
    if digest is not None:
        unpack += b'\x0a\x01' + struct.pack('<L', digest)
    return pack + unpack + b'\x00\x00'


def plain_header(method=module.COPY, props=b'', *, packed_size=8, chain=None, binds=None):
    names = b'\x00' + 'example.bin\0'.encode('utf-16-le')
    return (b'\x01\x04' + streams(method, props, packed_size=packed_size, chain=chain, binds=binds)
            + b'\x05\x01\x11' + number(len(names)) + names + b'\x00\x00')


def archive(header, packed=b'12345678', version=b'\x00\x04'):
    start = struct.pack('<QQ', len(packed), len(header)) + crc(header)
    return b'7z\xbc\xaf\x27\x1c' + version + crc(start) + start + packed + header


def inspect_bytes(tmp_path, content):
    path = tmp_path/'renamed.bin'
    path.write_bytes(content)
    return inventory.inspect_file(path)


def encoded_archive(header, *, kind='LZMA2', digest=True, dictionary=4096,
                    declared_size=None, append=b'', packed_digest=None):
    if kind == 'COPY':
        method, props, packed = module.COPY, b'', header
    elif kind == 'LZMA':
        method, props = module.LZMA, b'\x5d' + dictionary.to_bytes(4, 'little')
        packed = lzma.compress(header, format=lzma.FORMAT_RAW,
                              filters=[dict(id=lzma.FILTER_LZMA1, dict_size=4096)])
    else:
        method, props = module.LZMA2, b'\x00'
        packed = lzma.compress(header, format=lzma.FORMAT_RAW,
                              filters=[dict(id=lzma.FILTER_LZMA2, dict_size=4096)])
    packed += append
    description = b'\x17' + streams(method, props, pack_pos=8, packed_size=len(packed),
        unpacked_size=len(header) if declared_size is None else declared_size,
        digest=zlib.crc32(header) if digest else None, packed_digest=packed_digest)
    return archive(description, b'12345678' + packed)


@pytest.mark.parametrize('method,props,encrypted', [
    (module.COPY, b'', False), (module.LZMA, b'\x5d\x00\x10\x00\x00', False),
    (module.LZMA2, b'\x00', False), (module.AES, b'', True),
    (module.AES, b'\x13', True), (module.AES, b'\x53\x0f' + b'i' * 16, True),
])
def test_plain_coder_metadata(tmp_path, method, props, encrypted):
    row = inspect_bytes(tmp_path, archive(plain_header(method, props)))
    assert row['encryption'] == ('ENCRYPTED' if encrypted else 'NO_ENCRYPTION_INDICATOR')
    assert row['seven_zip_header_encrypted'] is False
    assert row['seven_zip_data_encrypted'] is encrypted
    assert row['member_count'] == 1


@pytest.mark.parametrize('kind', ['COPY', 'LZMA', 'LZMA2'])
@pytest.mark.parametrize('encrypted', [False, True])
def test_encoded_headers_reveal_data_coders(tmp_path, kind, encrypted):
    header = plain_header(module.AES, b'\x13') if encrypted else plain_header()
    row = inspect_bytes(tmp_path, encoded_archive(header, kind=kind))
    assert row['encryption'] == ('ENCRYPTED' if encrypted else 'NO_ENCRYPTION_INDICATOR')
    assert row['seven_zip_header_encoding'] == kind
    assert row['seven_zip_data_encrypted'] is encrypted


@pytest.mark.parametrize('kind', ['COPY', 'LZMA', 'LZMA2'])
def test_optional_decoded_crc_absent_with_complete_stream(tmp_path, kind):
    row = inspect_bytes(tmp_path, encoded_archive(plain_header(), kind=kind, digest=False))
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'


def test_header_aes_never_decrypts_or_reads_encoded_stream(tmp_path, monkeypatch):
    description = b'\x17' + streams(module.AES, b'\x13', packed_size=4096, unpacked_size=1024)
    calls, original = [], inventory.BoundedReader.at
    def record(reader, offset, size):
        calls.append((offset, size))
        return original(reader, offset, size)
    monkeypatch.setattr(inventory.BoundedReader, 'at', record)
    row = inspect_bytes(tmp_path, archive(description, b'x' * 4096))
    assert row['reason'] == '7Z_AES_HEADER' and row['seven_zip_header_encrypted'] is True
    assert row['seven_zip_data_encrypted'] is None and 'member_count' not in row
    assert calls == [(0, 512), (32 + 4096, len(description))]


def test_linear_aes_chain_and_unknown_coder_policy(tmp_path):
    chain = [coder(module.AES, b'\x13'), coder(module.LZMA2, b'\x00')]
    assert inspect_bytes(tmp_path, archive(plain_header(chain=chain)))['reason'] == '7Z_AES_DATA'
    assert inspect_bytes(tmp_path, archive(plain_header(b'\x7f')))['reason'] == '7Z_UNKNOWN_CODER'
    chain[1] = coder(b'\x7f')
    assert inspect_bytes(tmp_path, archive(plain_header(chain=chain)))['encryption'] == 'ENCRYPTED'


def bcj2_coder(inputs=4, outputs=1, props=b'', method=module.BCJ2):
    return (bytes([len(method) | 0x10 | (0x20 if props else 0)]) + method
            + number(inputs) + number(outputs)
            + (number(len(props)) + props if props else b''))


def bcj2_folder(*, branch=None, binds=None, indices=(0, 1, 2, 6), final=None):
    # Synthetic metadata only: three independent streams feed BCJ2, with a
    # fourth packed input consumed directly. No user archive data is embedded.
    branches = branch if branch is not None else [coder()] * 3
    pairs = binds if binds is not None else [(3, 0), (4, 1), (5, 2)]
    return (b'\x04' + b''.join(branches) + (final if final is not None else bcj2_coder())
            + b''.join(number(i) + number(o) for i, o in pairs)
            + b''.join(number(i) for i in indices))


def bcj2_streams(folder=None, *, sizes=(2, 2, 2, 2), outputs=4, repeats=1):
    folder = bcj2_folder() if folder is None else folder
    return (b'\x06\x00' + number(len(sizes)) + b'\x09'
            + b''.join(number(size) for size in sizes) + b'\x00\x07\x0b'
            + number(repeats) + b'\x00' + folder * repeats + b'\x0c'
            + number(8) * outputs * repeats + b'\x00\x00')


def bcj2_header(stream_info=None, members=1):
    return (b'\x01\x04' + (bcj2_streams() if stream_info is None else stream_info)
            + b'\x05' + number(members) + b'\x00\x00')


@pytest.mark.parametrize('encoded', [False, True])
@pytest.mark.parametrize('encrypted_branch', [None, 0, 1, 2])
def test_bcj2_branches_and_aes_markers(tmp_path, encoded, encrypted_branch):
    branches = [coder(module.LZMA, b'\x5d\x00\x10\x00\x00')] * 3
    if encrypted_branch is not None:
        branches[encrypted_branch] = coder(module.AES, b'\x13')
    header = bcj2_header(bcj2_streams(bcj2_folder(branch=branches, indices=(6, 2, 0, 1))))
    row = inspect_bytes(tmp_path, encoded_archive(header) if encoded else archive(header))
    assert row['encryption'] == ('ENCRYPTED' if encrypted_branch is not None else 'NO_ENCRYPTION_INDICATOR')
    assert module.BCJ2.hex() in row['seven_zip_methods']
    assert row['member_count'] == 1


def test_bcj2_single_coder_and_multiple_folders(tmp_path):
    folder = b'\x01' + bcj2_coder() + bytes(range(4))
    info = bcj2_streams(folder, outputs=1)
    assert inspect_bytes(tmp_path, archive(bcj2_header(info)))['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    info = bcj2_streams(sizes=(1,) * 8, repeats=2)
    row = inspect_bytes(tmp_path, archive(bcj2_header(info, members=2)))
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR' and row['member_count'] == 2


def test_bcj2_reordered_coders_and_aes_after_merge(tmp_path):
    # BCJ2 is coder 0, but AES (coder 1) owns the final output.
    folder = (b'\x04' + bcj2_coder() + coder(module.AES) + coder() * 2
              + bytes([4, 0, 1, 2, 2, 3]) + bytes([0, 3, 5, 6]))
    parsed = module._folder(module._Cursor(folder))
    assert parsed.final_output == 1 and parsed.packed_count == 4
    row = inspect_bytes(tmp_path, archive(bcj2_header(bcj2_streams(folder))))
    assert row['reason'] == '7Z_AES_DATA'


def test_bcj2_encoded_header_aes_marker_is_not_decoded(tmp_path, monkeypatch):
    folder = bcj2_folder(branch=[coder(module.AES), coder(), coder()])
    description = b'\x17' + bcj2_streams(folder, sizes=(1024,) * 4)
    def forbidden(*args):
        pytest.fail('encrypted metadata must not be decoded')
    monkeypatch.setattr(module, '_decode_header', forbidden)
    row = inspect_bytes(tmp_path, archive(description, b'x' * 4096))
    assert row['reason'] == '7Z_AES_HEADER'
    assert row['bytes_read'] == 512 + len(description)


@pytest.mark.parametrize('folder,reason', [
    (bcj2_folder(indices=(0, 1, 2, 2)), '7Z_INVALID_PACKED_INDICES'),
    (bcj2_folder(indices=(0, 1, 2, 7)), '7Z_INVALID_PACKED_INDICES'),
    (bcj2_folder(indices=(0, 1, 2, 3)), '7Z_INVALID_PACKED_INDICES'),
    (bcj2_folder(binds=[(3, 0), (3, 1), (5, 2)]), '7Z_INVALID_CODER_BINDINGS'),
    (bcj2_folder(binds=[(3, 0), (4, 0), (5, 2)]), '7Z_INVALID_CODER_BINDINGS'),
    (bcj2_folder(binds=[(7, 0), (4, 1), (5, 2)]), '7Z_INVALID_CODER_BINDINGS'),
    (bcj2_folder(binds=[(3, 4), (4, 1), (5, 2)]), '7Z_INVALID_CODER_BINDINGS'),
    # Self-cycle and a disconnected two-coder cycle, with valid packed indices.
    (bcj2_folder(binds=[(0, 0), (4, 1), (5, 2)], indices=(1, 2, 3, 6)), '7Z_INVALID_CODER_BINDINGS'),
    (bcj2_folder(binds=[(1, 0), (0, 1), (5, 2)], indices=(2, 3, 4, 6)), '7Z_INVALID_CODER_BINDINGS'),
    (bcj2_folder(final=bcj2_coder(inputs=3)), '7Z_INVALID_BCJ2_STREAM_COUNTS'),
    (bcj2_folder(final=bcj2_coder(outputs=2)), '7Z_INVALID_BCJ2_STREAM_COUNTS'),
    (bcj2_folder(final=coder(module.BCJ2)), '7Z_INVALID_BCJ2_STREAM_COUNTS'),
    (bcj2_folder(final=bcj2_coder(props=b'x')), '7Z_INVALID_CODER_PROPERTIES'),
    (bcj2_folder(final=bcj2_coder(method=b'\x7f')), '7Z_COMPLEX_CODER_UNSUPPORTED'),
])
def test_invalid_bcj2_graphs_stay_unknown(tmp_path, folder, reason):
    row = inspect_bytes(tmp_path, archive(bcj2_header(bcj2_streams(folder))))
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == reason


def test_bcj2_unknown_method_and_invalid_graph_with_aes(tmp_path):
    folder = bcj2_folder(branch=[coder(b'\x7f'), coder(), coder()])
    row = inspect_bytes(tmp_path, archive(bcj2_header(bcj2_streams(folder))))
    assert row['reason'] == '7Z_UNKNOWN_CODER'
    folder = bcj2_folder(branch=[coder(module.AES), coder(), coder()], indices=(0, 1, 2, 2))
    row = inspect_bytes(tmp_path, archive(bcj2_header(bcj2_streams(folder))))
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == '7Z_INVALID_PACKED_INDICES'


def test_bcj2_pack_counts_ranges_and_no_header_decoder(tmp_path):
    for sizes, reason in [((2, 2, 2), '7Z_PACK_STREAM_COUNT_MISMATCH'),
                          ((2, 2, 2, 3), '7Z_PACK_RANGE_INVALID')]:
        row = inspect_bytes(tmp_path, archive(bcj2_header(bcj2_streams(sizes=sizes))))
        assert row['encryption'] == 'UNKNOWN' and row['reason'] == reason
    row = inspect_bytes(tmp_path, archive(b'\x17' + bcj2_streams()))
    assert row['reason'] == '7Z_ENCODED_HEADER_CHAIN_UNSUPPORTED'
    folder = b'\x01' + bcj2_coder() + bytes(range(4))
    row = inspect_bytes(tmp_path, archive(b'\x17' + bcj2_streams(folder, outputs=1)))
    assert row['reason'] == '7Z_HEADER_CODEC_UNSUPPORTED'


def test_bcj2_large_payload_still_only_reads_metadata(tmp_path, monkeypatch):
    path = tmp_path/'large.7z'
    size = 100 * 1024 * 1024
    header = bcj2_header(bcj2_streams(sizes=(size - 6, 2, 2, 2)))
    start = struct.pack('<QQ', size, len(header)) + crc(header)
    with sparse_file(path) as stream:
        stream.write(b'7z\xbc\xaf\x27\x1c\x00\x04' + crc(start) + start)
        stream.seek(32 + size)
        stream.write(header)
    calls, original = [], inventory.BoundedReader.at
    def record(reader, offset, count):
        calls.append((offset, count))
        return original(reader, offset, count)
    monkeypatch.setattr(inventory.BoundedReader, 'at', record)
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    assert calls == [(0, 512), (32 + size, len(header))]
    assert row['bytes_read'] == 512 + len(header)


def test_aes_bytes_in_filename_properties_or_payload_are_not_markers(tmp_path):
    base = plain_header()
    # AES method bytes in an unrelated archive property and archive member data.
    header = b'\x01\x02\x42\x04' + module.AES + b'\x00' + base[1:]
    row = inspect_bytes(tmp_path, archive(header, module.AES * 2))
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'


@pytest.mark.parametrize('header,reason', [
    (b'\x17', '7Z_TRUNCATED_HEADER'),
    (b'\x01\x00x', '7Z_HEADER_TRAILING_DATA'),
    (b'\x01\x03', '7Z_ADDITIONAL_STREAMS_UNSUPPORTED'),
    (b'\x01\x05' + number(module.MAX_FILES + 1), '7Z_FILE_LIMIT'),
    (b'\x01\x05\x01\x00\x00', '7Z_FILE_STREAM_COUNT_MISMATCH'),
    (b'\x01\x05\x00\x42\x00\x00\x00', '7Z_FILE_PROPERTY_UNSUPPORTED'),
    (plain_header(module.AES, b'\x53'), '7Z_INVALID_AES_PROPERTIES'),
    (plain_header(module.LZMA2, b'\xff'), '7Z_INVALID_LZMA_PROPERTIES'),
    (plain_header(chain=[coder(), coder()], binds=[(0, 0)]), '7Z_INVALID_CODER_BINDINGS'),
    (plain_header(chain=[coder(), coder()], binds=[(9, 0)]), '7Z_INVALID_CODER_BINDINGS'),
])
def test_malformed_or_unsupported_headers_are_unknown(tmp_path, header, reason):
    row = inspect_bytes(tmp_path, archive(header))
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == reason


def test_bad_crc_and_ranges_never_classify(tmp_path):
    valid = archive(plain_header(module.AES, b'\x13'))
    for position, reason in [(8, '7Z_START_CRC_MISMATCH'), (-1, '7Z_NEXT_HEADER_CRC_MISMATCH')]:
        content = bytearray(valid)
        content[position] ^= 1
        row = inspect_bytes(tmp_path, content)
        assert row['encryption'] == 'UNKNOWN' and row['reason'] == reason
    row = inspect_bytes(tmp_path, archive(plain_header(packed_size=100)))
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == '7Z_PACK_RANGE_INVALID'


@pytest.mark.parametrize('kind', ['LZMA', 'LZMA2'])
def test_decoded_crc_sizes_and_trailing_bytes(tmp_path, kind):
    header = plain_header()
    for declared in (len(header) - 1, len(header) + 1, module.MAX_HEADER_BYTES + 1):
        row = inspect_bytes(tmp_path, encoded_archive(header, kind=kind, declared_size=declared))
        assert row['encryption'] == 'UNKNOWN'
    row = inspect_bytes(tmp_path, encoded_archive(header, kind=kind, append=b'extra'))
    assert row['reason'] == '7Z_COMPRESSED_HEADER_TRAILING_DATA'
    row = inspect_bytes(tmp_path, encoded_archive(header, kind=kind, packed_digest=1))
    assert row['reason'] == '7Z_PACKED_HEADER_CRC_MISMATCH'


def test_wrong_decoded_crc(tmp_path):
    header = plain_header()
    description = b'\x17' + streams(module.COPY, pack_pos=8, packed_size=len(header),
                                   unpacked_size=len(header), digest=1)
    row = inspect_bytes(tmp_path, archive(description, b'12345678' + header))
    assert row['reason'] == '7Z_DECODED_HEADER_CRC_MISMATCH'


def test_limits_apply_before_expensive_work(tmp_path, monkeypatch):
    row = inspect_bytes(tmp_path, encoded_archive(plain_header(), kind='LZMA', dictionary=0xffffffff))
    assert row['reason'] == '7Z_HEADER_DICTIONARY_LIMIT'
    monkeypatch.setattr(module, 'MAX_HEADER_BYTES', 8)
    row = inspect_bytes(tmp_path, archive(plain_header()))
    assert row['reason'] == '7Z_HEADER_SIZE_LIMIT'
    assert row['bytes_read'] <= 512


def test_decompression_output_cap_is_enforced_even_when_declared_size_is_small(tmp_path):
    row = inspect_bytes(tmp_path, encoded_archive(b'x' * (2 * module.MAX_HEADER_BYTES), declared_size=20))
    assert row['encryption'] == 'UNKNOWN'
    assert row['reason'] in ('7Z_INCOMPLETE_COMPRESSED_HEADER', '7Z_DECODED_HEADER_SIZE_MISMATCH')


def test_shared_read_budget(tmp_path, monkeypatch):
    content = encoded_archive(plain_header())
    monkeypatch.setattr(inventory, 'MAX_READ_CALLS', 2)
    row = inspect_bytes(tmp_path, content)
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'METADATA_READ_LIMIT'


def test_large_member_payload_is_not_read(tmp_path, monkeypatch):
    size = 100 * 1024 * 1024
    header = plain_header(packed_size=size)
    start = struct.pack('<QQ', size, len(header)) + crc(header)
    path = tmp_path/'sparse.bin'
    with sparse_file(path) as f:
        f.write(b'7z\xbc\xaf\x27\x1c\x00\x04' + crc(start) + start)
        f.seek(32 + size)
        f.write(header)
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    assert row['bytes_read'] == 512 + len(header)


def test_empty_archive_and_empty_directory(tmp_path):
    assert inspect_bytes(tmp_path, archive(b'', b''))['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    header = b'\x01\x05\x01\x0e\x01\x80\x00\x00'
    row = inspect_bytes(tmp_path, archive(header, b''))
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR' and row['member_count'] == 1


@pytest.mark.parametrize('bcj2', [False, True])
def test_resume_reclassifies_only_old_unknown_7z(tmp_path, monkeypatch, bcj2):
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    path = source/'example.7z'
    header = bcj2_header() if bcj2 else plain_header(module.AES, b'\x13')
    path.write_bytes(encoded_archive(header))
    (source/'ordinary.bin').write_bytes(b'ordinary')
    original = runner.inspect_file
    def old(path):
        if path.suffix == '.7z':
            return dict(format='7Z', encryption='UNKNOWN', structure='HEADER_CRC_CHECKED',
                        reason='7Z_COMPLEX_CODER_UNSUPPORTED' if bcj2 else
                               '7Z_ENCRYPTION_REQUIRES_DEEPER_PARSER', bytes_read=32)
        return original(path)
    monkeypatch.setattr(runner, 'inspect_file', old)
    runner.inventory(source, output)
    calls = []
    def new(target):
        calls.append(target)
        return original(target)
    monkeypatch.setattr(runner, 'inspect_file', new)
    second = runner.inventory(source, output, resume=True)
    assert calls == [path] and second['run']['reused'] == 1
    assert second['encryption_counts'] == {'NO_ENCRYPTION_INDICATOR' if bcj2 else 'ENCRYPTED': 1}
    third = runner.inventory(source, output, resume=True)
    assert third['run']['reused'] == 2 and third['run']['bytes_read'] == 0


@pytest.mark.parametrize('password,hidden,encoded', [
    (None, False, False), (None, False, True), ('test-only', False, False),
    ('test-only', False, True), ('test-only', True, True),
])
def test_independent_py7zr_writer(tmp_path, password, hidden, encoded):
    py7zr = pytest.importorskip('py7zr')  # Test-only; never used by the scanner.
    path = tmp_path/'independent.7z'
    with py7zr.SevenZipFile(path, 'w', password=password, header_encryption=hidden) as writer:
        if not encoded:
            writer.set_encoded_header_mode(False)
        writer.writestr(b'example content', 'example.txt')
        writer.writestr(b'another example', 'another.txt')
        writer.writestr(b'', 'empty.txt')
    row = inventory.inspect_file(path)
    assert row['encryption'] == ('ENCRYPTED' if password else 'NO_ENCRYPTION_INDICATOR')
    assert row['seven_zip_header_encrypted'] is hidden
    if not hidden:
        assert row['member_count'] == 3


@pytest.mark.parametrize('value', [0, 127, 128, 16383, 16384, 1 << 32, (1 << 64) - 1])
def test_number_decoder_boundaries(value):
    cursor = module._Cursor(number(value))
    assert cursor.number() == value
    cursor.done()


def test_truncated_variable_length_number_is_rejected():
    with pytest.raises(ValueError, match='7Z_TRUNCATED_HEADER'):
        module._Cursor(b'\xff\x01').number()
