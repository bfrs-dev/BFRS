"""Carve bounded NTFS 3.x FILE records for EFS metadata, never file contents.

Works without a partition table/boot sector. Physical records can be stale,
deleted or duplicate copies; neither current allocation nor paths are inferred.
"""
from __future__ import annotations

import json
import re
import sys

from .archive_name_hints import name_hint
from .ntfs_mft_data import NtfsMftDataExtractor, NtfsMftRecordError
from .raw_zip_inventory import _atomic_text, scan_image as _scan_image

FORMAT = 'BFRS_RAW_EFS_INVENTORY_V1'
DATABASE = 'efs_scan.sqlite'
SIGNATURES = re.compile(b'FILE')
MAX_RECORD_BYTES = 65536
ENCRYPTED = 0x4000
STATUSES = ('DIRECTORY_ENCRYPTION_DEFAULT', 'EFS_METADATA_AND_ENCRYPTED_FLAG',
            'ENCRYPTED_FLAG_ONLY', 'EFS_STREAM_ONLY', 'FILE_NAME_FLAG_ONLY')
LIMITATIONS = [
    'PHYSICAL_RECORDS_NOT_UNIQUE_OR_CURRENT_FILES',
    'IN_USE_FLAG_IS_HISTORICAL_NOT_CURRENT_ALLOCATION_PROOF',
    'DIRECTORY_FLAG_DOES_NOT_PROVE_CHILDREN_ENCRYPTED',
    'NO_DECRYPTION_EXTRACTION_OR_WALLET_CONTENT_VALIDATION',
    'EFS_STREAM_HEADER_ONLY_NO_CRYPTOGRAPHIC_PAYLOAD_VALIDATION',
    'NO_PATH_OR_VOLUME_RECONSTRUCTION_OR_EXTENSION_RECORD_JOIN',
    'CONTIGUOUS_FILE_RECORDS_ONLY_512_TO_65536_BYTES',
    'DAMAGED_OR_OVERWRITTEN_METADATA_MAY_BE_MISSED',
    'FULL_BYTE_COVERAGE_DOES_NOT_PROVE_ABSENCE_OF_EFS',
    'RAW_BYTES_NO_IMAGE_CONTAINER_OR_BITLOCKER_DECODING',
    'NTFS_3_X_METADATA_NOT_WINDOWS_VERSION_IDENTIFICATION',
    'SOURCE_IDENTITY_SAMPLED_NOT_FULL_HASH',
]


def _u(data, offset, size=4):
    return int.from_bytes(data[offset:offset + size], 'little')


def _reference(value):
    return {'record': value & ((1 << 48) - 1), 'sequence': value >> 48}


def _attributes(fixed, first, used):
    """Validate every envelope before accepting any encryption indicator."""
    offset = first
    instances = set()
    while offset + 4 <= used:
        kind = _u(fixed, offset)
        if kind == 0xffffffff:
            return
        if offset + 16 > used or not 0x10 <= kind <= 0x100 or kind % 16:
            raise NtfsMftRecordError('invalid_attribute_type_or_header')
        length = _u(fixed, offset + 4)
        form, name_len = fixed[offset + 8:offset + 10]
        flags, instance = _u(fixed, offset + 12, 2), _u(fixed, offset + 14, 2)
        minimum = 64 if form == 1 else 24
        if (form not in (0, 1) or length < minimum or length % 8
                or offset + length > used or instance in instances):
            raise NtfsMftRecordError('invalid_attribute_bounds_or_instance')
        instances.add(instance)
        name_start = _u(fixed, offset + 10, 2)
        name_end = name_start + name_len * 2
        if name_len and (name_start < minimum or name_start % 2 or name_end > length):
            raise NtfsMftRecordError('invalid_attribute_name_bounds')
        name = fixed[offset + name_start:offset + name_end].decode('utf-16-le') if name_len else ''
        if '\0' in name:
            raise NtfsMftRecordError('invalid_attribute_name')
        value = None
        if form == 0:
            start, size = _u(fixed, offset + 20, 2), _u(fixed, offset + 16)
            if start < minimum or start + size > length or (name_len and start < name_end):
                raise NtfsMftRecordError('invalid_resident_value_bounds')
            value = fixed[offset + start:offset + start + size]
        else:
            start = _u(fixed, offset + 32, 2)
            if start < minimum or start >= length or (name_len and start < name_end):
                raise NtfsMftRecordError('invalid_mapping_pairs_bounds')
            # Validate the bounded runlist shape without following disk extents.
            position, clusters, lcn = offset + start, 0, 0
            while position < offset + length:
                header = fixed[position]
                position += 1
                if header == 0:
                    break
                width, delta = header & 15, header >> 4
                if not 1 <= width <= 8 or delta > 8 or position + width + delta > offset + length:
                    raise NtfsMftRecordError('invalid_mapping_pairs')
                count = _u(fixed, position, width)
                if count == 0:
                    raise NtfsMftRecordError('empty_data_run')
                clusters += count
                if delta:
                    lcn += int.from_bytes(fixed[position + width:position + width + delta], 'little', signed=True)
                    if lcn < 0:
                        raise NtfsMftRecordError('negative_lcn')
                position += width + delta
            else:
                raise NtfsMftRecordError('unterminated_mapping_pairs')
            low, high = _u(fixed, offset + 16, 8), _u(fixed, offset + 24, 8)
            size = _u(fixed, offset + 48, 8)
            if (clusters and (high < low or clusters != high - low + 1)
                    or not clusters and size != 0
                    or low == 0 and _u(fixed, offset + 56, 8) > size):
                raise NtfsMftRecordError('invalid_nonresident_sizes')
        yield kind, name, flags, value, size, bool(form)
        offset += length
    raise NtfsMftRecordError('missing_attribute_end')


def parse_record(raw):
    """Return only EFS candidates from a fully validated contiguous FILE record."""
    size = len(raw)
    if (size < 512 or size > MAX_RECORD_BYTES or size & (size - 1)
            or raw[:4] != b'FILE' or _u(raw, 28) != size):
        raise NtfsMftRecordError('invalid_record_size')
    usa, count = _u(raw, 4, 2), _u(raw, 6, 2)
    if count < 2 or size % (count - 1):
        raise NtfsMftRecordError('invalid_usa_geometry')
    stride = size // (count - 1)
    if stride not in (512, 1024, 2048, 4096) or usa < 48 or usa % 2 or usa + count * 2 > stride - 2:
        raise NtfsMftRecordError('unsupported_usa_geometry')
    fixed, _, _ = NtfsMftDataExtractor()._apply_fixup(raw, stride)
    first, used = _u(fixed, 20, 2), _u(fixed, 24)
    sequence, flags = _u(fixed, 16, 2), _u(fixed, 22, 2)
    if (first < usa + count * 2 or first % 8 or first + 4 > used or used > size
            or not sequence or flags & ~3):
        raise NtfsMftRecordError('invalid_record_header')
    base = _u(fixed, 32, 8)
    if base and not base >> 48:
        raise NtfsMftRecordError('invalid_base_reference')
    si_flags, names, streams, data_flags = None, [], [], []
    attribute_list = False
    for kind, name, attr_flags, value, length, nonresident in _attributes(fixed, first, used):
        if kind == 0x10:
            if name or nonresident or len(value) not in (48, 72) or si_flags is not None or base:
                raise NtfsMftRecordError('invalid_standard_information')
            si_flags = _u(value, 32)
        elif kind == 0x30:
            if name or nonresident or len(value) < 66:
                raise NtfsMftRecordError('invalid_file_name')
            n, namespace = value[64:66]
            if not n or namespace > 3 or 66 + n * 2 != len(value):
                raise NtfsMftRecordError('invalid_file_name_length')
            filename = value[66:].decode('utf-16-le')
            if any(char in filename for char in ('\0', '/', '\\')):
                raise NtfsMftRecordError('invalid_file_name_characters')
            names.append({'name': filename, 'namespace': namespace,
                          'parent': _reference(_u(value, 0, 8)), 'flags': _u(value, 56)})
        elif kind == 0x80 and attr_flags & ENCRYPTED:
            data_flags.append({'stream_name': name, 'nonresident': nonresident})
        elif kind == 0x100 and name == '$EFS':
            streams.append({'nonresident': nonresident, 'declared_size': length,
                            'payload_validated': False})
        elif kind == 0x20:
            attribute_list = True
    if not base and si_flags is None:
        raise NtfsMftRecordError('base_record_without_standard_information')
    si_encrypted = bool((si_flags or 0) & ENCRYPTED)
    fn_encrypted = any(item['flags'] & ENCRYPTED for item in names)
    if not (si_encrypted or fn_encrypted or data_flags or streams):
        return None
    directory = bool(flags & 2)
    if directory and si_encrypted:
        status = 'DIRECTORY_ENCRYPTION_DEFAULT'
    elif not directory and (si_encrypted or data_flags) and streams:
        status = 'EFS_METADATA_AND_ENCRYPTED_FLAG'
    elif si_encrypted or data_flags:
        status = 'ENCRYPTED_FLAG_ONLY'
    elif streams:
        status = 'EFS_STREAM_ONLY'
    else:
        status = 'FILE_NAME_FLAG_ONLY'
    hints = [hint for item in names if (hint := name_hint(item['name'])) is not None]
    wallet_hint = any(hint['category'] == 'WALLET_NAME' for hint in hints)
    display_name = ('; '.join(item['name'] for item in names if item['namespace'] != 2)
                    or '; '.join(item['name'] for item in names))
    return {
        'record_type': 'EXTENSION_RECORD' if base else 'DIRECTORY_RECORD' if directory else 'FILE_RECORD',
        'record_status': status,
        'priority': 4 if wallet_hint else 2 if si_encrypted or data_flags else 1,
        'encryption': 'ENCRYPTION_DEFAULT' if directory and si_encrypted else
                      'ENCRYPTED_METADATA' if not directory and (si_encrypted or data_flags) else 'HINT_ONLY',
        'record_number_hint': _u(fixed, 44), 'sequence': sequence,
        'record_in_use_flag': bool(flags & 1), 'directory_flag': directory,
        'base_reference': _reference(base) if base else None,
        'record_size': size, 'fixup_stride': stride,
        'standard_information_flags': si_flags, 'file_names': names[:128],
        'display_name': display_name[:4096],
        'encrypted_data_attributes': data_flags[:128], 'efs_stream_headers': streams[:128],
        'attribute_list_present': attribute_list, 'name_hints': hints[:50],
        'report_details_truncated': (len(names) > 128 or len(data_flags) > 128
                                     or len(streams) > 128 or len(hints) > 50 or len(display_name) > 4096),
        'path_status': 'UNRESOLVED', 'current_allocation': 'UNKNOWN',
    }


def inspect_record(reader, offset, signature):
    try:
        header = reader.at(offset, 48)
        if len(header) != 48:
            return None
        size = _u(header, 28)
        if size < 512 or size > MAX_RECORD_BYTES or size & (size - 1):
            return None
        row = parse_record(reader.at(offset, size))
        if row is not None:
            row['offset'] = offset
        return row
    except ValueError:
        return None


def export(connection, output, identity, reason, io_counts, source_unchanged):
    metadata = {key: json.loads(value) for key, value in connection.execute('SELECT key,value FROM metadata')}
    cursor = metadata['next_offset']
    counts = dict(connection.execute('SELECT status,count(*) FROM hits GROUP BY status'))
    for filename, where in (('efs_hits.jsonl', ''), ('efs_wallet_names.jsonl', 'WHERE priority=4')):
        with _atomic_text(output, filename) as stream:
            for (payload,) in connection.execute(f'SELECT result FROM hits {where} ORDER BY priority DESC,offset'):
                stream.write(payload + '\n')
    summary = {
        'format': FORMAT, 'source': identity, 'source_size': identity['stat'][0],
        'scan_complete': cursor == identity['stat'][0] and source_unchanged and reason == 'COMPLETE',
        'source_unchanged': source_unchanged, 'stop_reason': reason, 'scanned_prefix_end': cursor,
        'signature_counts': metadata['counters'], 'evidence_counts': counts,
        'candidate_record_count': sum(counts.values()), 'io_this_run': io_counts,
        'count_scope': 'PHYSICAL_FILE_RECORDS_NOT_UNIQUE_FILES_OR_FOLDERS',
        'rejected_signature_scope': 'INVALID_UNSUPPORTED_OR_WITHOUT_EFS_INDICATORS',
        'limitations': LIMITATIONS,
    }
    with _atomic_text(output, 'summary.json') as stream:
        json.dump(summary, stream, ensure_ascii=False, indent=2)
    return summary


def scan_image(source, output, **kwargs):
    return _scan_image(source, output, _profile=sys.modules[__name__], **kwargs)
