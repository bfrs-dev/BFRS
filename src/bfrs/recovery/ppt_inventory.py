"""Bounded CurrentUserAtom/latest UserEditAtom encryption-marker inspection.

MS-PPT 2.3.2, 2.3.3 and Appendix A <6>/<11>: PowerPoint 2002 can use
the ordinary header token for encrypted documents. No slide/persist payloads
are decoded, and encryption references are reported without resolving targets.
"""
import struct

MAX_CHAIN_SECTORS = 65536
PPT_INVENTORY_REVISION = 1


class PPTMetadataLimit(ValueError):
    pass


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


class _Stream:
    """Map only the FAT prefix needed for targeted reads, without reading it as data."""
    def __init__(self, reader, ole, name):
        self.reader, self.ole = reader, ole
        self.entry = ole.direntries[ole._find(name)]
        _require(self.entry.entry_type == 2, 'PPT_EXPECTED_STREAM')
        self.size = self.entry.size
        self.mini = None
        self.chain, self.seen = [], set()
        if self.size < ole.minisectorcutoff:
            # olefile handles MiniFAT; all backing reads retain the shared budget.
            self.mini = ole.openstream(name)

    def at(self, offset, length):
        _require(0 <= offset <= self.size and 0 <= length <= self.size - offset,
                 'PPT_STREAM_RANGE_INVALID')
        if not length:
            return b''
        if self.mini is not None:
            self.mini.seek(offset)
            data = self.mini.read(length)
            _require(len(data) == length, 'PPT_TRUNCATED_STREAM')
            return data
        sector_size = self.ole.sectorsize
        first, last = offset // sector_size, (offset + length - 1) // sector_size
        if last >= MAX_CHAIN_SECTORS:
            raise PPTMetadataLimit('PPT_FAT_CHAIN_LIMIT')
        while len(self.chain) <= last:
            sector = self.ole.fat[self.chain[-1]] if self.chain else self.entry.isectStart
            _require(0 <= sector < len(self.ole.fat), 'PPT_FAT_SECTOR_INVALID')
            _require(sector not in self.seen, 'PPT_FAT_CYCLE')
            _require((sector + 1) * sector_size + sector_size <= self.reader.size,
                     'PPT_FAT_SECTOR_OUT_OF_FILE')
            self.seen.add(sector)
            self.chain.append(sector)
        parts = []
        for index in range(first, last + 1):
            start = offset % sector_size if index == first else 0
            take = min(length, sector_size - start)
            parts.append(self.reader.at((self.chain[index] + 1) * sector_size + start, take))
            length -= take
        return b''.join(parts)


def inspect_ppt(reader, ole):
    _require(ole.exists('Current User') and ole.exists('PowerPoint Document'),
             'PPT_REQUIRED_STREAM_MISSING')
    current = _Stream(reader, ole, 'Current User')
    data = current.at(0, 28)
    flags, record, length, fixed, token, edit_offset, name_len, version = struct.unpack_from('<HHLLLLHH', data)
    _require(flags == 0 and record == 0x0ff6 and fixed == 20,
             'PPT_INVALID_CURRENT_USER')
    _require(name_len <= 255 and length in (24 + name_len, 24 + 3 * name_len)
             and length + 8 <= current.size, 'PPT_INVALID_CURRENT_USER_SIZE')
    if version != 0x03f4 or data[24:26] != b'\x03\x00':
        raise PPTMetadataLimit('PPT_VERSION_UNSUPPORTED')
    release = struct.unpack('<L', current.at(28 + name_len, 4))[0]
    _require(release in (8, 9), 'PPT_INVALID_RELEASE_VERSION')
    if token not in (0xe391c05f, 0xf3d1c4df):
        raise PPTMetadataLimit('PPT_HEADER_TOKEN_UNSUPPORTED')
    document = _Stream(reader, ole, 'PowerPoint Document')
    _require(0 < edit_offset <= document.size - 36, 'PPT_EDIT_OFFSET_INVALID')
    result = dict(ppt_scope='CURRENT_USER_AND_LATEST_EDIT_METADATA_ONLY',
                  ppt_header_token=f'{token:08X}', ppt_current_edit_offset=edit_offset,
                  ppt_inventory_revision=PPT_INVENTORY_REVISION,
                  ppt_password_required='NOT_CHECKED')
    if token == 0xf3d1c4df:
        result.update(encryption='ENCRYPTED', reason='PPT_ENCRYPTED_HEADER_TOKEN',
                      structure='CURRENT_USER_CHECKED')
        return result
    header = document.at(edit_offset, 8)
    flags, record, length = struct.unpack('<HHL', header)
    _require(flags == 0 and record == 0x0ff5 and length in (28, 32),
             'PPT_INVALID_USER_EDIT')
    edit = document.at(edit_offset + 8, length)
    _require(edit[6:8] == b'\x00\x03', 'PPT_INVALID_USER_EDIT_VERSION')
    previous, directory, doc_id, seed = struct.unpack_from('<LLLL', edit, 8)
    _require(previous < directory < edit_offset and doc_id == 1 and 1 <= seed <= 0x100000,
             'PPT_INVALID_EDIT_REFERENCES')
    reference = struct.unpack_from('<L', edit, 28)[0] if length == 32 else None
    if reference is not None:
        _require(1 <= reference <= min(seed, 0xfffff), 'PPT_INVALID_ENCRYPTION_REFERENCE')
    result.update(encryption='ENCRYPTED' if reference is not None else 'NO_ENCRYPTION_INDICATOR',
                  reason='PPT_ENCRYPTION_REFERENCE' if reference is not None else 'PPT_NO_ENCRYPTION_MARKER',
                  structure='CURRENT_USER_AND_LATEST_EDIT_CHECKED',
                  ppt_encrypt_session_persist_id=reference)
    return result
