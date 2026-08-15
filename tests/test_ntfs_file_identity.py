from __future__ import annotations

from dataclasses import asdict
import json
from types import SimpleNamespace

from bfrs.recovery.ntfs_bitcoin_artifacts import (
    NTFSDataExtent, NTFSFileNameAlias, _Data, _Record,
)
from bfrs.recovery.ntfs_file_identity import (
    NTFSFileIdentityResolver, NTFSTimestamps, _timestamps,
)


def _fn(name, namespace, parent=5, sequence=1, ticks=132537600000000000):
    encoded = name.encode("utf-16-le")
    value = bytearray(66 + len(encoded))
    value[:8] = (parent | (sequence << 48)).to_bytes(8, "little")
    for offset in (8, 16, 24, 32):
        value[offset:offset + 8] = ticks.to_bytes(8, "little")
    value[40:48] = (4096).to_bytes(8, "little")
    value[48:56] = (2804).to_bytes(8, "little")
    value[64] = len(name)
    value[65] = namespace
    value[66:] = encoded
    return bytes(value)


def _context(*records):
    by_number = {item.number: item for item in records}
    return SimpleNamespace(current_records_by_number=by_number)


def _record(number, name, *, parent=5, parent_sequence=1, sequence=1,
            active=True, directory=False, data=None):
    alias = NTFSFileNameAlias(name, "win32", parent, parent_sequence)
    return _Record(number, sequence, active, directory, (alias,), data)


def test_dos_and_win32_filename_pair_and_only_dos():
    dos = NTFSFileIdentityResolver._filename(_fn("000000~1.ELE", 2))
    win = NTFSFileIdentityResolver._filename(_fn("0000000000001.Electrum", 1))
    assert (dos.namespace, win.namespace) == ("DOS", "WIN32")
    assert dos.filename == "000000~1.ELE"
    assert [dos.namespace] == ["DOS"]


def test_multiple_filename_attributes_are_walked():
    def resident(value):
        length = (24 + len(value) + 7) & ~7
        raw = bytearray(length)
        raw[:4] = (0x30).to_bytes(4, "little")
        raw[4:8] = length.to_bytes(4, "little")
        raw[16:20] = len(value).to_bytes(4, "little")
        raw[20:22] = (24).to_bytes(2, "little")
        raw[24:24 + len(value)] = value
        return raw
    attrs = resident(_fn("SHORT~1.ELE", 2)) + resident(_fn("long.Electrum", 1))
    fixed = bytes(bytearray(56) + attrs + (0xFFFFFFFF).to_bytes(4, "little"))
    found = tuple(NTFSFileIdentityResolver._attributes(fixed, 56, len(fixed)))
    assert [item[2] for item in found] == [0x30, 0x30]


def test_correct_parent_chain():
    root = _record(5, ".", parent=5, sequence=1, directory=True)
    users = _record(10, "Users", parent=5, sequence=1, directory=True)
    file = NTFSFileIdentityResolver._filename(_fn("wallet.ele", 1, 10, 1))
    result = NTFSFileIdentityResolver(_context(root, users))._path(file)
    assert result.complete
    assert result.path == r"\Users\wallet.ele"
    assert result.parent_chain_mft == (10, 5)


def test_sequence_mismatch_and_broken_parent_chain():
    parent = _record(10, "Users", sequence=2, directory=True)
    name = NTFSFileIdentityResolver._filename(_fn("wallet.ele", 1, 10, 1))
    mismatch = NTFSFileIdentityResolver(_context(parent))._path(name)
    broken = NTFSFileIdentityResolver(_context())._path(name)
    assert not mismatch.complete and "PARENT_SEQUENCE_MISMATCH" in mismatch.reason_codes[0]
    assert not broken.complete and "PARENT_RECORD_MISSING" in broken.reason_codes[0]


def test_si_and_filename_timestamps_are_separate():
    si = _timestamps((132537600000000000).to_bytes(8, "little") * 4)
    fn = NTFSFileIdentityResolver._filename(
        _fn("wallet.ele", 1, ticks=133000000000000000)
    ).timestamps
    inference = NTFSFileIdentityResolver._timestamp_inferences(si, (
        SimpleNamespace(timestamps=fn),
    ))
    assert si.created != fn.created
    assert "SI_FILE_NAME_TIMESTAMPS_DIFFER" in inference


def test_alternate_data_stream_and_multiple_extents_metadata():
    resolver = NTFSFileIdentityResolver(SimpleNamespace(
        boot=SimpleNamespace(volume_end=1_000_000), source=__file__,
    ))
    fixed = bytearray(128)
    fixed[12:14] = (0).to_bytes(2, "little")
    fixed[16:20] = (12).to_bytes(4, "little")
    resident = resolver._data(bytes(fixed), 0, 64, 0, "Zone.Identifier")
    assert resident.stream_name == "Zone.Identifier" and resident.resident
    extents = (
        NTFSDataExtent(0, 1, 10, 1000, 5096, False),
        NTFSDataExtent(1, 2, 30, 9000, 13096, False),
    )
    assert len(extents) == 2 and [item.physical_lcn_start for item in extents] == [10, 30]


def test_sibling_ele_enumeration_and_generated_series(monkeypatch):
    data = _Data(False, 100, 4096, 100, (), "metadata")
    parent = _record(20, "recovery", directory=True)
    first = _record(30, "000000~1.ELE", parent=20, data=data)
    second = _record(31, "000000~2.ELE", parent=20, data=data)
    resolver = NTFSFileIdentityResolver(_context(parent, first, second))
    monkeypatch.setattr(resolver, "_directory_index_state",
                        lambda *args: ("ACTIVE_INDX_ENTRY_CONFIRMED", ()))
    name = NTFSFileIdentityResolver._filename(_fn("000000~1.ELE", 2, 20, 1))
    directory = resolver._directory(name)
    assert len(directory.ele_siblings) == 2
    assert directory.generated_name_series
    assert directory.category == "RECOVERY_DIRECTORY"


def test_safe_report_has_no_file_contents_or_secrets():
    name = NTFSFileIdentityResolver._filename(_fn("wallet.ele", 1))
    encoded = json.dumps(asdict(name))
    for secret in ("seed", "xprv", "private_key", "file_contents"):
        assert secret not in encoded
