from types import SimpleNamespace

import pytest

from bfrs.recovery.ntfs_extents import NtfsMappingPairsDecoder, NtfsMappingPairsError
from bfrs.recovery.ntfs_system_files import (
    NtfsResolvedStream, NtfsStreamChunk, NtfsStreamRun, NtfsSystemFileResolver,
)
from bfrs.recovery.ntfs_historical_wallet_recovery import (
    NtfsHistoricalWalletRecoveryPipeline,
)
from bfrs.recovery.ntfs_bitcoin_artifacts import NTFSFileNameAlias, _Record
from bfrs.recovery.ntfs_wallet_history import NtfsWalletHistoryAnalyzer
from bfrs.recovery.usn_journal import UsnJournalReader, UsnRecord


def _usn(version=2, name="wallet.dat", *, file_ref=0x100000000002A,
         parent_ref=0x1000000000014, reason=0x100):
    minimum = 60 if version == 2 else 76
    encoded = name.encode("utf-16le")
    length = (minimum + len(encoded) + 7) & ~7
    data = bytearray(length)
    data[0:4] = length.to_bytes(4, "little")
    data[4:6] = version.to_bytes(2, "little")
    if version == 2:
        data[8:16] = file_ref.to_bytes(8, "little")
        data[16:24] = parent_ref.to_bytes(8, "little")
        ts, rsn, attrs, nl, no = 32, 40, 52, 56, 58
    else:
        data[8:24] = file_ref.to_bytes(16, "little")
        data[24:40] = parent_ref.to_bytes(16, "little")
        ts, rsn, attrs, nl, no = 48, 56, 68, 72, 74
    data[ts:ts + 8] = 132537600000000000 .to_bytes(8, "little")
    data[rsn:rsn + 4] = reason.to_bytes(4, "little")
    data[attrs:attrs + 4] = (0x20).to_bytes(4, "little")
    data[nl:nl + 2] = len(encoded).to_bytes(2, "little")
    data[no:no + 2] = minimum.to_bytes(2, "little")
    data[minimum:minimum + len(encoded)] = encoded
    return bytes(data)


def _event(name, ref=0x100000000002A, parent=0x1000000000014, reason=0, offset=0):
    return UsnRecord(ref, parent, "2020-12-30T00:00:00+00:00", reason, 0x20,
                     name, 2, 0, "disk.img", offset, offset)


def test_usn_v2_valid():
    result = UsnJournalReader().parse_buffer(_usn(), source_image="x", physical_offset=100, logical_j_offset=8)
    assert result.records[0].filename == "wallet.dat"
    assert result.records[0].physical_offset == 100


def test_usn_v3_valid():
    result = UsnJournalReader().parse_buffer(_usn(3, "default_wallet"), source_image="x")
    assert result.records[0].major_version == 3


@pytest.mark.parametrize("mutation", ["short_length", "truncated", "bad_name"])
def test_usn_malformed(mutation):
    data = bytearray(_usn())
    if mutation == "short_length":
        data[0:4] = (16).to_bytes(4, "little")
    elif mutation == "truncated":
        data = data[:-8]
    else:
        data[58:60] = (0x7FFE).to_bytes(2, "little")
    result = UsnJournalReader().parse_buffer(bytes(data), source_image="x")
    assert not result.records
    assert result.failures


def test_sparse_prefix_and_multiple_physical_runs():
    # sparse 2 clusters, LCN +5 for 1, then LCN +3 for 2
    mapping = NtfsMappingPairsDecoder().decode(b"\x01\x02\x11\x01\x05\x11\x02\x03\0",
        lowest_vcn=0, highest_vcn=4, cluster_size=512, partition_offset=4096)
    assert mapping.runs[0].sparse
    assert [e.physical_start for e in mapping.extents] == [6656, 8192]


def test_malformed_runlist_is_controlled():
    with pytest.raises(NtfsMappingPairsError):
        NtfsMappingPairsDecoder().decode(b"\x11\x01", lowest_vcn=0,
                                          highest_vcn=None, cluster_size=512)


def test_duplicate_usn_events_are_aggregated():
    artifacts = NtfsWalletHistoryAnalyzer().analyze((_event("wallet.dat", offset=1), _event("wallet.dat", offset=2)))
    assert len(artifacts) == 1
    assert artifacts[0].event_count == 2


def test_active_wallet_deduplication():
    alias = SimpleNamespace(filename="wallet.dat", parent_mft_record_number=20)
    record = SimpleNamespace(allocated=True, sequence=1, aliases=(alias,))
    context = SimpleNamespace(current_records_by_number={42: record})
    artifact = NtfsWalletHistoryAnalyzer().analyze((_event("wallet.dat"),), context)[0]
    assert artifact.state == "ACTIVE_CURRENT"


def test_historical_unknown_electrum_wallet_direct_child():
    events = (_event("Electrum", ref=10, parent=5), _event("wallets", ref=20, parent=10),
              _event("anything-user-chose", ref=30, parent=20))
    artifacts = NtfsWalletHistoryAnalyzer().analyze(events)
    assert any(a.name == "anything-user-chose" and a.family == "electrum" for a in artifacts)


@pytest.mark.parametrize("name,family", [("electrum.dat", "electrum"),
                                           ("wallet.dat", "bitcoin_core")])
def test_canonical_wallet_names(name, family):
    assert NtfsWalletHistoryAnalyzer().analyze((_event(name),))[0].family == family


def test_ordinary_wallet_word_outside_context_is_not_candidate():
    assert not NtfsWalletHistoryAnalyzer().analyze((_event("my_wallet_notes.txt"),))


def _resident(kind, value):
    length = (24 + len(value) + 7) & ~7
    out = bytearray(length)
    out[0:4], out[4:8] = kind.to_bytes(4, "little"), length.to_bytes(4, "little")
    out[16:20], out[20:22] = len(value).to_bytes(4, "little"), (24).to_bytes(2, "little")
    out[24:24 + len(value)] = value
    return bytes(out)


def _nonresident_j(runlist=b"\x01\x01\x11\x01\x05\0", *, name="$J",
                   low=0, high=1, instance=0, logical_size=1024):
    name = name.encode("utf-16le")
    roff, length = 72, (72 + len(runlist) + 7) & ~7
    out = bytearray(length)
    out[0:4], out[4:8] = (0x80).to_bytes(4, "little"), length.to_bytes(4, "little")
    out[8], out[9] = 1, len(name) // 2
    out[10:12] = (64).to_bytes(2, "little")
    out[14:16] = instance.to_bytes(2, "little")
    out[16:24], out[24:32] = low.to_bytes(8, "little"), high.to_bytes(8, "little")
    out[32:34] = roff.to_bytes(2, "little")
    out[48:56] = logical_size.to_bytes(8, "little")
    out[56:64] = logical_size.to_bytes(8, "little")
    out[64:64 + len(name)], out[roff:roff + len(runlist)] = name, runlist
    return bytes(out)


def _record(*attrs, number=0, sequence=1, base=0, base_sequence=0,
            allocated=True, directory=False):
    raw = bytearray(1024)
    raw[:4] = b"FILE"
    raw[4:6], raw[6:8] = (48).to_bytes(2, "little"), (3).to_bytes(2, "little")
    raw[20:22], raw[28:32] = (56).to_bytes(2, "little"), (1024).to_bytes(4, "little")
    raw[16:18] = sequence.to_bytes(2, "little")
    raw[22:24] = ((1 if allocated else 0) | (2 if directory else 0)).to_bytes(2, "little")
    raw[32:40] = (base | (base_sequence << 48)).to_bytes(8, "little")
    raw[44:48] = number.to_bytes(4, "little")
    pos = 56
    for attr in attrs:
        raw[pos:pos + len(attr)], pos = attr, pos + len(attr)
    raw[pos:pos + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    raw[24:28] = (pos + 8).to_bytes(4, "little")
    raw[48:54] = b"\xaa\xbb\x11\x22\x33\x44"
    raw[510:512] = raw[1022:1024] = b"\xaa\xbb"
    return bytes(raw)


def test_resident_attribute_list_extension_and_named_j_stream(tmp_path):
    entry = bytearray(32)
    entry[0:4], entry[4:6] = (0x80).to_bytes(4, "little"), (32).to_bytes(2, "little")
    entry[6], entry[7], entry[26:30] = 2, 26, "$J".encode("utf-16le")
    entry[16:22] = (9).to_bytes(6, "little")
    records = {6: _record(_resident(0x20, bytes(entry)), number=6),
               9: _record(_nonresident_j(), number=9, base=6, base_sequence=1)}
    image = tmp_path / "disk.img"
    image.write_bytes(b"\0" * 8192)
    context = SimpleNamespace(source=str(image), boot=SimpleNamespace(bytes_per_sector=512,
        cluster_size=512, volume_offset=0), read_current_record=lambda n: records.get(n),
        current_records_by_number={6: SimpleNamespace(sequence=1)})
    resolver = NtfsSystemFileResolver(context)
    attrs, extensions = resolver._attributes_with_extensions(6)
    stream = resolver._stream(6, "$J", attrs, extensions)
    assert stream is not None and stream.extension_records == (9,)
    assert stream.runs[0].sparse and stream.runs[1].physical_start == 2560


def test_failure_isolation_for_bad_extension(tmp_path):
    entry = bytearray(32)
    entry[0:4], entry[4:6], entry[16:22] = (0x80).to_bytes(4, "little"), (32).to_bytes(2, "little"), (99).to_bytes(6, "little")
    context = SimpleNamespace(source=str(tmp_path / "x"), boot=SimpleNamespace(bytes_per_sector=512,
        cluster_size=512, volume_offset=0), read_current_record=lambda n: _record(_resident(0x20, bytes(entry))) if n == 6 else None,
        current_records_by_number={6: SimpleNamespace(sequence=1)})
    resolver = NtfsSystemFileResolver(context)
    with pytest.raises(ValueError, match="attribute_list_extent_missing"):
        resolver._attributes_with_extensions(6)
    assert any("extension_record_failure" in f for f in resolver.failures)


def _alist_entry(name, lowest_vcn, record, instance):
    encoded = name.encode("utf-16le")
    length = (26 + len(encoded) + 7) & ~7
    value = bytearray(length)
    value[0:4], value[4:6] = (0x80).to_bytes(4, "little"), length.to_bytes(2, "little")
    value[6], value[7] = len(name), 26
    value[8:16] = lowest_vcn.to_bytes(8, "little")
    value[16:24] = (record | (1 << 48)).to_bytes(8, "little")
    value[24:26] = instance.to_bytes(2, "little")
    value[26:26 + len(encoded)] = encoded
    return bytes(value)


def _resident_named(name, payload=b"", instance=0):
    encoded = name.encode("utf-16le")
    value_offset = (24 + len(encoded) + 7) & ~7
    length = (value_offset + len(payload) + 7) & ~7
    out = bytearray(length)
    out[0:4], out[4:8] = (0x80).to_bytes(4, "little"), length.to_bytes(4, "little")
    out[9], out[10:12], out[14:16] = len(name), (24).to_bytes(2, "little"), instance.to_bytes(2, "little")
    out[16:20], out[20:22] = len(payload).to_bytes(4, "little"), value_offset.to_bytes(2, "little")
    out[24:24 + len(encoded)] = encoded
    out[value_offset:value_offset + len(payload)] = payload
    return bytes(out)


def _model(number, name=None, parent=5, *, directory=False, allocated=True,
           sequence=1, base=0):
    aliases = () if name is None else (
        NTFSFileNameAlias(name, "win32", parent, 1),
    )
    return _Record(number, sequence, allocated, directory, aliases, None, base,
                   1 if base else 0)


def _resolver_context(tmp_path, raw_records, models):
    image = tmp_path / "resolver.img"
    image.write_bytes(b"\0" * 4096)
    return SimpleNamespace(
        source=str(image),
        boot=SimpleNamespace(bytes_per_sector=512, cluster_size=512,
                             volume_offset=0, volume_end=4096),
        read_current_record=lambda number: raw_records.get(number),
        current_records_by_number=models,
    )


def _structural_usn_fixture(tmp_path, *, duplicate=False, bad_second_base=False):
    entries = [
        _alist_entry("$J", 0, 41, 1),
        _alist_entry("$J", 2, 42, 2),
        _alist_entry("$Max", 0, 40, 3),
    ]
    if duplicate:
        entries.insert(1, entries[0])
    raw = {
        40: _record(_resident(0x20, b"".join(entries)),
                    _resident_named("$Max", instance=3), number=40),
        41: _record(_nonresident_j(b"\x11\x02\x05\0", low=0, high=1,
                                  instance=1, logical_size=2048),
                    number=41, base=40, base_sequence=1),
        42: _record(_nonresident_j(b"\x11\x02\x09\0", low=2, high=3,
                                  instance=2, logical_size=2048),
                    number=42, base=99 if bad_second_base else 40,
                    base_sequence=1),
        30: _record(_resident_named("", b"x"), number=30),
    }
    models = {
        5: _model(5, ".", 5, directory=True),
        11: _model(11, "$Extend", 5, directory=True),
        30: _model(30, "$UsnJrnl", 5),
        31: _model(31, "$UsnJrnl", 11, allocated=False),
        40: _model(40, "$UsnJrnl", 11),
        41: _model(41, base=40),
        42: _model(42, base=40),
    }
    return NtfsSystemFileResolver(_resolver_context(tmp_path, raw, models))


def test_structural_usn_candidate_beats_first_false_and_stale_candidates(tmp_path):
    resolver = _structural_usn_fixture(tmp_path)
    system = resolver.resolve()
    assert system.usn_jrnl_record_number == 40
    assert system.usn_j is not None
    assert system.usn_j.extension_records == (41, 42)
    assert [run.logical_start for run in system.usn_j.runs] == [0, 1024]
    assert any("wrong_extend_parent:30" in item for item in system.failures)
    assert any("not_allocated:31" in item for item in system.failures)


def test_duplicate_attribute_list_entry_is_deduplicated(tmp_path):
    resolver = _structural_usn_fixture(tmp_path, duplicate=True)
    system = resolver.resolve()
    assert system.usn_jrnl_record_number == 40
    assert system.usn_j.extension_records == (41, 42)
    assert "attribute_list_duplicate_entry" in system.failures


def test_extension_with_wrong_base_record_rejects_candidate(tmp_path):
    resolver = _structural_usn_fixture(tmp_path, bad_second_base=True)
    system = resolver.resolve()
    assert system.usn_jrnl_record_number is None
    assert system.usn_j is None
    assert any("extension_base_record_mismatch" in item for item in system.failures)


def test_multiple_structurally_valid_usn_candidates_are_ambiguous(tmp_path):
    resolver = _structural_usn_fixture(tmp_path)
    context = resolver.context
    context.current_records_by_number[50] = _model(50, "$UsnJrnl", 11)
    context.read_current_record = lambda number, original=context.read_current_record: (
        _record(_nonresident_j(b"\x11\x02\x0c\0", low=0, high=1,
                              logical_size=1024), number=50)
        if number == 50 else original(number)
    )
    system = resolver.resolve()
    assert system.usn_jrnl_record_number is None
    assert "usn_candidate_ambiguous" in system.failures


def test_usn_v2_crosses_chunk_boundary():
    raw = _usn(name="wallet.dat")
    chunks = (NtfsStreamChunk(0, raw[:31], 1000, False),
              NtfsStreamChunk(31, raw[31:], 1031, False))
    result = UsnJournalReader().parse_stream(chunks, source_image="disk.img")
    assert [item.filename for item in result.records] == ["wallet.dat"]
    assert result.records[0].logical_j_offset == 0


def test_usn_v2_crosses_two_contiguous_logical_physical_runs():
    raw = _usn(name="default_wallet")
    chunks = (NtfsStreamChunk(4096, raw[:40], 2000, False),
              NtfsStreamChunk(4136, raw[40:], 9000, False))
    record = UsnJournalReader().parse_stream(chunks, source_image="disk.img").records[0]
    assert record.logical_j_offset == 4096
    assert len(record.physical_segments) == 2
    assert record.physical_segments[1]["physical_start"] == 9000


def test_sparse_gap_never_joins_record_tail():
    first, second = _usn(name="wallet.dat"), _usn(name="electrum.dat")
    chunks = (NtfsStreamChunk(0, first[:32], 100, False),
              NtfsStreamChunk(512, b"", None, True),
              NtfsStreamChunk(1024, second, 5000, True))
    result = UsnJournalReader().parse_stream(chunks, source_image="disk.img")
    assert [item.filename for item in result.records] == ["electrum.dat"]
    assert "usn_record_truncated_at_logical_gap" in result.failures


def test_stream_truncated_record_at_available_end():
    raw = _usn()
    result = UsnJournalReader().parse_stream(
        (NtfsStreamChunk(0, raw[:-5], 0, False),), source_image="disk.img")
    assert not result.records
    assert result.failures == ("usn_record_truncated_at_stream_end",)


def test_stream_runs_are_read_in_logical_vcn_order(tmp_path):
    image = tmp_path / "runs.img"
    image.write_bytes(b"A" * 64 + b"B" * 64)
    context = SimpleNamespace(source=str(image))
    resolver = NtfsSystemFileResolver.__new__(NtfsSystemFileResolver)
    resolver.context, resolver.source, resolver.failures = context, image, []
    stream = NtfsResolvedStream(1, "$J", 128, 128, (
        NtfsStreamRun(64, 64, 0, False),
        NtfsStreamRun(0, 64, 64, False),
    ))
    chunks = tuple(resolver.iter_stream_chunks(stream, chunk_size=32))
    assert [item.logical_start for item in chunks] == [0, 32, 64, 96]
    assert b"".join(item.data for item in chunks) == b"B" * 64 + b"A" * 64


def _volume_context(start, provenance, *, identity_shift=0):
    boot = SimpleNamespace(volume_offset=start, volume_end=start + 100000,
        bytes_per_sector=512, sectors_per_cluster=8, cluster_size=4096,
        mft_lcn=4, record_size=1024)
    extent = SimpleNamespace(logical_start=0,
        physical_start=start + 16384 + identity_shift, length=1024)
    return SimpleNamespace(source="disk.img", boot=boot, mft_extents=(extent,),
        provenance=provenance, current_records_by_number={})


class _FakeResolver:
    def __init__(self, context):
        self.context, self.failures = context, []

    def resolve(self):
        if self.context.provenance == "detached_broken":
            raise ValueError("damaged_mft")
        stream = SimpleNamespace(logical_size=len(_usn()), initialized_size=len(_usn()),
                                 runs=())
        return SimpleNamespace(usn_jrnl_record_number=11, usn_j=stream, failures=())

    def iter_stream_chunks(self, stream):
        raw = _usn(name="wallet.dat")
        yield NtfsStreamChunk(0, raw, self.context.boot.volume_offset + 50000, False)


def test_main_and_detached_volume_contexts(monkeypatch):
    monkeypatch.setattr("bfrs.recovery.ntfs_historical_wallet_recovery.NtfsSystemFileResolver",
                        _FakeResolver)
    result = NtfsHistoricalWalletRecoveryPipeline().run((
        _volume_context(0, "main"), _volume_context(200000, "detached_structural")))
    assert result.volumes_examined == 2
    assert result.detached_volumes_examined == 1
    assert {a.volume_start for a in result.historical_wallet_artifacts} == {0, 200000}


def test_duplicate_detached_geometry_is_deduplicated(monkeypatch):
    monkeypatch.setattr("bfrs.recovery.ntfs_historical_wallet_recovery.NtfsSystemFileResolver",
                        _FakeResolver)
    context = _volume_context(200000, "detached_structural")
    duplicate = _volume_context(200000, "detached_duplicate")
    result = NtfsHistoricalWalletRecoveryPipeline().run((context, duplicate))
    assert result.volumes_examined == 1


def test_broken_detached_does_not_stop_main(monkeypatch):
    monkeypatch.setattr("bfrs.recovery.ntfs_historical_wallet_recovery.NtfsSystemFileResolver",
                        _FakeResolver)
    result = NtfsHistoricalWalletRecoveryPipeline().run((
        _volume_context(0, "main"), _volume_context(200000, "detached_broken")))
    assert result.volumes_examined == 2
    assert len(result.historical_wallet_artifacts) == 1
    assert any("damaged_mft" in failure for failure in result.failures)


def test_detached_artifact_preserves_volume_and_physical_provenance(monkeypatch):
    monkeypatch.setattr("bfrs.recovery.ntfs_historical_wallet_recovery.NtfsSystemFileResolver",
                        _FakeResolver)
    result = NtfsHistoricalWalletRecoveryPipeline().run((
        _volume_context(200000, "detached_structural"),))
    artifact = result.historical_wallet_artifacts[0]
    assert artifact.volume_start == 200000
    assert artifact.volume_provenance == "detached_structural"
    assert artifact.provenance[0]["physical_source_segments"][0]["physical_start"] == 250000
