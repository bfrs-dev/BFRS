from types import SimpleNamespace

import pytest

from bfrs.recovery.ntfs_bitcoin_artifacts import NTFSFileNameAlias, _Record
from bfrs.recovery.ntfs_logfile import (
    LfsPageParser, LfsRecordExtractor, LfsStructureError,
    NtfsLogFileAnalyzer,
)
from bfrs.recovery.ntfs_system_files import NtfsStreamChunk


PAGE = 4096
SECTOR = 512
DATA_OFFSET = 64


def _fixup(page, usa_offset):
    usn = b"\xa5\x5a"
    count = len(page) // SECTOR + 1
    page[4:6] = usa_offset.to_bytes(2, "little")
    page[6:8] = count.to_bytes(2, "little")
    replacements = []
    for index in range(1, count):
        trailer = index * SECTOR - 2
        replacements.append(bytes(page[trailer:trailer + 2]))
        page[trailer:trailer + 2] = usn
    page[usa_offset:usa_offset + count * 2] = usn + b"".join(replacements)
    return bytes(page)


def _restart_page():
    page = bytearray(PAGE)
    page[:4] = b"RSTR"
    page[16:20] = PAGE.to_bytes(4, "little")
    page[20:24] = PAGE.to_bytes(4, "little")
    page[24:26] = (64).to_bytes(2, "little")
    page[64 + 20:64 + 22] = (64).to_bytes(2, "little")
    page[64 + 36:64 + 38] = (48).to_bytes(2, "little")
    page[64 + 38:64 + 40] = DATA_OFFSET.to_bytes(2, "little")
    return _fixup(page, 32)


def _record(payload=b"wallet.dat".decode().encode("utf-16le"), *,
            client_length=None, lsn=100, record_type=1):
    length = len(payload) if client_length is None else client_length
    record = bytearray((48 + len(payload) + 7) & ~7)
    record[0:8] = lsn.to_bytes(8, "little")
    record[8:16] = (90).to_bytes(8, "little")
    record[16:24] = (80).to_bytes(8, "little")
    record[24:28] = length.to_bytes(4, "little")
    record[28:32] = (7).to_bytes(4, "little")
    record[32:36] = record_type.to_bytes(4, "little")
    record[36:40] = (123).to_bytes(4, "little")
    record[40:42] = (1).to_bytes(2, "little")
    record[48:48 + len(payload)] = payload
    return bytes(record)


def _record_page(records=(), *, slack=b""):
    page = bytearray(PAGE)
    page[:4] = b"RCRD"
    cursor = DATA_OFFSET
    for record in records:
        page[cursor:cursor + len(record)] = record
        cursor += len(record)
    page[24:26] = cursor.to_bytes(2, "little")
    if slack:
        page[cursor + 16:cursor + 16 + len(slack)] = slack
    return _fixup(page, 40)


def _segments(logical=0, physical=1000, length=PAGE):
    return ({"logical_start": logical, "physical_start": physical,
             "length": length, "page_logical_start": logical},)


def _context(records=None, volume=0):
    return SimpleNamespace(
        boot=SimpleNamespace(bytes_per_sector=SECTOR, volume_offset=volume),
        current_records_by_number={} if records is None else records,
    )


def _analyze(pages, *, chunks=None, context=None, usn=()):
    data = b"".join(pages)
    if chunks is None:
        chunks = (NtfsStreamChunk(0, data, 10000, False),)
    return NtfsLogFileAnalyzer().analyze(
        chunks, context=_context() if context is None else context,
        logical_size=len(data), usn_artifacts=usn,
    )


def test_valid_rstr_page():
    page = LfsPageParser().parse(_restart_page(), logical_offset=0,
                                 bytes_per_sector=SECTOR)
    assert page.kind == "RSTR"
    assert page.restart.log_page_size == PAGE
    assert page.restart.record_header_length == 48


@pytest.mark.parametrize("mutation,reason", [
    (lambda p: p.__setitem__(slice(0, 4), b"NOPE"), "signature"),
    (lambda p: p.__setitem__(slice(510, 512), b"xx"), "usa"),
])
def test_malformed_rstr_page(mutation, reason):
    page = bytearray(_restart_page())
    mutation(page)
    with pytest.raises(LfsStructureError, match=reason):
        LfsPageParser().parse(bytes(page), logical_offset=0,
                              bytes_per_sector=SECTOR)


def test_truncated_page():
    with pytest.raises(LfsStructureError, match="truncated|size"):
        LfsPageParser().parse(_restart_page()[:300], logical_offset=0,
                              bytes_per_sector=SECTOR)


def test_valid_rcrd_page_and_lfs_record():
    page = LfsPageParser().parse(
        _record_page((_record(),)), logical_offset=PAGE,
        bytes_per_sector=SECTOR, expected_log_page_size=PAGE,
        log_page_data_offset=DATA_OFFSET, physical_segments=_segments(PAGE),
    )
    records, failures = LfsRecordExtractor().extract(
        page, data_offset=DATA_OFFSET, record_header_length=48)
    assert not failures
    assert records[0].lsn == 100
    assert records[0].transaction_id == 123
    assert records[0].client_data.decode("utf-16le") == "wallet.dat"


def test_false_rcrd_signature():
    page = bytearray(_record_page())
    page[0:4] = b"RCRD"[::-1]
    with pytest.raises(LfsStructureError, match="signature"):
        LfsPageParser().parse(bytes(page), logical_offset=0,
                              bytes_per_sector=SECTOR,
                              expected_log_page_size=PAGE,
                              log_page_data_offset=DATA_OFFSET)


def test_truncated_lfs_record_and_client_length_outside_record():
    page = bytearray(_record_page((_record(),)))
    page[24:26] = (DATA_OFFSET + 32).to_bytes(2, "little")
    page = LfsPageParser().parse(_fixup(bytearray(page), 40), logical_offset=0,
        bytes_per_sector=SECTOR, expected_log_page_size=PAGE,
        log_page_data_offset=DATA_OFFSET)
    _, failures = LfsRecordExtractor().extract(page, data_offset=DATA_OFFSET,
                                                record_header_length=48)
    assert "lfs_record_truncated" in failures

    page = LfsPageParser().parse(_record_page((_record(b"abc", client_length=999),)),
        logical_offset=0, bytes_per_sector=SECTOR,
        expected_log_page_size=PAGE, log_page_data_offset=DATA_OFFSET)
    _, failures = LfsRecordExtractor().extract(page, data_offset=DATA_OFFSET,
                                                record_header_length=48)
    assert "lfs_client_data_bounds_invalid" in failures


def test_page_crosses_chunk_and_physical_run_boundary():
    data = _restart_page() + _record_page((_record(),))
    split = PAGE + 101
    chunks = (NtfsStreamChunk(0, data[:split], 10000, False),
              NtfsStreamChunk(split, data[split:], 90000, False))
    result = _analyze((), chunks=chunks)
    assert result.restart_pages_valid == 1
    assert result.record_pages_valid == 1
    assert result.lfs_records_valid == 1
    assert len(result.evidences[0].physical_provenance) == 2


def test_sparse_gap_resets_partial_page():
    partial = _restart_page()[:1000]
    full = _restart_page()
    chunks = (NtfsStreamChunk(0, partial, 100, False),
              NtfsStreamChunk(PAGE, b"", None, True),
              NtfsStreamChunk(PAGE * 2, full, 9000, True))
    result = _analyze((), chunks=chunks)
    assert result.restart_pages_valid == 1
    assert "lfs_page_truncated_at_gap" in result.failures


def test_utf16_outside_valid_lfs_record_is_not_evidence():
    raw = "wallet.dat".encode("utf-16le")
    result = _analyze((_restart_page(), _record_page((), slack=raw)))
    assert result.record_pages_valid == 1
    assert not result.evidences


@pytest.mark.parametrize("text,family", [
    ("wallet.dat", "bitcoin_core"),
    ("electrum.dat", "electrum"),
    (r"Users\A\Electrum\wallets\my-custom-name", "electrum"),
    ("Users\\A\\Electrum\\wallets\\mój-portfel", "electrum"),
])
def test_wallet_evidence_from_validated_payload(text, family):
    result = _analyze((_restart_page(),
                       _record_page((_record(text.encode("utf-16le")),))))
    assert result.evidences[0].family == family
    assert result.evidences[0].confidence == "HIGH"
    assert result.evidences[0].state == "HISTORICAL"


def test_ordinary_wallet_text_has_no_high_confidence_and_prefetch_is_ignored():
    result = _analyze((_restart_page(), _record_page((
        _record("wallet documentation.txt".encode("utf-16le"), lsn=1),
        _record("ELECTRUM-4.0.9.EXE-DA21FCF0.pf".encode("utf-16le"), lsn=2),
    ))))
    assert not result.evidences
    assert result.ignored_application_references == 1


def test_duplicate_events_are_aggregated():
    result = _analyze((_restart_page(), _record_page((
        _record(lsn=1), _record(lsn=2),
    ))))
    assert len(result.evidences) == 1
    assert result.evidences[0].event_count == 2


def test_correlation_with_active_mft_and_usn():
    alias = NTFSFileNameAlias("wallet.dat", "win32", 5, 1)
    current = _Record(20, 1, True, False, (alias,), None)
    usn = SimpleNamespace(name="wallet.dat", state="HISTORICAL", volume_start=0)
    result = _analyze((_restart_page(), _record_page((_record(),))),
        context=_context({20: current}), usn=(usn,))
    evidence = result.evidences[0]
    assert evidence.state == "ACTIVE_CURRENT"
    assert evidence.correlated_sources == ("LOGFILE", "MFT", "USN_JOURNAL")


def test_logfile_name_alone_never_means_deleted():
    result = _analyze((_restart_page(), _record_page((_record(),))))
    assert result.evidences[0].state == "HISTORICAL"
