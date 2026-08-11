import json

import pytest

from bfrs.cli import BITCOIN_CORE_SIGNATURES_V1
from bfrs.core.models import ValidationStatus
from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator
from bfrs.recovery.ntfs_bitcoin_artifacts import (
    NTFSBitcoinArtifactLocator,
)
from bfrs.reporting.json_report import _ntfs_bitcoin_artifact_index
from bfrs.validators.candidate_policy import CandidatePolicy


SECTOR = 512
CLUSTER = 4096
RECORD = 1024
MFT_LCN = 4
MFT_RECORDS = 8
IMAGE_SIZE = 1024 * 1024


def align8(value: int) -> int:
    return (value + 7) & ~7


def resident(type_code: int, value: bytes) -> bytes:
    size = align8(24 + len(value))
    result = bytearray(size)
    result[0:4] = type_code.to_bytes(4, "little")
    result[4:8] = size.to_bytes(4, "little")
    result[16:20] = len(value).to_bytes(4, "little")
    result[20:22] = (24).to_bytes(2, "little")
    result[24:24 + len(value)] = value
    return bytes(result)


def filename(name: str, parent: int = 5, parent_sequence: int = 1, namespace: int = 1) -> bytes:
    encoded = name.encode("utf-16-le")
    value = bytearray(66 + len(encoded))
    reference = parent | (parent_sequence << 48)
    value[0:8] = reference.to_bytes(8, "little")
    value[64] = len(name)
    value[65] = namespace
    value[66:] = encoded
    return resident(0x30, bytes(value))


def data_resident(payload: bytes) -> bytes:
    return resident(0x80, payload)


def run(count: int, lcn_delta: int) -> bytes:
    length = count.to_bytes(1, "little")
    delta = lcn_delta.to_bytes(2 if lcn_delta > 127 else 1, "little", signed=True)
    return bytes(((len(delta) << 4) | 1,)) + length + delta


def sparse_run(count: int) -> bytes:
    return b"\x01" + count.to_bytes(1, "little")


def data_nonresident(
    pairs: bytes,
    highest_vcn: int,
    *,
    logical_size: int = 8192,
    allocated_size: int = 8192,
    flags: int = 0,
) -> bytes:
    size = align8(64 + len(pairs))
    result = bytearray(size)
    result[0:4] = (0x80).to_bytes(4, "little")
    result[4:8] = size.to_bytes(4, "little")
    result[8] = 1
    result[12:14] = flags.to_bytes(2, "little")
    result[24:32] = highest_vcn.to_bytes(8, "little")
    result[32:34] = (64).to_bytes(2, "little")
    result[40:48] = allocated_size.to_bytes(8, "little")
    result[48:56] = logical_size.to_bytes(8, "little")
    result[56:64] = logical_size.to_bytes(8, "little")
    result[64:64 + len(pairs)] = pairs
    return bytes(result)


def file_record(
    number: int,
    attributes: tuple[bytes, ...],
    *,
    allocated: bool = True,
    directory: bool = False,
    sequence: int = 1,
) -> bytes:
    fixed = bytearray(RECORD)
    fixed[:4] = b"FILE"
    fixed[4:6] = (48).to_bytes(2, "little")
    fixed[6:8] = (3).to_bytes(2, "little")
    fixed[16:18] = sequence.to_bytes(2, "little")
    fixed[20:22] = (56).to_bytes(2, "little")
    fixed[22:24] = ((1 if allocated else 0) | (2 if directory else 0)).to_bytes(2, "little")
    fixed[28:32] = RECORD.to_bytes(4, "little")
    fixed[44:48] = number.to_bytes(4, "little")
    cursor = 56
    for attribute in attributes:
        fixed[cursor:cursor + len(attribute)] = attribute
        cursor += len(attribute)
    fixed[cursor:cursor + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    fixed[24:28] = (cursor + 4).to_bytes(4, "little")
    usn = b"\xa5\x5a"
    replacements = (bytes(fixed[510:512]), bytes(fixed[1022:1024]))
    fixed[48:54] = usn + replacements[0] + replacements[1]
    fixed[510:512] = usn
    fixed[1022:1024] = usn
    return bytes(fixed)


def boot_sector() -> bytes:
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x52\x90"
    boot[3:11] = b"NTFS    "
    boot[11:13] = SECTOR.to_bytes(2, "little")
    boot[13] = CLUSTER // SECTOR
    boot[40:48] = (IMAGE_SIZE // SECTOR).to_bytes(8, "little")
    boot[48:56] = MFT_LCN.to_bytes(8, "little")
    boot[56:64] = (8).to_bytes(8, "little")
    boot[64] = (-10) & 0xFF
    boot[510:512] = b"\x55\xaa"
    return bytes(boot)


def image_with(records: dict[int, bytes], *, mbr: bool = False) -> bytes:
    volume_offset = CLUSTER if mbr else 0
    image = bytearray(IMAGE_SIZE + volume_offset)
    image[volume_offset:volume_offset + 512] = boot_sector()
    if mbr:
        image[510:512] = b"\x55\xaa"
        entry = bytearray(16)
        entry[4] = 0x07
        entry[8:12] = (volume_offset // 512).to_bytes(4, "little")
        entry[12:16] = (IMAGE_SIZE // 512).to_bytes(4, "little")
        image[446:462] = entry
    mft_pairs = run(MFT_RECORDS * RECORD // CLUSTER, MFT_LCN) + b"\x00"
    mft_data = data_nonresident(
        mft_pairs,
        MFT_RECORDS * RECORD // CLUSTER - 1,
        logical_size=MFT_RECORDS * RECORD,
        allocated_size=MFT_RECORDS * RECORD,
    )
    all_records = {0: file_record(0, (mft_data,)), **records}
    start = volume_offset + MFT_LCN * CLUSTER
    for number, record in all_records.items():
        image[start + number * RECORD:start + (number + 1) * RECORD] = record
    return bytes(image)


def locate(tmp_path, records: dict[int, bytes], *, mbr: bool = False):
    path = tmp_path / "ntfs.img"
    path.write_bytes(image_with(records, mbr=mbr))
    return NTFSBitcoinArtifactLocator().index(path)


def test_allocated_wallet_fragmented_nonresident_extents(tmp_path) -> None:
    pairs = run(1, 40) + run(1, 20) + b"\x00"
    wallet = file_record(6, (filename("wallet.dat"), data_nonresident(pairs, 1)))
    result = locate(tmp_path, {6: wallet})
    candidate = result.candidates[0]
    assert result.wallet_dat_candidate_count == 1
    assert candidate.allocation_state == "allocated"
    assert candidate.extent_count == 2
    assert [extent.vcn_start for extent in candidate.extents] == [0, 1]
    assert [extent.physical_lcn_start for extent in candidate.extents] == [40, 60]


def test_deleted_wallet_keeps_stale_possible_extent_map(tmp_path) -> None:
    wallet = file_record(6, (filename("wallet.dat"), data_nonresident(run(2, 40) + b"\x00", 1)), allocated=False)
    candidate = locate(tmp_path, {6: wallet}).candidates[0]
    assert candidate.allocation_state == "deleted"
    assert candidate.extent_trust == "stale_possible"
    assert candidate.extent_count == 1


def test_win32_and_dos_aliases_are_one_candidate(tmp_path) -> None:
    wallet = file_record(6, (filename("wallet.dat"), filename("WALLET~1.DAT", namespace=2), data_resident(b"secret")))
    result = locate(tmp_path, {6: wallet})
    assert result.wallet_dat_candidate_count == 1
    assert len(result.candidates) == 1
    assert {alias.filename for alias in result.candidates[0].aliases} == {"wallet.dat", "WALLET~1.DAT"}


def test_wallet_empty_png_is_not_candidate(tmp_path) -> None:
    png = file_record(6, (filename("Wallet-Empty.png"), data_resident(b"png")))
    result = locate(tmp_path, {6: png})
    assert result.wallet_dat_candidate_count == 0
    assert result.candidates == ()


def test_bitcoin_context_path_and_sequence_checked(tmp_path) -> None:
    root = file_record(5, (filename(".", parent=5),), directory=True)
    bitcoin = file_record(6, (filename("Bitcoin", parent=5),), directory=True)
    debug = file_record(7, (filename("debug.log", parent=6), data_resident(b"log")))
    result = locate(tmp_path, {5: root, 6: bitcoin, 7: debug})
    candidate = result.candidates[0]
    assert result.bitcoin_context_artifact_count == 2
    debug_candidate = next(item for item in result.candidates if item.filename == "debug.log")
    assert debug_candidate.artifact_class == "bitcoin_context_artifact"
    assert debug_candidate.path.endswith("Bitcoin\\debug.log")
    assert debug_candidate.partial_path is False


def test_bad_usa_is_controlled_invalid_record(tmp_path) -> None:
    wallet = bytearray(file_record(6, (filename("wallet.dat"), data_resident(b"x"))))
    wallet[510:512] = b"bad"[:2]
    result = locate(tmp_path, {6: bytes(wallet)})
    assert result.mft_records_invalid >= 1
    assert result.wallet_dat_candidate_count == 0


def test_resident_payload_is_absent_from_safe_json(tmp_path) -> None:
    wallet = file_record(6, (filename("wallet.dat"), data_resident(b"DO-NOT-REPORT")))
    result = locate(tmp_path, {6: wallet})
    candidate = result.candidates[0]
    assert candidate.resident is True
    assert candidate.logical_size == len(b"DO-NOT-REPORT")
    payload = _ntfs_bitcoin_artifact_index(result)
    encoded = json.dumps(payload)
    assert "DO-NOT-REPORT" not in encoded
    assert "payload" not in payload["candidates"][0]


def test_extent_outside_image_is_controlled_without_read(tmp_path) -> None:
    wallet = file_record(6, (filename("wallet.dat"), data_nonresident(run(1, 5000) + b"\x00", 0, logical_size=CLUSTER, allocated_size=CLUSTER)))
    candidate = locate(tmp_path, {6: wallet}).candidates[0]
    assert candidate.data_recovery_state == "extent_outside_image"


def test_compressed_data_is_controlled_unsupported(tmp_path) -> None:
    wallet = file_record(6, (filename("wallet.dat"), data_nonresident(run(1, 40) + b"\x00", 0, flags=1)))
    candidate = locate(tmp_path, {6: wallet}).candidates[0]
    assert candidate.data_recovery_state == "unsupported_compressed_data"


def test_encrypted_and_sparse_data_states_are_safe(tmp_path) -> None:
    encrypted = file_record(6, (filename("wallet.dat"), data_nonresident(run(1, 40) + b"\x00", 0, flags=0x4000)))
    encrypted_candidate = locate(tmp_path, {6: encrypted}).candidates[0]
    assert encrypted_candidate.data_recovery_state == "unsupported_encrypted_data"

    sparse = file_record(6, (filename("wallet.dat"), data_nonresident(run(1, 40) + sparse_run(1) + b"\x00", 1, flags=0x8000)))
    sparse_candidate = locate(tmp_path, {6: sparse}).candidates[0]
    assert sparse_candidate.extents[1].sparse is True
    assert sparse_candidate.extents[1].physical_byte_start is None


def test_stale_parent_sequence_produces_partial_path(tmp_path) -> None:
    parent = file_record(5, (filename("Bitcoin", parent=5, parent_sequence=2),), directory=True, sequence=2)
    wallet = file_record(6, (filename("wallet.dat", parent=5, parent_sequence=1), data_resident(b"x")))
    candidate = next(item for item in locate(tmp_path, {5: parent, 6: wallet}).candidates if item.filename == "wallet.dat")
    assert candidate.path == "wallet.dat"
    assert candidate.partial_path is True


def test_mft_attribute_list_marks_stream_incomplete(tmp_path) -> None:
    path = tmp_path / "attribute-list.img"
    raw = bytearray(image_with({}))
    pairs = run(MFT_RECORDS * RECORD // CLUSTER, MFT_LCN) + b"\x00"
    mft_data = data_nonresident(pairs, 1, logical_size=MFT_RECORDS * RECORD, allocated_size=MFT_RECORDS * RECORD)
    record_zero = file_record(0, (resident(0x20, b"list"), mft_data))
    start = MFT_LCN * CLUSTER
    raw[start:start + RECORD] = record_zero
    path.write_bytes(raw)
    result = NTFSBitcoinArtifactLocator().index(path)
    assert result.mft_attribute_list_present is True
    assert result.mft_stream_may_be_incomplete is True
    assert "mft_attribute_list_present" in result.diagnostics


def test_mbr_primary_partition_is_discovered_without_type_trust(tmp_path) -> None:
    wallet = file_record(6, (filename("wallet.dat"), data_resident(b"x")))
    path = tmp_path / "mbr.img"
    raw = bytearray(image_with({6: wallet}, mbr=True))
    raw[450] = 0x83
    path.write_bytes(raw)
    result = NTFSBitcoinArtifactLocator().index(path)
    assert result.volume_offset == CLUSTER
    assert result.wallet_dat_candidate_count == 1


def test_no_ntfs_is_controlled_empty_diagnostic(tmp_path) -> None:
    path = tmp_path / "raw.img"
    path.write_bytes(b"not ntfs" + b"\x00" * 1024)
    result = NTFSBitcoinArtifactLocator().index(path)
    assert result.volume_offset is None
    assert result.candidates == ()
    assert "supported_ntfs_volume_not_found" in result.diagnostics


def test_coordinator_runs_index_without_changing_wallet_status(tmp_path) -> None:
    path = tmp_path / "coordinator.img"
    wallet = file_record(6, (filename("wallet.dat"), data_resident(b"x")))
    path.write_bytes(image_with({6: wallet}))
    result = FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_size=64 * 1024,
    ).scan(path)
    assert result.ntfs_bitcoin_artifact_index.wallet_dat_candidate_count == 1
    assert result.status is ValidationStatus.REJECTED
    assert result.structural_wallet_count == 0
    assert result.fragment_wallet_count == 0
