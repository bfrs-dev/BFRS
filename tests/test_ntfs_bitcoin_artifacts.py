import json

import pytest

from bfrs.cli import BITCOIN_CORE_SIGNATURES_V1
from bfrs.core.models import ValidationStatus
from bfrs.core.models import RawHit
from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator
from bfrs.recovery.ntfs_bitcoin_artifacts import (
    NTFSBitcoinArtifactLocator,
)
from bfrs.recovery.ntfs_stale_file import (
    NTFS_FILE_RECORD_SIGNATURE,
    NTFSStaleFileRecordRecoveryPipeline,
)
from bfrs.recovery.ntfs_directory_index import (
    NTFSDirectoryIndexArtifactRecoveryPipeline,
)
from bfrs.reporting.json_report import (
    _ntfs_directory_index_artifact_recovery,
)
from bfrs.reporting.json_report import _ntfs_bitcoin_artifact_index
from bfrs.reporting.json_report import _ntfs_mft_recovery_diagnostic
from bfrs.reporting.json_report import _ntfs_stale_file_record_recovery
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


def boot_sector(cluster_size: int = CLUSTER) -> bytes:
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x52\x90"
    boot[3:11] = b"NTFS    "
    boot[11:13] = SECTOR.to_bytes(2, "little")
    boot[13] = cluster_size // SECTOR
    boot[40:48] = (IMAGE_SIZE // SECTOR).to_bytes(8, "little")
    boot[48:56] = MFT_LCN.to_bytes(8, "little")
    boot[56:64] = (8).to_bytes(8, "little")
    boot[64] = (-10) & 0xFF
    boot[510:512] = b"\x55\xaa"
    return bytes(boot)


def image_with(
    records: dict[int, bytes],
    *,
    mbr: bool = False,
    mirror_records: dict[int, bytes] | None = None,
    cluster_size: int = CLUSTER,
) -> bytes:
    volume_offset = CLUSTER if mbr else 0
    image = bytearray(IMAGE_SIZE + volume_offset)
    image[volume_offset:volume_offset + 512] = boot_sector(cluster_size)
    if mbr:
        image[510:512] = b"\x55\xaa"
        entry = bytearray(16)
        entry[4] = 0x07
        entry[8:12] = (volume_offset // 512).to_bytes(4, "little")
        entry[12:16] = (IMAGE_SIZE // 512).to_bytes(4, "little")
        image[446:462] = entry
    mft_cluster_count = (
        MFT_RECORDS * RECORD + cluster_size - 1
    ) // cluster_size
    mft_pairs = run(mft_cluster_count, MFT_LCN) + b"\x00"
    mft_data = data_nonresident(
        mft_pairs,
        mft_cluster_count - 1,
        logical_size=MFT_RECORDS * RECORD,
        allocated_size=mft_cluster_count * cluster_size,
    )
    all_records = {0: file_record(0, (mft_data,)), **records}
    start = volume_offset + MFT_LCN * cluster_size
    for number, record in all_records.items():
        image[start + number * RECORD:start + (number + 1) * RECORD] = record
    mirror_start = volume_offset + 8 * cluster_size
    for number, record in (mirror_records or {}).items():
        image[
            mirror_start + number * RECORD:
            mirror_start + (number + 1) * RECORD
        ] = record
    return bytes(image)


def locate(tmp_path, records: dict[int, bytes], *, mbr: bool = False):
    path = tmp_path / "ntfs.img"
    path.write_bytes(image_with(records, mbr=mbr))
    return NTFSBitcoinArtifactLocator().index(path)


def filename_value(
    name: str,
    *,
    parent: int = 6,
    parent_sequence: int = 1,
    namespace: int = 1,
) -> bytes:
    encoded = name.encode("utf-16-le")
    value = bytearray(66 + len(encoded))
    value[0:8] = (parent | (parent_sequence << 48)).to_bytes(8, "little")
    value[64] = len(name)
    value[65] = namespace
    value[66:] = encoded
    return bytes(value)


def named_resident(type_code: int, name: str, value: bytes) -> bytes:
    encoded_name = name.encode("utf-16-le")
    value_offset = align8(24 + len(encoded_name))
    size = align8(value_offset + len(value))
    result = bytearray(size)
    result[0:4] = type_code.to_bytes(4, "little")
    result[4:8] = size.to_bytes(4, "little")
    result[9] = len(name)
    result[10:12] = (24).to_bytes(2, "little")
    result[16:20] = len(value).to_bytes(4, "little")
    result[20:22] = value_offset.to_bytes(2, "little")
    result[24:24 + len(encoded_name)] = encoded_name
    result[value_offset:value_offset + len(value)] = value
    return bytes(result)


def index_entry(
    name: str,
    *,
    record: int = 7,
    sequence: int = 1,
    parent: int = 6,
    parent_sequence: int = 1,
) -> bytes:
    key = filename_value(
        name, parent=parent, parent_sequence=parent_sequence
    )
    size = align8(16 + len(key))
    result = bytearray(size)
    result[0:8] = (record | (sequence << 48)).to_bytes(8, "little")
    result[8:10] = size.to_bytes(2, "little")
    result[10:12] = len(key).to_bytes(2, "little")
    result[16:16 + len(key)] = key
    return bytes(result)


def index_end() -> bytes:
    result = bytearray(16)
    result[8:10] = (16).to_bytes(2, "little")
    result[12:14] = (2).to_bytes(2, "little")
    return bytes(result)


def index_root(
    active: tuple[bytes, ...],
    *,
    slack: bytes = b"",
    name: str = "$I30",
    block_size: int = CLUSTER,
) -> bytes:
    chain = b"".join(active) + index_end()
    value = bytearray(32 + len(chain) + len(slack))
    value[0:4] = (0x30).to_bytes(4, "little")
    value[4:8] = (1).to_bytes(4, "little")
    value[8:12] = block_size.to_bytes(4, "little")
    value[12] = block_size // CLUSTER
    value[16:20] = (16).to_bytes(4, "little")
    value[20:24] = (16 + len(chain)).to_bytes(4, "little")
    value[24:28] = (16 + len(chain) + len(slack)).to_bytes(4, "little")
    value[32:32 + len(chain)] = chain
    value[32 + len(chain):] = slack
    return named_resident(0x90, name, bytes(value))


def named_nonresident(
    type_code: int,
    name: str,
    pairs: bytes,
    *,
    logical_size: int,
    highest_vcn: int,
) -> bytes:
    encoded_name = name.encode("utf-16-le")
    pairs_offset = align8(64 + len(encoded_name))
    size = align8(pairs_offset + len(pairs))
    result = bytearray(size)
    result[0:4] = type_code.to_bytes(4, "little")
    result[4:8] = size.to_bytes(4, "little")
    result[8] = 1
    result[9] = len(name)
    result[10:12] = (64).to_bytes(2, "little")
    result[24:32] = highest_vcn.to_bytes(8, "little")
    result[32:34] = pairs_offset.to_bytes(2, "little")
    result[40:48] = logical_size.to_bytes(8, "little")
    result[48:56] = logical_size.to_bytes(8, "little")
    result[56:64] = logical_size.to_bytes(8, "little")
    result[64:64 + len(encoded_name)] = encoded_name
    result[pairs_offset:pairs_offset + len(pairs)] = pairs
    return bytes(result)


def indx_block(
    active: tuple[bytes, ...],
    *,
    slack: bytes = b"",
    valid_usa: bool = True,
) -> bytes:
    chain = b"".join(active) + index_end()
    result = bytearray(CLUSTER)
    result[:4] = b"INDX"
    result[4:6] = (40).to_bytes(2, "little")
    result[6:8] = (CLUSTER // SECTOR + 1).to_bytes(2, "little")
    result[16:24] = (0).to_bytes(8, "little")
    result[24:28] = (40).to_bytes(4, "little")
    result[28:32] = (40 + len(chain)).to_bytes(4, "little")
    result[32:36] = (40 + len(chain) + len(slack)).to_bytes(4, "little")
    result[64:64 + len(chain)] = chain
    result[64 + len(chain):64 + len(chain) + len(slack)] = slack
    usn = b"\xa5\x5a"
    replacements = []
    for sector in range(1, CLUSTER // SECTOR + 1):
        trailer = sector * SECTOR - 2
        replacements.append(bytes(result[trailer:trailer + 2]))
        result[trailer:trailer + 2] = usn
    result[40:42] = usn
    for index, replacement in enumerate(replacements, start=1):
        result[40 + index * 2:42 + index * 2] = replacement
    if not valid_usa:
        result[SECTOR - 2:SECTOR] = b"\x00\x00"
    return bytes(result)


def directory_recovery(
    tmp_path,
    directory_attributes: tuple[bytes, ...],
    *,
    target_sequence: int = 1,
    allocation_block: bytes | None = None,
):
    directory = file_record(
        6,
        (filename("Bitcoin", parent=5),) + directory_attributes,
        directory=True,
    )
    target = file_record(7, (filename("current.dat"),), sequence=target_sequence)
    image = bytearray(image_with({6: directory, 7: target}))
    if allocation_block is not None:
        image[80 * CLUSTER:81 * CLUSTER] = allocation_block
    path = tmp_path / "directory-index.img"
    path.write_bytes(image)
    locator = NTFSBitcoinArtifactLocator()
    locator.index(path)
    return NTFSDirectoryIndexArtifactRecoveryPipeline(
        context=locator.stale_recovery_context,
        locator=locator,
    ).run()


def test_directory_index_active_root_and_current_reference(tmp_path) -> None:
    result = directory_recovery(
        tmp_path, (index_root((index_entry("wallet.dat"),)),)
    )
    assert result.directory_record_count == 1
    assert result.index_root_count == 1
    assert result.active_entry_count == 1
    assert result.wallet_candidate_count == 1
    candidate = result.candidates[0]
    assert candidate.entry_state == "active"
    assert candidate.reference_state == "current_reference_matches"
    assert candidate.validation_strength == "active_ntfs_directory_index_entry"


def test_directory_index_root_structural_slack_and_raw_string(tmp_path) -> None:
    structural = index_entry("wallet.dat")
    result = directory_recovery(
        tmp_path, (index_root((index_entry("example.txt"),), slack=structural),)
    )
    assert result.active_entry_count == 1
    assert result.structural_slack_entry_count == 1
    assert result.slack_wallet_candidate_count == 1
    wallet = next(
        item
        for item in result.candidates
        if item.artifact_class in {"wallet_dat", "wallet_backup_like"}
    )
    assert wallet.entry_state == "slack"

    false_positive = "wallet.dat".encode("utf-16-le") + bytes(96)
    rejected = directory_recovery(
        tmp_path, (index_root((), slack=false_positive),)
    )
    assert rejected.wallet_candidate_count == 0
    assert rejected.structural_slack_entry_count == 0


def test_directory_index_wallet_empty_and_other_index_name(tmp_path) -> None:
    result = directory_recovery(
        tmp_path,
        (
            index_root((), slack=index_entry("Wallet-Empty.png")),
            index_root((index_entry("wallet.dat"),), name="$O"),
        ),
    )
    assert result.index_root_count == 1
    assert result.wallet_candidate_count == 0


def test_directory_index_reused_sequence_and_parent_mismatch(tmp_path) -> None:
    result = directory_recovery(
        tmp_path,
        (
            index_root(
                (),
                slack=index_entry(
                    "wallet.dat", sequence=5, parent=9, parent_sequence=2
                ),
            ),
        ),
        target_sequence=12,
    )
    candidate = result.candidates[0]
    assert candidate.reference_state == "current_record_reused_sequence_differs"
    assert candidate.parent_reference_state == "embedded_parent_reference_mismatch"


def test_directory_index_end_marker_and_entry_bounds(tmp_path) -> None:
    bytes_after_end = index_entry("wallet.dat")
    root = index_root((), slack=bytes_after_end)
    result = directory_recovery(tmp_path, (root,))
    assert result.active_entry_count == 0
    assert result.slack_wallet_candidate_count == 1

    malformed = bytearray(index_entry("wallet.dat"))
    malformed[8:10] = (0xFFF8).to_bytes(2, "little")
    bounded = directory_recovery(
        tmp_path, (index_root((), slack=bytes(malformed)),)
    )
    assert bounded.structural_slack_entry_count == 0
    assert bounded.wallet_candidate_count == 0


def test_directory_index_allocation_valid_and_bad_usa(tmp_path) -> None:
    allocation = named_nonresident(
        0xA0,
        "$I30",
        run(1, 80) + b"\x00",
        logical_size=CLUSTER,
        highest_vcn=0,
    )
    valid = directory_recovery(
        tmp_path,
        (index_root(()), allocation),
        allocation_block=indx_block((index_entry("wallet.dat"),)),
    )
    assert valid.index_allocation_stream_count == 1
    assert valid.indx_block_count == 1
    assert valid.indx_block_valid_count == 1
    assert valid.active_wallet_candidate_count == 1

    invalid = directory_recovery(
        tmp_path,
        (index_root(()), allocation),
        allocation_block=indx_block(
            (), slack=index_entry("wallet.dat"), valid_usa=False
        ),
    )
    assert invalid.indx_block_invalid_count == 1
    assert invalid.wallet_candidate_count == 0
    assert invalid.structural_slack_entry_count == 0


def test_directory_index_allocation_structural_slack_and_safe_json(tmp_path) -> None:
    allocation = named_nonresident(
        0xA0,
        "$I30",
        run(1, 80) + b"\x00",
        logical_size=CLUSTER,
        highest_vcn=0,
    )
    result = directory_recovery(
        tmp_path,
        (index_root(()), allocation),
        allocation_block=indx_block((), slack=index_entry("wallet.dat")),
    )
    assert result.slack_wallet_candidate_count == 1
    assert result.candidates[0].index_source == "index_allocation"
    payload = _ntfs_directory_index_artifact_recovery(result)
    encoded = json.dumps(payload, sort_keys=True).lower()
    assert payload["wallet_candidate_count"] == 1
    assert "raw" not in payload["candidates"][0]
    assert "private_key" not in encoded


def test_directory_index_missing_and_out_of_range_references(tmp_path) -> None:
    result = directory_recovery(
        tmp_path,
        (
            index_root(
                (
                    index_entry("debug.log", record=4),
                    index_entry("peers.dat", record=8),
                )
            ),
        ),
    )
    states = {item.filename: item.reference_state for item in result.candidates}
    assert states["debug.log"] == "current_record_missing"
    assert states["peers.dat"] == "record_number_out_of_range"


def test_directory_index_duplicate_location_is_one_candidate(
    tmp_path, monkeypatch
) -> None:
    original = NTFSDirectoryIndexArtifactRecoveryPipeline._parse_node

    def duplicate_slack(self, *args, **kwargs):
        active, slack, attempts = original(self, *args, **kwargs)
        return active, slack + slack, attempts

    monkeypatch.setattr(
        NTFSDirectoryIndexArtifactRecoveryPipeline,
        "_parse_node",
        duplicate_slack,
    )
    result = directory_recovery(
        tmp_path, (index_root((), slack=index_entry("wallet.dat")),)
    )
    wallet_candidates = tuple(
        item
        for item in result.candidates
        if item.artifact_class in {"wallet_dat", "wallet_backup_like"}
    )
    assert result.wallet_candidate_count == 1
    assert len(wallet_candidates) == 1


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
    stale = result.ntfs_stale_file_record_recovery
    assert stale.raw_file_hit_count >= 2
    assert stale.current_mft_excluded_count >= 2
    assert stale.wallet_candidate_count == 0


def malformed_attribute() -> bytes:
    value = bytearray(16)
    value[0:4] = (0x80).to_bytes(4, "little")
    value[4:8] = (24).to_bytes(4, "little")
    return bytes(value)


def locate_image(tmp_path, raw: bytes):
    path = tmp_path / "mft-recovery.img"
    path.write_bytes(raw)
    return NTFSBitcoinArtifactLocator().index(path)


def test_mirror_valid_main_valid_identical(tmp_path) -> None:
    record = file_record(1, (filename("$MFTMirr"),), directory=True)
    result = locate_image(
        tmp_path,
        image_with({1: record}, mirror_records={1: record}),
    )
    diagnostic = result.mft_recovery_diagnostic
    comparison = diagnostic.mirror_comparisons[1]
    assert diagnostic.mirror_record_count_expected == 4
    assert diagnostic.mirror_record_count_read == 4
    assert comparison.classification == "identical"
    assert comparison.fixed_record_sha256_equal is True


@pytest.mark.parametrize("cluster_size", [4096, 8192, 65536])
def test_mft_mirror_is_exactly_four_records_for_supported_geometry(
    tmp_path,
    cluster_size: int,
) -> None:
    main_records = {
        number: file_record(number, (filename(f"$Meta{number}"),))
        for number in range(1, 5)
    }
    mirror_records = {
        number: file_record(number, (filename(f"$Meta{number}"),))
        for number in range(4)
    }
    mirror_records[4] = file_record(4, (filename("wallet.dat"),))
    result = locate_image(
        tmp_path,
        image_with(
            main_records,
            mirror_records=mirror_records,
            cluster_size=cluster_size,
        ),
    )
    diagnostic = result.mft_recovery_diagnostic
    assert diagnostic.mirror_record_count_expected == 4
    assert diagnostic.mirror_record_count_read == 4
    assert len(diagnostic.mirror_comparisons) == 4
    assert all(
        item.mft_record_number < 4
        for item in diagnostic.mirror_comparisons
    )
    assert diagnostic.mirror_artifact_candidates == ()


def test_mirror_valid_main_invalid_is_alternative_artifact_source(tmp_path) -> None:
    mirror_wallet = file_record(
        1,
        (filename("wallet.dat"), data_resident(b"MIRROR-PAYLOAD")),
    )
    broken_main = bytearray(mirror_wallet)
    broken_main[510:512] = b"XX"
    result = locate_image(
        tmp_path,
        image_with(
            {1: bytes(broken_main)},
            mirror_records={1: mirror_wallet},
        ),
    )
    diagnostic = result.mft_recovery_diagnostic
    comparison = diagnostic.mirror_comparisons[1]
    assert comparison.classification == "mirror_valid_main_invalid"
    assert diagnostic.mirror_artifact_candidates[0].filename == "wallet.dat"
    assert diagnostic.mirror_artifact_candidates[0].source_kind == "mft_mirror"
    assert diagnostic.partial_salvage_count == 0
    encoded = json.dumps(_ntfs_mft_recovery_diagnostic(result))
    assert "MIRROR-PAYLOAD" not in encoded


def test_mirror_valid_main_valid_different(tmp_path) -> None:
    main = file_record(1, (filename("$MFTMirr"),), sequence=1)
    mirror = file_record(1, (filename("$MFTMirr"),), sequence=2)
    result = locate_image(
        tmp_path,
        image_with({1: main}, mirror_records={1: mirror}),
    )
    comparison = result.mft_recovery_diagnostic.mirror_comparisons[1]
    assert comparison.classification == "mirror_valid_main_valid_different"
    assert comparison.sequence_equal is False


def test_invalid_usa_never_allows_partial_salvage(tmp_path) -> None:
    main = bytearray(
        file_record(6, (filename("wallet.dat"), data_resident(b"x")))
    )
    main[510:512] = b"XX"
    result = locate_image(tmp_path, image_with({6: bytes(main)}))
    diagnostic = result.mft_recovery_diagnostic
    invalid = next(
        item for item in diagnostic.invalid_main_records
        if item.mft_record_number == 6
    )
    assert invalid.failure_stage == "usa_invalid"
    assert not any(
        item.mft_record_number == 6
        for item in diagnostic.partial_salvage_candidates
    )


def test_valid_prefix_wallet_and_data_are_salvaged_before_damage(tmp_path) -> None:
    main = file_record(
        6,
        (
            filename("wallet.dat"),
            data_resident(b"DO-NOT-REPORT"),
            malformed_attribute(),
        ),
    )
    result = locate_image(tmp_path, image_with({6: main}))
    diagnostic = result.mft_recovery_diagnostic
    salvage = next(
        item for item in diagnostic.partial_salvage_candidates
        if item.mft_record_number == 6
    )
    assert diagnostic.salvaged_wallet_candidate_count == 1
    assert salvage.valid_prefix_attribute_count == 2
    assert salvage.aliases[0].filename == "wallet.dat"
    assert salvage.resident is True
    assert salvage.logical_size == len(b"DO-NOT-REPORT")
    assert salvage.extent_trust == "partial_invalid_record"
    assert salvage.source_kind == "invalid_mft_partial"
    encoded = json.dumps(_ntfs_mft_recovery_diagnostic(result))
    assert "DO-NOT-REPORT" not in encoded


def test_raw_wallet_string_is_not_salvaged_as_filename(tmp_path) -> None:
    main = file_record(
        6,
        (resident(0x10, b"wallet.dat"), malformed_attribute()),
    )
    diagnostic = locate_image(
        tmp_path, image_with({6: main})
    ).mft_recovery_diagnostic
    assert diagnostic.salvaged_wallet_candidate_count == 0


def test_salvaged_wallet_empty_png_is_not_wallet_candidate(tmp_path) -> None:
    main = file_record(
        6,
        (filename("Wallet-Empty.png"), malformed_attribute()),
    )
    diagnostic = locate_image(
        tmp_path, image_with({6: main})
    ).mft_recovery_diagnostic
    assert diagnostic.salvaged_wallet_candidate_count == 0


def test_mirror_bitcoin_context_uses_existing_path_classification(tmp_path) -> None:
    bitcoin = file_record(
        1, (filename("Bitcoin", parent=1),), directory=True
    )
    debug = file_record(
        2, (filename("debug.log", parent=1), data_resident(b"log"))
    )
    result = locate_image(
        tmp_path,
        image_with(
            {1: bitcoin, 2: debug},
            mirror_records={1: bitcoin, 2: debug},
        ),
    )
    candidates = result.mft_recovery_diagnostic.mirror_artifact_candidates
    debug_candidate = next(item for item in candidates if item.filename == "debug.log")
    assert debug_candidate.artifact_class == "bitcoin_context_artifact"


def image_with_physical_records(
    base: bytes,
    records: dict[int, bytes],
) -> bytes:
    raw = bytearray(base)
    for offset, record in records.items():
        raw[offset:offset + len(record)] = record
    return bytes(raw)


def stale_recovery(
    tmp_path,
    raw: bytes,
    offsets: list[int],
    *,
    range_start: int = 0,
    range_end: int | None = None,
    sample_limit: int = 100,
):
    path = tmp_path / "stale-file.img"
    path.write_bytes(raw)
    locator = NTFSBitcoinArtifactLocator()
    locator.index(path)
    pipeline = NTFSStaleFileRecordRecoveryPipeline(
        source=path,
        range_start=range_start,
        range_end=len(raw) if range_end is None else range_end,
        context=locator.stale_recovery_context,
        locator=locator,
        diagnostic_sample_limit=sample_limit,
    )
    for offset in offsets:
        pipeline.process_hit(
            RawHit(
                start_offset=offset,
                end_offset=offset + 4,
                hit_type=NTFS_FILE_RECORD_SIGNATURE,
                confidence=0.0,
                source=str(path),
            )
        )
    return pipeline.finish()


def test_stale_recovery_excludes_exact_current_mft_boundary(tmp_path) -> None:
    raw = image_with({})
    result = stale_recovery(tmp_path, raw, [MFT_LCN * CLUSTER])
    assert result.raw_file_hit_count == 1
    assert result.current_mft_excluded_count == 1
    assert result.structural_stale_record_count == 0


def test_stale_recovery_excludes_four_mft_mirror_records(tmp_path) -> None:
    mirror = file_record(0, (filename("$MFT"),))
    raw = image_with({}, mirror_records={0: mirror})
    mirror_offset = 8 * CLUSTER
    result = stale_recovery(tmp_path, raw, [mirror_offset])
    assert result.mftmirr_excluded_count == 1
    assert result.structural_stale_record_count == 0


def test_valid_stale_wallet_and_deleted_state_are_structural_only(tmp_path) -> None:
    offset = 600_000
    wallet = file_record(
        900,
        (filename("wallet.dat"), data_resident(b"SECRET")),
        allocated=False,
        sequence=7,
    )
    raw = image_with_physical_records(image_with({}), {offset: wallet})
    result = stale_recovery(tmp_path, raw, [offset])
    record = result.records[0]
    assert result.structural_stale_record_count == 1
    assert result.wallet_candidate_count == 1
    assert record.allocation_state == "deleted"
    assert record.validation_strength == "structural_stale_ntfs_file"
    assert record.resident is True
    assert record.logical_size == len(b"SECRET")
    assert record.comparison_to_current == (
        "stale_copy_record_number_out_of_range"
    )
    encoded = json.dumps(_ntfs_stale_file_record_recovery(result))
    assert "SECRET" not in encoded


def test_stale_wallet_empty_png_is_not_wallet(tmp_path) -> None:
    offset = 600_000
    record = file_record(900, (filename("Wallet-Empty.png"),))
    raw = image_with_physical_records(image_with({}), {offset: record})
    result = stale_recovery(tmp_path, raw, [offset])
    assert result.structural_stale_record_count == 1
    assert result.wallet_candidate_count == 0


def test_raw_file_and_random_wallet_string_fail_strict_usa(tmp_path) -> None:
    first = 600_000
    second = 602_000
    bad_usa = bytearray(file_record(900, (filename("wallet.dat"),)))
    bad_usa[510:512] = b"XX"
    random = (b"FILE" + b"wallet.dat").ljust(RECORD, b"\x00")
    raw = image_with_physical_records(
        image_with({}), {first: bytes(bad_usa), second: random}
    )
    result = stale_recovery(tmp_path, raw, [first, second])
    assert result.structural_stale_record_count == 0
    assert result.wallet_candidate_count == 0
    assert result.rejected_record_count == 2


def test_stale_fragmented_nonresident_data_has_stale_extent_trust(tmp_path) -> None:
    offset = 600_000
    pairs = run(1, 40) + run(1, 20) + b"\x00"
    record = file_record(
        900,
        (filename("wallet.dat"), data_nonresident(pairs, 1)),
    )
    raw = image_with_physical_records(image_with({}), {offset: record})
    result = stale_recovery(tmp_path, raw, [offset])
    recovered = result.records[0]
    assert recovered.extent_count == 2
    assert recovered.extent_trust == "stale_record_possible"
    assert [item.physical_lcn_start for item in recovered.extents] == [40, 60]


def test_invalid_stale_runlist_preserves_name_but_not_extents(tmp_path) -> None:
    offset = 600_000
    invalid_data = data_nonresident(run(1, 40) + b"\x00", 5)
    record = file_record(900, (filename("wallet.dat"), invalid_data))
    raw = image_with_physical_records(image_with({}), {offset: record})
    result = stale_recovery(tmp_path, raw, [offset])
    recovered = result.records[0]
    assert result.wallet_candidate_count == 1
    assert recovered.data_recovery_state.startswith("invalid:mapping_pairs")
    assert recovered.extent_count == 0
    assert recovered.extents == ()


def test_stale_extent_outside_volume_is_not_reported_as_valid(tmp_path) -> None:
    offset = 600_000
    outside = data_nonresident(
        run(1, 5000) + b"\x00",
        0,
        logical_size=CLUSTER,
        allocated_size=CLUSTER,
    )
    record = file_record(900, (filename("wallet.dat"), outside))
    raw = image_with_physical_records(image_with({}), {offset: record})
    recovered = stale_recovery(tmp_path, raw, [offset]).records[0]
    assert recovered.data_recovery_state == "extent_outside_image"
    assert recovered.extent_count == 0
    assert recovered.extents == ()


def test_stale_bitcoin_context_is_not_wallet_evidence(tmp_path) -> None:
    offset = 600_000
    record = file_record(900, (filename("debug.log"),))
    raw = image_with_physical_records(image_with({}), {offset: record})
    result = stale_recovery(tmp_path, raw, [offset])
    assert result.wallet_candidate_count == 0
    assert result.bitcoin_context_candidate_count == 1
    assert result.records[0].artifact_class == "bitcoin_context_artifact"


def test_stale_record_number_collision_differs_from_current(tmp_path) -> None:
    offset = 600_000
    current = file_record(6, (filename("current.txt"),), sequence=1)
    stale = file_record(6, (filename("wallet.dat"),), sequence=2)
    raw = image_with_physical_records(
        image_with({6: current}), {offset: stale}
    )
    result = stale_recovery(tmp_path, raw, [offset])
    assert result.records[0].comparison_to_current == (
        "stale_copy_differs_current"
    )


def test_exact_current_copy_outside_mft_is_stale_match(tmp_path) -> None:
    offset = 600_000
    current = file_record(6, (filename("current.txt"),), sequence=3)
    raw = image_with_physical_records(
        image_with({6: current}), {offset: current}
    )
    result = stale_recovery(tmp_path, raw, [offset, offset])
    assert result.raw_file_hit_count == 2
    assert result.candidate_record_count == 1
    assert result.structural_stale_record_count == 1
    assert result.records[0].comparison_to_current == (
        "stale_copy_matches_current"
    )


def test_stale_record_read_respects_requested_range(tmp_path) -> None:
    offset = 600_000
    record = file_record(900, (filename("wallet.dat"),))
    raw = image_with_physical_records(image_with({}), {offset: record})
    result = stale_recovery(
        tmp_path,
        raw,
        [offset],
        range_start=offset,
        range_end=offset + RECORD - 1,
    )
    assert result.structural_stale_record_count == 0
    assert dict(result.rejection_counts) == {"candidate_outside_safe_range": 1}


def test_coordinator_same_scan_pass_recovers_stale_wallet_without_status_change(
    tmp_path,
) -> None:
    offset = 600_000
    stale_wallet = file_record(900, (filename("wallet.dat"),))
    path = tmp_path / "coordinator-stale.img"
    path.write_bytes(
        image_with_physical_records(image_with({}), {offset: stale_wallet})
    )
    result = FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_size=64 * 1024,
    ).scan(path)
    stale = result.ntfs_stale_file_record_recovery
    assert dict(result.evidence["raw_hit_counts_by_signature"])[
        NTFS_FILE_RECORD_SIGNATURE
    ] >= 2
    assert stale.wallet_candidate_count == 1
    assert stale.records[0].physical_offset == offset
    assert result.hotspot_count == 0
    assert result.status is ValidationStatus.REJECTED
    assert result.structural_wallet_count == 0
    assert result.fragment_wallet_count == 0


def test_stale_json_sample_is_deterministic_and_aggregate_is_complete(
    tmp_path,
) -> None:
    offsets = [600_000, 602_000, 604_000]
    physical_records = {
        offset: file_record(900 + index, (filename(f"old-{index}.tmp"),))
        for index, offset in enumerate(offsets)
    }
    raw = image_with_physical_records(image_with({}), physical_records)
    result = stale_recovery(
        tmp_path, raw, offsets, sample_limit=2
    )
    assert result.structural_stale_record_count == 3
    assert [item.physical_offset for item in result.records] == offsets[:2]
