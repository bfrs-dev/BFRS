from bfrs.recovery.ntfs_bitcoin_artifacts import NTFSBitcoinArtifactLocator
from bfrs.recovery.ntfs_detached_metadata import NTFSDetachedMetadataRecoveryPipeline
from bfrs.recovery.ntfs_detached_volume import (
    NTFSDetachedVolumeCandidate,
    NTFSDetachedVolumeDiscovery,
)
from bfrs.reporting.json_report import _ntfs_detached_metadata_recovery

from tests.test_ntfs_bitcoin_artifacts import (
    CLUSTER, IMAGE_SIZE, MFT_LCN, RECORD, SECTOR,
    data_nonresident, data_resident, file_record, filename, image_with, index_entry,
    index_root, indx_block, named_nonresident, run,
)


def detached_candidate(*, volume_end=IMAGE_SIZE):
    return NTFSDetachedVolumeCandidate(
        classification="detached",
        validation_strength="detached_volume_structural",
        provenance="unknown",
        volume_start=0,
        volume_end=volume_end,
        volume_size_bytes=volume_end,
        bytes_per_sector=SECTOR,
        sectors_per_cluster=CLUSTER // SECTOR,
        cluster_size=CLUSTER,
        total_sectors=volume_end // SECTOR,
        mft_lcn=MFT_LCN,
        mftmirr_lcn=8,
        mft_record_size=RECORD,
        index_block_size=CLUSTER,
        volume_serial=1,
        boot_copy_count=1,
        primary_boot_offsets=(0,),
        backup_boot_offsets=(),
        mft0_physical_offset=MFT_LCN * CLUSTER,
        mft0_valid=True,
        mft0_failure_reason=None,
        mftmirr0_physical_offset=8 * CLUSTER,
        mftmirr0_valid=True,
        mftmirr0_failure_reason=None,
        boot_pair_valid=False,
        reasons=(),
    )


def discovery(path, *volumes):
    return NTFSDetachedVolumeDiscovery(
        source=str(path), raw_boot_anchor_count=len(volumes),
        candidate_boot_sector_count=len(volumes), valid_boot_sector_count=len(volumes),
        invalid_boot_sector_count=0, geometry_hypothesis_count=len(volumes),
        boot_only_geometry_count=0, correlated_geometry_count=len(volumes),
        detached_volume_count=len(volumes), current_volume_copy_count=0,
        rejection_counts=(), volumes=tuple(volumes), diagnostics=(),
    )


def recover(tmp_path, raw, *, candidate=None, file_offsets=(), indx_offsets=(),
            range_end=None):
    path = tmp_path / "detached.img"
    path.write_bytes(raw)
    volume = detached_candidate(volume_end=len(raw)) if candidate is None else candidate
    return NTFSDetachedMetadataRecoveryPipeline(
        source=path, discovery=discovery(path, volume),
        locator=NTFSBitcoinArtifactLocator(), raw_file_offsets=file_offsets,
        raw_indx_offsets=indx_offsets, range_start=0,
        range_end=len(raw) if range_end is None else range_end,
    ).run()


def test_detached_logical_mft_wallet_path_deleted_context_and_safe_json(tmp_path):
    root = file_record(5, (filename("Root", parent=5),), directory=True)
    directory = file_record(6, (filename("Bitcoin", parent=5),), directory=True)
    wallet = file_record(
        7, (filename("wallet.dat", parent=6),), allocated=False
    )
    context = file_record(4, (filename("bitcoin.conf", parent=6),))
    result = recover(tmp_path, image_with({4: context, 5: root, 6: directory, 7: wallet}))
    volume = result.volumes[0]
    assert (volume.mft_records_scanned, volume.mft_record_count) == (8, 8)
    assert volume.mft_records_valid >= 5
    assert volume.directory_record_count == 2
    assert result.wallet_candidate_count == 1
    assert result.bitcoin_context_candidate_count >= 1
    candidate = next(item for item in volume.candidates if item.filename == "wallet.dat")
    assert candidate.source_layer == "detached_logical_mft"
    assert candidate.path == "Root\\Bitcoin\\wallet.dat"
    assert not candidate.partial_path
    assert candidate.allocation_state == "deleted"
    assert candidate.provenance == "unknown"
    payload = _ntfs_detached_metadata_recovery(result)
    encoded = str(payload).casefold()
    assert "resident payload" not in encoded
    assert payload["wallet_candidate_count"] == 1


def test_wallet_empty_is_not_wallet_and_stale_parent_is_partial(tmp_path):
    negative = file_record(7, (filename("Wallet-Empty.png", parent=99),))
    result = recover(tmp_path, image_with({7: negative}))
    assert result.wallet_candidate_count == 0
    assert all(item.filename != "Wallet-Empty.png" for item in result.volumes[0].candidates)


def test_detached_wallet_data_reports_metadata_and_extents_without_payload(tmp_path):
    resident = file_record(
        1, (filename("wallet.dat"), data_resident(b"secret payload"))
    )
    nonresident = file_record(
        2, (
            filename("wallet-old.bak"),
            data_nonresident(
                run(1, 100) + b"\x00", 0,
                logical_size=1234, allocated_size=CLUSTER,
            ),
        ),
    )
    result = recover(tmp_path, image_with({1: resident, 2: nonresident}))
    items = {item.filename: item for item in result.volumes[0].candidates}
    assert items["wallet.dat"].resident
    assert items["wallet.dat"].logical_size == len(b"secret payload")
    assert items["wallet.dat"].initialized_size == len(b"secret payload")
    mapped = items["wallet-old.bak"]
    assert mapped.nonresident
    assert mapped.logical_size == 1234
    assert mapped.allocated_size == CLUSTER
    assert mapped.initialized_size == 1234
    assert mapped.extent_trust == "detached_logical_mft"
    assert mapped.extents[0].physical_byte_start == 100 * CLUSTER
    payload = _ntfs_detached_metadata_recovery(result)
    assert "secret payload" not in str(payload)


def test_fragmented_logical_mft_reader(tmp_path):
    raw = bytearray(image_with({1: file_record(1, (filename("wallet.dat"),))}))
    pairs = run(1, MFT_LCN) + run(1, 6) + b"\x00"
    mapping = data_nonresident(
        pairs, 1, logical_size=8 * RECORD, allocated_size=2 * CLUSTER
    )
    record0 = file_record(0, (mapping,))
    first = MFT_LCN * CLUSTER
    second_source = first + CLUSTER
    second_target = 10 * CLUSTER
    raw[second_target:second_target + CLUSTER] = raw[second_source:second_source + CLUSTER]
    raw[first:first + RECORD] = record0
    result = recover(tmp_path, raw)
    volume = result.volumes[0]
    assert volume.mft_records_scanned == 8
    assert volume.mft_records_valid >= 2
    assert result.wallet_candidate_count == 1


def test_detached_index_root_active_slack_and_local_reference_states(tmp_path):
    root = index_root(
        (index_entry("wallet.dat", record=7, sequence=1),),
        slack=index_entry("wallet-old.bak", record=7, sequence=2),
    )
    directory = file_record(
        6, (filename("Bitcoin", parent=5), root), directory=True
    )
    target = file_record(7, (filename("other.dat"),), sequence=1)
    result = recover(tmp_path, image_with({6: directory, 7: target}))
    items = [item for item in result.volumes[0].candidates if "index" in item.source_layer]
    assert {item.entry_state for item in items} == {"active", "slack"}
    assert {item.reference_state for item in items} == {
        "detached_reference_matches", "detached_record_reused_sequence_differs"
    }
    assert result.wallet_candidate_count == 2


def test_detached_index_missing_and_out_of_range_reference_states(tmp_path):
    root = index_root((
        index_entry("wallet.dat", record=3, sequence=1),
        index_entry("wallet-old.bak", record=99, sequence=1),
    ))
    directory = file_record(6, (filename("Directory"), root), directory=True)
    result = recover(tmp_path, image_with({6: directory}))
    states = {item.filename: item.reference_state for item in result.volumes[0].candidates}
    assert states == {
        "wallet.dat": "detached_record_missing",
        "wallet-old.bak": "detached_record_number_out_of_range",
    }


def test_index_false_string_and_bad_indx_usa_are_rejected(tmp_path):
    allocation = named_nonresident(
        0xA0, "$I30", run(1, 80) + b"\x00",
        logical_size=CLUSTER, highest_vcn=0,
    )
    directory = file_record(
        6, (filename("Directory", parent=5), index_root(()), allocation),
        directory=True,
    )
    raw = bytearray(image_with({6: directory}))
    raw[80 * CLUSTER:81 * CLUSTER] = indx_block(
        (), slack=index_entry("wallet.dat"), valid_usa=False
    )
    result = recover(tmp_path, raw)
    volume = result.volumes[0]
    assert volume.indx_block_invalid_count == 1
    assert result.wallet_candidate_count == 0


def test_fragmented_index_allocation_reads_each_mapped_block(tmp_path):
    allocation = named_nonresident(
        0xA0, "$I30", run(1, 80) + run(1, 10) + b"\x00",
        logical_size=2 * CLUSTER, highest_vcn=1,
    )
    directory = file_record(
        6, (filename("Directory", parent=5), index_root(()), allocation),
        directory=True,
    )
    raw = bytearray(image_with({6: directory}))
    first = indx_block((index_entry("wallet.dat"),))
    second = bytearray(indx_block((index_entry("wallet-old.bak"),)))
    second[16:24] = (1).to_bytes(8, "little")
    raw[80 * CLUSTER:81 * CLUSTER] = first
    raw[90 * CLUSTER:91 * CLUSTER] = second
    result = recover(tmp_path, raw)
    volume = result.volumes[0]
    assert volume.index_allocation_stream_count == 1
    assert volume.indx_block_count == 2
    assert volume.indx_block_valid_count == 2
    assert result.wallet_candidate_count == 2


def test_raw_exact_mft_exclusion_and_stale_file(tmp_path):
    stale_offset = 600_000
    raw = bytearray(image_with({}))
    raw[stale_offset:stale_offset + RECORD] = file_record(
        900, (filename("wallet.dat"),)
    )
    result = recover(
        tmp_path, raw,
        file_offsets=(MFT_LCN * CLUSTER, stale_offset),
    )
    volume = result.volumes[0]
    assert volume.raw_file_hit_count_within_volume == 2
    assert volume.detached_current_mft_excluded_count == 1
    assert volume.structural_stale_file_count == 1
    stale = next(item for item in volume.candidates if item.source_layer == "detached_stale_file")
    assert stale.physical_metadata_offset == stale_offset


def test_raw_indx_current_exclusion_and_stale_wallet(tmp_path):
    allocation = named_nonresident(
        0xA0, "$I30", run(1, 80) + b"\x00",
        logical_size=CLUSTER, highest_vcn=0,
    )
    directory = file_record(
        6, (filename("Directory", parent=5), index_root(()), allocation),
        directory=True,
    )
    raw = bytearray(image_with({6: directory}))
    current_offset = 80 * CLUSTER
    stale_offset = 90 * CLUSTER
    raw[current_offset:current_offset + CLUSTER] = indx_block(())
    raw[stale_offset:stale_offset + CLUSTER] = indx_block(
        (), slack=index_entry("wallet.dat")
    )
    result = recover(tmp_path, raw, indx_offsets=(current_offset, stale_offset))
    volume = result.volumes[0]
    assert volume.detached_current_indx_excluded_count == 1
    assert volume.structural_stale_indx_count == 1
    assert any(item.source_layer == "detached_stale_indx_slack" for item in volume.candidates)


def test_overlapping_geometries_are_evaluated_independently(tmp_path):
    raw = image_with({})
    path = tmp_path / "overlap.img"
    path.write_bytes(raw)
    one = detached_candidate(volume_end=len(raw))
    two = detached_candidate(volume_end=len(raw))
    result = NTFSDetachedMetadataRecoveryPipeline(
        source=path, discovery=discovery(path, one, two),
        locator=NTFSBitcoinArtifactLocator(),
        raw_file_offsets=(MFT_LCN * CLUSTER,), range_end=len(raw),
    ).run()
    assert result.volume_count == 2
    assert [item.detached_current_mft_excluded_count for item in result.volumes] == [1, 1]


def test_current_and_boot_only_geometries_are_not_recovered(tmp_path):
    raw = image_with({})
    path = tmp_path / "classification.img"
    path.write_bytes(raw)
    current = detached_candidate(volume_end=len(raw))
    current = type(current)(
        **{name: getattr(current, name) for name in current.__dataclass_fields__
           if name not in {"classification", "validation_strength"}},
        classification="current", validation_strength="geometry_correlated",
    )
    result = NTFSDetachedMetadataRecoveryPipeline(
        source=path, discovery=discovery(path, current),
        locator=NTFSBitcoinArtifactLocator(), range_end=len(raw),
    ).run()
    assert result.volume_count == 0
    assert result.wallet_candidate_count == 0


def test_volume_and_cli_bounds_are_controlled(tmp_path):
    raw = image_with({})
    too_small = detached_candidate(volume_end=MFT_LCN * CLUSTER + RECORD)
    bounded = recover(tmp_path, raw, candidate=too_small)
    assert bounded.volumes[0].mft_records_scanned == 0
    assert dict(bounded.volumes[0].rejection_counts)["detached_extent_outside_safe_range"] == 1
    cli = recover(tmp_path, raw, range_end=MFT_LCN * CLUSTER + RECORD)
    assert cli.volumes[0].mft_records_scanned == 0
    assert dict(cli.volumes[0].rejection_counts)["detached_extent_outside_safe_range"] == 1
