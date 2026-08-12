from pathlib import Path

from bfrs.core.models import RawHit
from bfrs.recovery.ntfs_bitcoin_artifacts import NTFSBitcoinArtifactLocator
from bfrs.recovery.ntfs_detached_volume import (
    NTFS_BOOT_SECTOR_SIGNATURE,
    NTFSDetachedVolumeDiscoveryPipeline,
)
from bfrs.reporting.json_report import _ntfs_detached_volume_discovery

from tests.test_ntfs_bitcoin_artifacts import (
    CLUSTER,
    MFT_LCN,
    boot_sector,
    file_record,
    image_with,
)


def _hit(boot_offset: int) -> RawHit:
    return RawHit(boot_offset + 3, boot_offset + 11, NTFS_BOOT_SECTOR_SIGNATURE, 1.0, "test", {})


def _strict_boot(*, serial: int = 1) -> bytes:
    value = bytearray(boot_sector())
    value[68] = (-12) & 0xFF
    value[72:80] = serial.to_bytes(8, "little")
    return bytes(value)


def _pipeline(path: Path):
    locator = NTFSBitcoinArtifactLocator()
    locator.index(path)
    return NTFSDetachedVolumeDiscoveryPipeline(
        source=path, current_context=locator.stale_recovery_context, locator=locator
    )


def test_current_primary_is_not_detached(tmp_path) -> None:
    raw = bytearray(image_with({}))
    raw[:512] = _strict_boot()
    path = tmp_path / "current.img"
    path.write_bytes(raw)
    pipeline = _pipeline(path)
    pipeline.process_hit(_hit(0))
    result = pipeline.finish()
    current = next(volume for volume in result.volumes if volume.volume_start == 0)
    assert current.classification == "current"
    assert current.mft0_valid
    assert result.detached_volume_count == 0


def test_overlapping_detached_primary_with_mft0(tmp_path) -> None:
    raw = bytearray(image_with({}))
    raw.extend(b"\x00" * (128 * CLUSTER))
    raw[:512] = _strict_boot(serial=1)
    detached_start = 128 * CLUSTER
    raw[detached_start:detached_start + 512] = _strict_boot(serial=2)
    mft0 = detached_start + MFT_LCN * CLUSTER
    raw[mft0:mft0 + 1024] = file_record(0, ())
    mftmirr0 = detached_start + 8 * CLUSTER
    raw[mftmirr0:mftmirr0 + 1024] = file_record(0, ())
    path = tmp_path / "overlap.img"
    path.write_bytes(raw)
    pipeline = _pipeline(path)
    pipeline.process_hit(_hit(detached_start))
    result = pipeline.finish()
    detached = next(volume for volume in result.volumes if volume.volume_start == detached_start)
    assert detached.classification == "detached"
    assert detached.validation_strength == "detached_volume_structural"
    assert detached.mft0_valid
    assert detached.mftmirr0_valid
    assert detached.volume_size_bytes == 1024 * 1024
    assert detached.volume_size == detached.volume_size_bytes
    assert detached.provenance == "unknown"
    assert detached.classification not in {
        "previous_partition", "system_partition", "previous_bitcoin_volume"
    }
    payload = _ntfs_detached_volume_discovery(result)["volumes"]
    serialized = next(item for item in payload if item["volume_start"] == detached_start)
    assert serialized["volume_size_bytes"] == 1024 * 1024
    assert serialized["provenance"] == "unknown"
    assert "volume_size" not in serialized


def test_random_ntfs_anchor_and_exact_anchor_minus_three_are_rejected(tmp_path) -> None:
    raw = bytearray(4096)
    raw[515:523] = b"NTFS    "
    raw[1022:1024] = b"\x55\xaa"
    path = tmp_path / "random.img"
    path.write_bytes(raw)
    pipeline = _pipeline(path)
    pipeline.process_hit(_hit(512))
    result = pipeline.finish()
    assert result.valid_boot_sector_count == 0
    assert result.invalid_boot_sector_count == 1


def test_backup_inference_and_boot_pair_correlation(tmp_path) -> None:
    boot = bytearray(_strict_boot(serial=3))
    total_sectors = 64
    boot[40:48] = total_sectors.to_bytes(8, "little")
    boot[48:56] = (4).to_bytes(8, "little")
    boot[56:64] = (5).to_bytes(8, "little")
    start = 4096
    backup = start + (total_sectors - 1) * 512
    raw = bytearray(backup + 512)
    raw[start:start + 512] = boot
    raw[backup:backup + 512] = boot
    path = tmp_path / "pair.img"
    path.write_bytes(raw)
    pipeline = _pipeline(path)
    pipeline.process_hit(_hit(start))
    pipeline.process_hit(_hit(backup))
    result = pipeline.finish()
    candidate = next(volume for volume in result.volumes if volume.volume_start == start)
    assert candidate.boot_pair_valid
    assert candidate.validation_strength == "detached_volume_structural"
    assert candidate.primary_boot_offsets == (start,)
    assert candidate.backup_boot_offsets == (backup,)
