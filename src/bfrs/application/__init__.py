"""Application-layer contracts shared by BFRS front ends."""

from bfrs.application.scan_config import (
    DEFAULT_CHUNK_MIB,
    DEFAULT_CLUSTER_MIB,
    DEFAULT_MINIMUM_DISTINCT_TYPES,
    DEFAULT_MINIMUM_HITS,
    DEFAULT_OVERLAP_KIB,
    DEFAULT_PADDING_MIB,
    ScanConfig,
    ScanConfigError,
)
from bfrs.application.scan_events import (
    ScanCheckpointSavedEvent,
    ScanCompletedEvent,
    ScanEvent,
    ScanFailedEvent,
    ScanProgressEvent,
    ScanStartedEvent,
    ScanStoppedEvent,
    TargetCounts,
    freeze_counts,
    thaw_counts,
)

__all__ = [
    "DEFAULT_CHUNK_MIB",
    "DEFAULT_CLUSTER_MIB",
    "DEFAULT_MINIMUM_DISTINCT_TYPES",
    "DEFAULT_MINIMUM_HITS",
    "DEFAULT_OVERLAP_KIB",
    "DEFAULT_PADDING_MIB",
    "ScanCheckpointSavedEvent",
    "ScanCompletedEvent",
    "ScanConfig",
    "ScanConfigError",
    "ScanEvent",
    "ScanFailedEvent",
    "ScanProgressEvent",
    "ScanStartedEvent",
    "ScanStoppedEvent",
    "TargetCounts",
    "freeze_counts",
    "thaw_counts",
]
