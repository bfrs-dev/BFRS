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
from bfrs.application.result_service import (
    FindingView,
    ResultReport,
    ResultService,
    ResultSummary,
    ResultServiceError,
)
from bfrs.application.scan_service import (
    ScanController,
    ScanRunResult,
    ScanService,
    ScanServiceError,
    build_cli_arguments,
)

__all__ = [
    "DEFAULT_CHUNK_MIB",
    "DEFAULT_CLUSTER_MIB",
    "DEFAULT_MINIMUM_DISTINCT_TYPES",
    "DEFAULT_MINIMUM_HITS",
    "DEFAULT_OVERLAP_KIB",
    "DEFAULT_PADDING_MIB",
    "FindingView",
    "ResultReport",
    "ResultService",
    "ResultSummary",
    "ResultServiceError",
    "ScanCheckpointSavedEvent",
    "ScanCompletedEvent",
    "ScanConfig",
    "ScanConfigError",
    "ScanEvent",
    "ScanFailedEvent",
    "ScanProgressEvent",
    "ScanController",
    "ScanRunResult",
    "ScanService",
    "ScanServiceError",
    "ScanStartedEvent",
    "ScanStoppedEvent",
    "TargetCounts",
    "build_cli_arguments",
    "freeze_counts",
    "thaw_counts",
]
