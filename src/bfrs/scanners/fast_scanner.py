"""Generic single-pass scanner for public chunk detectors."""

from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Protocol

from bfrs.core.chunk_reader import Chunk, ChunkReader
from bfrs.core.models import RawHit
from bfrs.core.worker_control import wait_for_single_future


@dataclass(frozen=True, slots=True)
class ScanProgress:
    """Safe aggregate progress for one bounded streaming scan."""

    scanned_bytes: int
    total_bytes: int
    raw_hits: int
    raw_by_target: dict[str, int] = field(default_factory=dict)
    rejected_by_target: dict[str, int] = field(default_factory=dict)
    pending_validation_by_target: dict[str, int] = field(default_factory=dict)
    validated_occurrences_by_target: dict[str, int] = field(default_factory=dict)
    validated_unique_by_target: dict[str, int] = field(default_factory=dict)
    anchors_total: int = 0
    stage: str | None = None
    complete: bool = False

    @property
    def percent_complete(self) -> float:
        if self.total_bytes == 0:
            return 100.0
        return min(100.0, self.scanned_bytes * 100.0 / self.total_bytes)


@dataclass(frozen=True, slots=True)
class SignatureAssessment:
    confidence: float = 0.0
    structural_status: str = "ANCHOR_ONLY"
    validation_status: str = "UNVALIDATED"
    reason_codes: tuple[str, ...] = ()
    correlated_evidence: tuple[str, ...] = ()
    safe_metadata: dict[str, object] = field(default_factory=dict)
    recommended_recovery_action: str = "REVIEW_CONTEXT"


class SignatureClassifier(Protocol):
    def __call__(self, signature: "Signature", chunk: Chunk,
                 local_offset: int) -> SignatureAssessment: ...


class ChunkDetector(Protocol):
    required_overlap: int

    def detect_chunk(self, chunk: Chunk, *, source: str,
                     ownership_start: int,
                     ownership_end: int,
                     status: Callable[[str], None] | None = None,
                     ) -> Iterable[RawHit]: ...


@dataclass(frozen=True, slots=True)
class Signature:
    name: str
    pattern: bytes
    category: str
    target: str = "unknown"
    artifact_kind: str = "signature_anchor"
    classifier: SignatureClassifier | None = field(
        default=None, compare=False, hash=False, repr=False)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("signature name must not be empty")
        if not self.pattern:
            raise ValueError("signature pattern must not be empty")
        if not self.category:
            raise ValueError("signature category must not be empty")


class BinarySignatureDetector:
    """Public fixed-pattern adapter used by the shared streaming scanner."""

    def __init__(self, signatures: Iterable[Signature]) -> None:
        collected = tuple(signatures)
        if not collected:
            raise ValueError("at least one signature is required")
        identities = {(item.name, item.pattern) for item in collected}
        if len(identities) != len(collected):
            raise ValueError("duplicate signature name and pattern")
        self.signatures = collected
        self.required_overlap = max(len(item.pattern) for item in collected) - 1

    def detect_chunk(self, chunk: Chunk, *, source: str,
                     ownership_start: int,
                     ownership_end: int,
                     status: Callable[[str], None] | None = None,
                     ) -> Iterator[RawHit]:
        for signature in self.signatures:
            local_offset = chunk.data.find(signature.pattern)
            while local_offset != -1:
                absolute_offset = chunk.offset + local_offset
                if ownership_start <= absolute_offset < ownership_end:
                    assessment = (signature.classifier(
                        signature, chunk, local_offset)
                        if signature.classifier is not None else
                        SignatureAssessment())
                    yield RawHit(
                        start_offset=absolute_offset,
                        end_offset=absolute_offset + len(signature.pattern),
                        hit_type=signature.name,
                        confidence=assessment.confidence,
                        source=source,
                        evidence={"category": signature.category},
                        target=signature.target,
                        artifact_kind=signature.artifact_kind,
                        structural_status=assessment.structural_status,
                        validation_status=assessment.validation_status,
                        reason_codes=assessment.reason_codes,
                        correlated_evidence=assessment.correlated_evidence,
                        safe_metadata=dict(assessment.safe_metadata),
                        recommended_recovery_action=(
                            assessment.recommended_recovery_action),
                    )
                local_offset = chunk.data.find(signature.pattern, local_offset + 1)


class FastScanner:
    def __init__(self, signatures: Iterable[Signature], *,
                 chunk_detectors: Iterable[ChunkDetector] = ()) -> None:
        collected = tuple(signatures)
        detectors = tuple(chunk_detectors)
        if not collected and not detectors:
            raise ValueError("at least one signature or chunk detector is required")
        self.signatures = collected
        self.detectors: tuple[ChunkDetector, ...] = (
            *((BinarySignatureDetector(collected),) if collected else ()),
            *detectors,
        )
        self.required_overlap = max(
            (detector.required_overlap for detector in self.detectors), default=0)

    def scan(
        self,
        reader: ChunkReader,
        start: int = 0,
        end: int | None = None,
        *,
        progress: Callable[[ScanProgress], None] | None = None,
        resume_results: Mapping[tuple[int, int], tuple[RawHit, ...]] | None = None,
        unit_complete: Callable[[tuple[int, int], tuple[RawHit, ...], int, int], None]
        | None = None,
    ) -> Iterator[RawHit]:
        file_size = reader.file_size
        range_end = file_size if end is None else end

        if start < 0:
            raise ValueError("start must not be negative")
        if range_end > file_size:
            raise ValueError("end must not exceed file size")
        if start > range_end:
            raise ValueError("start must not exceed end")

        if range_end - start > reader.chunk_size:
            if reader.overlap < self.required_overlap:
                raise ValueError(
                    f"reader overlap must be at least {self.required_overlap} bytes"
                )

        source = str(reader.path.resolve())
        seen: set[tuple[str, str, int, int]] = set()
        raw_by_target: Counter[str] = Counter()
        rejected_by_target: Counter[str] = Counter()
        pending_by_target: Counter[str] = Counter()
        validated_by_target: Counter[str] = Counter()
        validated_fingerprints: dict[str, set[str]] = {}
        raw_hits = 0
        anchors_total = 0
        emitted_progress = False
        resumed = dict(resume_results or {})
        used_resumed: set[tuple[int, int]] = set()
        process_backed_detector = next((
            detector for detector in self.detectors
            if callable(getattr(detector, "submit_chunk", None))
        ), None)
        branch_enabled = (
            process_backed_detector is not None
            and len(self.detectors) > 1
            and range_end - start > reader.chunk_size)
        if not resumed and unit_complete is None:
            units = (
                (
                    chunk.offset,
                    (range_end if chunk.end_offset >= range_end else
                     min(chunk.offset + reader.chunk_size - reader.overlap,
                         range_end)),
                    chunk,
                )
                for chunk in reader.iter_chunks(start=start, end=range_end)
            )
        else:
            units = reader.iter_owned_chunks(
                start=start, end=range_end,
                skip_ownership_ranges=resumed)
        try:
            for ownership_start, ownership_end, chunk in units:
                unit_key = (ownership_start, ownership_end)
                if chunk is None:
                    unit_hits = resumed[unit_key]
                    used_resumed.add(unit_key)
                else:
                    def report_stage(stage: str) -> None:
                        if progress is not None:
                            progress(ScanProgress(
                                scanned_bytes=max(0, ownership_start - start),
                                total_bytes=range_end - start,
                                raw_hits=raw_hits,
                                raw_by_target=dict(raw_by_target),
                                rejected_by_target=dict(rejected_by_target),
                                pending_validation_by_target=dict(pending_by_target),
                                validated_occurrences_by_target=dict(
                                    validated_by_target),
                                validated_unique_by_target={
                                    target: len(fingerprints)
                                    for target, fingerprints
                                    in validated_fingerprints.items()
                                },
                                anchors_total=anchors_total,
                                stage=stage,
                            ))

                    def run_detector(detector: ChunkDetector) -> tuple[RawHit, ...]:
                        return tuple(detector.detect_chunk(
                            chunk, source=source, ownership_start=ownership_start,
                            ownership_end=ownership_end, status=report_stage))

                    branch_future = (
                        process_backed_detector.submit_chunk(
                            chunk, source=source, ownership_start=ownership_start,
                            ownership_end=ownership_end)
                        if branch_enabled else None)
                    detector_hits: dict[int, tuple[RawHit, ...]] = {}
                    for index, detector in enumerate(self.detectors):
                        if detector is process_backed_detector and branch_future is not None:
                            continue
                        detector_hits[index] = run_detector(detector)
                    if branch_future is not None:
                        index = self.detectors.index(process_backed_detector)
                        detector_hits[index] = wait_for_single_future(
                            branch_future,
                            operation="mnemonic branch",
                            unit_id=f"ownership[{ownership_start}..{ownership_end})",
                        )
                    ordered_hits = (
                        (hit.start_offset, index, ordinal, hit)
                        for index in range(len(self.detectors))
                        for ordinal, hit in enumerate(detector_hits[index]))
                    unit_hits = tuple(
                        item[3] for item in sorted(
                            ordered_hits,
                            key=lambda item: (item[0], item[1], item[2])))
                    if unit_complete is not None:
                        unit_complete(unit_key, unit_hits,
                                      ownership_end - start, range_end - start)
                for hit in unit_hits:
                    identity = (
                        hit.target, hit.artifact_kind,
                        hit.start_offset, hit.end_offset)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    raw_hits += 1
                    raw_by_target[hit.target] += 1
                    if hit.target == "internal":
                        anchors_total += 1
                    elif (hit.validation_status == "REJECTED" or
                          hit.structural_status == "REJECTED"):
                        rejected_by_target[hit.target] += 1
                    elif hit.validation_status == "UNVALIDATED":
                        pending_by_target[hit.target] += 1
                    else:
                        validated_by_target[hit.target] += 1
                        if hit.safe_fingerprint is not None:
                            validated_fingerprints.setdefault(
                                hit.target, set()).add(hit.safe_fingerprint)
                    yield hit
                if progress is not None:
                    scanned_bytes = max(0, ownership_end - start)
                    progress(ScanProgress(
                        scanned_bytes=scanned_bytes,
                        total_bytes=range_end - start,
                        raw_hits=raw_hits,
                        raw_by_target=dict(raw_by_target),
                        rejected_by_target=dict(rejected_by_target),
                        pending_validation_by_target=dict(pending_by_target),
                        validated_occurrences_by_target=dict(validated_by_target),
                        validated_unique_by_target={
                            target: len(fingerprints)
                            for target, fingerprints in validated_fingerprints.items()
                        },
                        anchors_total=anchors_total,
                        complete=ownership_end >= range_end,
                    ))
                    emitted_progress = True
            unexpected = set(resumed) - used_resumed
            if unexpected:
                raise ValueError("checkpoint contains incompatible ownership ranges")
        except BaseException:
            for detector in self.detectors:
                abort = getattr(detector, "abort", None)
                if abort is not None:
                    abort()
                else:
                    close = getattr(detector, "close", None)
                    if close is not None:
                        close()
            raise
        else:
            for detector in self.detectors:
                close = getattr(detector, "close", None)
                if close is not None:
                    close()
        if progress is not None and not emitted_progress:
            progress(ScanProgress(
                scanned_bytes=0,
                total_bytes=0,
                raw_hits=0,
                complete=True,
            ))
