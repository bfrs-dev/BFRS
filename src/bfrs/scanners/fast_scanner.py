"""Generic single-pass scanner for public chunk detectors."""

from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Protocol

from bfrs.core.chunk_reader import Chunk, ChunkReader
from bfrs.core.models import RawHit


@dataclass(frozen=True, slots=True)
class ScanProgress:
    """Safe aggregate progress for one bounded streaming scan."""

    scanned_bytes: int
    total_bytes: int
    findings_total: int
    findings_by_target: dict[str, int] = field(default_factory=dict)
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
        findings_by_target: Counter[str] = Counter()
        findings_total = 0
        anchors_total = 0
        emitted_progress = False
        try:
            for chunk in reader.iter_chunks(start=start, end=range_end):
                ownership_end = (range_end if chunk.end_offset >= range_end else
                                 min(chunk.offset + reader.chunk_size - reader.overlap,
                                     range_end))
                for detector in self.detectors:
                    def report_stage(stage: str) -> None:
                        if progress is not None:
                            progress(ScanProgress(
                                scanned_bytes=max(0, chunk.offset - start),
                                total_bytes=range_end - start,
                                findings_total=findings_total,
                                findings_by_target=dict(findings_by_target),
                                anchors_total=anchors_total,
                                stage=stage,
                            ))
                    for hit in detector.detect_chunk(
                            chunk, source=source, ownership_start=chunk.offset,
                            ownership_end=ownership_end, status=report_stage):
                        identity = (
                            hit.target, hit.artifact_kind,
                            hit.start_offset, hit.end_offset)
                        if identity in seen:
                            continue
                        seen.add(identity)
                        if hit.target == "internal":
                            anchors_total += 1
                        else:
                            findings_total += 1
                            findings_by_target[hit.target] += 1
                        yield hit
                if progress is not None:
                    scanned_bytes = max(0, ownership_end - start)
                    progress(ScanProgress(
                        scanned_bytes=scanned_bytes,
                        total_bytes=range_end - start,
                        findings_total=findings_total,
                        findings_by_target=dict(findings_by_target),
                        anchors_total=anchors_total,
                        complete=ownership_end >= range_end,
                    ))
                    emitted_progress = True
        finally:
            for detector in self.detectors:
                close = getattr(detector, "close", None)
                if close is not None:
                    close()
        if progress is not None and not emitted_progress:
            progress(ScanProgress(
                scanned_bytes=0,
                total_bytes=0,
                findings_total=0,
                complete=True,
            ))
