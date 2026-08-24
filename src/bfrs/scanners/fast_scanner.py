"""Generic single-pass scanner for public chunk detectors."""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Protocol

from bfrs.core.chunk_reader import Chunk, ChunkReader
from bfrs.core.models import RawHit


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
                     ownership_end: int) -> Iterable[RawHit]: ...


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
                     ownership_end: int) -> Iterator[RawHit]:
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
        for chunk in reader.iter_chunks(start=start, end=range_end):
            ownership_end = (range_end if chunk.end_offset >= range_end else
                             min(chunk.offset + reader.chunk_size - reader.overlap,
                                 range_end))
            for detector in self.detectors:
                for hit in detector.detect_chunk(
                        chunk, source=source, ownership_start=chunk.offset,
                        ownership_end=ownership_end):
                    identity = (
                        hit.target, hit.artifact_kind,
                        hit.start_offset, hit.end_offset)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    yield hit
