"""Seed-only orchestration and safe deduplication."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

from .document_seed_recovery import DOCUMENT_EXTENSIONS, DocumentSeedRecovery
from .mnemonic_candidate import MnemonicCandidate, MnemonicRecovery
from .raw_mnemonic_scanner import (
    MnemonicOccurrence,
    RawMnemonicScanner,
    RawMnemonicScanResult,
    UnitComplete,
)


@dataclass(frozen=True, slots=True)
class MnemonicPipelineResult:
    source: str
    start_offset: int
    end_offset: int
    recovery: MnemonicRecovery
    occurrences: tuple[MnemonicOccurrence, ...] = ()


class MnemonicRecoveryPipeline:
    def __init__(self, *, chunk_size: int, overlap: int) -> None:
        self.scanner = RawMnemonicScanner(chunk_size=chunk_size, overlap=overlap)
        self.documents = DocumentSeedRecovery(self.scanner)

    def scan(self, source: str | Path, *, start: int = 0,
             end: int | None = None,
             progress: Callable[[int, int], None] | None = None,
             workers: int = 1,
             resume_results: dict[tuple[int, int], RawMnemonicScanResult] | None = None,
             unit_complete: UnitComplete | None = None) -> MnemonicPipelineResult:
        path = Path(source).resolve()
        range_end = path.stat().st_size if end is None else end
        raw = self.scanner.scan_path(path, start=start, end=range_end,
                                     progress=progress, workers=workers,
                                     resume_results=resume_results,
                                     unit_complete=unit_complete)
        occurrences = list(raw.occurrences)
        failures = list(raw.failures)
        if start == 0 and range_end == path.stat().st_size and path.suffix.lower() in DOCUMENT_EXTENSIONS:
            document = self.documents.scan_path(path)
            occurrences.extend(document.occurrences)
            failures.extend(document.failures)
        if start == 0 and range_end == path.stat().st_size:
            ntfs = self.documents.scan_ntfs_image(path)
            occurrences.extend(ntfs.occurrences)
            failures.extend(ntfs.failures)

        grouped: dict[tuple[str, str], list[MnemonicOccurrence]] = {}
        for item in occurrences:
            grouped.setdefault((item.candidate.mnemonic_standard,
                                item.candidate.fingerprint), []).append(item)
        candidates: list[MnemonicCandidate] = []
        duplicate_occurrences = 0
        for items in grouped.values():
            first = items[0].candidate
            duplicate_occurrences += len(items) - 1
            provenance = tuple({
                "source_kind": item.candidate.source_kind,
                "physical_start": item.candidate.physical_start,
                "physical_end": item.candidate.physical_end,
                "encoding": item.candidate.encoding,
                "path": item.candidate.path,
                "allocation_state": item.candidate.allocation_state,
            } for item in items)
            candidates.append(replace(first,
                                      confidence=("HIGH" if any(
                                          item.candidate.confidence == "HIGH" for item in items)
                                          else first.confidence),
                                      duplicate_count=len(items), provenance=provenance,
                                      correlated_sources=tuple(sorted({
                                          item.candidate.source_kind for item in items}))))
        recovery = MnemonicRecovery(
            anchors_found=raw.anchors_found, candidates_total=len(candidates),
            high_confidence_candidates=sum(item.confidence == "HIGH" for item in candidates),
            bip39_valid=sum(item.mnemonic_standard == "BIP39" for item in candidates),
            electrum_valid=sum(item.mnemonic_standard == "ELECTRUM" for item in candidates),
            structural_fragments=0, checksum_invalid=raw.checksum_invalid,
            known_file_candidates=sum(any(provenance["source_kind"] == "KNOWN_FILE_CONTENT"
                                          for provenance in item.provenance) for item in candidates),
            deleted_file_candidates=sum(any(provenance["allocation_state"] == "DELETED_FILE"
                                            for provenance in item.provenance) for item in candidates),
            raw_candidates=sum(any(provenance["source_kind"] == "RAW_BYTES"
                                   for provenance in item.provenance) for item in candidates),
            document_candidates=sum(any(provenance["source_kind"] == "DOCUMENT_EXTRACTED_TEXT"
                                        for provenance in item.provenance) for item in candidates),
            unique_secret_fingerprints=len({item.fingerprint for item in candidates}),
            duplicate_occurrences=duplicate_occurrences,
            failures=tuple(dict.fromkeys(failures)), candidates=tuple(candidates))
        return MnemonicPipelineResult(str(path), start, range_end, recovery,
                                      tuple(occurrences))
