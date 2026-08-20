"""Bounded-memory recovery of validated mnemonic phrases from byte streams."""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import deque
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import re
import signal
import unicodedata
from typing import Callable

from .bip39_validator import BIP39Validator, WORD_COUNTS
from .electrum_seed_validator import ElectrumSeedValidator
from .electrum_v1_validator import ElectrumV1Validator
from .mnemonic_normalizer import electrum_normalize
from .mnemonic_candidate import MnemonicCandidate


_TOKEN = re.compile(r"[^\W\d_]+", re.UNICODE)
_ENCODINGS = ("utf-8", "utf-16-le", "utf-16-be")
_DOMAIN = b"BFRS-MNEMONIC-FINGERPRINT-V1\0"
_MAX_PARALLEL_OWNERSHIP = 16 * 1024 * 1024
_WORKER_SCANNER: RawMnemonicScanner | None = None


def resolve_worker_count(workers: int) -> int:
    if workers < 0:
        raise ValueError("workers must be nonnegative")
    return min(max((os.cpu_count() or 1) - 1, 1), 4) if workers == 0 else workers


@dataclass(frozen=True, slots=True)
class MnemonicSecret:
    """A deliberately non-printing container used only by the opt-in exporter."""

    _value: str = field(repr=False)

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "MnemonicSecret(<redacted>)"


@dataclass(frozen=True, slots=True)
class MnemonicOccurrence:
    candidate: MnemonicCandidate
    secret: MnemonicSecret = field(repr=False)


@dataclass(frozen=True, slots=True)
class RawMnemonicScanResult:
    occurrences: tuple[MnemonicOccurrence, ...]
    anchors_found: int
    checksum_invalid: int
    failures: tuple[str, ...]


def _initialize_worker(chunk_size: int, overlap: int) -> None:
    """Initialize immutable wordlist indexes once in each child process."""
    global _WORKER_SCANNER
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    _WORKER_SCANNER = RawMnemonicScanner(chunk_size=chunk_size, overlap=overlap)


def _scan_work_unit(unit: tuple[str, int, int, int, int]) -> RawMnemonicScanResult:
    path, scan_start, scan_end, ownership_start, ownership_end = unit
    if _WORKER_SCANNER is None:  # pragma: no cover - protects non-pool callers
        raise RuntimeError("mnemonic worker was not initialized")
    with Path(path).open("rb") as source:
        source.seek(scan_start)
        data = source.read(scan_end - scan_start)
    return _WORKER_SCANNER.scan_bytes(
        data, source=str(Path(path).resolve()), base_offset=scan_start,
        ownership_start=ownership_start, ownership_end=ownership_end)


UnitComplete = Callable[[tuple[str, int, int, int, int], RawMnemonicScanResult,
                         int, int], None]


class RawMnemonicScanner:
    """Scan overlapping chunks; retained state is bounded by one chunk and overlap."""

    def __init__(self, *, chunk_size: int = 64 * 1024 * 1024,
                 overlap: int = 64 * 1024) -> None:
        if overlap < 4096:
            raise ValueError("mnemonic overlap must be at least 4096 bytes")
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.bip39 = BIP39Validator()
        self.electrum = ElectrumSeedValidator()
        self.electrum_v1 = ElectrumV1Validator()
        membership: dict[str, list[int]] = {}
        for bit, words in enumerate(self.bip39.wordlists.values()):
            for word in words:
                membership.setdefault(word, [0, 0, 0])[0] |= 1 << bit
        for bit, words in enumerate(self.electrum.wordlists.values()):
            for word in words:
                membership.setdefault(word, [0, 0, 0])[1] |= 1 << bit
        for word in self.electrum_v1.wordlist:
            membership.setdefault(word, [0, 0, 0])[2] = 1
        self._membership = {word: (masks[0], masks[1], masks[2])
                            for word, masks in membership.items()}
        self._max_token_chars = max(map(len, self._membership))
        self._normalize_token = lru_cache(maxsize=8192)(self._normalize_token_uncached)

    @staticmethod
    def _normalize_token_uncached(token: str) -> tuple[str, str]:
        return (unicodedata.normalize("NFKD", token).casefold(),
                electrum_normalize(token))

    @staticmethod
    def _fingerprint(standard: str, normalized: str) -> str:
        material = _DOMAIN + standard.encode("ascii") + b"\0" + normalized.encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def scan_path(self, source: str | Path, *, start: int = 0,
                  end: int | None = None,
                  progress: Callable[[int, int], None] | None = None,
                  workers: int = 1,
                  resume_results: dict[tuple[int, int], RawMnemonicScanResult] | None = None,
                  unit_complete: UnitComplete | None = None) -> RawMnemonicScanResult:
        path = Path(source).resolve()
        range_end = path.stat().st_size if end is None else end
        worker_count = resolve_worker_count(workers)
        units = self._plan_work_units(path, start, range_end)
        planned = {(unit[3], unit[4]): unit for unit in units}
        resumed = resume_results or {}
        unexpected = set(resumed) - set(planned)
        if unexpected:
            raise ValueError("checkpoint contains incompatible ownership ranges")
        results = [(end_offset - start_offset, result)
                   for (start_offset, end_offset), result in resumed.items()]
        completed = sum(size for size, _ in results)
        total = range_end - start
        pending = [unit for unit in units if (unit[3], unit[4]) not in resumed]
        if progress is not None and completed:
            progress(completed, total)
        if worker_count == 1:
            for unit in pending:
                result = self._scan_local_unit(unit)
                owned = unit[4] - unit[3]
                results.append((owned, result))
                completed += owned
                if unit_complete is not None:
                    unit_complete(unit, result, completed, total)
                if progress is not None:
                    progress(completed, total)
        else:
            results.extend(self._scan_path_parallel(
                pending, worker_count, progress, unit_complete, completed, total))
        return self._merge_results(results)

    def _plan_work_units(self, source: Path, start: int, range_end: int
                         ) -> list[tuple[str, int, int, int, int]]:
        step = min(self.chunk_size - self.overlap, _MAX_PARALLEL_OWNERSHIP)
        path = str(source)
        units = []
        ownership_start = start
        while ownership_start < range_end:
            ownership_end = min(ownership_start + step, range_end)
            scan_end = min(ownership_end + self.overlap, range_end)
            if scan_end >= range_end:
                ownership_end = range_end
            units.append((path, ownership_start, scan_end,
                          ownership_start, ownership_end))
            ownership_start = ownership_end
        return units

    def _scan_local_unit(self, unit: tuple[str, int, int, int, int]
                         ) -> RawMnemonicScanResult:
        path, scan_start, scan_end, ownership_start, ownership_end = unit
        with Path(path).open("rb") as source:
            source.seek(scan_start)
            data = source.read(scan_end - scan_start)
        return self.scan_bytes(data, source=path, base_offset=scan_start,
                               ownership_start=ownership_start,
                               ownership_end=ownership_end)

    def _scan_path_parallel(self, units: list[tuple[str, int, int, int, int]],
                            workers: int, progress: Callable[[int, int], None] | None,
                            unit_complete: UnitComplete | None, completed: int, total: int
                            ) -> list[tuple[int, RawMnemonicScanResult]]:
        results: list[tuple[int, RawMnemonicScanResult]] = []
        if not units:
            return results
        executor = ProcessPoolExecutor(
            max_workers=workers, initializer=_initialize_worker,
            initargs=(self.chunk_size, self.overlap))
        futures = {}
        try:
            futures = {executor.submit(_scan_work_unit, unit): unit for unit in units}
            for future in as_completed(futures):
                unit = futures[future]
                owned = unit[4] - unit[3]
                results.append((owned, future.result()))
                result = results[-1][1]
                completed += owned
                if unit_complete is not None:
                    unit_complete(unit, result, completed, total)
                if progress is not None:
                    progress(completed, total)
        except BaseException:
            for future in futures:
                future.cancel()
            for process in tuple(getattr(executor, "_processes", {}).values()):
                process.terminate()
            executor.shutdown(wait=True, cancel_futures=True)
            raise
        else:
            executor.shutdown(wait=True)
        return results

    @staticmethod
    def _merge_results(results: list[tuple[int, RawMnemonicScanResult]]) -> RawMnemonicScanResult:
        occurrences: dict[tuple[str, int, int, str], MnemonicOccurrence] = {}
        anchors = invalid = 0
        failures: list[str] = []
        for _, result in results:
            anchors += result.anchors_found
            invalid += result.checksum_invalid
            failures.extend(result.failures)
            for occurrence in result.occurrences:
                item = occurrence.candidate
                key = (item.encoding or "", item.physical_start or 0,
                       item.physical_end or 0, item.mnemonic_standard)
                occurrences[key] = occurrence
        ordered = tuple(occurrences[key] for key in sorted(occurrences))
        return RawMnemonicScanResult(ordered, anchors, invalid,
                                     tuple(sorted(set(failures))))

    def scan_bytes(self, data: bytes, *, source: str = "<memory>",
                   base_offset: int = 0, source_kind: str = "RAW_BYTES",
                   ownership_start: int | None = None,
                   ownership_end: int | None = None) -> RawMnemonicScanResult:
        found: dict[tuple[str, int, int, str], MnemonicOccurrence] = {}
        anchors = invalid = 0
        failures: list[str] = []
        for encoding in _ENCODINGS:
            try:
                encoded_data = data if encoding == "utf-8" else data[:len(data) // 2 * 2]
                error_mode = "surrogateescape" if encoding == "utf-8" else "surrogatepass"
                text = encoded_data.decode(encoding, errors=error_mode)
                # Token boundaries are mapped in one monotonic pass.  Each span is
                # encoded at most once, preserving the decoder's exact error policy
                # without a per-character offset table.
                window: deque[tuple[str, str, int, int, int, int, int, str]] = deque(maxlen=24)
                previous_end: int | None = None
                previous_v1_member = False
                previous_raw_end: int | None = None
                v1_run_length = 0
                char_cursor = byte_cursor = 0
                for match in _TOKEN.finditer(text):
                    original = match.group(0)
                    if len(original) > self._max_token_chars:
                        word = electrum_word = ""
                        bip_mask = electrum_mask = electrum_v1_member = 0
                    else:
                        word, electrum_word = self._normalize_token(original)
                        membership = self._membership.get(word, (0, 0, 0))
                        bip_mask = membership[0]
                        electrum_mask = self._membership.get(
                            electrum_word, (0, 0, 0))[1]
                        electrum_v1_member = membership[2]
                    known = bool(bip_mask or electrum_mask or electrum_v1_member)
                    separator = "" if previous_end is None else text[previous_end:match.start()]
                    separator_invalid = (len(separator) > 32 or "\x00" in separator or
                                         any(character.isalnum() or character == "_"
                                             for character in separator))
                    if separator_invalid or not known:
                        window.clear()
                    previous_end = match.end()
                    raw_start = byte_cursor + len(text[char_cursor:match.start()].encode(
                        encoding, errors=error_mode))
                    raw_end = raw_start + len(original.encode(encoding, errors=error_mode))
                    char_cursor, byte_cursor = match.end(), raw_end
                    v1_extends_run = (bool(electrum_v1_member) and previous_v1_member and
                                      bool(separator) and len(separator) <= 32 and
                                      separator.isspace())
                    if v1_extends_run and previous_raw_end is not None:
                        # A V1 candidate is valid only when the entire maximal old-word
                        # run has exactly 12 or 24 words.  Invalidate a candidate that
                        # was tentatively emitted before a following word was observed.
                        previous_physical_end = base_offset + previous_raw_end
                        for key in tuple(found):
                            if (key[0] == encoding and key[2] == previous_physical_end and
                                    key[3] == "ELECTRUM_V1"):
                                del found[key]
                                anchors -= 1
                        v1_run_length += 1
                    else:
                        v1_run_length = 1 if electrum_v1_member else 0
                    previous_v1_member = bool(electrum_v1_member)
                    previous_raw_end = raw_end
                    if not known:
                        continue
                    window.append((original, word, electrum_word, bip_mask, electrum_mask,
                                   raw_start, raw_end, separator))
                    available = tuple(window)
                    for count in range(12, min(24, len(available)) + 1):
                        selected = available[-count:]
                        physical_start = base_offset + selected[0][5]
                        physical_end = base_offset + selected[-1][6]
                        if ((ownership_start is not None and physical_start < ownership_start) or
                                (ownership_end is not None and physical_start >= ownership_end)):
                            continue
                        bip_languages = (1 << len(self.bip39.wordlists)) - 1
                        electrum_languages = (1 << len(self.electrum.wordlists)) - 1
                        for item in selected:
                            bip_languages &= item[3]
                            electrum_languages &= item[4]
                        validations = []
                        # Mnemonic words must be adjacent source tokens separated only
                        # by reasonable whitespace.  Punctuation, markup, and foreign
                        # tokens may never be filtered out to manufacture a phrase.
                        contiguous_source = all(
                            item[7] and len(item[7]) <= 32 and item[7].isspace()
                            for item in selected[1:])
                        span_start, span_end = selected[0][5], selected[-1][6]
                        span_bytes = encoded_data[span_start:span_end]
                        span_text = span_bytes.decode(encoding, errors=error_mode)
                        span_parts = span_text.split()
                        bip39_span_integrity = (
                            len(span_parts) == count and
                            tuple(self._normalize_token(part)[0] for part in span_parts) ==
                            tuple(item[1] for item in selected)
                        )
                        electrum_span_integrity = (
                            len(span_parts) == count and
                            tuple(self._normalize_token(part)[1] for part in span_parts) ==
                            tuple(item[2] for item in selected)
                        )
                        if (count in WORD_COUNTS and bip_languages and
                                contiguous_source and bip39_span_integrity):
                            words = tuple(item[1] for item in selected)
                            normalized = " ".join(words)
                            languages = tuple(name for bit, name in enumerate(self.bip39.wordlists)
                                              if bip_languages & (1 << bit))
                            validations.append(("BIP39", self.bip39.validate_words(
                                words, normalized=normalized, languages=languages)))
                        if (count in {12, 24} and v1_run_length == count and
                                contiguous_source and bip39_span_integrity and
                                all(item[1] in self.electrum_v1.indices for item in selected)):
                            words = tuple(item[1] for item in selected)
                            normalized = " ".join(words)
                            validations.append(("ELECTRUM_V1",
                                                self.electrum_v1.validate_words(
                                                    words, normalized=normalized)))
                        if (electrum_languages and contiguous_source and
                                electrum_span_integrity):
                            words = tuple(item[2] for item in selected)
                            normalized = " ".join(words)
                            languages = tuple(name for bit, name in enumerate(self.electrum.wordlists)
                                              if electrum_languages & (1 << bit))
                            validations.append(("ELECTRUM", self.electrum.validate_words(
                                words, normalized=normalized, languages=languages)))
                        for standard, validation in validations:
                            valid = validation.status in {
                                "BIP39_VALID", "ELECTRUM_SEED_VALID",
                                "ELECTRUM_V1_STRICT_VALID", "ELECTRUM_V1_COMPAT_VALID"}
                            if validation.status == "BIP39_CHECKSUM_INVALID":
                                invalid += 1
                            if not valid:
                                continue
                            anchors += 1
                            normalized = validation.normalized
                            fingerprint = self._fingerprint(standard, normalized)
                            candidate_id = hashlib.sha256(
                                f"{source}|{physical_start}|{physical_end}|{standard}|{fingerprint}"
                                .encode("utf-8")).hexdigest()[:24]
                            reason_codes = validation.reason_codes
                            if standard == "ELECTRUM_V1":
                                reason_codes += ("ELECTRUM_V1_SOURCE_SPAN_VALID",)
                            elif standard == "ELECTRUM":
                                reason_codes += ("ELECTRUM_SOURCE_SPAN_VALID",)
                            candidate = MnemonicCandidate(
                                candidate_id=candidate_id, family="MNEMONIC",
                                mnemonic_standard=standard,
                                validation_status=validation.status,
                                seed_type=getattr(validation, "seed_type", None),
                                language=validation.language,
                                word_count=validation.word_count,
                                checksum_valid=getattr(validation, "checksum_valid", None),
                                completeness="COMPLETE",
                                confidence=("MEDIUM" if standard == "ELECTRUM_V1" or
                                            source_kind == "RAW_BYTES" else "HIGH"),
                                reason_codes=reason_codes,
                                fingerprint=fingerprint, source_kind=source_kind,
                                source=source, physical_start=physical_start,
                                physical_end=physical_end, encoding=encoding,
                            )
                            key = (encoding, physical_start, physical_end, standard)
                            found[key] = MnemonicOccurrence(candidate, MnemonicSecret(normalized))
            except (UnicodeError, ValueError) as error:
                failures.append(f"{encoding}:{type(error).__name__}")
        return RawMnemonicScanResult(tuple(found.values()), anchors, invalid,
                                     tuple(dict.fromkeys(failures)))
