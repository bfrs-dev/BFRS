"""Bounded-memory recovery of validated mnemonic phrases from byte streams."""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import deque
import hashlib
from pathlib import Path
import re
import unicodedata

from bfrs.core.chunk_reader import ChunkReader

from .bip39_validator import BIP39Validator, WORD_COUNTS
from .electrum_seed_validator import ElectrumSeedValidator
from .mnemonic_normalizer import electrum_normalize
from .mnemonic_candidate import MnemonicCandidate


_TOKEN = re.compile(r"[^\W\d_]+", re.UNICODE)
_ENCODINGS = ("utf-8", "utf-16-le", "utf-16-be")
_DOMAIN = b"BFRS-MNEMONIC-FINGERPRINT-V1\0"


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
        self._all_words = frozenset().union(
            *self.bip39.wordlists.values(), *self.electrum.wordlists.values())

    @staticmethod
    def _fingerprint(standard: str, normalized: str) -> str:
        material = _DOMAIN + standard.encode("ascii") + b"\0" + normalized.encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def scan_path(self, source: str | Path, *, start: int = 0,
                  end: int | None = None) -> RawMnemonicScanResult:
        reader = ChunkReader(source, self.chunk_size, self.overlap)
        occurrences: dict[tuple[str, int, int, str], MnemonicOccurrence] = {}
        anchors = invalid = 0
        failures: list[str] = []
        for chunk in reader.iter_chunks(start, end):
            result = self.scan_bytes(chunk.data, source=str(Path(source).resolve()),
                                     base_offset=chunk.offset)
            anchors += result.anchors_found
            invalid += result.checksum_invalid
            failures.extend(result.failures)
            for occurrence in result.occurrences:
                item = occurrence.candidate
                key = (item.encoding or "", item.physical_start or 0,
                       item.physical_end or 0, item.mnemonic_standard)
                occurrences[key] = occurrence
        return RawMnemonicScanResult(tuple(occurrences.values()), anchors, invalid,
                                     tuple(dict.fromkeys(failures)))

    def scan_bytes(self, data: bytes, *, source: str = "<memory>",
                   base_offset: int = 0, source_kind: str = "RAW_BYTES") -> RawMnemonicScanResult:
        found: dict[tuple[str, int, int, str], MnemonicOccurrence] = {}
        anchors = invalid = 0
        failures: list[str] = []
        for encoding in _ENCODINGS:
            try:
                encoded_data = data if encoding == "utf-8" else data[:len(data) // 2 * 2]
                error_mode = "surrogateescape" if encoding == "utf-8" else "surrogatepass"
                text = encoded_data.decode(encoding, errors=error_mode)
                window: deque[tuple[str, str, int, int]] = deque(maxlen=24)
                previous_end: int | None = None
                for match in _TOKEN.finditer(text):
                    original = match.group(0)
                    word = unicodedata.normalize("NFKD", original).casefold()
                    known = (word in self._all_words or
                             electrum_normalize(original) in self._all_words)
                    separator = "" if previous_end is None else text[previous_end:match.start()]
                    separator_invalid = (len(separator) > 32 or "\x00" in separator or
                                         any(character.isalnum() or character == "_"
                                             for character in separator))
                    if separator_invalid or not known:
                        window.clear()
                    previous_end = match.end()
                    if not known:
                        continue
                    window.append((original, word, match.start(), match.end()))
                    available = tuple(window)
                    for count in range(12, min(24, len(available)) + 1):
                        selected = available[-count:]
                        phrase = " ".join(item[0] for item in selected)
                        validations = []
                        if count in WORD_COUNTS:
                            validations.append(("BIP39", self.bip39.validate(phrase)))
                        validations.append(("ELECTRUM", self.electrum.validate(phrase)))
                        start_char, end_char = selected[0][2], selected[-1][3]
                        raw_start = len(text[:start_char].encode(encoding, errors=error_mode))
                        raw_end = len(text[:end_char].encode(encoding, errors=error_mode))
                        for standard, validation in validations:
                            valid = validation.status in {"BIP39_VALID", "ELECTRUM_SEED_VALID"}
                            if validation.status == "BIP39_CHECKSUM_INVALID":
                                invalid += 1
                            if not valid:
                                continue
                            anchors += 1
                            normalized = validation.normalized
                            fingerprint = self._fingerprint(standard, normalized)
                            physical_start = base_offset + raw_start
                            physical_end = base_offset + raw_end
                            candidate_id = hashlib.sha256(
                                f"{source}|{physical_start}|{physical_end}|{standard}|{fingerprint}"
                                .encode("utf-8")).hexdigest()[:24]
                            candidate = MnemonicCandidate(
                                candidate_id=candidate_id, family="MNEMONIC",
                                mnemonic_standard=standard,
                                validation_status=validation.status,
                                seed_type=getattr(validation, "seed_type", None),
                                language=validation.language,
                                word_count=validation.word_count,
                                checksum_valid=getattr(validation, "checksum_valid", None),
                                completeness="COMPLETE", confidence="HIGH",
                                reason_codes=validation.reason_codes,
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
