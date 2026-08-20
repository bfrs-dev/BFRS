"""Strict forensic validation for Electrum's pre-2.0 old mnemonic format."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re

from .mnemonic_normalizer import electrum_normalize


WORD_COUNTS = frozenset({12, 24})
_HEX_LENGTHS = {12: 32, 24: 64}
_HEX = re.compile(r"[0-9a-f]+")


@dataclass(frozen=True, slots=True)
class ElectrumV1Validation:
    status: str
    seed_type: str | None
    language: str | None
    word_count: int
    normalized: str = field(repr=False)
    reason_codes: tuple[str, ...]


class ElectrumV1Validator:
    """Exact old-wordlist codec with stricter acceptance than ``is_old_seed``."""

    def __init__(self, wordlist_path: Path | None = None) -> None:
        path = wordlist_path or Path(__file__).with_name("wordlists").joinpath(
            "electrum_old_english.txt")
        words = tuple(item.strip() for item in path.read_text(encoding="utf-8").splitlines()
                      if item.strip() and not item.lstrip().startswith("#"))
        if len(words) != 1626 or len(set(words)) != 1626:
            raise ValueError("invalid Electrum V1 wordlist")
        self.wordlist = words
        self.indices = {word: index for index, word in enumerate(words)}

    def mn_encode(self, message: str) -> tuple[str, ...]:
        if not message or len(message) % 8 or _HEX.fullmatch(message.lower()) is None:
            raise ValueError("Electrum V1 entropy must be nonempty whole 32-bit hex chunks")
        n = len(self.wordlist)
        result: list[str] = []
        for offset in range(0, len(message), 8):
            value = int(message[offset:offset + 8], 16)
            w1 = value % n
            w2 = (value // n + w1) % n
            w3 = (value // n // n + w2) % n
            result.extend((self.wordlist[w1], self.wordlist[w2], self.wordlist[w3]))
        return tuple(result)

    def mn_decode(self, words: tuple[str, ...]) -> str:
        if not words or len(words) % 3:
            raise ValueError("Electrum V1 word count must be divisible by three")
        n = len(self.wordlist)
        output: list[str] = []
        try:
            for offset in range(0, len(words), 3):
                w1, w2, w3 = (self.indices[word] for word in words[offset:offset + 3])
                value = w1 + n * ((w2 - w1) % n) + n * n * ((w3 - w2) % n)
                output.append(f"{value:08x}")
        except KeyError as error:
            raise ValueError("word is not in the Electrum V1 wordlist") from error
        return "".join(output)

    def validate(self, phrase: str) -> ElectrumV1Validation:
        normalized = electrum_normalize(phrase)
        return self.validate_words(tuple(normalized.split()), normalized=normalized)

    def validate_words(self, words: tuple[str, ...], *, normalized: str | None = None
                       ) -> ElectrumV1Validation:
        normalized = " ".join(words) if normalized is None else normalized
        count = len(words)
        if count not in WORD_COUNTS:
            return ElectrumV1Validation(
                "ELECTRUM_V1_WORD_COUNT_INVALID", None, None, count, normalized,
                ("ELECTRUM_V1_WORD_COUNT_INVALID",))
        if any(word not in self.indices for word in words):
            return ElectrumV1Validation(
                "ELECTRUM_V1_WORD_INVALID", None, None, count, normalized,
                ("ELECTRUM_V1_WORD_INVALID",))
        decoded = self.mn_decode(words)
        expected_length = _HEX_LENGTHS[count]
        if len(decoded) != expected_length or _HEX.fullmatch(decoded) is None:
            return ElectrumV1Validation(
                "ELECTRUM_V1_INVALID_ENTROPY_LENGTH", None, "english", count,
                normalized, ("ELECTRUM_V1_WORDLIST_VALID",
                             "ELECTRUM_V1_INVALID_ENTROPY_LENGTH"))
        if self.mn_encode(decoded) != words:
            return ElectrumV1Validation(
                "ELECTRUM_V1_ROUNDTRIP_INVALID", None, "english", count,
                normalized, ("ELECTRUM_V1_WORDLIST_VALID",
                             "ELECTRUM_V1_ROUNDTRIP_INVALID"))
        compatibility = count == 24
        return ElectrumV1Validation(
            "ELECTRUM_V1_COMPAT_VALID" if compatibility else "ELECTRUM_V1_STRICT_VALID",
            "old_24_compat" if compatibility else "old", "english", count, normalized,
            ("ELECTRUM_V1_WORDLIST_VALID", "ELECTRUM_V1_ROUNDTRIP_VALID",
             "ELECTRUM_V1_ENTROPY_LENGTH_VALID"))
