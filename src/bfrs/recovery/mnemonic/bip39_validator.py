"""Offline validation of BIP-39 mnemonic checksums."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import unicodedata

from .mnemonic_normalizer import bip39_normalize


WORD_COUNTS = frozenset({12, 15, 18, 21, 24})
LANGUAGES = (
    "chinese_simplified", "chinese_traditional", "czech", "english",
    "french", "italian", "japanese", "korean", "portuguese", "spanish",
)


@dataclass(frozen=True, slots=True)
class BIP39Validation:
    status: str
    language: str | None
    word_count: int
    checksum_valid: bool | None
    normalized: str = field(repr=False)
    reason_codes: tuple[str, ...]


class BIP39Validator:
    def __init__(self, wordlist_dir: Path | None = None) -> None:
        root = wordlist_dir or Path(__file__).with_name("wordlists")
        self.wordlists = {}
        self.indices = {}
        for language in LANGUAGES:
            words = tuple(unicodedata.normalize("NFKD", item.strip())
                          for item in (root / f"bip39_{language}.txt")
                          .read_text(encoding="utf-8").splitlines() if item.strip())
            if len(words) != 2048 or len(set(words)) != 2048:
                raise ValueError(f"invalid BIP39 wordlist:{language}")
            self.wordlists[language] = frozenset(words)
            self.indices[language] = {word: index for index, word in enumerate(words)}

    def validate(self, phrase: str) -> BIP39Validation:
        normalized = bip39_normalize(phrase)
        return self.validate_words(tuple(normalized.split()), normalized=normalized)

    def validate_words(self, words: tuple[str, ...], *, normalized: str | None = None,
                       languages: tuple[str, ...] | None = None) -> BIP39Validation:
        normalized = " ".join(words) if normalized is None else normalized
        if len(words) not in WORD_COUNTS:
            return BIP39Validation("BIP39_WORD_COUNT_INVALID", None, len(words),
                                   None, normalized, ("BIP39_WORD_COUNT_INVALID",))
        requested = self.indices if languages is None else (
            language for language in languages if language in self.indices)
        languages = tuple(language for language in requested
                          if all(word in self.indices[language] for word in words))
        if not languages:
            return BIP39Validation("BIP39_WORD_INVALID", None, len(words), None,
                                   normalized, ("BIP39_WORD_INVALID",))
        if len(languages) > 1:
            return BIP39Validation("BIP39_LANGUAGE_AMBIGUOUS", None, len(words),
                                   None, normalized, ("BIP39_LANGUAGE_AMBIGUOUS",))
        language = languages[0]
        combined = 0
        for word in words:
            combined = (combined << 11) | self.indices[language][word]
        bit_length = len(words) * 11
        entropy_length = bit_length * 32 // 33
        checksum_length = entropy_length // 32
        checksum_mask = (1 << checksum_length) - 1
        checksum = combined & checksum_mask
        entropy = (combined >> checksum_length).to_bytes(entropy_length // 8, "big")
        expected = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_length)
        valid = checksum == expected
        return BIP39Validation(
            "BIP39_VALID" if valid else "BIP39_CHECKSUM_INVALID",
            language, len(words), valid, normalized,
            ("BIP39_CHECKSUM_VALID", "BIP39_WORDLIST_VALID") if valid else
            ("BIP39_CHECKSUM_INVALID", "BIP39_WORDLIST_VALID"),
        )
