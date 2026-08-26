"""Validation of modern Electrum mnemonic seed-version prefixes."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
from pathlib import Path
import unicodedata

from .mnemonic_normalizer import electrum_normalize, electrum_normalize_words


PREFIXES = (("2fa_segwit", "102"), ("2fa", "101"),
            ("segwit", "100"), ("standard", "01"))
LANGUAGES = ("english", "spanish", "japanese", "portuguese", "chinese_simplified")


@dataclass(frozen=True, slots=True)
class ElectrumSeedValidation:
    status: str
    seed_type: str | None
    language: str | None
    word_count: int
    normalized: str = field(repr=False)
    reason_codes: tuple[str, ...]


class ElectrumSeedValidator:
    def __init__(self, wordlist_dir: Path | None = None) -> None:
        root = wordlist_dir or Path(__file__).with_name("wordlists")
        self.wordlists = {}
        for language in LANGUAGES:
            words = frozenset(electrum_normalize(item.strip())
                              for item in (root / f"electrum_{language}.txt")
                              .read_text(encoding="utf-8").splitlines()
                              if item.strip() and not item.lstrip().startswith("#"))
            if len(words) < 1000:
                raise ValueError(f"invalid Electrum wordlist:{language}")
            self.wordlists[language] = words

    def validate(self, phrase: str) -> ElectrumSeedValidation:
        word_text = electrum_normalize_words(phrase)
        return self.validate_words(tuple(word_text.split()))

    def validate_words(self, words: tuple[str, ...], *, normalized: str | None = None,
                       languages: tuple[str, ...] | None = None) -> ElectrumSeedValidation:
        normalized = " ".join(words) if normalized is None else normalized
        languages = tuple(name for name, values in self.wordlists.items()
                          if all(word in values for word in words)) if languages is None else languages
        if not languages or not 12 <= len(words) <= 24:
            return ElectrumSeedValidation("REJECTED", None, None, len(words),
                                          normalized, ("ELECTRUM_WORD_STRUCTURE_INVALID",))
        digest = hmac.new(b"Seed version", electrum_normalize(normalized).encode("utf-8"),
                          hashlib.sha512).hexdigest()
        seed_type = next((name for name, prefix in PREFIXES
                          if digest.startswith(prefix)), None)
        if seed_type == "2fa" and not (len(words) == 12 or len(words) >= 20):
            seed_type = None
        if seed_type is None:
            return ElectrumSeedValidation("ELECTRUM_SEED_VERSION_INVALID", None,
                                          languages[0] if len(languages) == 1 else None,
                                          len(words), normalized,
                                          ("ELECTRUM_SEED_VERSION_INVALID",))
        return ElectrumSeedValidation(
            "ELECTRUM_SEED_VALID", seed_type,
            languages[0] if len(languages) == 1 else "ambiguous",
            len(words), normalized,
            ("ELECTRUM_HMAC_SEED_VERSION_VALID", "ELECTRUM_WORDLIST_VALID"),
        )
