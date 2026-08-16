"""Normalization rules for mnemonic standards."""

import string
import unicodedata


def bip39_normalize(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKD", text).split())


def _is_cjk(character: str) -> bool:
    value = ord(character)
    return any(low <= value <= high for low, high in (
        (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0x3040, 0x30FF),
        (0xAC00, 0xD7AF), (0x1100, 0x11FF), (0xFF00, 0xFFEF),
    ))


def electrum_normalize(text: str) -> str:
    value = unicodedata.normalize("NFKD", text).lower()
    value = "".join(char for char in value if not unicodedata.combining(char))
    value = " ".join(value.split())
    return "".join(char for index, char in enumerate(value)
                   if not (char in string.whitespace and index > 0
                           and index + 1 < len(value)
                           and _is_cjk(value[index - 1])
                           and _is_cjk(value[index + 1])))
