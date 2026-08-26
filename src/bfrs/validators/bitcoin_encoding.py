"""Shared Bitcoin text encodings used by public and secret validators."""

import hashlib


BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {value: index for index, value in enumerate(BASE58_ALPHABET)}


def decode_base58(value: bytes) -> bytes | None:
    number = 0
    try:
        for character in value:
            number = number * 58 + _BASE58_INDEX[character]
    except KeyError:
        return None
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(value) - len(value.lstrip(b"1"))) + body


def decode_base58check(value: bytes) -> bytes | None:
    decoded = decode_base58(value)
    if decoded is None or len(decoded) < 5:
        return None
    payload, checksum = decoded[:-4], decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return payload if checksum == expected else None
