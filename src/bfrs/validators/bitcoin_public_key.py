"""Validation of public SEC keys represented as bytes or hexadecimal text."""

from dataclasses import dataclass
import hashlib

from bfrs.core.secp256k1 import decode_sec_public_key
from bfrs.validators.bitcoin_record_key import (
    BITCOIN_RECORD_PUBKEY_NOT_ON_CURVE,
    BITCOIN_RECORD_PUBKEY_PREFIX_INVALID,
)


@dataclass(frozen=True, slots=True)
class BitcoinPublicKeyValidation:
    valid: bool
    compressed: bool | None
    safe_fingerprint: str | None
    reason_codes: tuple[str, ...]


def validate_sec_public_key(public_key: bytes) -> BitcoinPublicKeyValidation:
    if len(public_key) not in (33, 65):
        return BitcoinPublicKeyValidation(
            False, None, None, ("BITCOIN_PUBLIC_KEY_LENGTH_INVALID",)
        )
    compressed = len(public_key) == 33
    if (compressed and public_key[0] not in (2, 3)) or (
        not compressed and public_key[0] != 4
    ):
        return BitcoinPublicKeyValidation(
            False, compressed, None, (BITCOIN_RECORD_PUBKEY_PREFIX_INVALID,)
        )
    if decode_sec_public_key(public_key) is None:
        return BitcoinPublicKeyValidation(
            False, compressed, None, (BITCOIN_RECORD_PUBKEY_NOT_ON_CURVE,)
        )
    return BitcoinPublicKeyValidation(
        True,
        compressed,
        hashlib.sha256(public_key).hexdigest(),
        ("BITCOIN_PUBLIC_KEY_SECP256K1_VALID",),
    )


def validate_textual_sec_public_key(value: str) -> BitcoinPublicKeyValidation:
    if not isinstance(value, str):
        raise TypeError("public key must be a string")
    if len(value) not in (66, 130):
        return BitcoinPublicKeyValidation(
            False, None, None, ("BITCOIN_PUBLIC_KEY_LENGTH_INVALID",)
        )
    try:
        public_key = bytes.fromhex(value)
    except ValueError:
        return BitcoinPublicKeyValidation(
            False, None, None, ("BITCOIN_PUBLIC_KEY_HEX_INVALID",)
        )
    return validate_sec_public_key(public_key)
