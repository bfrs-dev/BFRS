"""Offline validation of public Bitcoin mainnet addresses."""

from dataclasses import dataclass

from bfrs.validators.bitcoin_encoding import decode_base58, decode_base58check


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_INDEX = {character: index for index, character in enumerate(_BECH32_CHARSET)}
_BECH32_CONSTANT = 1
_BECH32M_CONSTANT = 0x2BC830A3


@dataclass(frozen=True, slots=True)
class BitcoinAddressValidation:
    address: str
    valid: bool
    address_type: str | None
    encoding: str | None
    checksum_valid: bool
    reason_codes: tuple[str, ...]


def _bech32_polymod(values: tuple[int, ...]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _hrp_expand(hrp: str) -> tuple[int, ...]:
    return tuple(ord(character) >> 5 for character in hrp) + (0,) + tuple(
        ord(character) & 31 for character in hrp
    )


def _convert_bits(
    values: tuple[int, ...],
    from_bits: int,
    to_bits: int,
) -> bytes | None:
    accumulator = 0
    bit_count = 0
    result = bytearray()
    maximum = (1 << to_bits) - 1
    for value in values:
        if value < 0 or value >> from_bits:
            return None
        accumulator = (accumulator << from_bits) | value
        bit_count += from_bits
        while bit_count >= to_bits:
            bit_count -= to_bits
            result.append((accumulator >> bit_count) & maximum)
    if bit_count >= from_bits or ((accumulator << (to_bits - bit_count)) & maximum):
        return None
    return bytes(result)


def _invalid(
    address: str,
    reason: str,
    *,
    encoding: str | None = None,
    checksum_valid: bool = False,
) -> BitcoinAddressValidation:
    return BitcoinAddressValidation(
        address, False, None, encoding, checksum_valid, (reason,)
    )


def _validate_base58(address: str) -> BitcoinAddressValidation:
    try:
        encoded = address.encode("ascii")
    except UnicodeEncodeError:
        return _invalid(address, "BITCOIN_ADDRESS_CHARACTER_SET_INVALID")
    decoded = decode_base58(encoded)
    if decoded is None:
        return _invalid(address, "BITCOIN_ADDRESS_BASE58_INVALID")
    payload = decode_base58check(encoded)
    if payload is None:
        return _invalid(address, "BITCOIN_ADDRESS_CHECKSUM_INVALID")
    if len(decoded) != 25 or len(payload) != 21:
        return _invalid(
            address,
            "BITCOIN_ADDRESS_PAYLOAD_LENGTH_INVALID",
            encoding="BASE58CHECK",
            checksum_valid=True,
        )
    address_type = {0x00: "P2PKH", 0x05: "P2SH"}.get(payload[0])
    if address_type is None:
        return _invalid(
            address,
            "BITCOIN_ADDRESS_MAINNET_VERSION_INVALID",
            encoding="BASE58CHECK",
            checksum_valid=True,
        )
    return BitcoinAddressValidation(
        address,
        True,
        address_type,
        "BASE58CHECK",
        True,
        ("BITCOIN_ADDRESS_BASE58CHECK_VALID",),
    )


def _validate_bech32(address: str) -> BitcoinAddressValidation:
    if not 8 <= len(address) <= 90:
        return _invalid(address, "BITCOIN_ADDRESS_LENGTH_INVALID")
    if any(ord(character) < 33 or ord(character) > 126 for character in address):
        return _invalid(address, "BITCOIN_ADDRESS_CHARACTER_SET_INVALID")
    if address.lower() != address and address.upper() != address:
        return _invalid(address, "BITCOIN_ADDRESS_MIXED_CASE")
    normalized = address.lower()
    separator = normalized.rfind("1")
    if separator < 1 or separator + 7 > len(normalized):
        return _invalid(address, "BITCOIN_ADDRESS_BECH32_STRUCTURE_INVALID")
    hrp = normalized[:separator]
    if hrp != "bc":
        return _invalid(address, "BITCOIN_ADDRESS_MAINNET_HRP_INVALID")
    try:
        data = tuple(_BECH32_INDEX[character] for character in normalized[separator + 1 :])
    except KeyError:
        return _invalid(address, "BITCOIN_ADDRESS_CHARACTER_SET_INVALID")
    polymod = _bech32_polymod(_hrp_expand(hrp) + data)
    encoding = {
        _BECH32_CONSTANT: "BECH32",
        _BECH32M_CONSTANT: "BECH32M",
    }.get(polymod)
    if encoding is None:
        return _invalid(address, "BITCOIN_ADDRESS_CHECKSUM_INVALID")
    witness_data = data[:-6]
    if not witness_data or witness_data[0] > 16:
        return _invalid(
            address,
            "BITCOIN_ADDRESS_WITNESS_VERSION_INVALID",
            encoding=encoding,
            checksum_valid=True,
        )
    witness_version = witness_data[0]
    program = _convert_bits(witness_data[1:], 5, 8)
    if program is None or not 2 <= len(program) <= 40:
        return _invalid(
            address,
            "BITCOIN_ADDRESS_WITNESS_PROGRAM_LENGTH_INVALID",
            encoding=encoding,
            checksum_valid=True,
        )
    if witness_version == 0 and len(program) not in (20, 32):
        return _invalid(
            address,
            "BITCOIN_ADDRESS_WITNESS_PROGRAM_LENGTH_INVALID",
            encoding=encoding,
            checksum_valid=True,
        )
    if witness_version == 0 and encoding != "BECH32":
        return _invalid(
            address,
            "BITCOIN_ADDRESS_WITNESS_ENCODING_INVALID",
            encoding=encoding,
            checksum_valid=True,
        )
    if witness_version > 0 and encoding != "BECH32M":
        return _invalid(
            address,
            "BITCOIN_ADDRESS_WITNESS_ENCODING_INVALID",
            encoding=encoding,
            checksum_valid=True,
        )
    if witness_version == 0:
        address_type = "P2WPKH" if len(program) == 20 else "P2WSH"
    elif witness_version == 1 and len(program) == 32:
        address_type = "P2TR"
    else:
        address_type = "OTHER_WITNESS"
    return BitcoinAddressValidation(
        address,
        True,
        address_type,
        encoding,
        True,
        ("BITCOIN_ADDRESS_BECH32_CHECKSUM_VALID",),
    )


def validate_bitcoin_mainnet_address(address: str) -> BitcoinAddressValidation:
    if not isinstance(address, str):
        raise TypeError("address must be a string")
    if address.startswith(("1", "3")):
        return _validate_base58(address)
    if address.lower().startswith("bc1"):
        return _validate_bech32(address)
    return _invalid(address, "BITCOIN_ADDRESS_PREFIX_NOT_SUPPORTED")
