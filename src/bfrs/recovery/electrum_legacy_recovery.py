"""Strict structural detection of confirmed pre-keystore Electrum storage."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
import re

from bfrs.recovery.mnemonic.electrum_v1_validator import ElectrumV1Validator


LEGACY_ELECTRUM_SIGNATURE_PATTERNS = (
    ("electrum_legacy_seed_version_single_quote", b"'seed_version'"),
    ("electrum_legacy_master_public_key_single_quote", b"'master_public_key'"),
    ("electrum_legacy_master_public_keys_single_quote", b"'master_public_keys'"),
    ("electrum_legacy_accounts_single_quote", b"'accounts'"),
    ("electrum_legacy_use_encryption_single_quote", b"'use_encryption'"),
    ("electrum_legacy_addresses_single_quote", b"'addresses'"),
    ("electrum_legacy_change_addresses_single_quote", b"'change_addresses'"),
    ("electrum_legacy_imported_keys_single_quote", b"'imported_keys'"),
    ("electrum_legacy_master_public_key_json", b'"master_public_key"'),
    ("electrum_legacy_master_public_keys_json", b'"master_public_keys"'),
    ("electrum_legacy_accounts_json", b'"accounts"'),
    ("electrum_legacy_use_encryption_json", b'"use_encryption"'),
    ("electrum_legacy_addresses_json", b'"addresses"'),
    ("electrum_legacy_change_addresses_json", b'"change_addresses"'),
    ("electrum_legacy_imported_keys_json", b'"imported_keys"'),
    ("electrum_legacy_tuple_plaintext", b"(1, False,"),
    ("electrum_legacy_tuple_encrypted", b"(1, True,"),
    ("electrum_legacy_list_plaintext", b"[1, False,"),
    ("electrum_legacy_list_encrypted", b"[1, True,"),
)
LEGACY_ELECTRUM_SIGNATURE_NAMES = frozenset(
    name for name, _ in LEGACY_ELECTRUM_SIGNATURE_PATTERNS
)
MAX_LEGACY_WALLET_SIZE = 32 * 1024 * 1024
MAX_FRAGMENT_SIZE = 256 * 1024
MAX_FRAGMENT_FIELD_SPAN = 64 * 1024
HEX_OLD_MPK = re.compile(r"[0-9a-fA-F]{128}")
HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\Z"
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
WALLET_TYPES = frozenset({
    "old", "standard", "xpub", "imported", "bip44", "2fa",
    "trezor", "keepkey", "ledger", "btchip",
})
STRUCTURAL_FIELDS = frozenset({
    "seed_version", "wallet_type", "accounts", "master_public_key",
    "master_public_keys", "master_private_keys", "use_encryption",
    "imported_keys", "keypairs", "key_type", "seed",
    "addresses", "change_addresses",
})


def _decoded_texts(raw: bytes):
    """Yield historically plausible text decodings without duplicates."""
    seen = set()
    for encoding in ("utf-8", "cp1252", "cp1250", "latin-1"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if text in seen:
            continue
        seen.add(text)
        yield text, encoding.upper().replace("-", "_")


def _python2_literal_compat(text: str) -> str:
    """Remove Python 2 long-integer suffixes outside quoted strings."""
    output = []
    quote = None
    escaped = False
    for index, character in enumerate(text):
        if quote is not None:
            output.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
            output.append(character)
            continue
        if (character in {"L", "l"} and output and output[-1].isdigit()
                and (index + 1 == len(text) or not text[index + 1].isalnum())):
            continue
        output.append(character)
    return "".join(output)


@dataclass(frozen=True, slots=True)
class LegacyDetection:
    start: int
    end: int
    legacy_format: str
    format_generation: str
    serialization_type: str
    completeness: str
    encryption_state: str
    confidence: str
    reason_codes: tuple[str, ...]
    safe_metadata: dict
    digest: str


def _balanced_dicts(data: bytes, required_anchor_offset: int | None = None):
    """Yield balanced dict byte ranges while respecting both quote styles."""
    starts = [index for index, byte in enumerate(data) if byte == 0x7B]
    if required_anchor_offset is not None:
        starts = [item for item in starts if item <= required_anchor_offset][-64:]
    for start in starts:
        depth = 0
        quote = None
        escaped = False
        for end in range(start, min(len(data), start + MAX_LEGACY_WALLET_SIZE)):
            current = data[end]
            if quote is not None:
                if escaped:
                    escaped = False
                elif current == 0x5C:
                    escaped = True
                elif current == quote:
                    quote = None
                continue
            if current in (0x22, 0x27):
                quote = current
            elif current == 0x7B:
                depth += 1
            elif current == 0x7D:
                depth -= 1
                if depth == 0:
                    yield start, end + 1
                    break


def _balanced_legacy_sequences(data: bytes,
                               required_anchor_offset: int | None = None):
    """Yield only sequences beginning with the exact historical tuple prefix."""
    prefixes = (b"(1, False,", b"(1, True,", b"[1, False,", b"[1, True,")
    starts = sorted({position
                     for prefix in prefixes
                     for position in _all_occurrences(data, prefix)})
    if required_anchor_offset is not None:
        starts = [item for item in starts if item <= required_anchor_offset][-16:]
    pairs = {0x28: 0x29, 0x5B: 0x5D, 0x7B: 0x7D}
    for start in starts:
        stack = []
        quote = None
        escaped = False
        for end in range(start, min(len(data), start + MAX_LEGACY_WALLET_SIZE)):
            current = data[end]
            if quote is not None:
                if escaped:
                    escaped = False
                elif current == 0x5C:
                    escaped = True
                elif current == quote:
                    quote = None
                continue
            if current in (0x22, 0x27):
                quote = current
            elif current in pairs:
                stack.append(pairs[current])
            elif current in pairs.values():
                if not stack or current != stack.pop():
                    break
                if not stack:
                    yield start, end + 1
                    break


def _all_occurrences(data: bytes, token: bytes):
    position = data.find(token)
    while position >= 0:
        yield position
        position = data.find(token, position + 1)


def _base58check_address(value) -> bool:
    if not isinstance(value, str) or not 26 <= len(value) <= 35:
        return False
    number = 0
    try:
        for character in value:
            number = number * 58 + BASE58_ALPHABET.index(character)
    except ValueError:
        return False
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    raw = b"\x00" * (len(value) - len(value.lstrip("1"))) + raw
    if len(raw) != 25 or raw[0] not in {0x00, 0x6F}:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def _network_host(value) -> bool:
    if not isinstance(value, str):
        return False
    if HOSTNAME.fullmatch(value) is not None:
        return True
    parts = value.split(".")
    return len(parts) == 4 and all(
        part.isdigit() and str(int(part)) == part and 0 <= int(part) <= 255
        for part in parts
    )


def _public_key_shape(value) -> bool:
    if isinstance(value, str):
        return bool(HEX_OLD_MPK.fullmatch(value) or value.startswith("xpub"))
    if isinstance(value, (list, tuple)):
        return 2 <= len(value) <= 4 and all(isinstance(item, str) for item in value)
    return False


def _wallet_type(value) -> bool:
    return isinstance(value, str) and (
        value in WALLET_TYPES or re.fullmatch(r"[1-9]\d?of[1-9]\d?", value)
    )


class ElectrumLegacyStructuralValidator:
    def __init__(self) -> None:
        self.electrum_v1 = ElectrumV1Validator()

    def validate(self, value, *, serialization_type: str, raw: bytes,
                 start: int, end: int, text_encoding: str = "UTF_8"
                 ) -> LegacyDetection | None:
        if not isinstance(value, dict) or not all(isinstance(key, (str, int)) for key in value):
            return None
        # Modern post-conversion storage belongs to the existing validator.
        if "keystore" in value or any(re.fullmatch(r"x\d+/", str(key)) for key in value):
            return None
        seed_version = value.get("seed_version")
        if type(seed_version) is not int or not 1 <= seed_version <= 13:
            return None
        accounts = value.get("accounts")
        addresses = value.get("addresses")
        change_addresses = value.get("change_addresses")
        account_layout = isinstance(accounts, dict)
        address_layout = (isinstance(addresses, (list, tuple))
                          and isinstance(change_addresses, (list, tuple))
                          and all(_base58check_address(item) for item in addresses)
                          and all(_base58check_address(item)
                                  for item in change_addresses))
        if not account_layout and not address_layout:
            return None
        wallet_type = value.get("wallet_type")
        if wallet_type is not None and not _wallet_type(wallet_type):
            return None
        old_mpk = value.get("master_public_key")
        mpks = value.get("master_public_keys")
        valid_old_mpk = isinstance(old_mpk, str) and bool(HEX_OLD_MPK.fullmatch(old_mpk))
        valid_mpks = (isinstance(mpks, dict) and bool(mpks)
                      and all(isinstance(key, str) and _public_key_shape(item)
                              for key, item in mpks.items()))
        imported_keys = value.get("imported_keys", {})
        if (not isinstance(imported_keys, dict)
                or not all(_base58check_address(address)
                           and isinstance(private, str) and bool(private)
                           for address, private in imported_keys.items())):
            return None
        imported = self._imported(accounts if account_layout else {}, value)
        if not (valid_old_mpk or valid_mpks or imported):
            return None
        if seed_version <= 6 and not (valid_old_mpk or valid_mpks):
            return None
        use_encryption = value.get("use_encryption", False)
        if type(use_encryption) is not bool:
            return None
        master_private = value.get("master_private_keys", {})
        if not isinstance(master_private, dict):
            return None
        has_seed = isinstance(value.get("seed"), str) and bool(value.get("seed"))
        seed_confirmation = self._seed_confirmation(value.get("seed"))
        has_private = has_seed or bool(master_private) or bool(value.get("imported_keys"))
        watch_only = not has_private
        encryption = "FIELD_LEVEL_ENCRYPTED" if use_encryption and has_private else "PLAINTEXT_STRUCTURE"
        generation = ("ELECTRUM_1_X_LITERAL_STORAGE" if serialization_type == "PYTHON_LITERAL"
                      and wallet_type is None else "ELECTRUM_2_0_TO_2_7_TRANSITIONAL_STORAGE")
        legacy_format = ("ELECTRUM_1X_PYTHON_LITERAL" if generation.startswith("ELECTRUM_1")
                         else f"ELECTRUM_TRANSITIONAL_{serialization_type}")
        safe_field_names = STRUCTURAL_FIELDS - {
            "seed", "master_private_keys", "imported_keys", "keypairs",
        }
        fields = sorted(str(key) for key in value if str(key) in safe_field_names)
        safe = {
            "seed_version": seed_version,
            "wallet_type": wallet_type,
            "keystore_category": ("IMPORTED" if imported else
                                  "OLD_DETERMINISTIC" if valid_old_mpk else "BIP32_PRE_KEYSTORE"),
            "watch_only": watch_only,
            "imported": imported,
            "use_encryption": use_encryption,
            "has_seed_material": has_seed,
            "seed_confirmation": seed_confirmation,
            "has_private_material": has_private,
            "has_imported_keys": bool(imported_keys),
            "has_master_public_key": valid_old_mpk,
            "has_master_public_keys": valid_mpks,
            "account_count": len(accounts) if account_layout else 0,
            "address_layout": "ACCOUNTS" if account_layout else "ADDRESS_LISTS",
            "receiving_address_count": len(addresses) if address_layout else None,
            "change_address_count": len(change_addresses) if address_layout else None,
            "structural_fields": fields,
            "text_encoding": text_encoding,
        }
        reasons = ["ELECTRUM_LEGACY_STORAGE_STRUCTURE_VALID", "LEGACY_REQUIRED_FIELDS_VALID"]
        if use_encryption and has_private:
            reasons.append("LEGACY_FIELD_LEVEL_ENCRYPTION_DECLARED")
        if watch_only:
            reasons.append("LEGACY_WATCH_ONLY_STRUCTURE")
        if imported:
            reasons.append("LEGACY_IMPORTED_STRUCTURE")
        if seed_confirmation in {
                "ELECTRUM_V1_STRICT_VALID", "ELECTRUM_V1_COMPAT_VALID"}:
            reasons.append("ELECTRUM_V1_SEED_CONFIRMED")
        return LegacyDetection(
            start, end, legacy_format, generation, serialization_type,
            "COMPLETE", encryption, "HIGH", tuple(reasons), safe,
            hashlib.sha256(raw).hexdigest(),
        )

    def validate_sequence(self, value, *, raw: bytes, start: int, end: int,
                          text_encoding: str) -> LegacyDetection | None:
        """Validate the exact pre-dict 14-field electrum.dat layout."""
        if not isinstance(value, (tuple, list)) or len(value) != 14:
            return None
        (version, use_encryption, fee, host, port, blocks, seed, addresses,
         private_keys, change_addresses, status, history, labels,
         addressbook) = value
        if type(version) is not int or version != 1:
            return None
        if type(use_encryption) is not bool:
            return None
        if (not isinstance(fee, (int, float)) or isinstance(fee, bool)
                or not 0 <= fee <= 1):
            return None
        if not _network_host(host):
            return None
        if type(port) is not int or not 1 <= port <= 65535:
            return None
        if type(blocks) is not int or not 0 <= blocks <= 100_000_000:
            return None
        if not isinstance(seed, str) or not seed:
            return None
        if not isinstance(addresses, list) or not addresses:
            return None
        if not all(_base58check_address(item) for item in addresses):
            return None
        if not isinstance(change_addresses, list):
            return None
        change_as_indices = all(type(item) is int and 0 <= item < len(addresses)
                                for item in change_addresses)
        change_as_addresses = all(_base58check_address(item)
                                  for item in change_addresses)
        if change_addresses and not (change_as_indices or change_as_addresses):
            return None
        if not isinstance(private_keys, str):
            return None
        if not use_encryption:
            try:
                decoded_private = ast.literal_eval(
                    _python2_literal_compat(private_keys))
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                return None
            if not isinstance(decoded_private, list):
                return None
        if not all(isinstance(item, dict) for item in (status, history, labels)):
            return None
        if not isinstance(addressbook, list) or not all(
                isinstance(item, str) for item in addressbook):
            return None
        seed_confirmation = self._seed_confirmation(seed)
        reasons = [
            "ELECTRUM_PRE_DICT_SEQUENCE_STRUCTURE_VALID",
            "ELECTRUM_PRE_DICT_EXACT_ARITY_VALID",
            "ELECTRUM_PRE_DICT_NETWORK_AND_ADDRESS_EVIDENCE_VALID",
        ]
        if seed_confirmation in {
                "ELECTRUM_V1_STRICT_VALID", "ELECTRUM_V1_COMPAT_VALID"}:
            reasons.append("ELECTRUM_V1_SEED_CONFIRMED")
        serialization = "PYTHON_TUPLE" if isinstance(value, tuple) else "PYTHON_LIST"
        safe = {
            "storage_version": version,
            "use_encryption": use_encryption,
            "network_endpoint_present": True,
            "receiving_address_count": len(addresses),
            "change_address_count": len(change_addresses),
            "change_representation": (
                "INDICES" if change_as_indices else "ADDRESSES"),
            "has_seed_material": True,
            "has_private_material": bool(private_keys),
            "seed_confirmation": seed_confirmation,
            "text_encoding": text_encoding,
        }
        return LegacyDetection(
            start, end, "ELECTRUM_PRE_DICT_SEQUENCE",
            "ELECTRUM_0_X_PRE_DICT_STORAGE", serialization, "COMPLETE",
            "FIELD_LEVEL_ENCRYPTED" if use_encryption else "PLAINTEXT_STRUCTURE",
            "HIGH", tuple(reasons), safe, hashlib.sha256(raw).hexdigest(),
        )

    def _seed_confirmation(self, seed) -> str:
        if not isinstance(seed, str) or not seed:
            return "NOT_APPLICABLE"
        words = tuple(seed.casefold().split())
        if len(words) not in {12, 24} or not all(word.isalpha() for word in words):
            return "NOT_APPLICABLE"
        result = self.electrum_v1.validate_words(words)
        return result.status

    @staticmethod
    def _imported(accounts, value) -> bool:
        if value.get("wallet_type") == "imported" or value.get("key_type") == "imported":
            return True
        if isinstance(value.get("keypairs"), dict) and value["keypairs"]:
            return True
        for account in accounts.values():
            if isinstance(account, dict) and isinstance(account.get("imported"), dict):
                return True
        return False


class ElectrumLegacyCandidateAssembler:
    def __init__(self) -> None:
        self.validator = ElectrumLegacyStructuralValidator()

    def analyze_bytes(self, data: bytes, *, required_anchor_offset: int | None = None):
        found = {}
        balanced_wallet_like = False
        for start, end in _balanced_dicts(data, required_anchor_offset):
            if required_anchor_offset is not None and not start <= required_anchor_offset < end:
                continue
            raw = data[start:end]
            has_layout = (b"accounts" in raw or
                          (b"addresses" in raw and b"change_addresses" in raw))
            if (b"seed_version" in raw and has_layout
                    and (b"master_public_key" in raw or b"wallet_type" in raw)):
                balanced_wallet_like = True
            value = serialization = encoding = None
            for text, selected_encoding in _decoded_texts(raw):
                try:
                    value = json.loads(text)
                    serialization = "JSON"
                    encoding = selected_encoding
                    break
                except json.JSONDecodeError:
                    try:
                        value = ast.literal_eval(_python2_literal_compat(text))
                        serialization = "PYTHON_LITERAL"
                        encoding = selected_encoding
                        break
                    except (ValueError, SyntaxError, MemoryError, RecursionError):
                        continue
            if value is None or serialization is None:
                continue
            candidate = self.validator.validate(
                value, serialization_type=serialization, raw=raw,
                start=start, end=end, text_encoding=encoding or "UNKNOWN",
            )
            if candidate is not None:
                found[(start, end, candidate.legacy_format)] = candidate
        for start, end in _balanced_legacy_sequences(data, required_anchor_offset):
            if required_anchor_offset is not None and not start <= required_anchor_offset < end:
                continue
            raw = data[start:end]
            value = encoding = None
            for text, selected_encoding in _decoded_texts(raw):
                try:
                    value = ast.literal_eval(_python2_literal_compat(text))
                    encoding = selected_encoding
                    break
                except (ValueError, SyntaxError, MemoryError, RecursionError):
                    continue
            if value is None:
                continue
            candidate = self.validator.validate_sequence(
                value, raw=raw, start=start, end=end,
                text_encoding=encoding or "UNKNOWN",
            )
            if candidate is not None:
                found[(start, end, candidate.legacy_format)] = candidate
        if found:
            return tuple(found.values())
        if balanced_wallet_like:
            return ()
        fragment = self._fragment(data, required_anchor_offset)
        return () if fragment is None else (fragment,)

    def _fragment(self, data: bytes, required_anchor_offset: int | None):
        if required_anchor_offset is None:
            sample_start = 0
            sample = data[:MAX_FRAGMENT_SIZE]
            local_anchor = None
        else:
            sample_start = max(0, required_anchor_offset - MAX_FRAGMENT_SIZE)
            sample_end = min(len(data), required_anchor_offset + MAX_FRAGMENT_SIZE)
            sample = data[sample_start:sample_end]
            local_anchor = required_anchor_offset - sample_start
        occurrences = []
        for field in STRUCTURAL_FIELDS:
            encoded = field.encode("ascii")
            for token in (b"'" + encoded + b"'", b'"' + encoded + b'"'):
                position = sample.find(token)
                while position >= 0:
                    occurrences.append((position, field, token[:1]))
                    position = sample.find(token, position + 1)
        if not occurrences:
            return None
        if local_anchor is None:
            center = min(item[0] for item in occurrences)
        else:
            center = local_anchor
        nearby = [item for item in occurrences
                  if abs(item[0] - center) <= MAX_FRAGMENT_FIELD_SPAN]
        if not nearby:
            return None
        first = min(item[0] for item in nearby)
        last = max(item[0] for item in nearby)
        start = sample.rfind(b"{", max(0, first - 4096), first + 1)
        start = first if start < 0 else start
        end = min(len(sample), last + MAX_FRAGMENT_FIELD_SPAN)
        terminators = [position for marker in (b"\x00" * 8, b"\xff" * 8)
                       if (position := sample.find(marker, last)) > last]
        if terminators:
            end = min(end, min(terminators))
        tail = sample[start:end]
        fields = {field for position, field, _ in nearby if start <= position < end}
        seed_version = ElectrumLegacyCandidateAssembler._fragment_seed_version(tail)
        valid_mpk = ElectrumLegacyCandidateAssembler._fragment_old_mpk(tail)
        valid_mpks = ElectrumLegacyCandidateAssembler._fragment_public_masters(tail)
        has_seed = ElectrumLegacyCandidateAssembler._field_has_value(tail, "seed")
        account_layout = "accounts" in fields
        address_layout = {"addresses", "change_addresses"} <= fields
        correlated_core = (
            seed_version is not None
            and (valid_mpk or valid_mpks)
            and (account_layout or address_layout or has_seed)
        )
        damaged_prefix_core = (
            valid_mpk and has_seed and (account_layout or address_layout)
            and "use_encryption" in fields
        )
        if len(fields) < 3 or not (correlated_core or damaged_prefix_core):
            return None
        if "master_public_key" in fields and not valid_mpk:
            return None
        if required_anchor_offset is not None and not start <= local_anchor < end:
            return None
        quote_style = ("PYTHON_LITERAL" if sum(q == b"'" for _, _, q in nearby)
                       >= sum(q == b'"' for _, _, q in nearby) else "JSON")
        completeness = "TRUNCATED" if tail.rstrip()[-1:] != b"}" else "STRUCTURAL_FRAGMENT"
        safe = {
            "structural_fields": sorted(fields),
            "preserved_field_count": len(fields),
            "reconstructed_seed_version": seed_version,
            "has_seed_material": has_seed,
            "has_master_public_key": valid_mpk,
            "has_master_public_keys": valid_mpks,
            "address_layout": ("ACCOUNTS" if account_layout else
                               "ADDRESS_LISTS" if address_layout else None),
            "logical_object_reconstructed": True,
        }
        seed_text = self._fragment_seed_text(tail)
        seed_confirmation = self.validator._seed_confirmation(seed_text)
        safe["seed_confirmation"] = seed_confirmation
        reasons = [
            "ELECTRUM_LEGACY_STRUCTURAL_FRAGMENT",
            "LEGACY_MULTIPLE_FIELDS_PRESERVED",
            "ELECTRUM_LEGACY_LOGICAL_OBJECT_RECONSTRUCTED",
        ]
        if seed_confirmation in {
                "ELECTRUM_V1_STRICT_VALID", "ELECTRUM_V1_COMPAT_VALID"}:
            reasons.append("ELECTRUM_V1_SEED_CONFIRMED")
        return LegacyDetection(
            sample_start + start, sample_start + start + len(tail),
            f"ELECTRUM_TRANSITIONAL_{quote_style}_FRAGMENT",
            "ELECTRUM_1_X_TO_2_7_LEGACY_STORAGE", quote_style,
            completeness, "UNKNOWN", "MEDIUM",
            tuple(reasons),
            safe, hashlib.sha256(tail).hexdigest(),
        )

    @staticmethod
    def _fragment_seed_version(raw: bytes) -> int | None:
        match = re.search(
            rb"[\"']seed_version[\"']\s*:\s*(\d{1,3})\b", raw
        )
        if match is None:
            return None
        value = int(match.group(1))
        return value if 1 <= value <= 13 else None

    @staticmethod
    def _fragment_old_mpk(raw: bytes) -> bool:
        match = re.search(
            rb"[\"']master_public_key[\"']\s*:\s*[\"']([0-9a-fA-F]{128})[\"']",
            raw,
        )
        return match is not None

    @staticmethod
    def _fragment_public_masters(raw: bytes) -> bool:
        match = re.search(
            rb"[\"']master_public_keys[\"']\s*:\s*.{0,2048}?"
            rb"(?:xpub[1-9A-HJ-NP-Za-km-z]{16,}|[0-9a-fA-F]{128})",
            raw,
            re.DOTALL,
        )
        return match is not None

    @staticmethod
    def _field_has_value(raw: bytes, field: str) -> bool:
        encoded = re.escape(field.encode("ascii"))
        return re.search(rb"[\"']" + encoded + rb"[\"']\s*:\s*[\"'][^\"']+", raw) is not None

    @staticmethod
    def _fragment_seed_text(raw: bytes) -> str | None:
        match = re.search(rb"[\"']seed[\"']\s*:\s*([\"'])([^\"']+)\1", raw)
        if match is None:
            return None
        try:
            return match.group(2).decode("ascii")
        except UnicodeDecodeError:
            return None
