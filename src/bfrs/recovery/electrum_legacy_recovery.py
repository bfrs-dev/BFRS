"""Strict structural detection of confirmed pre-keystore Electrum storage."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
import re


LEGACY_ELECTRUM_SIGNATURE_PATTERNS = (
    ("electrum_legacy_seed_version_single_quote", b"'seed_version'"),
    ("electrum_legacy_master_public_key_single_quote", b"'master_public_key'"),
    ("electrum_legacy_master_public_keys_single_quote", b"'master_public_keys'"),
    ("electrum_legacy_accounts_single_quote", b"'accounts'"),
    ("electrum_legacy_use_encryption_single_quote", b"'use_encryption'"),
)
LEGACY_ELECTRUM_SIGNATURE_NAMES = frozenset(
    name for name, _ in LEGACY_ELECTRUM_SIGNATURE_PATTERNS
)
MAX_LEGACY_WALLET_SIZE = 32 * 1024 * 1024
MAX_FRAGMENT_SIZE = 256 * 1024
HEX_OLD_MPK = re.compile(r"[0-9a-fA-F]{128}")
WALLET_TYPES = frozenset({
    "old", "standard", "xpub", "imported", "bip44", "2fa",
    "trezor", "keepkey", "ledger", "btchip",
})
STRUCTURAL_FIELDS = frozenset({
    "seed_version", "wallet_type", "accounts", "master_public_key",
    "master_public_keys", "master_private_keys", "use_encryption",
    "imported_keys", "keypairs", "key_type", "seed",
})


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
    def validate(self, value, *, serialization_type: str, raw: bytes,
                 start: int, end: int) -> LegacyDetection | None:
        if not isinstance(value, dict) or not all(isinstance(key, (str, int)) for key in value):
            return None
        # Modern post-conversion storage belongs to the existing validator.
        if "keystore" in value or any(re.fullmatch(r"x\d+/", str(key)) for key in value):
            return None
        seed_version = value.get("seed_version")
        if type(seed_version) is not int or not 1 <= seed_version <= 13:
            return None
        accounts = value.get("accounts")
        if not isinstance(accounts, dict):
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
        imported = self._imported(accounts, value)
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
            "has_private_material": has_private,
            "has_master_public_key": valid_old_mpk,
            "has_master_public_keys": valid_mpks,
            "account_count": len(accounts),
            "structural_fields": fields,
        }
        reasons = ["ELECTRUM_LEGACY_STORAGE_STRUCTURE_VALID", "LEGACY_REQUIRED_FIELDS_VALID"]
        if use_encryption and has_private:
            reasons.append("LEGACY_FIELD_LEVEL_ENCRYPTION_DECLARED")
        if watch_only:
            reasons.append("LEGACY_WATCH_ONLY_STRUCTURE")
        if imported:
            reasons.append("LEGACY_IMPORTED_STRUCTURE")
        return LegacyDetection(
            start, end, legacy_format, generation, serialization_type,
            "COMPLETE", encryption, "HIGH", tuple(reasons), safe,
            hashlib.sha256(raw).hexdigest(),
        )

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
            if (b"seed_version" in raw and b"accounts" in raw
                    and (b"master_public_key" in raw or b"wallet_type" in raw)):
                balanced_wallet_like = True
            value = serialization = None
            try:
                value = json.loads(raw.decode("utf-8"))
                serialization = "JSON"
            except (UnicodeDecodeError, json.JSONDecodeError):
                try:
                    value = ast.literal_eval(raw.decode("utf-8"))
                    serialization = "PYTHON_LITERAL"
                except (UnicodeDecodeError, ValueError, SyntaxError, MemoryError, RecursionError):
                    continue
            candidate = self.validator.validate(
                value, serialization_type=serialization, raw=raw,
                start=start, end=end,
            )
            if candidate is not None:
                found[(start, end, candidate.legacy_format)] = candidate
        if found:
            return tuple(found.values())
        if balanced_wallet_like:
            return ()
        fragment = self._fragment(data, required_anchor_offset)
        return () if fragment is None else (fragment,)

    @staticmethod
    def _fragment(data: bytes, required_anchor_offset: int | None):
        if required_anchor_offset is None:
            sample_start = 0
            sample = data[:MAX_FRAGMENT_SIZE]
            start = sample.find(b"{")
        else:
            sample_start = max(0, required_anchor_offset - MAX_FRAGMENT_SIZE)
            sample_end = min(len(data), required_anchor_offset + MAX_FRAGMENT_SIZE)
            sample = data[sample_start:sample_end]
            local_anchor = required_anchor_offset - sample_start
            start = sample.rfind(b"{", 0, local_anchor + 1)
        if start < 0:
            return None
        tail = sample[start:]
        terminators = [position for marker in (b"\x00", b"\r\n\x00", b"\n\x00")
                       if (position := tail.find(marker)) > 0]
        if terminators:
            tail = tail[:min(terminators)]
        fields = set()
        for field in STRUCTURAL_FIELDS:
            encoded = field.encode("ascii")
            if b"'" + encoded + b"'" in tail or b'"' + encoded + b'"' in tail:
                fields.add(field)
        strong = "seed_version" in fields and "accounts" in fields and bool(
            fields & {"master_public_key", "master_public_keys", "wallet_type"}
        )
        if not strong or len(fields) < 3:
            return None
        if required_anchor_offset is not None and not start <= local_anchor < len(sample):
            return None
        quote_style = "PYTHON_LITERAL" if b"'seed_version'" in tail else "JSON"
        completeness = "TRUNCATED" if tail.rstrip()[-1:] != b"}" else "STRUCTURAL_FRAGMENT"
        safe = {"structural_fields": sorted(fields), "preserved_field_count": len(fields)}
        return LegacyDetection(
            sample_start + start, sample_start + start + len(tail),
            f"ELECTRUM_TRANSITIONAL_{quote_style}_FRAGMENT",
            "ELECTRUM_1_X_TO_2_7_LEGACY_STORAGE", quote_style,
            completeness, "UNKNOWN", "MEDIUM",
            ("ELECTRUM_LEGACY_STRUCTURAL_FRAGMENT", "LEGACY_MULTIPLE_FIELDS_PRESERVED"),
            safe, hashlib.sha256(tail).hexdigest(),
        )
