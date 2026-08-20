from __future__ import annotations

import hashlib

import pytest

from bfrs.recovery.mnemonic.bip39_validator import BIP39Validator
from bfrs.recovery.mnemonic.electrum_seed_validator import ElectrumSeedValidator
from bfrs.recovery.mnemonic.electrum_v1_validator import ElectrumV1Validator
from bfrs.recovery.mnemonic.mnemonic_recovery_pipeline import MnemonicRecoveryPipeline
from bfrs.recovery.mnemonic.raw_mnemonic_scanner import RawMnemonicScanner


OFFICIAL_ENTROPY = "8edad31a95e7d59f8837667510d75a4d"
OFFICIAL_WORDS = (
    "hardly point goal hallway patience key stone difference ready caught listen fact")
INVALID_33_HEX = (
    "hurry idiot prefer sunset mention mist jaw inhale impossible kingdom rare squeeze")


def _scanner() -> RawMnemonicScanner:
    return RawMnemonicScanner(chunk_size=8192, overlap=4096)


def _v1_occurrences(payload: bytes):
    return [item for item in _scanner().scan_bytes(payload).occurrences
            if item.candidate.mnemonic_standard == "ELECTRUM_V1"]


def _bip39_phrase() -> str:
    validator = BIP39Validator()
    entropy = bytes(range(16))
    bits = "".join(f"{byte:08b}" for byte in entropy)
    bits += f"{hashlib.sha256(entropy).digest()[0]:08b}"[:4]
    words = sorted(validator.indices["english"],
                   key=validator.indices["english"].get)
    return " ".join(words[int(bits[index:index + 11], 2)]
                    for index in range(0, len(bits), 11))


def _electrum_v2_phrase() -> str:
    validator = ElectrumSeedValidator()
    words = sorted(validator.wordlists["english"])
    for number in range(100_000):
        phrase = " ".join([words[0]] * 11 + [words[number % len(words)]])
        if validator.validate(phrase).status == "ELECTRUM_SEED_VALID":
            return phrase
    raise AssertionError("deterministic Electrum 2+ fixture not found")


def test_official_electrum_v1_vector_encode_decode_and_strict_validation():
    validator = ElectrumV1Validator()
    words = tuple(OFFICIAL_WORDS.split())
    assert len(validator.wordlist) == 1626
    assert validator.mn_decode(words) == OFFICIAL_ENTROPY
    assert validator.mn_encode(OFFICIAL_ENTROPY) == words
    result = validator.validate(OFFICIAL_WORDS)
    assert result.status == "ELECTRUM_V1_STRICT_VALID"
    assert result.seed_type == "old"
    assert result.reason_codes == (
        "ELECTRUM_V1_WORDLIST_VALID", "ELECTRUM_V1_ROUNDTRIP_VALID",
        "ELECTRUM_V1_ENTROPY_LENGTH_VALID")
    assert OFFICIAL_ENTROPY not in repr(result)


@pytest.mark.parametrize("entropy", [
    "000102030405060708090a0b0c0d0e0f",
    "00112233445566778899aabbccddeeff",
    "fedcba98765432100123456789abcdef",
])
def test_deterministic_128_bit_roundtrips(entropy):
    validator = ElectrumV1Validator()
    words = validator.mn_encode(entropy)
    assert len(words) == 12
    assert validator.mn_decode(words) == entropy
    assert validator.validate_words(words).status == "ELECTRUM_V1_STRICT_VALID"


def test_electrum_weak_33_hex_compatibility_case_is_strictly_rejected():
    validator = ElectrumV1Validator()
    words = tuple(INVALID_33_HEX.split())
    assert len(validator.mn_decode(words)) == 33
    result = validator.validate_words(words)
    assert result.status == "ELECTRUM_V1_INVALID_ENTROPY_LENGTH"
    assert "ELECTRUM_V1_INVALID_ENTROPY_LENGTH" in result.reason_codes
    assert not _v1_occurrences(INVALID_33_HEX.encode())


def test_electrum_v1_word_and_count_failures():
    validator = ElectrumV1Validator()
    words = tuple(OFFICIAL_WORDS.split())
    assert validator.validate_words(words[:11]).status == "ELECTRUM_V1_WORD_COUNT_INVALID"
    assert validator.validate_words(words + ("like",)).status == "ELECTRUM_V1_WORD_COUNT_INVALID"
    damaged = words[:5] + ("not-in-old-wordlist",) + words[6:]
    assert validator.validate_words(damaged).status == "ELECTRUM_V1_WORD_INVALID"
    assert not _v1_occurrences(" ".join(words[:11]).encode())
    thirteen = _scanner().scan_bytes(" ".join(words + ("like",)).encode())
    assert not [item for item in thirteen.occurrences
                if item.candidate.mnemonic_standard == "ELECTRUM_V1"]
    assert thirteen.anchors_found == 0


@pytest.mark.parametrize("separator", ["    ", "\t", "\n", "\r\n", " \r\n\t "])
def test_electrum_v1_scanner_accepts_whitespace_and_mixed_case(separator):
    payload = separator.join(OFFICIAL_WORDS.upper().split()).encode()
    matches = _v1_occurrences(payload)
    assert len([item for item in matches if item.candidate.encoding == "utf-8"]) == 1
    assert matches[0].candidate.validation_status == "ELECTRUM_V1_STRICT_VALID"


@pytest.mark.parametrize("separator", [",", " ; ", " / ", "-", "<b>"])
def test_electrum_v1_scanner_rejects_punctuation_and_markup_separators(separator):
    payload = separator.join(OFFICIAL_WORDS.split()).encode()
    assert not _v1_occurrences(payload)


def test_electrum_v1_scanner_rejects_foreign_token_inside_phrase():
    words = OFFICIAL_WORDS.split()
    payload = " ".join(words[:6] + ["intruder-token"] + words[6:]).encode()
    assert not _v1_occurrences(payload)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
def test_electrum_v1_encodings_source_span_and_negative(encoding):
    prefix = "noise:"
    payload = (prefix + OFFICIAL_WORDS + ":tail").encode(encoding)
    match = next(item for item in _v1_occurrences(payload)
                 if item.candidate.encoding == encoding)
    candidate = match.candidate
    assert candidate.physical_start == len(prefix.encode(encoding))
    assert candidate.physical_end == len((prefix + OFFICIAL_WORDS).encode(encoding))
    assert payload[candidate.physical_start:candidate.physical_end].decode(encoding) == OFFICIAL_WORDS
    broken = ",".join(OFFICIAL_WORDS.split()).encode(encoding)
    assert not [item for item in _v1_occurrences(broken)
                if item.candidate.encoding == encoding]


def test_electrum_v1_raw_confidence_and_secret_safe_metadata():
    match = next(item for item in _v1_occurrences(OFFICIAL_WORDS.encode())
                 if item.candidate.encoding == "utf-8")
    assert match.candidate.confidence == "MEDIUM"
    assert "ELECTRUM_V1_SOURCE_SPAN_VALID" in match.candidate.reason_codes
    serialized = str(match.candidate.safe_dict())
    assert OFFICIAL_WORDS not in serialized
    assert OFFICIAL_ENTROPY not in serialized


def test_electrum_v1_24_word_compatibility():
    validator = ElectrumV1Validator()
    entropy = OFFICIAL_ENTROPY + "00112233445566778899aabbccddeeff"
    words = validator.mn_encode(entropy)
    assert len(words) == 24
    assert validator.mn_decode(words) == entropy
    result = validator.validate_words(words)
    assert result.status == "ELECTRUM_V1_COMPAT_VALID"
    match = next(item for item in _v1_occurrences(" ".join(words).encode())
                 if item.candidate.word_count == 24 and item.candidate.encoding == "utf-8")
    assert match.candidate.confidence == "MEDIUM"
    matches = [item for item in _v1_occurrences(" ".join(words).encode())
               if item.candidate.encoding == "utf-8"]
    assert len(matches) == 1
    assert not _v1_occurrences(" ".join(words + ("like",)).encode())


@pytest.mark.parametrize("payload", [
    "This ordinary English paragraph discusses weather, people, work, and time without containing a wallet recovery phrase.",
    "similar term; related concept; word-like entry; dictionary definition; see also another term",
    '<html><script>const config = {name: "wallet", value: false};</script></html>',
    'PUBLIC:PROPERTY NAME="text"; seed_version = 4; use_encryption = false;',
])
def test_electrum_v1_false_positive_controls(payload):
    assert not _v1_occurrences(payload.encode())


def test_electrum_v1_deduplicates_same_secret_without_cross_standard_identity(tmp_path):
    source = tmp_path / "duplicates.bin"
    source.write_bytes((OFFICIAL_WORDS + " foreign " + OFFICIAL_WORDS).encode())
    result = MnemonicRecoveryPipeline(chunk_size=8192, overlap=4096).scan(source)
    candidates = [item for item in result.recovery.candidates
                  if item.mnemonic_standard == "ELECTRUM_V1"]
    assert len(candidates) == 1
    assert candidates[0].duplicate_count == 2
    assert result.recovery.duplicate_occurrences >= 1


def test_standard_interactions_remain_independent():
    old_result = _scanner().scan_bytes(OFFICIAL_WORDS.encode())
    assert {item.candidate.mnemonic_standard for item in old_result.occurrences} == {
        "ELECTRUM_V1"}
    bip39_result = _scanner().scan_bytes(_bip39_phrase().encode())
    assert "BIP39" in {item.candidate.mnemonic_standard for item in bip39_result.occurrences}
    assert "ELECTRUM_V1" not in {
        item.candidate.mnemonic_standard for item in bip39_result.occurrences}
    modern_result = _scanner().scan_bytes(_electrum_v2_phrase().encode())
    standards = {item.candidate.mnemonic_standard for item in modern_result.occurrences}
    assert "ELECTRUM" in standards
    assert "ELECTRUM_V1" not in standards
    invalid_result = _scanner().scan_bytes(INVALID_33_HEX.encode())
    assert not {"ELECTRUM_V1", "BIP39"} & {
        item.candidate.mnemonic_standard for item in invalid_result.occurrences}
